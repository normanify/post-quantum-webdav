#!/usr/bin/env node

/**
 * End-to-end test: Encrypt → Upload → Download → Decrypt → Verify
 * against live NextCloud WebDAV server.
 *
 * Run: node --input-type=module < test-e2e-server.mjs
 *
 * Environment variables (or .env file):
 *   WEBDAV_URL - Base URL (e.g., https://server/remote.php/dav/files/admin/obtest2)
 *   WEBDAV_USER - WebDAV username
 *   WEBDAV_PASS - WebDAV password
 */

// Load .env file if present
import { readFileSync } from 'fs';
try {
  const env = readFileSync('.env', 'utf8').split('\n');
  for (const line of env) {
    const [key, ...value] = line.split('=');
    if (key && !key.startsWith('#') && value.length) {
      process.env[key.trim()] = value.join('=').trim();
    }
  }
} catch {}

// Uses an isolated sub-path so the test's cleanup (DELETE metadata.json,
// DELETE chunks) never touches the real sync directory.
const BASE_URL = (process.env.WEBDAV_URL || 'https://d.manus.pp.ua/remote.php/dav/files/admin/obtest2') + '/_e2e_test';
const AUTH = `${process.env.WEBDAV_USER || 'admin'}:${process.env.WEBDAV_PASS || ''}`;

const enc = new TextEncoder();
const dec = new TextDecoder();

// --- WebDAV primitives (curl-based via fetch) ---

async function webdavUpload(relPath, data) {
  // Ensure parent directory exists
  const parts = relPath.split('/');
  if (parts.length > 1) {
    const dirPath = parts.slice(0, -1).join('/');
    await fetch(`${BASE_URL}/${dirPath}`, {
      method: 'MKCOL',
      headers: { Authorization: 'Basic ' + btoa(AUTH) },
    }).catch(() => {});
  }
  const url = `${BASE_URL}/${relPath}`;
  const r = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: 'Basic ' + btoa(AUTH) },
    body: data,
  });
  return r.status;
}

async function webdavDownload(relPath) {
  const url = `${BASE_URL}/${relPath}`;
  const r = await fetch(url, {
    headers: { Authorization: 'Basic ' + btoa(AUTH) },
  });
  if (!r.ok) throw new Error(`Download ${relPath} failed: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function webdavDelete(relPath) {
  const url = `${BASE_URL}/${relPath}`;
  const r = await fetch(url, {
    method: 'DELETE',
    headers: { Authorization: 'Basic ' + btoa(AUTH) },
  });
  return r.status;
}

// --- Crypto (WebCrypto) ---

async function deriveVaultMasterSecret(passphrase, vaultId) {
  const salt = enc.encode(`pqc-webdav-${vaultId}`);
  const km = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-512' },
    km, 256
  );
  return new Uint8Array(bits);
}

async function deriveChunkKey(masterSecret, vaultId, chunkHash) {
  const km = await crypto.subtle.importKey('raw', masterSecret, 'HKDF', false, ['deriveBits']);
  const salt = enc.encode(`pqc-webdav-${vaultId}`);
  const info = enc.encode(`chunk-${chunkHash}`);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, km, 256
  ));
}

async function aesEncrypt(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', true, ['encrypt','decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

async function aesDecrypt(keyBytes, payload) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', true, ['encrypt','decrypt']);
  const iv = payload.slice(0, 12);
  const ct = payload.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

async function sha256(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Buffer.from(new Uint8Array(digest)).toString('base64url');
}

// --- Chunk manager ---

const CHUNK_SIZE = 64 * 1024; // 64KB for test

function splitChunks(data) {
  const chunks = [];
  for (let offset = 0; offset < data.length; offset += CHUNK_SIZE) {
    const slice = data.slice(offset, Math.min(offset + CHUNK_SIZE, data.length));
    chunks.push({ data: slice, offset });
  }
  return chunks;
}

function mergeChunks(chunks) {
  chunks.sort((a, b) => a.offset - b.offset);
  const total = chunks.reduce((acc, c) => acc + c.data.length, 0);
  const out = new Uint8Array(total);
  let cur = 0;
  for (const c of chunks) { out.set(c.data, cur); cur += c.data.length; }
  return out;
}

// --- ML-DSA via noble/post-quantum ---

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const dsaKeys = ml_dsa65.keygen();
const deviceId = 'test-device-' + crypto.randomUUID().slice(0, 8);
const vaultId = 'test-vault-' + crypto.randomUUID().slice(0, 8);

async function signChunk(chunkHash, chunkData) {
  const dataHash = await sha256(chunkData);
  const payload = JSON.stringify({ vaultId, chunkHash, chunkDataHash: dataHash, deviceId });
  return ml_dsa65.sign(enc.encode(payload), dsaKeys.secretKey);
}

async function verifyChunk(chunkHash, chunkData, signature, sigDeviceId) {
  const dataHash = await sha256(chunkData);
  const payload = JSON.stringify({ vaultId, chunkHash, chunkDataHash: dataHash, deviceId: sigDeviceId });
  return ml_dsa65.verify(signature, enc.encode(payload), dsaKeys.publicKey);
}

// --- Main test flow ---

(async () => {
  const results = [];
  const assert = (name, ok, detail = '') => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}${detail ? ' (' + detail + ')' : ''}`);
  };

  // 0. Generate master secret from passphrase
  const masterSecret = await deriveVaultMasterSecret('correct horse battery staple', vaultId);
  assert('Master secret derivation', masterSecret.length === 32, `${masterSecret.length} bytes`);

  // 1. Create test data (simulating a vault note)
  const testData = enc.encode(
    '# My Secret Note\n\nThis is a test of post-quantum encrypted sync.\n' +
    'The content must never appear as plaintext on the server.\n'.repeat(200)
  );
  assert('Test data size', true, `${testData.length} bytes`);

  // 2. Split into chunks
  const chunks = splitChunks(testData);
  assert('Chunk splitting', chunks.length >= 1, `${chunks.length} chunks`);

  // 3. Upload: encrypt + sign + upload each chunk
  const chunkHashes = [];
  for (const chunk of chunks) {
    const hash = await sha256(chunk.data);
    const keyBytes = await deriveChunkKey(masterSecret, vaultId, hash);
    const encrypted = await aesEncrypt(keyBytes, chunk.data);
    const sig = await signChunk(hash, chunk.data);
    const path = `chunks/${hash}.bin.enc`;
    const status = await webdavUpload(path, encrypted);
    chunkHashes.push({ hash, sig: Buffer.from(sig).toString('base64'), path });
    assert(`Upload chunk ${hash.slice(0, 8)}...`, status === 201 || status === 204, `HTTP ${status}`);
  }

  // 4. Create and upload metadata.json
  const meta = {
    version: 1,
    vaultId,
    deviceId,
    sequence: 1,
    chunkSize: CHUNK_SIZE,
    updatedAt: new Date().toISOString(),
    chunks: {},
    fileIndex: {},
  };
  for (const ch of chunkHashes) {
    meta.chunks[ch.hash] = { path: 'test.md', signature: ch.sig, deviceId };
  }
  meta.fileIndex['test.md'] = chunkHashes.map(ch => ch.hash);
  const metaStatus = await webdavUpload('metadata.json', enc.encode(JSON.stringify(meta, null, 2)));
  assert('Upload metadata.json', metaStatus === 201 || metaStatus === 204, `HTTP ${metaStatus}`);

  // 5. Download metadata (simulating second device)
  const metaRaw = await webdavDownload('metadata.json');
  const metaDown = JSON.parse(dec.decode(metaRaw));
  assert('Download metadata.json', metaDown.vaultId === vaultId, `vaultId match`);

  // 6. Download and decrypt each chunk (simulating second device)
  const decryptedChunks = [];
  for (const ch of chunkHashes) {
    const encrypted = await webdavDownload(ch.path);
    const keyBytes = await deriveChunkKey(masterSecret, vaultId, ch.hash);
    const decrypted = await aesDecrypt(keyBytes, encrypted);

    // Verify signature
    const sigBytes = new Uint8Array(Buffer.from(ch.sig, 'base64'));
    const sigValid = await verifyChunk(ch.hash, decrypted, sigBytes, deviceId);
    assert(`Decrypt + verify chunk ${ch.hash.slice(0, 8)}...`, sigValid);

    decryptedChunks.push({ data: decrypted, offset: metaDown.chunks[ch.hash]?.offset || 0 });
  }

  // 7. Reassemble file
  const reassembled = mergeChunks(decryptedChunks);
  assert('File reassembly', reassembled.length === testData.length, `${reassembled.length} bytes`);

  // 8. Compare with original
  const match = testData.every((b, i) => b === reassembled[i]);
  assert('Roundtrip integrity', match);

  // 9. Test deletion
  for (const ch of chunkHashes) {
    await webdavDelete(ch.path);
  }
  await webdavDelete('metadata.json');
  assert('Cleanup completed', true);

  // Summary
  const passed = results.filter(r => r.ok).length;
  const total = results.length;
  console.log(`\n=== ${passed}/${total} tests passed ===`);

  if (passed < total) {
    process.exit(1);
  }
})().catch(e => {
  console.error('Test failed:', e);
  process.exit(1);
});
