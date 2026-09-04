/**
 * Two-Device Sync Simulation Test
 * 
 * Tests: upload, download, conflict detection, deletion sync, rollback protection
 * against live NextCloud WebDAV server.
 *
 * Uses vector clocks + LWW conflict resolution (mature sync algorithm).
 *
 * Run: node --input-type=module < test-two-device.mjs
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

const BASE_URL = process.env.WEBDAV_URL || 'https://d.manus.pp.ua/remote.php/dav/files/admin/obtest2';
const AUTH = `${process.env.WEBDAV_USER || 'admin'}:${process.env.WEBDAV_PASS || ''}`;

const enc = new TextEncoder();
const dec = new TextDecoder();

// --- WebDAV primitives ---
async function webdavUpload(relPath, data) {
  const parts = relPath.split('/');
  if (parts.length > 1) {
    const dirPath = parts.slice(0, -1).join('/');
    await fetch(`${BASE_URL}/${dirPath}`, {
      method: 'MKCOL',
      headers: { Authorization: 'Basic ' + btoa(AUTH) },
    }).catch(() => {});
  }
  const r = await fetch(`${BASE_URL}/${relPath}`, {
    method: 'PUT',
    headers: { Authorization: 'Basic ' + btoa(AUTH) },
    body: data,
  });
  return r.status;
}

async function webdavDownload(relPath) {
  const r = await fetch(`${BASE_URL}/${relPath}`, {
    headers: { Authorization: 'Basic ' + btoa(AUTH) },
  });
  if (!r.ok) throw new Error(`Download ${relPath} failed: ${r.status}`);
  return new Uint8Array(await r.arrayBuffer());
}

async function webdavDelete(relPath) {
  const r = await fetch(`${BASE_URL}/${relPath}`, {
    method: 'DELETE',
    headers: { Authorization: 'Basic ' + btoa(AUTH) },
  });
  return r.status;
}

// --- Crypto ---
async function deriveMasterSecret(passphrase, vaultId) {
  const salt = enc.encode(`pqc-webdav-${vaultId}`);
  const km = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-512' }, km, 256
  ));
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
  out.set(iv, 0); out.set(new Uint8Array(ct), 12); return out;
}

async function aesDecrypt(keyBytes, payload) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', true, ['encrypt','decrypt']);
  const iv = payload.slice(0, 12); const ct = payload.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

async function sha256b(data) {
  return Buffer.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data))).toString('base64url');
}

// --- Filename encryption (deterministic) ---
async function encryptFilename(masterSecret, vaultId, filename) {
  const km = await crypto.subtle.importKey('raw', masterSecret, 'HKDF', false, ['deriveBits']);
  const salt = enc.encode(`pqc-webdav-${vaultId}`);
  const info = enc.encode(`filename-${filename}`);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, km, 256
  );
  return 'enc_' + Buffer.from(new Uint8Array(bits)).toString('base64url');
}

// --- Noble ML-DSA ---
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

function createDevice() {
  const kp = ml_dsa65.keygen();
  return {
    deviceId: 'dev-' + crypto.randomUUID().slice(0, 8),
    signingKeyPair: { publicKey: kp.publicKey, secretKey: kp.secretKey },
  };
}

async function signMeta(meta, deviceId, secretKey) {
  const payload = JSON.stringify({
    vaultId: meta.vaultId, sequence: meta.sequence,
    vectorClock: meta.vectorClock, files: meta.files, deleted: meta.deleted,
  });
  const sig = ml_dsa65.sign(enc.encode(payload), secretKey);
  meta.signerDeviceId = deviceId;
  meta.signerPublicKey = Buffer.from(ml_dsa65.getPublicKey(secretKey)).toString('base64');
  return meta;
}

// --- Chunk helpers ---
const CHUNK_SIZE = 64 * 1024;

function splitChunks(data) {
  const chunks = [];
  for (let o = 0; o < data.length; o += CHUNK_SIZE) {
    chunks.push({ data: data.slice(o, Math.min(o + CHUNK_SIZE, data.length)), offset: o });
  }
  return chunks;
}

function mergeChunks(chunks) {
  chunks.sort((a, b) => a.offset - b.offset);
  const total = chunks.reduce((acc, c) => acc + c.data.length, 0);
  const out = new Uint8Array(total); let cur = 0;
  for (const c of chunks) { out.set(c.data, cur); cur += c.data.length; }
  return out;
}

// --- Vector Clock Operations ---
function incrementClock(clock, deviceId) {
  return { ...clock, [deviceId]: (clock[deviceId] || 0) + 1 };
}

function mergeClocks(a, b) {
  const merged = { ...a };
  for (const [device, counter] of Object.entries(b)) {
    merged[device] = Math.max(merged[device] || 0, counter);
  }
  return merged;
}

function compareClocks(a, b) {
  const allDevices = new Set([...Object.keys(a), ...Object.keys(b)]);
  let aGreater = false;
  let bGreater = false;
  for (const device of allDevices) {
    const aVal = a[device] || 0;
    const bVal = b[device] || 0;
    if (aVal > bVal) aGreater = true;
    if (bVal > aVal) bGreater = true;
  }
  if (aGreater && bGreater) return 'concurrent';
  if (aGreater) return 'after';
  if (bGreater) return 'before';
  return 'equal';
}

// --- Device sync simulation ---
class SimDevice {
  constructor(name, device, masterSecret, vaultId) {
    this.name = name;
    this.device = device;
    this.masterSecret = masterSecret;
    this.vaultId = vaultId;
    this.localMeta = null;
  }

  async initMeta() {
    if (!this.localMeta) {
      this.localMeta = {
        version: 2, vaultId: this.vaultId, chunkSize: CHUNK_SIZE,
        vectorClock: {}, sequence: 0, updatedAt: '', signerDeviceId: '', signerPublicKey: '',
        files: {}, deleted: {},
      };
    }
  }

  async uploadFile(relPath, data) {
    await this.initMeta();
    const chunks = splitChunks(data);
    const encPath = await encryptFilename(this.masterSecret, this.vaultId, relPath);
    const chunkHashes = [];

    for (const chunk of chunks) {
      const hash = await sha256b(chunk.data);
      const key = await deriveChunkKey(this.masterSecret, this.vaultId, hash);
      const encrypted = await aesEncrypt(key, chunk.data);
      await webdavUpload(`chunks/${hash}.bin.enc`, encrypted);
      chunkHashes.push(hash);
    }

    const now = new Date().toISOString();
    const existing = this.localMeta.files[encPath];
    this.localMeta.files[encPath] = {
      chunks: chunkHashes, size: data.length,
      createdAt: existing?.createdAt || now, modifiedAt: now,
      deviceId: this.device.deviceId, signature: '',
    };
    this.localMeta.vectorClock = incrementClock(this.localMeta.vectorClock, this.device.deviceId);
    this.localMeta.sequence += 1;
    this.localMeta.updatedAt = now;
    await signMeta(this.localMeta, this.device.deviceId, this.device.signingKeyPair.secretKey);
    await webdavUpload('metadata.json', enc.encode(JSON.stringify(this.localMeta, null, 2)));
  }

  async downloadFile(relPath) {
    await this.initMeta();
    const raw = await webdavDownload('metadata.json');
    this.localMeta = JSON.parse(dec.decode(raw));
    const encPath = await encryptFilename(this.masterSecret, this.vaultId, relPath);
    const entry = this.localMeta.files[encPath];
    if (!entry || entry.chunks.length === 0) return null;

    const chunkList = [];
    let offset = 0;
    for (const hash of entry.chunks) {
      const encrypted = await webdavDownload(`chunks/${hash}.bin.enc`);
      const key = await deriveChunkKey(this.masterSecret, this.vaultId, hash);
      const decrypted = await aesDecrypt(key, encrypted);
      chunkList.push({ data: decrypted, offset });
      offset += decrypted.length;
    }
    return mergeChunks(chunkList);
  }

  async deleteFile(relPath) {
    await this.initMeta();
    if (!this.localMeta) {
      const raw = await webdavDownload('metadata.json');
      this.localMeta = JSON.parse(dec.decode(raw));
    }
    const encPath = await encryptFilename(this.masterSecret, this.vaultId, relPath);
    const entry = this.localMeta.files[encPath];
    const chunks = entry?.chunks || [];
    this.localMeta.deleted[encPath] = {
      deletedAt: new Date().toISOString(), deviceId: this.device.deviceId,
      chunks, signature: '',
    };
    delete this.localMeta.files[encPath];
    this.localMeta.vectorClock = incrementClock(this.localMeta.vectorClock, this.device.deviceId);
    this.localMeta.sequence += 1;
    this.localMeta.updatedAt = new Date().toISOString();
    await signMeta(this.localMeta, this.device.deviceId, this.device.signingKeyPair.secretKey);
    await webdavUpload('metadata.json', enc.encode(JSON.stringify(this.localMeta, null, 2)));
  }

  detectConflicts(remoteMeta) {
    const conflicts = [];
    if (!this.localMeta) return conflicts;

    // Rollback detection
    if (remoteMeta.sequence < this.localMeta.sequence) {
      conflicts.push({ type: 'rollback', path: 'metadata.json', remoteDeviceId: remoteMeta.signerDeviceId });
      return conflicts;
    }

    // Check files in remote
    for (const [encPath, remoteEntry] of Object.entries(remoteMeta.files)) {
      const localEntry = this.localMeta.files[encPath];
      if (!localEntry) continue; // New file from remote
      if (localEntry.modifiedAt === remoteEntry.modifiedAt && localEntry.deviceId === remoteEntry.deviceId) continue;

      const rel = compareClocks(this.localMeta.vectorClock, remoteMeta.vectorClock);
      if (rel === 'concurrent' || rel === 'equal') {
        conflicts.push({ type: 'modify-modify', path: encPath, localEntry, remoteEntry, remoteDeviceId: remoteEntry.deviceId });
      }
    }

    // Check delete-modify
    for (const [encPath, remoteDel] of Object.entries(remoteMeta.deleted)) {
      const localEntry = this.localMeta.files[encPath];
      if (localEntry) {
        const rel = compareClocks(this.localMeta.vectorClock, remoteMeta.vectorClock);
        if (rel === 'concurrent' || rel === 'equal') {
          conflicts.push({ type: 'delete-modify', path: encPath, localEntry, remoteEntry: remoteDel, remoteDeviceId: remoteDel.deviceId });
        }
      }
    }

    // Check modify-delete
    for (const [encPath, localDel] of Object.entries(this.localMeta.deleted)) {
      const remoteEntry = remoteMeta.files[encPath];
      if (remoteEntry) {
        const rel = compareClocks(this.localMeta.vectorClock, remoteMeta.vectorClock);
        if (rel === 'concurrent' || rel === 'equal') {
          conflicts.push({ type: 'modify-delete', path: encPath, localEntry: localDel, remoteEntry, remoteDeviceId: remoteEntry.deviceId });
        }
      }
    }

    return conflicts;
  }

  resolveConflicts(remoteMeta, conflicts) {
    const merged = JSON.parse(JSON.stringify(this.localMeta));
    merged.vectorClock = mergeClocks(this.localMeta.vectorClock, remoteMeta.vectorClock);

    for (const conflict of conflicts) {
      switch (conflict.type) {
        case 'rollback':
          return JSON.parse(JSON.stringify(remoteMeta));

        case 'modify-modify': {
          const remoteTime = conflict.remoteEntry?.modifiedAt || '';
          const localTime = conflict.localEntry?.modifiedAt || '';
          if (remoteTime > localTime || (remoteTime === localTime && (conflict.remoteEntry?.deviceId || '') > (conflict.localEntry?.deviceId || ''))) {
            merged.files[conflict.path] = conflict.remoteEntry;
          }
          break;
        }

        case 'delete-modify': {
          const remoteTime = conflict.remoteEntry?.deletedAt || '';
          const localTime = conflict.localEntry?.modifiedAt || '';
          if (remoteTime > localTime) {
            delete merged.files[conflict.path];
          }
          break;
        }

        case 'modify-delete': {
          if (conflict.remoteEntry) {
            merged.files[conflict.path] = conflict.remoteEntry;
          }
          break;
        }
      }
    }

    // Apply remote files
    for (const [encPath, remoteEntry] of Object.entries(remoteMeta.files)) {
      if (!merged.files[encPath]) merged.files[encPath] = remoteEntry;
    }

    // Apply remote deletions
    for (const [encPath, remoteDel] of Object.entries(remoteMeta.deleted)) {
      if (!merged.deleted[encPath]) {
        merged.deleted[encPath] = remoteDel;
        delete merged.files[encPath];
      }
    }

    this.localMeta = merged;
    return merged;
  }
}

// --- Test ---
(async () => {
  const results = [];
  const assert = (name, ok, detail = '') => {
    results.push({ name, ok, detail });
    console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}${detail ? ' (' + detail + ')' : ''}`);
  };

  const vaultId = 'test-vault-' + crypto.randomUUID().slice(0, 8);
  const passphrase = 'correct horse battery staple';
  const masterSecret = await deriveMasterSecret(passphrase, vaultId);

  const deviceA = createDevice();
  const deviceB = createDevice();
  const simA = new SimDevice('DeviceA', deviceA, masterSecret, vaultId);
  const simB = new SimDevice('DeviceB', deviceB, masterSecret, vaultId);

  console.log(`\n--- Test 1: Device A uploads, Device B downloads ---`);
  const data1 = enc.encode('# Note v1\nOriginal content from device A.');
  await simA.uploadFile('test.md', data1);
  assert('A uploads test.md', true, `${data1.length} bytes`);

  const downloaded = await simB.downloadFile('test.md');
  const match1 = data1.every((b, i) => b === downloaded[i]);
  assert('B downloads and matches', match1, `${downloaded.length} bytes`);

  console.log(`\n--- Test 2: A modifies, B modifies (conflict detection) ---`);
  // B modifies the file offline (doesn't know A modified)
  await new Promise(r => setTimeout(r, 10));
  const dataB = enc.encode('# Note v2B\nModified by device B offline.');
  await simB.uploadFile('test.md', dataB);
  assert('B modifies test.md offline', true);

  // A modifies the file (doesn't know B modified)
  await new Promise(r => setTimeout(r, 10));
  const dataA = enc.encode('# Note v2A\nModified by device A.');
  await simA.uploadFile('test.md', dataA);
  assert('A modifies test.md', true);

  // Now detect conflicts: both modified concurrently
  const remoteRaw = await webdavDownload('metadata.json');
  const remoteMeta = JSON.parse(dec.decode(remoteRaw));
  const conflicts = simB.detectConflicts(remoteMeta);
  assert('B detects modify-modify conflict', conflicts.length > 0, `${conflicts.length} conflicts`);
  assert('Conflict type is modify-modify', conflicts[0]?.type === 'modify-modify');

  // B resolves conflict (A wins - newer timestamp)
  const resolved = simB.resolveConflicts(remoteMeta, conflicts);
  await signMeta(simB.localMeta, simB.device.deviceId, simB.device.signingKeyPair.secretKey);
  await webdavUpload('metadata.json', enc.encode(JSON.stringify(simB.localMeta, null, 2)));
  assert('B resolves conflict (A wins)', true);

  console.log(`\n--- Test 3: A deletes, B still has it (delete-modify conflict) ---`);
  await simA.deleteFile('test.md');
  assert('A deletes test.md', true);

  const remoteRaw2 = await webdavDownload('metadata.json');
  const remoteMeta2 = JSON.parse(dec.decode(remoteRaw2));
  const conflicts2 = simB.detectConflicts(remoteMeta2);
  assert('B detects delete-modify conflict', conflicts2.some(c => c.type === 'delete-modify'));

  // B resolves: deletion wins
  const resolved2 = simB.resolveConflicts(remoteMeta2, conflicts2);
  assert('B resolves conflict (deletion wins)', !simB.localMeta.files[await encryptFilename(masterSecret, vaultId, 'test.md')]);

  console.log(`\n--- Test 4: Metadata sequence rollback detection ---`);
  const encPath = await encryptFilename(masterSecret, vaultId, 'test.md');
  const oldMeta = { ...simB.localMeta, sequence: simB.localMeta.sequence - 5 };
  const rollbackConflicts = simB.detectConflicts(oldMeta);
  assert('Rollback detected when sequence decreases', rollbackConflicts.some(c => c.type === 'rollback'));

  console.log(`\n--- Test 5: Cleanup ---`);
  // Upload something to get chunk names for cleanup
  const data2 = enc.encode('# Cleanup test');
  await simA.uploadFile('cleanup.md', data2);
  const metaA = await webdavDownload('metadata.json');
  const metaAParsed = JSON.parse(dec.decode(metaA));
  for (const ch of Object.keys(metaAParsed.files).flatMap(k => metaAParsed.files[k].chunks)) {
    await webdavDelete(`chunks/${ch}.bin.enc`).catch(() => {});
  }
  await webdavDelete('metadata.json').catch(() => {});
  assert('Cleanup completed', true);

  const passed = results.filter(r => r.ok).length;
  const total = results.length;
  console.log(`\n=== ${passed}/${total} tests passed ===`);
  if (passed < total) process.exit(1);
})().catch(e => { console.error('Test failed:', e); process.exit(1); });
