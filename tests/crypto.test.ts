import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  sha256,
  bytesToBase64,
  base64ToBytes,
  generateKey,
  generateIv,
  deriveKey,
} from '../src/crypto/aes';
import { encryptFilename } from '../src/crypto/filename';
import { deriveVaultMasterSecret } from '../src/crypto/key-manager';
import { pqcDsa, pqcKem } from '../src/crypto/pqc-provider';

describe('AES-GCM encryption', () => {
  const key = new Uint8Array(32).fill(7);

  it('encrypt/decrypt roundtrip preserves data', async () => {
    const data = new TextEncoder().encode('hello world');
    const encrypted = await encrypt(key, data);
    expect(encrypted.length).toBeGreaterThan(data.length);
    expect(await decrypt(key, encrypted)).toEqual(data);
  });

  it('produces unique ciphertext per call (random IV)', async () => {
    const data = new TextEncoder().encode('same message');
    const e1 = await encrypt(key, data);
    const e2 = await encrypt(key, data);
    expect(e1).not.toEqual(e2);
  });

  it('decrypt with wrong key throws', async () => {
    const data = new TextEncoder().encode('secret');
    const encrypted = await encrypt(key, data);
    const wrongKey = new Uint8Array(32).fill(9);
    await expect(decrypt(wrongKey, encrypted)).rejects.toThrow();
  });

  it('tampered ciphertext throws (GCM auth)', async () => {
    const data = new TextEncoder().encode('integrity check');
    const encrypted = await encrypt(key, data);
    encrypted[15] ^= 0xff;
    await expect(decrypt(key, encrypted)).rejects.toThrow();
  });

  it('empty payload roundtrips', async () => {
    const encrypted = await encrypt(key, new Uint8Array(0));
    expect(await decrypt(key, encrypted)).toEqual(new Uint8Array(0));
  });

  it('large payload (5MB) roundtrips', async () => {
    const data = new Uint8Array(5 * 1024 * 1024);
    fillRandom(data);
    const encrypted = await encrypt(key, data);
    expect(await decrypt(key, encrypted)).toEqual(data);
  });
});

function fillRandom(buf: Uint8Array): void {
  const MAX = 65536;
  for (let i = 0; i < buf.length; i += MAX) {
    crypto.getRandomValues(buf.subarray(i, Math.min(i + MAX, buf.length)));
  }
}

describe('base64url helpers', () => {
  it('roundtrips arbitrary bytes', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const b64 = bytesToBase64(bytes);
    expect(b64).not.toContain('+');
    expect(b64).not.toContain('/');
    expect(b64).not.toContain('=');
    expect(base64ToBytes(b64)).toEqual(bytes);
  });

  it('roundtrips empty array', () => {
    expect(base64ToBytes(bytesToBase64(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  it('handles random 32-byte key', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    expect(base64ToBytes(bytesToBase64(key))).toEqual(key);
  });
});

describe('sha256', () => {
  it('is deterministic and stable across engines', async () => {
    const data = new TextEncoder().encode('post-quantum-webdav');
    const h1 = await sha256(data);
    const h2 = await sha256(data);
    expect(h1).toBe(h2);
    expect(h1).toBe('Hqg7vBNDMd9ZWKHfZDvLF8fnoRXoPnhYYia6Zjcqm1Q'); // verified against node:crypto SHA-256 of this exact string
  });

  it('differs for different content', async () => {
    const a = await sha256(new TextEncoder().encode('aaa'));
    const b = await sha256(new TextEncoder().encode('aab'));
    expect(a).not.toBe(b);
  });
});

describe('generateKey / generateIv / deriveKey', () => {
  it('generateKey returns 256-bit AES key', async () => {
    const k = await generateKey();
    expect(k.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
  });

  it('generateIv produces 12 random bytes', () => {
    const iv1 = generateIv();
    const iv2 = generateIv();
    expect(iv1).toHaveLength(12);
    expect(iv2).toHaveLength(12);
    expect(iv1).not.toEqual(iv2);
  });

  it('deriveKey is deterministic and 32 bytes', async () => {
    const secret = new Uint8Array(32).fill(1);
    const salt = new TextEncoder().encode('salt');
    const info = new TextEncoder().encode('info');
    const k1 = await deriveKey(secret, salt, info);
    const k2 = await deriveKey(secret, salt, info);
    expect(k1).toEqual(k2);
    expect(k1).toHaveLength(32);
  });
});

describe('filename encryption', () => {
  const masterSecret = new Uint8Array(32).fill(42);
  const vaultId = 'vault-123';

  it('is deterministic for same path', async () => {
    const a = await encryptFilename(masterSecret, vaultId, 'notes/foo.md');
    const b = await encryptFilename(masterSecret, vaultId, 'notes/foo.md');
    expect(a).toBe(b);
  });

  it('produces URL-safe names with f_ prefix', async () => {
    const enc = await encryptFilename(masterSecret, vaultId, 'notes/foo.md');
    expect(enc.startsWith('f_')).toBe(true);
    expect(enc).not.toMatch(/[+/=]/);
  });

  it('never leaks plaintext path structure', async () => {
    const enc = await encryptFilename(masterSecret, vaultId, 'secret-folder/private-note.md');
    expect(enc).not.toContain('secret-folder');
    expect(enc).not.toContain('private-note');
    expect(enc).not.toContain('/');
  });

  it('differs when master secret changes', async () => {
    const a = await encryptFilename(masterSecret, vaultId, 'a.md');
    const b = await encryptFilename(new Uint8Array(32).fill(43), vaultId, 'a.md');
    expect(a).not.toBe(b);
  });

  it('differs when vault id changes', async () => {
    const a = await encryptFilename(masterSecret, vaultId, 'a.md');
    const b = await encryptFilename(masterSecret, 'vault-456', 'a.md');
    expect(a).not.toBe(b);
  });
});

describe('vault master secret derivation', () => {
  it('is deterministic for same passphrase and vault', async () => {
    const s1 = await deriveVaultMasterSecret('correct horse battery staple', 'vault-a');
    const s2 = await deriveVaultMasterSecret('correct horse battery staple', 'vault-a');
    expect(s1).toEqual(s2);
    expect(s1).toHaveLength(32);
  });

  it('differs for different passphrases', async () => {
    const a = await deriveVaultMasterSecret('pass-1', 'vault-a');
    const b = await deriveVaultMasterSecret('pass-2', 'vault-a');
    expect(a).not.toEqual(b);
  });
}, 60_000);

describe('post-quantum crypto (ML-DSA-65 + ML-KEM-768)', () => {
  it('generates a signing key pair of expected sizes', () => {
    const kp = pqcDsa.generateKeyPair();
    expect(kp.publicKey.length).toBeGreaterThan(0);
    expect(kp.secretKey.length).toBeGreaterThan(0);
    expect(kp.publicKey).not.toEqual(kp.secretKey);
  });

  it('signs and verifies a message', () => {
    const kp = pqcDsa.generateKeyPair();
    const msg = new TextEncoder().encode('authenticate me');
    const sig = pqcDsa.sign(kp.secretKey, msg);
    expect(pqcDsa.verify(kp.publicKey, msg, sig)).toBe(true);
  });

  it('rejects tampered message', () => {
    const kp = pqcDsa.generateKeyPair();
    const msg = new TextEncoder().encode('authenticate me');
    const sig = pqcDsa.sign(kp.secretKey, msg);
    const tampered = new TextEncoder().encode('authenticate me!');
    expect(pqcDsa.verify(kp.publicKey, tampered, sig)).toBe(false);
  });

  it('rejects signature from a different key', () => {
    const kp1 = pqcDsa.generateKeyPair();
    const kp2 = pqcDsa.generateKeyPair();
    const msg = new TextEncoder().encode('msg');
    const sig = pqcDsa.sign(kp1.secretKey, msg);
    expect(pqcDsa.verify(kp2.publicKey, msg, sig)).toBe(false);
  });

  it('ML-KEM encapsulate/decapsulate yields the same shared secret', () => {
    const alice = pqcKem.generateKeyPair();
    const bob = pqcKem.generateKeyPair();
    const { ciphertext, sharedSecret } = pqcKem.encapsulate(bob.publicKey);
    const recovered = pqcKem.decapsulate(bob.secretKey, ciphertext);
    expect(recovered).toEqual(sharedSecret);
    expect(sharedSecret.length).toBeGreaterThan(0);
    expect(ciphertext.length).toBeGreaterThan(0);
  });

  it('ML-KEM decapsulation with wrong secret key differs', () => {
    const alice = pqcKem.generateKeyPair();
    const bob = pqcKem.generateKeyPair();
    const eve = pqcKem.generateKeyPair();
    const { ciphertext, sharedSecret } = pqcKem.encapsulate(bob.publicKey);
    const wrong = pqcKem.decapsulate(eve.secretKey, ciphertext);
    expect(wrong).not.toEqual(sharedSecret);
  });
});