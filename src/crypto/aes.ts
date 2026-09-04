/**
 * Basic crypto module using the Web Crypto API (AES-256-GCM).
 *
 * Uses browser-native WebCrypto so it works on both desktop (Electron) and
 * mobile Obsidian. No native Node crypto dependency.
 */

/** Export raw bytes to base64url string (no padding). */
export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Import a base64url string to raw bytes. */
export function base64ToBytes(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
  const bin = atob(base64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/** Generate a random 32-byte encryption key. */
export async function generateKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/** Generate a random 16-byte IV (initialization vector). */
export function generateIv(): Uint8Array {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  return iv;
}

function toCryptoKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    keyBytes as unknown as BufferSource,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data using AES-256-GCM.
 *
 * Returns a combined payload: [12-byte IV][ciphertext + 16-byte tag].
 */
export async function encrypt(
  keyBytes: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const key = await toCryptoKey(keyBytes);
  const iv = generateIv();
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    data as unknown as BufferSource
  );
  const result = new Uint8Array(iv.length + cipher.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(cipher), iv.length);
  return result;
}

/**
 * Decrypt data produced by `encrypt`.
 * Expects payload: [12-byte IV][ciphertext + 16-byte tag].
 */
export async function decrypt(
  keyBytes: Uint8Array,
  payload: Uint8Array
): Promise<Uint8Array> {
  const key = await toCryptoKey(keyBytes);
  const iv = payload.slice(0, 12);
  const cipher = payload.slice(12);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    cipher as unknown as BufferSource
  );
  return new Uint8Array(plain);
}

/** Compute SHA-256 hash of data. */
export async function sha256(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
  return bytesToBase64(new Uint8Array(digest));
}

/** Derive an AES key from a master secret using HKDF-SHA256. */
export async function deriveKey(
  masterSecret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    masterSecret as unknown as BufferSource,
    'HKDF',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as unknown as BufferSource,
      info: info as unknown as BufferSource,
    },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}
