/**
 * Filename encryption for metadata privacy.
 * Uses HKDF-SHA256 derived from master secret → deterministic (same file → same name).
 */

/**
 * Derive a deterministic encrypted name for a relative path.
 * Same input always produces the same output (HKDF is a PRF).
 *
 * @param masterSecret - 32-byte Vault Master Secret
 * @param vaultId - Vault UUID
 * @param relPath - Plaintext relative path within vault (e.g. "notes/foo.md")
 * @returns Encrypted pseudo-random path (URL-safe)
 */
export async function encryptFilename(
  masterSecret: Uint8Array,
  vaultId: string,
  relPath: string
): Promise<string> {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey(
    'raw', masterSecret as unknown as BufferSource, 'HKDF', false, ['deriveBits']
  );
  const salt = enc.encode(`pqc-webdav-${vaultId}`);
  const info = enc.encode(`filename-${relPath}`);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt as unknown as BufferSource, info: info as unknown as BufferSource },
    km, 256
  );
  const hash = new Uint8Array(bits);
  // Prefix with 'f_' to make it a valid filename, use base64url
  return 'f_' + base64url(hash);
}

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
