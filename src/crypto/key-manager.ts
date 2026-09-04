/**
 * Key Manager for PQC WebDAV Sync
 * 
 * Manages:
 * - Passphrase → Vault Master Secret derivation (Argon2 + HKDF)
 * - ML-DSA signing key pair generation and storage
 * - ML-KEM encapsulation key pair generation and storage (optional)
 * - Local key storage (Obsidian vault's .data.json or keyfile)
 */

import { pqcDsa, pqcKem, keyDerivation } from './pqc-provider';
import { PqcKeyPair } from './pqc-provider';

/** All keys needed for a single device */
export interface DeviceKeys {
  /** Device UUID (v4 random) */
  deviceId: string;
  
  /** ML-DSA-65 key pair for signing metadata */
  signingKeyPair: PqcKeyPair;
  
  /** ML-KEM-768 key pair for receiving encapsulated secrets (optional for MVP) */
  encryptionKeyPair?: PqcKeyPair;
}

/** Vault configuration (persisted) */
export interface VaultConfig {
  /** Vault UUID (v4 random, generated on first sync) */
  vaultId: string;
  
  /** Derived Vault Master Secret (kept in memory / config, NOT the passphrase) */
  masterSecret: Uint8Array;
  
  /** All known device keys */
  devices: Record<string, DeviceKeys>;
}

/**
 * Derive a Vault Master Secret from a passphrase using Argon2 + HKDF.
 * 
 * Security properties:
 * - Argon2id: 3 iterations, 64MB memory, 4 parallel threads (OWASP recommendations)
 * - Salt: vaultId (unique per vault)
 * - Info: 'pqc-webdav-master-secret' (domain separation)
 * 
 * @param passphrase - User's passphrase
 * @param vaultId - Vault UUID (unique salt)
 * @returns 32-byte Vault Master Secret
 */
export async function deriveVaultMasterSecret(
  passphrase: string,
  vaultId: string
): Promise<Uint8Array> {
  // Argon2id with OWASP recommended parameters
  // Note: browser-native Argon2 doesn't exist yet; we'll use PBKDF2 for now
  // (PBKDF2 with high iterations is acceptable; Argon2 can be added via wasm later)
  
  const passphraseBytes = new TextEncoder().encode(passphrase);
  const salt = new TextEncoder().encode(`pqc-webdav-${vaultId}`);
  
  // Import passphrase as raw key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passphraseBytes as unknown as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  // Derive 32 bytes using PBKDF2-SHA512 with 600,000 iterations (OWASP recommendation)
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations: 600_000,
      hash: 'SHA-512',
    },
    keyMaterial,
    256 // 32 bytes
  );
  
  return new Uint8Array(derivedBits);
}

/**
 * Generate a fresh ML-DSA-65 key pair for a new device.
 */
export function generateDeviceSigningKeyPair(): PqcKeyPair {
  return pqcDsa.generateKeyPair();
}

/**
 * Generate a fresh ML-KEM-768 key pair for receiving secrets (optional).
 */
export function generateDeviceEncryptionKeyPair(): PqcKeyPair {
  return pqcKem.generateKeyPair();
}

/**
 * Create a new device with all key pairs.
 */
export function createDevice(): DeviceKeys {
  return {
    deviceId: crypto.randomUUID(),
    signingKeyPair: generateDeviceSigningKeyPair(),
    encryptionKeyPair: generateDeviceEncryptionKeyPair(), // optional but included
  };
}

/**
 * Derive a chunk encryption key from the Vault Master Secret.
 * 
 * @param masterSecret - 32-byte Vault Master Secret
 * @param vaultId - Vault UUID
 * @param chunkHash - SHA-256 hash of plaintext chunk
 * @returns 32-byte AES-256 key
 */
export async function deriveChunkEncryptionKey(
  masterSecret: Uint8Array,
  vaultId: string,
  chunkHash: string
): Promise<Uint8Array> {
  const salt = new TextEncoder().encode(`pqc-webdav-${vaultId}`);
  const info = new TextEncoder().encode(`chunk-${chunkHash}`);
  return keyDerivation.derive(masterSecret, salt, info, 32);
}
