/**
 * Post-Quantum Cryptography Provider Abstraction
 * 
 * Abstracts ML-KEM-768 (key encapsulation) and ML-DSA-65 (signatures)
 * for the PQC WebDAV Sync plugin.
 * 
 * Future migration path:
 * - @noble/post-quantum (current)
 * - Native WebCrypto (when browser support lands)
 * - @oqs/liboqs-js (if performance becomes critical)
 */

// Re-export noble/post-quantum for now
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export interface PqcKeyPair {
  publicKey: Uint8Array;
  /** Named `secretKey` internally to match noble API; called "privateKey" externally for convention. */
  secretKey: Uint8Array;
}

export interface PqcSignature {
  signature: Uint8Array;
  publicKey: Uint8Array;
}

export interface PqcKeyEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

/**
 * The `@noble/post-quantum` public exports are typed with conditional
 * `TArg`/`TRet` helpers that resolve to `any` under typescript-eslint type-aware
 * linting. Re-declaring the narrow surface we actually use keeps the provider
 * fully typed (and lint-clean) without masking real safety issues.
 */
interface MldsaApi {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}

interface MlkemApi {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(recipientPublicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

const mldsa = ml_dsa65 as unknown as MldsaApi;
const mlkem = ml_kem768 as unknown as MlkemApi;

/**
 * ML-DSA (Dilithium) operations for integrity verification.
 * ML-DSA-65: ~3309B signature, ~4032B private key, ~1952B public key
 */
export const pqcDsa = {
  /**
   * Generate an ML-DSA-65 key pair for signing.
   */
  generateKeyPair(): PqcKeyPair {
    const keyPair = mldsa.keygen();
    return {
      publicKey: new Uint8Array(keyPair.publicKey),
      secretKey: new Uint8Array(keyPair.secretKey),
    };
  },

  /**
   * Sign a message with ML-DSA-65.
   * @param secretKey - 4032 bytes
   * @param message - data to sign
   * @returns signature (~3309 bytes)
   */
  sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
    const signature = mldsa.sign(message, secretKey);
    return new Uint8Array(signature);
  },

  /**
   * Verify an ML-DSA-65 signature.
   * @param publicKey - 1952 bytes
   * @param message - original data
   * @param signature - 3309 bytes
   * @returns true if valid
   */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    return mldsa.verify(signature, message, publicKey);
  },
};

/**
 * ML-KEM (Kyber) operations for key encapsulation.
 * ML-KEM-768: ~1184B ciphertext, ~1088B shared secret, ~3168B key pair
 */
export const pqcKem = {
  /**
   * Generate an ML-KEM-768 key pair for encapsulation.
   */
  generateKeyPair(): PqcKeyPair {
    const keyPair = mlkem.keygen();
    return {
      publicKey: new Uint8Array(keyPair.publicKey),
      secretKey: new Uint8Array(keyPair.secretKey),
    };
  },

  /**
   * Encapsulate a shared secret using a recipient's public key.
   * @param recipientPublicKey - ML-KEM-768 public key
   * @returns { ciphertext, sharedSecret } - ciphertext (~1184B) and shared secret (~32B)
   */
  encapsulate(recipientPublicKey: Uint8Array): PqcKeyEncapsulation {
    const result = mlkem.encapsulate(recipientPublicKey);
    return {
      ciphertext: new Uint8Array(result.cipherText),
      sharedSecret: new Uint8Array(result.sharedSecret),
    };
  },

  /**
   * Decapsulate a ciphertext to recover the shared secret.
   * @param recipientPrivateKey - ML-KEM-768 private key
   * @param ciphertext - 1184 bytes
   * @returns shared secret (~32 bytes)
   */
  decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    const sharedSecret = mlkem.decapsulate(ciphertext, secretKey);
    return new Uint8Array(sharedSecret);
  },
};

/**
 * HKDF key derivation using WebCrypto (browser-native, no external deps).
 */
export const keyDerivation = {
  /**
   * Derive a key using HKDF-SHA256.
   * @param secret - Input secret (e.g., passphrase-derived hash or ML-KEM shared secret)
   * @param salt - Salt (e.g., vault_id)
   * @param info - Context info (e.g., 'chunk-encryption', device_id)
   * @param length - Output length in bytes (default: 32 for AES-256)
   */
  async derive(
    secret: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number = 32
  ): Promise<Uint8Array> {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      secret as unknown as BufferSource,
      'HKDF',
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as unknown as BufferSource, info: info as unknown as BufferSource },
      cryptoKey,
      length * 8
    );
    return new Uint8Array(bits);
  },
};
