import { WebDavClient, WebDavConfig } from '../webdav/client';
import { ChunkManager, ChunkInfo } from '../chunk/chunk-manager';
import { encrypt, decrypt, sha256 } from '../crypto/aes';
import { pqcDsa } from '../crypto/pqc-provider';
import { DeviceKeys } from '../crypto/key-manager';

/** Metadata schema version */
const SCHEMA_VERSION = 1;

/** Metadata entry for a single chunk on the server */
export interface ChunkMeta {
  path: string;
  offset: number;
  size: number;
  signature: string;
  createdAt: string;
  updatedAt: string;
  deviceId: string;
}

/** Vault metadata stored on WebDAV as metadata.json */
export interface VaultMetadata {
  version: number;
  vaultId: string;
  chunkSize: number;
  sequence: number;
  updatedAt: string;
  chunks: Record<string, ChunkMeta>;
  fileIndex: Record<string, string[]>;
  deleted: Record<string, { deletedAt: string; hashes: string[] }>;
  trustedDevices: Record<string, { publicKey: string; addedAt: string }>;
}

export function createEmptyMetadata(vaultId: string, chunkSize: number): VaultMetadata {
  return {
    version: SCHEMA_VERSION,
    vaultId,
    chunkSize,
    sequence: 0,
    updatedAt: new Date().toISOString(),
    chunks: {},
    fileIndex: {},
    deleted: {},
    trustedDevices: {},
  };
}

export class SyncEngine {
  private webdav: WebDavClient;
  private chunkManager: ChunkManager;
  private deviceId: string;
  private signingKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
  private masterSecret: Uint8Array;
  private vaultId: string;

  constructor(opts: {
    webdavConfig: WebDavConfig;
    chunkSize?: number;
    deviceId: string;
    signingKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array };
    masterSecret: Uint8Array;
    vaultId: string;
  }) {
    this.webdav = new WebDavClient(opts.webdavConfig);
    this.chunkManager = new ChunkManager(opts.chunkSize);
    this.deviceId = opts.deviceId;
    this.signingKeyPair = opts.signingKeyPair;
    this.masterSecret = opts.masterSecret;
    this.vaultId = opts.vaultId;
  }

  private deriveChunkKey = async (chunkHash: string): Promise<Uint8Array> => {
    const salt = new TextEncoder().encode(`pqc-webdav-${this.vaultId}`);
    const info = new TextEncoder().encode(`chunk-${chunkHash}`);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.masterSecret as unknown as BufferSource,
      'HKDF',
      false,
      ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as unknown as BufferSource, info: info as unknown as BufferSource },
      cryptoKey,
      256
    );
    return new Uint8Array(bits);
  };

  private computeChunkSignature = async (chunkHash: string, data: Uint8Array): Promise<Uint8Array> => {
    const chunkDataHash = await sha256(data);
    const signingPayload = new TextEncoder().encode(
      JSON.stringify({ vaultId: this.vaultId, chunkHash, chunkDataHash, deviceId: this.deviceId })
    );
    return pqcDsa.sign(this.signingKeyPair.secretKey, signingPayload);
  };

  async downloadMetadata(): Promise<VaultMetadata> {
    try {
      const raw = await this.webdav.downloadBytes('metadata.json');
      const text = new TextDecoder().decode(raw);
      return JSON.parse(text) as VaultMetadata;
    } catch {
      return createEmptyMetadata(this.vaultId, this.chunkManager['chunkSize']);
    }
  }

  async uploadMetadata(meta: VaultMetadata): Promise<void> {
    meta.sequence += 1;
    meta.updatedAt = new Date().toISOString();
    const json = JSON.stringify(meta, null, 2);
    await this.webdav.uploadBytes('metadata.json', new TextEncoder().encode(json));
  }

  async uploadFile(
    relPath: string,
    fileData: Uint8Array,
    meta: VaultMetadata
  ): Promise<{ meta: VaultMetadata; uploaded: number }> {
    const chunks = await this.chunkManager.split(fileData);
    let uploaded = 0;

    for (const { data, info } of chunks) {
      const keyBytes = await this.deriveChunkKey(info.hash);
      const encrypted = await encrypt(keyBytes, data);
      const sig = await this.computeChunkSignature(info.hash, data);
      const chunkPath = `chunks/${info.hash}.bin.enc`;
      await this.webdav.uploadBytes(chunkPath, encrypted);
      meta.chunks[info.hash] = {
        path: relPath,
        offset: info.offset,
        size: info.size,
        signature: Buffer.from(sig).toString('base64'),
        createdAt: meta.chunks[info.hash]?.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        deviceId: this.deviceId,
      };
      uploaded++;
    }
    meta.fileIndex[relPath] = chunks.map(c => c.info.hash);
    return { meta, uploaded };
  }

  async downloadFile(
    relPath: string,
    meta: VaultMetadata
  ): Promise<Uint8Array | null> {
    const hashes = meta.fileIndex[relPath];
    if (!hashes || hashes.length === 0) return null;

    const chunkDataList: { data: Uint8Array; offset: number }[] = [];

    for (const hash of hashes) {
      const chunkMeta = meta.chunks[hash];
      if (!chunkMeta) return null;

      const chunkPath = `chunks/${hash}.bin.enc`;
      const encrypted = await this.webdav.downloadBytes(chunkPath);
      const keyBytes = await this.deriveChunkKey(hash);
      const decrypted = await decrypt(keyBytes, encrypted);

      const signingPayload = new TextEncoder().encode(
        JSON.stringify({ vaultId: this.vaultId, chunkHash: hash, chunkDataHash: await sha256(decrypted), deviceId: chunkMeta.deviceId })
      );
      const sigBytes = new Uint8Array(Buffer.from(chunkMeta.signature, 'base64'));
      const sigValid = pqcDsa.verify(
        this.signingKeyPair.publicKey,
        signingPayload,
        sigBytes
      );
      if (!sigValid) {
        console.warn(`Signature verification failed for chunk ${hash}`);
      }

      chunkDataList.push({ data: decrypted, offset: chunkMeta.offset });
    }

    return this.chunkManager.merge(chunkDataList);
  }

  async deleteFile(
    relPath: string,
    meta: VaultMetadata
  ): Promise<{ meta: VaultMetadata; deletedChunks: number }> {
    const hashes = meta.fileIndex[relPath] || [];
    meta.deleted[relPath] = { deletedAt: new Date().toISOString(), hashes };
    delete meta.fileIndex[relPath];
    return { meta, deletedChunks: hashes.length };
  }

  async garbageCollect(
    meta: VaultMetadata,
    maxAgeDays: number = 30
  ): Promise<{ meta: VaultMetadata; removed: number }> {
    const now = Date.now();
    const threshold = now - maxAgeDays * 86400000;
    let removed = 0;

    for (const [path, del] of Object.entries(meta.deleted)) {
      if (new Date(del.deletedAt).getTime() < threshold) {
        for (const hash of del.hashes) {
          try { await this.webdav.delete(`chunks/${hash}.bin.enc`); } catch {}
          delete meta.chunks[hash];
          removed++;
        }
        delete meta.deleted[path];
      }
    }
    return { meta, removed };
  }
}
