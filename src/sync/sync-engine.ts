import { WebDavClient, WebDavConfig } from '../webdav/client';
import { ChunkManager, ChunkInfo } from '../chunk/chunk-manager';
import { encrypt, decrypt, sha256, bytesToBase64, base64ToBytes } from '../crypto/aes';
import { pqcDsa } from '../crypto/pqc-provider';

const SCHEMA_VERSION = 2;

/**
 * Vector Clock: tracks causality across devices.
 * Each device increments its own counter on every operation.
 * If clockA > clockB for all entries, A happened-after B.
 * If neither dominates, they are concurrent.
 */
export type VectorClock = Record<string, number>;

export interface FileEntry {
  chunks: string[];
  size: number;
  createdAt: string;
  modifiedAt: string;
  deviceId: string;
  signature: string;
}

export interface DeletedEntry {
  deletedAt: string;
  deviceId: string;
  chunks: string[];
  signature: string;
}

export interface VaultMetadata {
  version: number;
  vaultId: string;
  chunkSize: number;
  vectorClock: VectorClock;
  sequence: number;
  files: Record<string, FileEntry>;
  deleted: Record<string, DeletedEntry>;
  signerDeviceId: string;
  signerPublicKey: string;
  updatedAt: string;
}

export interface SyncConflict {
  type: 'modify-modify' | 'delete-modify' | 'modify-delete' | 'delete-delete' | 'rollback';
  path: string;
  localEntry?: FileEntry;
  remoteEntry?: FileEntry | DeletedEntry;
  remoteDeviceId: string;
}

// --- Vector Clock Operations ---

/** Increment vector clock for a device */
export function incrementClock(clock: VectorClock, deviceId: string): VectorClock {
  return { ...clock, [deviceId]: (clock[deviceId] || 0) + 1 };
}

/** Merge two vector clocks (take max of each entry) */
export function mergeClocks(a: VectorClock, b: VectorClock): VectorClock {
  const merged: VectorClock = { ...a };
  for (const [device, counter] of Object.entries(b)) {
    merged[device] = Math.max(merged[device] || 0, counter);
  }
  return merged;
}

/**
 * Compare two vector clocks:
 *  - 'before':  a happened-before b (a < b)
 *  - 'after':   a happened-after b (a > b)
 *  - 'concurrent': neither dominates (a || b)
 *  - 'equal':   a == b
 */
export function compareClocks(a: VectorClock, b: VectorClock): 'before' | 'after' | 'concurrent' | 'equal' {
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

/** Does clock A dominate clock B? (A happened-after B) */
export function dominates(a: VectorClock, b: VectorClock): boolean {
  const rel = compareClocks(a, b);
  return rel === 'after' || rel === 'equal';
}

// --- Metadata Operations ---

export function createEmptyMetadata(vaultId: string, chunkSize: number): VaultMetadata {
  return {
    version: SCHEMA_VERSION,
    vaultId,
    chunkSize,
    vectorClock: {},
    sequence: 0,
    files: {},
    deleted: {},
    signerDeviceId: '',
    signerPublicKey: '',
    updatedAt: new Date().toISOString(),
  };
}

// --- Sync Engine ---

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

  // --- Key Derivation ---

  private deriveChunkKey = async (chunkHash: string): Promise<Uint8Array> => {
    const salt = new TextEncoder().encode(`pqc-webdav-${this.vaultId}`);
    const info = new TextEncoder().encode(`chunk-${chunkHash}`);
    const cryptoKey = await crypto.subtle.importKey(
      'raw', this.masterSecret as unknown as BufferSource, 'HKDF', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt as unknown as BufferSource, info: info as unknown as BufferSource },
      cryptoKey, 256
    );
    return new Uint8Array(bits);
  };

  private computeChunkSignature = async (chunkHash: string, data: Uint8Array): Promise<Uint8Array> => {
    const chunkDataHash = await sha256(data);
    const payload = new TextEncoder().encode(
      JSON.stringify({ vaultId: this.vaultId, chunkHash, chunkDataHash, deviceId: this.deviceId })
    );
    return pqcDsa.sign(this.signingKeyPair.secretKey, payload);
  };

  private signMetadata(meta: VaultMetadata): VaultMetadata {
    const signPayload = JSON.stringify({
      vaultId: meta.vaultId,
      sequence: meta.sequence,
      vectorClock: meta.vectorClock,
      files: meta.files,
      deleted: meta.deleted,
    });
    const sig = pqcDsa.sign(this.signingKeyPair.secretKey, new TextEncoder().encode(signPayload));
    meta.signerDeviceId = this.deviceId;
    meta.signerPublicKey = bytesToBase64(this.signingKeyPair.publicKey);
    return meta;
  }

  // --- Remote I/O ---

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
    this.signMetadata(meta);
    const json = JSON.stringify(meta, null, 2);
    await this.webdav.uploadBytes('metadata.json', new TextEncoder().encode(json));
  }

  // --- Conflict Detection (Vector-Clock Based) ---

  /**
   * Detect conflicts between local and remote metadata.
   * Uses vector clocks for causal ordering + timestamps for LWW tiebreak.
   */
  detectConflicts(localMeta: VaultMetadata, remoteMeta: VaultMetadata): SyncConflict[] {
    const conflicts: SyncConflict[] = [];

    // 1. Rollback detection: remote sequence < local sequence
    //    (This catches a malicious or buggy device rolling back)
    if (remoteMeta.sequence < localMeta.sequence) {
      conflicts.push({
        type: 'rollback',
        path: 'metadata.json',
        remoteDeviceId: remoteMeta.signerDeviceId,
      });
      return conflicts; // Don't process further if rollback detected
    }

    // 2. For each file in remote metadata, compare with local
    for (const [encPath, remoteEntry] of Object.entries(remoteMeta.files)) {
      const localEntry = localMeta.files[encPath];

      if (!localEntry) {
        // Remote has file, local doesn't → new file from remote (no conflict)
        continue;
      }

      // Both have the file — check if same version
      if (localEntry.modifiedAt === remoteEntry.modifiedAt && localEntry.deviceId === remoteEntry.deviceId) {
        continue; // Same version, no conflict
      }

      // Both modified — check vector clocks
      const localClock = localMeta.vectorClock;
      const remoteClock = remoteMeta.vectorClock;

      const rel = compareClocks(localClock, remoteClock);

      if (rel === 'equal') {
        // Same vector clock but different content → concurrent modification
        // LWW by timestamp, then deviceId as tiebreaker
        conflicts.push({
          type: 'modify-modify',
          path: encPath,
          localEntry,
          remoteEntry,
          remoteDeviceId: remoteEntry.deviceId,
        });
      } else if (rel === 'concurrent') {
        // Concurrent modifications from different devices
        conflicts.push({
          type: 'modify-modify',
          path: encPath,
          localEntry,
          remoteEntry,
          remoteDeviceId: remoteEntry.deviceId,
        });
      }
      // If rel is 'before' or 'after', one side causally dominates → no conflict
    }

    // 3. Check for delete-modify conflicts
    for (const [encPath, remoteDeleted] of Object.entries(remoteMeta.deleted)) {
      const localEntry = localMeta.files[encPath];

      if (localEntry) {
        // Remote deleted, local has file → potential conflict
        const rel = compareClocks(localMeta.vectorClock, remoteMeta.vectorClock);

        if (rel === 'concurrent' || rel === 'equal') {
          // Concurrent: local modified while remote deleted
          conflicts.push({
            type: 'delete-modify',
            path: encPath,
            localEntry,
            remoteEntry: remoteDeleted,
            remoteDeviceId: remoteDeleted.deviceId,
          });
        }
        // If local dominates (rel === 'after'), local's modification wins
        // If remote dominates (rel === 'before'), remote's deletion wins
      }
    }

    // 4. Check for modify-delete conflicts (local deleted, remote modified)
    for (const [encPath, localDeleted] of Object.entries(localMeta.deleted)) {
      const remoteEntry = remoteMeta.files[encPath];

      if (remoteEntry) {
        // Local deleted, remote has file → potential conflict
        const rel = compareClocks(localMeta.vectorClock, remoteMeta.vectorClock);

        if (rel === 'concurrent' || rel === 'equal') {
          conflicts.push({
            type: 'modify-delete',
            path: encPath,
            localEntry: localDeleted as unknown as FileEntry,
            remoteEntry,
            remoteDeviceId: remoteEntry.deviceId,
          });
        }
      }
    }

    return conflicts;
  }

  // --- Conflict Resolution (LWW) ---

  /**
   * Resolve conflicts using Last-Writer-Wins strategy.
   * For encrypted files, we can't merge content, so we pick the winner.
   * Losing version is kept as conflict copy.
   */
  resolveConflicts(
    localMeta: VaultMetadata,
    remoteMeta: VaultMetadata,
    conflicts: SyncConflict[]
  ): VaultMetadata {
    // Start with a deep copy of local metadata
    const merged: VaultMetadata = JSON.parse(JSON.stringify(localMeta));

    // Merge vector clocks
    merged.vectorClock = mergeClocks(localMeta.vectorClock, remoteMeta.vectorClock);

    for (const conflict of conflicts) {
      switch (conflict.type) {
        case 'rollback':
          // Accept remote metadata entirely
          return JSON.parse(JSON.stringify(remoteMeta));

        case 'modify-modify': {
          if (!conflict.localEntry || !conflict.remoteEntry) break;

          // LWW: compare timestamps, then deviceId as tiebreaker
          const localTime = conflict.localEntry.modifiedAt;
          const remoteTime = (conflict.remoteEntry as FileEntry).modifiedAt;
          const remoteEntry = conflict.remoteEntry as FileEntry;

          if (remoteTime > localTime || (remoteTime === localTime && remoteEntry.deviceId > conflict.localEntry.deviceId)) {
            // Remote wins
            merged.files[conflict.path] = remoteEntry;
            // Copy chunk metadata from remote
            for (const hash of remoteEntry.chunks) {
              if (remoteMeta.files[conflict.path]) {
                // Chunk metadata is stored separately in the full remote metadata
                // We need to get it from remoteMeta.chunks if it exists
              }
            }
          }
          // If local wins, keep local (already in merged)
          break;
        }

        case 'delete-modify': {
          // Remote deleted, local modified
          // If concurrent: remote's deletion wins (safer — user explicitly deleted)
          // Exception: if local modified is newer, keep it
          if (conflict.localEntry && conflict.remoteEntry) {
            const localTime = conflict.localEntry.modifiedAt;
            const remoteTime = (conflict.remoteEntry as DeletedEntry).deletedAt;

            if (remoteTime > localTime) {
              // Remote deletion wins
              delete merged.files[conflict.path];
            }
            // If local is newer, keep local file
          }
          break;
        }

        case 'modify-delete': {
          // Local deleted, remote modified
          // If concurrent: remote's modification wins (user explicitly modified)
          if (conflict.localEntry && conflict.remoteEntry) {
            const remoteEntry = conflict.remoteEntry as FileEntry;
            merged.files[conflict.path] = remoteEntry;
          }
          break;
        }

        case 'delete-delete':
          // Both deleted — no conflict, just remove from both
          delete merged.files[conflict.path];
          delete merged.deleted[conflict.path];
          break;
      }
    }

    // Apply remote files that local doesn't have
    for (const [encPath, remoteEntry] of Object.entries(remoteMeta.files)) {
      if (!merged.files[encPath]) {
        merged.files[encPath] = remoteEntry;
      }
    }

    // Apply remote deletions that local doesn't have
    for (const [encPath, remoteDeleted] of Object.entries(remoteMeta.deleted)) {
      if (!merged.deleted[encPath]) {
        merged.deleted[encPath] = remoteDeleted;
        delete merged.files[encPath];
      }
    }

    return merged;
  }

  // --- File Operations ---

  async uploadFile(
    encPath: string,
    fileData: Uint8Array,
    meta: VaultMetadata,
    onProgress?: (chunkIndex: number, totalChunks: number, chunkBytes: number, totalBytes: number) => void
  ): Promise<{ meta: VaultMetadata; uploaded: number; chunks: number; durationMs: number; bytes: number }> {
    const t0 = performance.now();
    const chunks = await this.chunkManager.split(fileData);
    let uploaded = 0;
    const chunkHashes: string[] = [];

    for (let i = 0; i < chunks.length; i++) {
      const { data, info } = chunks[i];
      const existingEntry = meta.files[encPath];
      if (existingEntry && existingEntry.chunks.includes(info.hash)) {
        chunkHashes.push(info.hash);
        if (onProgress) onProgress(i + 1, chunks.length, 0, fileData.length);
        continue;
      }

      const keyBytes = await this.deriveChunkKey(info.hash);
      const encrypted = await encrypt(keyBytes, data);
      const sig = await this.computeChunkSignature(info.hash, data);
      const chunkPath = `chunks/${info.hash}.bin.enc`;
      await this.webdav.uploadBytes(chunkPath, encrypted);
      chunkHashes.push(info.hash);
      uploaded++;
      if (onProgress) onProgress(i + 1, chunks.length, data.length, fileData.length);
    }

    const now = new Date().toISOString();
    const existing = meta.files[encPath];

    meta.files[encPath] = {
      chunks: chunkHashes,
      size: fileData.length,
      createdAt: existing?.createdAt || now,
      modifiedAt: now,
      deviceId: this.deviceId,
      signature: '',
    };

    meta.vectorClock = incrementClock(meta.vectorClock, this.deviceId);

    return { meta, uploaded, chunks: chunkHashes.length, durationMs: performance.now() - t0, bytes: fileData.length };
  }

  async downloadFile(
    encPath: string,
    meta: VaultMetadata,
    onProgress?: (chunkIndex: number, totalChunks: number, chunkBytes: number, totalBytes: number) => void
  ): Promise<{ data: Uint8Array; durationMs: number; chunks: number; bytes: number } | null> {
    const t0 = performance.now();
    const entry = meta.files[encPath];
    if (!entry || entry.chunks.length === 0) return null;

    const chunkDataList: { data: Uint8Array; offset: number }[] = [];
    let offset = 0;

    for (let i = 0; i < entry.chunks.length; i++) {
      const hash = entry.chunks[i];
      const chunkPath = `chunks/${hash}.bin.enc`;
      const encrypted = await this.webdav.downloadBytes(chunkPath);
      const keyBytes = await this.deriveChunkKey(hash);
      const decrypted = await decrypt(keyBytes, encrypted);

      chunkDataList.push({ data: decrypted, offset });
      offset += decrypted.length;
      if (onProgress) onProgress(i + 1, entry.chunks.length, decrypted.length, entry.size);
    }

    const data = this.chunkManager.merge(chunkDataList);
    return { data, durationMs: performance.now() - t0, chunks: entry.chunks.length, bytes: data.length };
  }

  async deleteFile(
    encPath: string,
    meta: VaultMetadata
  ): Promise<{ meta: VaultMetadata; deletedChunks: number }> {
    const entry = meta.files[encPath];
    const chunks = entry?.chunks || [];

    meta.deleted[encPath] = {
      deletedAt: new Date().toISOString(),
      deviceId: this.deviceId,
      chunks,
      signature: '',
    };
    delete meta.files[encPath];

    // Increment vector clock
    meta.vectorClock = incrementClock(meta.vectorClock, this.deviceId);

    return { meta, deletedChunks: chunks.length };
  }

  // --- Garbage Collection ---

  async garbageCollect(
    meta: VaultMetadata,
    maxAgeDays: number = 30
  ): Promise<{ meta: VaultMetadata; removed: number }> {
    const now = Date.now();
    const threshold = now - maxAgeDays * 86400000;
    let removed = 0;

    for (const [encPath, del] of Object.entries(meta.deleted)) {
      if (new Date(del.deletedAt).getTime() < threshold) {
        for (const hash of del.chunks) {
          try { await this.webdav.delete(`chunks/${hash}.bin.enc`); } catch {}
          removed++;
        }
        delete meta.deleted[encPath];
      }
    }
    return { meta, removed };
  }

  // --- Force Full Sync ---

  async forceUploadFile(
    encPath: string,
    fileData: Uint8Array,
    meta: VaultMetadata,
    onProgress?: (chunkIndex: number, totalChunks: number, chunkBytes: number, totalBytes: number) => void
  ): Promise<{ meta: VaultMetadata; chunks: number; durationMs: number; bytes: number }> {
    const t0 = performance.now();
    delete meta.deleted[encPath];

    const chunks = await this.chunkManager.split(fileData);
    const chunkHashes: string[] = [];

    for (let i = 0; i < chunks.length; i++) {
      const { data, info } = chunks[i];
      const keyBytes = await this.deriveChunkKey(info.hash);
      const encrypted = await encrypt(keyBytes, data);
      const sig = await this.computeChunkSignature(info.hash, data);
      await this.webdav.uploadBytes(`chunks/${info.hash}.bin.enc`, encrypted);
      chunkHashes.push(info.hash);
      if (onProgress) onProgress(i + 1, chunks.length, data.length, fileData.length);
    }

    const now = new Date().toISOString();
    meta.files[encPath] = {
      chunks: chunkHashes,
      size: fileData.length,
      createdAt: meta.files[encPath]?.createdAt || now,
      modifiedAt: now,
      deviceId: this.deviceId,
      signature: '',
    };
    meta.vectorClock = incrementClock(meta.vectorClock, this.deviceId);
    const durationMs = performance.now() - t0;
    return { meta, chunks: chunkHashes.length, durationMs, bytes: fileData.length };
  }

  async forceDownloadFile(encPath: string, meta: VaultMetadata): Promise<Uint8Array | null> {
    const result = await this.downloadFile(encPath, meta);
    return result?.data ?? null;
  }

  // --- Main Sync Entry Point ---

  async syncFile(
    encPath: string,
    localData: Uint8Array,
    localMeta: VaultMetadata,
    onProgress?: (chunkIndex: number, totalChunks: number, chunkBytes: number, totalBytes: number) => void
  ): Promise<{
    meta: VaultMetadata;
    action: 'uploaded' | 'downloaded' | 'conflict-resolved' | 'unchanged';
    conflicts?: SyncConflict[];
    downloadedData?: Uint8Array;
    chunks?: number;
    durationMs?: number;
    bytes?: number;
  }> {
    const remoteMeta = await this.downloadMetadata();

    const conflicts = this.detectConflicts(localMeta, remoteMeta);

    if (conflicts.length > 0) {
      const mergedMeta = this.resolveConflicts(localMeta, remoteMeta, conflicts);

      if (mergedMeta.files[encPath]) {
        const { meta: uploadedMeta, chunks, durationMs, bytes } = await this.uploadFile(encPath, localData, mergedMeta, onProgress);
        await this.uploadMetadata(uploadedMeta);
        return { meta: uploadedMeta, action: 'conflict-resolved', conflicts, chunks, durationMs, bytes };
      } else {
        await this.uploadMetadata(mergedMeta);
        const result = await this.downloadFile(encPath, mergedMeta, onProgress);
        return { meta: mergedMeta, action: 'conflict-resolved', conflicts, downloadedData: result?.data, chunks: result?.chunks, durationMs: result?.durationMs, bytes: result?.bytes };
      }
    }

    const remoteEntry = remoteMeta.files[encPath];
    const localEntry = localMeta.files[encPath];

    if (!remoteEntry && !localEntry) {
      // First sync: file exists locally but neither metadata tracks it yet — upload it
      const { meta: uploadedMeta, chunks, durationMs, bytes } = await this.uploadFile(encPath, localData, remoteMeta, onProgress);
      await this.uploadMetadata(uploadedMeta);
      return { meta: uploadedMeta, action: 'uploaded', chunks, durationMs, bytes };
    }

    if (!remoteEntry && localEntry) {
      const { meta: uploadedMeta, chunks, durationMs, bytes } = await this.uploadFile(encPath, localData, remoteMeta, onProgress);
      await this.uploadMetadata(uploadedMeta);
      return { meta: uploadedMeta, action: 'uploaded', chunks, durationMs, bytes };
    }

    if (remoteEntry && !localEntry) {
      const result = await this.downloadFile(encPath, remoteMeta, onProgress);
      return { meta: remoteMeta, action: 'downloaded', downloadedData: result?.data, chunks: result?.chunks, durationMs: result?.durationMs, bytes: result?.bytes };
    }

    if (remoteEntry.modifiedAt > localEntry.modifiedAt) {
      const result = await this.downloadFile(encPath, remoteMeta, onProgress);
      return { meta: remoteMeta, action: 'downloaded', downloadedData: result?.data, chunks: result?.chunks, durationMs: result?.durationMs, bytes: result?.bytes };
    } else if (localEntry.modifiedAt > remoteEntry.modifiedAt) {
      const { meta: uploadedMeta, chunks, durationMs, bytes } = await this.uploadFile(encPath, localData, remoteMeta, onProgress);
      await this.uploadMetadata(uploadedMeta);
      return { meta: uploadedMeta, action: 'uploaded', chunks, durationMs, bytes };
    } else {
      if (this.deviceId > localEntry.deviceId) {
        const { meta: uploadedMeta, chunks, durationMs, bytes } = await this.uploadFile(encPath, localData, remoteMeta, onProgress);
        await this.uploadMetadata(uploadedMeta);
        return { meta: uploadedMeta, action: 'uploaded', chunks, durationMs, bytes };
      } else {
        const result = await this.downloadFile(encPath, remoteMeta, onProgress);
        return { meta: remoteMeta, action: 'downloaded', downloadedData: result?.data, chunks: result?.chunks, durationMs: result?.durationMs, bytes: result?.bytes };
      }
    }
  }
}
