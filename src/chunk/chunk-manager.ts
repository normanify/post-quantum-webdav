import { sha256, bytesToBase64 } from '../crypto/aes';

export interface ChunkInfo {
  /** Base64(SHA-256) of the plaintext chunk data — the chunk's identity. */
  hash: string;
  /** Byte offset of this chunk within the original file. */
  offset: number;
  /** Plaintext size in bytes. */
  size: number;
}

export interface SplitResult {
  chunks: ChunkInfo[];
  /** Whether the file was large enough to warrant splitting. */
  split: boolean;
}

/**
 * Chunk manager: splits a file into fixed-size chunks and can reassemble
 * them. Chunks are identified by their SHA-256 hash (deduplication key).
 */
export class ChunkManager {
  /** Default chunk size: 256 KB. */
  static readonly DEFAULT_CHUNK_SIZE = 256 * 1024;

  private chunkSize: number;

  constructor(chunkSize: number = ChunkManager.DEFAULT_CHUNK_SIZE) {
    this.chunkSize = chunkSize;
  }

  /** Number of chunks a file of `size` bytes will produce. */
  countChunks(size: number): number {
    if (size === 0) return 1;
    return Math.ceil(size / this.chunkSize);
  }

  /**
   * Split a file buffer into chunks.
   * Returns an array of { data, info } where data is the plaintext slice
   * and info carries the hash + offset + size.
   */
  async split(file: Uint8Array): Promise<{ data: Uint8Array; info: ChunkInfo }[]> {
    const out: { data: Uint8Array; info: ChunkInfo }[] = [];
    if (file.length === 0) {
      const info: ChunkInfo = { hash: await sha256(file), offset: 0, size: 0 };
      out.push({ data: file, info });
      return out;
    }
    for (let offset = 0; offset < file.length; offset += this.chunkSize) {
      const end = Math.min(offset + this.chunkSize, file.length);
      const slice = file.slice(offset, end);
      const info: ChunkInfo = {
        hash: await sha256(slice),
        offset,
        size: slice.length,
      };
      out.push({ data: slice, info });
    }
    return out;
  }

  /**
   * Reassemble a file from its chunks in ascending offset order.
   * Caller is responsible for providing complete, ordered chunks.
   */
  merge(chunks: { data: Uint8Array; offset: number }[]): Uint8Array {
    if (chunks.length === 0) return new Uint8Array(0);
    const sorted = [...chunks].sort((a, b) => a.offset - b.offset);
    const total = sorted.reduce((acc, c) => acc + c.data.length, 0);
    const out = new Uint8Array(total);
    let cursor = 0;
    for (const c of sorted) {
      out.set(c.data, cursor);
      cursor += c.data.length;
    }
    return out;
  }

  /**
   * Determine which chunks of this file are missing locally, given the set of
   * hashes already present. Returns hashes that need fetching.
   */
  missingChunks(chunks: ChunkInfo[], presentHashes: Set<string>): string[] {
    return chunks.map(c => c.hash).filter(h => !presentHashes.has(h));
  }

  /** Compute a stable file-id/hash from its full content. */
  async fileHash(data: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
    return bytesToBase64(new Uint8Array(digest));
  }
}
