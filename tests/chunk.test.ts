import { describe, it, expect } from 'vitest';
import { ChunkManager } from '../src/chunk/chunk-manager';
import { sha256 } from '../src/crypto/aes';

const CM = ChunkManager.DEFAULT_CHUNK_SIZE;

describe('ChunkManager', () => {
  it('countChunks: empty file counts as 1', () => {
    const cm = new ChunkManager(64);
    expect(cm.countChunks(0)).toBe(1);
  });

  it('countChunks: exact multiples and partial', () => {
    const cm = new ChunkManager(64);
    expect(cm.countChunks(64)).toBe(1);
    expect(cm.countChunks(65)).toBe(2);
    expect(cm.countChunks(128)).toBe(2);
    expect(cm.countChunks(192)).toBe(3);
  });

  it('split empty file -> one empty chunk', async () => {
    const cm = new ChunkManager(64);
    const chunks = await cm.split(new Uint8Array(0));
    expect(chunks).toHaveLength(1);
    expect(chunks[0].data).toHaveLength(0);
    expect(chunks[0].info.size).toBe(0);
    expect(chunks[0].info.offset).toBe(0);
  });

  it('split/merge roundtrip across sizes', async () => {
    const cm = new ChunkManager(100);
    for (const size of [1, 99, 100, 101, 500, 1024 * 32]) {
      const data = new Uint8Array(size);
      crypto.getRandomValues(data);
      const chunks = await cm.split(data);
      const merged = cm.merge(chunks.map(c => ({ data: c.data, offset: c.info.offset })));
      expect(merged).toEqual(data);
    }
  });

  it('chunk hashes are content-addressed (same data, same hash)', async () => {
    const cm = new ChunkManager(50);
    const data = new TextEncoder().encode('repeating-repeating-repeating-content');
    const [a] = await cm.split(data);
    const [b] = await cm.split(data);
    expect(a.info.hash).toBe(b.info.hash);
  });

  it('hashes differ when content differs', async () => {
    const cm = new ChunkManager(50);
    const [a] = await cm.split(new TextEncoder().encode('aaaa'));
    const [b] = await cm.split(new TextEncoder().encode('aaab'));
    expect(a.info.hash).not.toBe(b.info.hash);
  });

  it('merge sorts by offset regardless of input order', () => {
    const cm = new ChunkManager(100);
    const chunks = [
      { data: new TextEncoder().encode('chunk2'), offset: 100 },
      { data: new TextEncoder().encode('chunk1'), offset: 0 },
    ];
    const merged = cm.merge(chunks);
    expect(new TextDecoder().decode(merged)).toBe('chunk1chunk2');
  });

  it('merge empty -> empty', () => {
    expect(new ChunkManager().merge([])).toEqual(new Uint8Array(0));
  });

  it('missingChunks reports only absent hashes', async () => {
    const cm = new ChunkManager(50);
    const data = new Uint8Array(150);
    crypto.getRandomValues(data);
    const chunks = await cm.split(data);
    const missing = cm.missingChunks(chunks.map(c => c.info), new Set([chunks[0].info.hash]));
    expect(missing).toHaveLength(2);
    expect(missing[0]).toBe(chunks[1].info.hash);
  });

  it('fileHash is deterministic', async () => {
    const data = new TextEncoder().encode('vault-id-hash');
    expect(await new ChunkManager().fileHash(data)).toBe(await sha256(data));
  });

  it('split large file produces correct chunk metadata', async () => {
    const cm = new ChunkManager(CM);
    const data = new Uint8Array(CM * 2 + 17);
    fillRandom(data);
    const chunks = await cm.split(data);
    expect(chunks).toHaveLength(3);
    expect(chunks[0].info.offset).toBe(0);
    expect(chunks[1].info.offset).toBe(CM);
    expect(chunks[2].info.offset).toBe(CM * 2);
    expect(chunks[2].info.size).toBe(17);
  });
});

function fillRandom(buf: Uint8Array): void {
  const MAX = 65536;
  for (let i = 0; i < buf.length; i += MAX) {
    crypto.getRandomValues(buf.subarray(i, Math.min(i + MAX, buf.length)));
  }
}