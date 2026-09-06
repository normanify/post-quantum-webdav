import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('../src/webdav/client', async () => {
  const { MockWebDavClient } = await import('./helpers/mock-webdav');
  return { WebDavClient: MockWebDavClient };
});

import { SyncEngine, createEmptyMetadata, type VaultMetadata } from '../src/sync/sync-engine';
import { encryptFilename } from '../src/crypto/filename';
import { MockWebDavClient } from './helpers/mock-webdav';

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

const MS = new Uint8Array(32).fill(7);
const VAULT_ID = 'vault-1';

/** Deterministic fake clock — every timestamp in the sim lives in this one domain. */
const T = (sec: number) => `2026-09-06T00:00:${String(sec).padStart(2, '0')}.000Z`;

/** Advance the fake clock — the engine reads Date.now() for every timestamp. */
function at(sec: number): void {
  vi.setSystemTime(new Date(T(sec)));
}

interface DeviceState {
  name: string;
  deviceId: string;
  engine: SyncEngine;
  /** logical path -> plaintext bytes (the "vault" on this device) */
  vault: Map<string, Uint8Array>;
  /** logical path -> file mtime (file.stat.mtime on this device) */
  mtime: Map<string, string>;
  meta: VaultMetadata;
}

interface SyncStats {
  uploaded: number;
  downloaded: number;
  conflictResolved: number;
  unchanged: number;
  deleted: number;
  propagated: number;
  errors: number;
}

function makeEngine(deviceId: string): SyncEngine {
  return new SyncEngine({
    webdavConfig: { serverUrl: 'https://example.com/dav', username: 'u', password: 'p', basePath: 'vault' },
    chunkSize: 100,
    deviceId,
    signingKeyPair: { publicKey: new Uint8Array(32).fill(1), secretKey: new Uint8Array(64).fill(2) },
    masterSecret: MS,
    vaultId: VAULT_ID,
  });
}

function makeDevice(name: string): DeviceState {
  return {
    name,
    deviceId: name,
    engine: makeEngine(name),
    vault: new Map(),
    mtime: new Map(),
    meta: createEmptyMetadata(VAULT_ID, 100),
  };
}

/** Local write on a device: content + mtime (Obsidian file.stat.mtime). */
function edit(dev: DeviceState, path: string, content: string, at: string): void {
  dev.vault.set(path, enc(content));
  dev.mtime.set(path, at);
}

/** Delete the file from the device's vault (the file is gone on disk). */
function deleteLocal(dev: DeviceState, path: string): void {
  dev.vault.delete(path);
  dev.mtime.delete(path);
}

/**
 * Faithful model of Plugin.syncNow() (src/main.ts): iterate the local vault
 * files, refresh the local entry's ownership from the file mtime before each
 * syncFile call, then propagate local deletions for paths this device
 * previously tracked (remote-only files are never wiped).
 */
async function simulateSyncNow(dev: DeviceState): Promise<SyncStats> {
  const prevLocalEntries = Object.keys(dev.meta.files);
  const localFiles = [...dev.vault.keys()].sort();
  const localEncPaths = new Set<string>();
  for (const p of localFiles) localEncPaths.add(await encryptFilename(MS, VAULT_ID, p));

  const stats: SyncStats = { uploaded: 0, downloaded: 0, conflictResolved: 0, unchanged: 0, deleted: 0, propagated: 0, errors: 0 };

  for (const p of localFiles) {
    const encPath = await encryptFilename(MS, VAULT_ID, p);
    // main.ts syncNow: the vault file's current mtime and device own the
    // entry before any sync decision is made.
    const localEntry = dev.meta.files[encPath];
    if (localEntry) {
      localEntry.modifiedAt = dev.mtime.get(p)!;
      localEntry.deviceId = dev.deviceId;
    }
    try {
      const result = await dev.engine.syncFile(encPath, dev.vault.get(p)!, dev.meta);
      dev.meta = result.meta;
      switch (result.action) {
        case 'uploaded':
          stats.uploaded++;
          break;
        case 'unchanged':
          stats.unchanged++;
          break;
        case 'downloaded':
          stats.downloaded++;
          if (result.downloadedData) {
            dev.vault.set(p, result.downloadedData);
            dev.mtime.set(p, new Date().toISOString());
          }
          break;
        case 'conflict-resolved':
          stats.conflictResolved++;
          if (result.downloadedData) {
            dev.vault.set(p, result.downloadedData);
            dev.mtime.set(p, new Date().toISOString());
          }
          break;
        case 'deleted':
          stats.deleted++;
          dev.vault.delete(p);
          dev.mtime.delete(p);
          break;
      }
    } catch {
      stats.errors++;
    }
  }

  // Propagate local deletions — tombstone only files this device tracked.
  for (const encPath of prevLocalEntries) {
    if (!localEncPaths.has(encPath)) {
      try {
        const res = await dev.engine.deleteFile(encPath, dev.meta);
        dev.meta = res.meta;
        stats.propagated++;
      } catch {
        stats.errors++;
      }
    }
  }
  if (stats.propagated > 0) {
    await dev.engine.uploadMetadata(dev.meta);
  }
  return stats;
}

/**
 * No-ghost invariant across a set of devices:
 *  - every vault file is tracked exactly once (no untracked locals, no
 *    phantom metadata entries),
 *  - no path is alive AND tombstoned at the same time,
 *  - every chunk referenced by the metadata (files + tombstones) exists on
 *    the server (a referenced-but-missing chunk would corrupt a future
 *    download — the classic "ghost file" failure mode).
 */
async function assertNoGhosts(devices: DeviceState[]): Promise<void> {
  const server = MockWebDavClient.instances[0];
  const chunksOnServer = new Set(
    [...server.files.keys()]
      .filter(k => k.startsWith('chunks/'))
      .map(k => k.slice('chunks/'.length, -'.bin.enc'.length))
  );

  for (const dev of devices) {
    const vaultEncPaths = new Set(
      await Promise.all([...dev.vault.keys()].map(p => encryptFilename(MS, VAULT_ID, p)))
    );
    const metaFilePaths = new Set(Object.keys(dev.meta.files));

    expect(vaultEncPaths.size, `untracked/phantom files on ${dev.name}`).toBe(metaFilePaths.size);
    for (const encPath of vaultEncPaths) {
      expect(metaFilePaths.has(encPath), `vault file not tracked on ${dev.name}: ${encPath}`).toBe(true);
    }

    for (const encPath of metaFilePaths) {
      expect(dev.meta.deleted[encPath], `ghost: ${encPath} alive and deleted on ${dev.name}`).toBeUndefined();
    }

    const referenced = new Set<string>();
    for (const e of Object.values(dev.meta.files)) e.chunks.forEach(c => referenced.add(c));
    for (const d of Object.values(dev.meta.deleted)) d.chunks.forEach(c => referenced.add(c));
    for (const c of referenced) {
      expect(chunksOnServer.has(c), `referenced chunk ${c} missing on server (${dev.name})`).toBe(true);
    }
  }
}

/** A full sync round on every device must transfer nothing (zero churn). */
async function expectNoTransfers(
  devs: DeviceState[],
  chunkUploads: () => number,
  metaUploads: () => number
): Promise<void> {
  const chunksBefore = chunkUploads();
  const metasBefore = metaUploads();
  for (const d of devs) {
    const stats = await simulateSyncNow(d);
    expect(stats.uploaded).toBe(0);
    expect(stats.downloaded).toBe(0);
    expect(stats.conflictResolved).toBe(0);
    expect(stats.deleted).toBe(0);
    expect(stats.propagated).toBe(0);
    expect(stats.errors).toBe(0);
  }
  expect(chunkUploads()).toBe(chunksBefore);
  expect(metaUploads()).toBe(metasBefore);
}

describe('multi-device simulation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(T(0)));
    MockWebDavClient.reset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('two devices converge through create/edit/delete/recreate with zero churn; fresh device pulls identical state', async () => {
    const A = makeDevice('dev-a');
    const B = makeDevice('dev-b');
    const server = MockWebDavClient.instances[0];
    const chunkUploads = () => server.uploadLog.filter(p => p.startsWith('chunks/')).length;
    const metaUploads = () => server.uploadLog.filter(p => p === 'metadata.json').length;

    // A creates notes/a.md v1 (mtime T1) → uploads at T2
    at(1);
    edit(A, 'notes/a.md', 'v1', T(1));
    at(2);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);

    // B has the same vault structure (stub) → downloads v1 at T4
    at(3);
    edit(B, 'notes/a.md', 'stub', T(3));
    at(4);
    expect((await simulateSyncNow(B)).downloaded).toBe(1);
    expect(dec(B.vault.get('notes/a.md')!)).toBe('v1');

    // A edits v2 (mtime T4) → uploads (same-device ownership path)
    at(4);
    edit(A, 'notes/a.md', 'v2', T(4));
    at(5);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);

    // B pulls v2 (its download-write mtime T4 < A's upload stamp T5)
    at(6);
    expect((await simulateSyncNow(B)).downloaded).toBe(1);
    expect(dec(B.vault.get('notes/a.md')!)).toBe('v2');

    // B edits v3 (mtime T6) → uploads, ownership now attributed to dev-b
    at(6);
    edit(B, 'notes/a.md', 'v3', T(6));
    at(7);
    expect((await simulateSyncNow(B)).uploaded).toBe(1);

    // A pulls v3 at T8
    at(8);
    expect((await simulateSyncNow(A)).downloaded).toBe(1);
    expect(dec(A.vault.get('notes/a.md')!)).toBe('v3');

    // A deletes the file → tombstone propagates to the server
    at(9);
    deleteLocal(A, 'notes/a.md');
    at(10);
    expect((await simulateSyncNow(A)).propagated).toBe(1);
    const encA = await encryptFilename(MS, VAULT_ID, 'notes/a.md');
    const afterDelete = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(afterDelete.files[encA]).toBeUndefined();
    expect(afterDelete.deleted[encA]).toBeDefined();

    // B follows the tombstone (content unchanged since last sync)
    at(11);
    expect((await simulateSyncNow(B)).deleted).toBe(1);
    expect(B.vault.has('notes/a.md')).toBe(false);

    // A recreates the note with new content (mtime T12) → uploads
    at(12);
    edit(A, 'notes/a.md', 'v4', T(12));
    at(13);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);

    // B re-seeds the structure (stub) → downloads v4
    at(14);
    edit(B, 'notes/a.md', 'stub', T(14));
    at(15);
    expect((await simulateSyncNow(B)).downloaded).toBe(1);
    expect(dec(B.vault.get('notes/a.md')!)).toBe('v4');

    // B creates notes/b.md → A downloads it
    at(16);
    edit(B, 'notes/b.md', 'from-b', T(16));
    at(17);
    expect((await simulateSyncNow(B)).uploaded).toBe(1);
    at(18);
    edit(A, 'notes/b.md', 'stub', T(18));
    at(19);
    expect((await simulateSyncNow(A)).downloaded).toBe(1);
    expect(dec(A.vault.get('notes/b.md')!)).toBe('from-b');

    // --- Zero-churn: further full syncs on both devices transfer nothing ---
    at(30);
    await expectNoTransfers([A, B], chunkUploads, metaUploads);

    // --- Fresh device C pulls the exact converged state ---
    // Stub mtimes are OLD (T0) — a genuinely new device has no local edits, so
    // LWW must download remote content instead of uploading the stubs over it.
    at(31);
    const C = makeDevice('dev-c');
    edit(C, 'notes/a.md', 'stub', T(0));
    edit(C, 'notes/b.md', 'stub', T(0));
    at(32);
    const statsC = await simulateSyncNow(C);
    expect(statsC.downloaded).toBe(2);
    expect(statsC.errors).toBe(0);
    expect(dec(C.vault.get('notes/a.md')!)).toBe('v4');
    expect(dec(C.vault.get('notes/b.md')!)).toBe('from-b');

    // No loss, no ghosts: all three devices hold identical bytes
    await assertNoGhosts([A, B, C]);
    expect([...A.vault.keys()].sort()).toEqual([...B.vault.keys()].sort());
    for (const p of A.vault.keys()) {
      expect(B.vault.get(p)!).toEqual(A.vault.get(p)!);
      expect(C.vault.get(p)!).toEqual(A.vault.get(p)!);
    }
  });

  it('concurrent edits on two devices converge to a single winner (no split-brain)', async () => {
    const A = makeDevice('dev-a');
    const B = makeDevice('dev-b');
    const server = MockWebDavClient.instances[0];

    // v1 exists on both devices
    at(1);
    edit(A, 'notes/c.md', 'v1', T(1));
    at(2);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);
    at(3);
    edit(B, 'notes/c.md', 'stub', T(3));
    at(4);
    expect((await simulateSyncNow(B)).downloaded).toBe(1);

    // Both devices edit without syncing in between: A at T5, B at T6
    at(5);
    edit(A, 'notes/c.md', 'edit from A', T(5));
    at(6);
    edit(B, 'notes/c.md', 'edit from B', T(6));

    // A syncs first → uploads its edit (stamp T7)
    at(7);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);

    // B syncs: its edit (T6) predates A's sync stamp (T7) → downloads A's version
    at(8);
    expect((await simulateSyncNow(B)).downloaded).toBe(1);

    // One winner everywhere — no split-brain, the losing edit is gone on all devices
    expect(dec(B.vault.get('notes/c.md')!)).toBe('edit from A');
    expect(dec(B.vault.get('notes/c.md')!)).toEqual(dec(A.vault.get('notes/c.md')!));
    const remoteMeta = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    const encC = await encryptFilename(MS, VAULT_ID, 'notes/c.md');
    expect(remoteMeta.files[encC].deviceId).toBe('dev-a');

    // Convergence holds across further syncs without transfer churn
    expect(remoteMeta.deleted[encC]).toBeUndefined();
    await assertNoGhosts([A, B]);
  });

  it('concurrent delete vs edit: deletion wins when newer, edit wins when newer (no ghosts)', async () => {
    const A = makeDevice('dev-a');
    const B = makeDevice('dev-b');
    const server = MockWebDavClient.instances[0];
    const encD = await encryptFilename(MS, VAULT_ID, 'notes/d.md');

    // Both devices have notes/d.md v1
    at(1);
    edit(A, 'notes/d.md', 'v1', T(1));
    at(2);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);
    at(3);
    edit(B, 'notes/d.md', 'stub', T(3));
    at(4);
    expect((await simulateSyncNow(B)).downloaded).toBe(1);

    // --- Direction 1: deletion is NEWER than B's last change → deletion wins.
    at(5);
    deleteLocal(A, 'notes/d.md');
    at(6);
    expect((await simulateSyncNow(A)).propagated).toBe(1); // tombstone deletedAt T6
    at(7);
    expect((await simulateSyncNow(B)).deleted).toBe(1); // B follows the tombstone
    expect(B.vault.has('notes/d.md')).toBe(false);
    const serverMeta1 = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(serverMeta1.files[encD]).toBeUndefined();
    expect(serverMeta1.deleted[encD]).toBeDefined();

    // --- Direction 2: edit is NEWER than the deletion → edit wins.
    at(8);
    edit(A, 'notes/d.md', 'v2', T(8)); // A recreates
    at(9);
    expect((await simulateSyncNow(A)).uploaded).toBe(1);
    at(10);
    edit(B, 'notes/d.md', 'stub', T(10));
    at(11);
    expect((await simulateSyncNow(B)).downloaded).toBe(1); // B re-pulls v2
    at(12);
    deleteLocal(A, 'notes/d.md');
    at(13);
    expect((await simulateSyncNow(A)).propagated).toBe(1); // tombstone deletedAt T13 (v2 chunks)
    // B edits while the tombstone exists → content differs → the edit wins
    at(14);
    edit(B, 'notes/d.md', 'v3 edit', T(14));
    at(15);
    expect((await simulateSyncNow(B)).uploaded).toBe(1);
    expect(dec(B.vault.get('notes/d.md')!)).toBe('v3 edit');
    const serverMeta2 = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(serverMeta2.files[encD]).toBeDefined();
    expect(serverMeta2.deleted[encD]).toBeUndefined();

    // A's device intentionally deleted the file, so its local tombstone stays
    // (a locally-missing path is never resurrected by syncNow — that's the
    // plugin's documented limitation; forceFullSync('remote') is the recovery).
    expect(A.vault.has('notes/d.md')).toBe(false);
    expect(A.meta.deleted[encD]).toBeDefined();

    await assertNoGhosts([A, B]);
  });
});