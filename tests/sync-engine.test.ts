import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/webdav/client', async () => {
  const { MockWebDavClient } = await import('./helpers/mock-webdav');
  return { WebDavClient: MockWebDavClient };
});

import { SyncEngine, createEmptyMetadata, type VaultMetadata } from '../src/sync/sync-engine';
import { sha256 } from '../src/crypto/aes';
import { MockWebDavClient } from './helpers/mock-webdav';

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

function makeEngine(deviceId = 'dev-a'): SyncEngine {
  return new SyncEngine({
    webdavConfig: { serverUrl: 'https://example.com/dav', username: 'u', password: 'p', basePath: 'vault' },
    chunkSize: 100,
    deviceId,
    signingKeyPair: { publicKey: new Uint8Array(32).fill(1), secretKey: new Uint8Array(64).fill(2) },
    masterSecret: new Uint8Array(32).fill(7),
    vaultId: 'vault-1',
  });
}

function blankMeta(): VaultMetadata {
  return createEmptyMetadata('vault-1', 100);
}

describe('SyncEngine', () => {
  beforeEach(() => {
    MockWebDavClient.reset();
  });

  it('first sync uploads file and metadata, second sync is unchanged', async () => {
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];

    const res = await engine.syncFile('f_abc', enc('hello world'), blankMeta());
    expect(res.action).toBe('uploaded');
    expect(res.meta.files['f_abc'].size).toBe(11);
    expect(server.files.has('metadata.json')).toBe(true);
    expect([...server.files.keys()].some(k => k.startsWith('chunks/'))).toBe(true);
    expect(res.meta.sequence).toBe(1);

    const res2 = await engine.syncFile('f_abc', enc('hello world'), res.meta);
    expect(res2.action).toBe('unchanged');
    expect(server.uploadLog.filter(p => p.startsWith('chunks/'))).toHaveLength(1);
  });

  it('downloads remote-only file onto a fresh device', async () => {
    const engineA = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    await engineA.syncFile('f_xyz', enc('remote content'), blankMeta());

    const engineB = makeEngine('dev-b');
    const resB = await engineB.syncFile('f_xyz', enc('local stub'), blankMeta());
    expect(resB.action).toBe('downloaded');
    expect(resB.downloadedData && dec(resB.downloadedData)).toBe('remote content');
  });

  it('uploads when local content is newer', async () => {
    const engine = makeEngine('dev-a');
    const first = await engine.syncFile('f_a', enc('v1'), blankMeta());

    const localMeta = first.meta;
    // Local edit bumps the local clock, so this is a plain newer-content
    // upload, not a same-clock modify-modify conflict.
    localMeta.vectorClock['dev-a'] = 2;
    localMeta.files['f_a'].modifiedAt = '2030-01-01T00:00:00.000Z';
    const res = await engine.syncFile('f_a', enc('v2 local edit'), localMeta);
    expect(res.action).toBe('uploaded');
    expect(res.meta.files['f_a'].size).toBe(13);
  });

  it('downloads when remote content is newer', async () => {
    const engineA = makeEngine('dev-a');
    const first = await engineA.syncFile('f_a', enc('v1'), blankMeta());

    // Device B publishes a newer version straight to the remote
    const engineB = makeEngine('dev-b');
    const remoteMeta = await engineB.downloadMetadata();
    const pushed = await engineB.forceUploadFile('f_a', enc('v2 remote edit'), remoteMeta);
    await engineB.uploadMetadata(pushed.meta);

    // Device A still has the stale v1 entry and content
    const engineALocal = makeEngine('dev-a');
    const stale = blankMeta();
    stale.files['f_a'] = first.meta.files['f_a'];
    const res = await engineALocal.syncFile('f_a', enc('v1'), stale);
    expect(res.action).toBe('downloaded');
    expect(res.downloadedData && dec(res.downloadedData)).toBe('v2 remote edit');
  });

  it('deviceId tiebreak decides when timestamps are equal', async () => {
    const engineA = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    const first = await engineA.syncFile('f_t', enc('same-time'), blankMeta());

    const localMeta = first.meta;
    const remoteEntry = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    localMeta.files['f_t'].modifiedAt = remoteEntry.files['f_t'].modifiedAt;
    localMeta.files['f_t'].deviceId = 'dev-a';

    const engineB = makeEngine('dev-b');
    const res = await engineB.syncFile('f_t', enc('different content'), localMeta);
    expect(res.action).toBe('uploaded');
  });

  it('follows remote tombstone when local content is unchanged', async () => {
    const engineA = makeEngine('dev-a');
    const first = await engineA.syncFile('f_t', enc('tombstone test'), blankMeta());
    const delRes = await engineA.deleteFile('f_t', await engineA.downloadMetadata());
    await engineA.uploadMetadata(delRes.meta);

    // Device B still holds the pre-delete entry for f_t but has no local edits
    const engineB = makeEngine('dev-b');
    const server = MockWebDavClient.instances[0];
    const metaB = blankMeta();
    metaB.files['f_t'] = first.meta.files['f_t'];
    const resB = await engineB.syncFile('f_t', enc('tombstone test'), metaB);
    expect(resB.action).toBe('deleted');
    expect(resB.meta.files['f_t']).toBeUndefined();
    expect(resB.meta.deleted['f_t']).toBeDefined();
    const remoteAfter = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(remoteAfter.files['f_t']).toBeUndefined();
  });

  it('re-uploads a recreated file after remote delete (different content)', async () => {
    const engineA = makeEngine('dev-a');
    await engineA.syncFile('f_t', enc('original'), blankMeta());
    const metaA = await engineA.downloadMetadata();
    const delRes = await engineA.deleteFile('f_t', metaA);
    await engineA.uploadMetadata(delRes.meta);

    const engineB = makeEngine('dev-b');
    const metaB = blankMeta();
    const resB = await engineB.syncFile('f_t', enc('brand new content'), metaB);
    expect(resB.action).toBe('uploaded');
    expect(resB.meta.files['f_t'].size).toBe(17);
  });

  it('empty file roundtrips with one chunk', async () => {
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    const up = await engine.syncFile('f_empty', new Uint8Array(0), blankMeta());
    expect(up.meta.files['f_empty'].size).toBe(0);
    expect(up.meta.files['f_empty'].chunks).toHaveLength(1);

    const down = await engine.downloadFile('f_empty', up.meta);
    expect(down?.data).toEqual(new Uint8Array(0));
  });

  it('multi-chunk file uploads and downloads intact', async () => {
    const engineA = makeEngine('dev-a');
    const big = new Uint8Array(523);
    crypto.getRandomValues(big);
    await engineA.syncFile('f_big', big, blankMeta());

    const engineB = makeEngine('dev-b');
    const resB = await engineB.syncFile('f_big', new Uint8Array(0), blankMeta());
    expect(resB.action).toBe('downloaded');
    expect(resB.downloadedData).toEqual(big);
  });

  it('tampered chunk fails download with integrity error', async () => {
    const engineA = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    await engineA.syncFile('f_int', enc('integrity-critical-data'), blankMeta());

    for (const key of server.files.keys()) {
      if (key.startsWith('chunks/')) {
        const tampered = Uint8Array.from(server.files.get(key)!);
        tampered[tampered.length - 1] ^= 0xff;
        server.setFile(key, tampered);
      }
    }
    const engineB = makeEngine('dev-b');
    await expect(engineB.syncFile('f_int', new Uint8Array(0), blankMeta())).rejects.toThrow(/tampered|corrupt|mismatch/i);
  });

  it('missing chunk on server fails download', async () => {
    const engineA = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    await engineA.syncFile('f_missing', enc('will lose a chunk'), blankMeta());
    for (const key of [...server.files.keys()]) {
      if (key.startsWith('chunks/')) server.files.delete(key);
    }
    const engineB = makeEngine('dev-b');
    await expect(engineB.syncFile('f_missing', new Uint8Array(0), blankMeta())).rejects.toThrow(/404|not found/i);
  });

  it('garbageCollect removes stale tombstone chunks but keeps fresh ones', async () => {
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    const meta = blankMeta();
    meta.deleted['f_old'] = {
      deletedAt: new Date(Date.now() - 40 * 86400000).toISOString(),
      deviceId: 'dev-a', chunks: ['chunk-old'], signature: '',
    };
    meta.deleted['f_new'] = {
      deletedAt: new Date(Date.now() - 5 * 86400000).toISOString(),
      deviceId: 'dev-a', chunks: ['chunk-new'], signature: '',
    };
    server.setFile('chunks/chunk-old.bin.enc', enc('x'));
    server.setFile('chunks/chunk-new.bin.enc', enc('y'));

    const gc = await engine.garbageCollect(meta, 30);
    expect(gc.removed).toBe(1);
    expect(server.files.has('chunks/chunk-old.bin.enc')).toBe(false);
    expect(server.files.has('chunks/chunk-new.bin.enc')).toBe(true);
    expect(gc.meta.deleted['f_old']).toBeUndefined();
    expect(gc.meta.deleted['f_new']).toBeDefined();
  });

  it('modify-modify conflict: remote (newer) wins and is downloaded', async () => {
    const h1 = await sha256(enc('AA'));
    const h2 = await sha256(enc('BB'));
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    // Seed the remote chunk via the real upload path — chunks are stored
    // encrypted, so a plaintext setFile would fail GCM auth on download.
    await engine.forceUploadFile('f_seed', enc('BB'), blankMeta());

    const remoteMeta = blankMeta();
    remoteMeta.sequence = 5;
    remoteMeta.vectorClock = { 'dev-a': 1, 'dev-b': 2 };
    remoteMeta.files['f_c'] = {
      chunks: [h2], size: 2, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T10:00:00.000Z', deviceId: 'dev-b', signature: '',
    };
    server.setFile('metadata.json', enc(JSON.stringify(remoteMeta)));

    const localMeta = blankMeta();
    localMeta.sequence = 4;
    localMeta.vectorClock = { 'dev-a': 2, 'dev-b': 1 };
    localMeta.files['f_c'] = {
      chunks: [h1], size: 2, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T09:00:00.000Z', deviceId: 'dev-a', signature: '',
    };

    const res = await engine.syncFile('f_c', enc('AA'), localMeta);
    expect(res.action).toBe('conflict-resolved');
    expect(res.downloadedData && dec(res.downloadedData)).toBe('BB');
    const serverMeta = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(serverMeta.files['f_c'].deviceId).toBe('dev-b');
  });

  it('modify-modify conflict: local (newer) wins and is uploaded', async () => {
    const h1 = await sha256(enc('LL'));
    const h2 = await sha256(enc('RR'));
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];

    const remoteMeta = blankMeta();
    remoteMeta.sequence = 5;
    remoteMeta.vectorClock = { 'dev-a': 1, 'dev-b': 2 };
    remoteMeta.files['f_d'] = {
      chunks: [h2], size: 2, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T09:00:00.000Z', deviceId: 'dev-b', signature: '',
    };
    server.setFile('metadata.json', enc(JSON.stringify(remoteMeta)));

    const localMeta = blankMeta();
    localMeta.sequence = 4;
    localMeta.vectorClock = { 'dev-a': 2, 'dev-b': 1 };
    localMeta.files['f_d'] = {
      chunks: [h1], size: 2, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T10:00:00.000Z', deviceId: 'dev-a', signature: '',
    };

    const res = await engine.syncFile('f_d', enc('LL'), localMeta);
    expect(res.action).toBe('conflict-resolved');
    const serverMeta = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(serverMeta.files['f_d'].deviceId).toBe('dev-a');
  });

  it('delete-modify conflict: remote deletion wins when newer', async () => {
    const h1 = await sha256(enc('content'));
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];

    const remoteMeta = blankMeta();
    remoteMeta.sequence = 5;
    remoteMeta.vectorClock = { 'dev-a': 1, 'dev-b': 2 };
    remoteMeta.deleted['f_e'] = {
      deletedAt: '2026-09-06T11:00:00.000Z', deviceId: 'dev-b', chunks: [h1], signature: '',
    };
    server.setFile('metadata.json', enc(JSON.stringify(remoteMeta)));

    const localMeta = blankMeta();
    localMeta.sequence = 4;
    localMeta.vectorClock = { 'dev-a': 2, 'dev-b': 1 };
    localMeta.files['f_e'] = {
      chunks: [h1], size: 7, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T09:00:00.000Z', deviceId: 'dev-a', signature: '',
    };

    const res = await engine.syncFile('f_e', enc('content'), localMeta);
    expect(res.action).toBe('deleted');
  });

  it('modify-delete conflict: remote modification wins and is downloaded', async () => {
    const h1 = await sha256(enc('old local'));
    const h2 = await sha256(enc('new remote'));
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    // Seed the remote chunk via the real upload path — chunks are stored
    // encrypted, so a plaintext setFile would fail GCM auth on download.
    await engine.forceUploadFile('f_seed', enc('new remote'), blankMeta());

    const remoteMeta = blankMeta();
    remoteMeta.sequence = 5;
    remoteMeta.vectorClock = { 'dev-a': 1, 'dev-b': 2 };
    remoteMeta.files['f_md'] = {
      chunks: [h2], size: 10, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T11:00:00.000Z', deviceId: 'dev-b', signature: '',
    };
    server.setFile('metadata.json', enc(JSON.stringify(remoteMeta)));

    const localMeta = blankMeta();
    localMeta.sequence = 4;
    localMeta.vectorClock = { 'dev-a': 2, 'dev-b': 1 };
    localMeta.deleted['f_md'] = {
      deletedAt: '2026-09-06T09:00:00.000Z', deviceId: 'dev-a', chunks: [h1], signature: '',
    };

    const res = await engine.syncFile('f_md', new Uint8Array(0), localMeta);
    expect(res.action).toBe('conflict-resolved');
    expect(res.downloadedData && dec(res.downloadedData)).toBe('new remote');
  });

  it('delete-modify conflict: local (newer) modification wins', async () => {
    const h1 = await sha256(enc('local content'));
    const h2 = await sha256(enc('old remote'));
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];

    const remoteMeta = blankMeta();
    remoteMeta.sequence = 5;
    remoteMeta.vectorClock = { 'dev-a': 1, 'dev-b': 2 };
    remoteMeta.deleted['f_dm'] = {
      deletedAt: '2026-09-06T09:00:00.000Z', deviceId: 'dev-b', chunks: [h2], signature: '',
    };
    server.setFile('metadata.json', enc(JSON.stringify(remoteMeta)));

    const localMeta = blankMeta();
    localMeta.sequence = 4;
    localMeta.vectorClock = { 'dev-a': 2, 'dev-b': 1 };
    localMeta.files['f_dm'] = {
      chunks: [h1], size: 13, createdAt: '2026-01-01T00:00:00.000Z',
      modifiedAt: '2026-09-06T11:00:00.000Z', deviceId: 'dev-a', signature: '',
    };

    const res = await engine.syncFile('f_dm', enc('local content'), localMeta);
    expect(res.action).toBe('conflict-resolved');
    const serverMeta = JSON.parse(dec(server.files.get('metadata.json')!)) as VaultMetadata;
    expect(serverMeta.files['f_dm'].deviceId).toBe('dev-a');
  });

  it('uploads local file when remote metadata is missing (fresh server)', async () => {
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    const res = await engine.syncFile('f_fresh', enc('seed'), blankMeta());
    expect(res.action).toBe('uploaded');
    expect(server.files.has('metadata.json')).toBe(true);
  });

  it('rejects sync when metadata download fails (network error, not 404)', async () => {
    const engineA = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    await engineA.syncFile('f_g', enc('existing remote'), blankMeta());

    server.failDownloads = 1;
    const engineB = makeEngine('dev-b');
    await expect(engineB.syncFile('f_g', new Uint8Array(0), blankMeta())).rejects.toThrow(/network|failed/i);
  });

  it('throws on rollback (remote sequence older than local)', async () => {
    const engine = makeEngine('dev-a');
    const server = MockWebDavClient.instances[0];
    const remoteMeta = blankMeta();
    remoteMeta.sequence = 2;
    server.setFile('metadata.json', enc(JSON.stringify(remoteMeta)));

    const localMeta = blankMeta();
    localMeta.sequence = 7;

    await expect(engine.syncFile('f_h', enc('data'), localMeta)).rejects.toThrow(/rollback/i);
  });

  it('forceUploadFile replaces tombstone and bumps clock', async () => {
    const engine = makeEngine('dev-a');
    const meta = blankMeta();
    meta.deleted['f_i'] = { deletedAt: '2026-01-01T00:00:00.000Z', deviceId: 'dev-a', chunks: ['old'], signature: '' };
    const res = await engine.forceUploadFile('f_i', enc('forced'), meta);
    expect(res.meta.files['f_i'].size).toBe(6);
    expect(res.meta.deleted['f_i']).toBeUndefined();
    expect(res.meta.vectorClock['dev-a']).toBe(1);
  });

  it('detectConflicts finds modify-modify when clocks are concurrent', async () => {
    const engine = makeEngine('dev-a');
    const hA = await sha256(enc('local content'));
    const hB = await sha256(enc('remote content'));
    const remote = blankMeta();
    remote.vectorClock = { a: 1, b: 1 };
    remote.files['f'] = { chunks: [hB], size: 1, createdAt: '', modifiedAt: '2026-01-02', deviceId: 'b', signature: '' };
    const local = blankMeta();
    local.vectorClock = { a: 2, b: 0 };
    local.files['f'] = { chunks: [hA], size: 1, createdAt: '', modifiedAt: '2026-01-01', deviceId: 'a', signature: '' };
    const conflicts = engine.detectConflicts(local, remote);
    expect(conflicts.some(c => c.type === 'modify-modify' && c.path === 'f')).toBe(true);
  });
});