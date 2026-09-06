import { describe, it, expect } from 'vitest';
import { LocalState } from '../src/storage';
import { createDevice } from '../src/crypto/key-manager';
import { createEmptyMetadata } from '../src/sync/sync-engine';

class FakeAdapter {
  files = new Map<string, string>();
  async read(path: string): Promise<string> {
    const v = this.files.get(path);
    if (v === undefined) throw new Error(`ENOENT: ${path}`);
    return v;
  }
  async write(path: string, content: string): Promise<void> {
    this.files.set(path, content);
  }
  async exists(path: string): Promise<boolean> {
    return this.files.has(path);
  }
}

function makeState() {
  const device = createDevice();
  return {
    vaultId: 'vault-abc',
    device,
    metadata: createEmptyMetadata('vault-abc', 1024 * 1024),
    lastSync: null,
  };
}

describe('LocalState', () => {
  it('returns null when state file is missing or corrupt', async () => {
    const adapter = new FakeAdapter();
    const state = new LocalState(adapter as never, '.obsidian');
    expect(await state.load()).toBeNull();
    adapter.files.set('.obsidian/plugins/post-quantum-webdav/state.json', '{not valid json');
    expect(await state.load()).toBeNull();
  });

  it('persists and restores device keys across base64 roundtrip', async () => {
    const adapter = new FakeAdapter();
    const ls = new LocalState(adapter as never, '.obsidian');
    const original = makeState();
    await ls.save(original);

    const restored = await ls.load();
    expect(restored).not.toBeNull();
    expect(restored!.vaultId).toBe('vault-abc');
    expect(restored!.device.deviceId).toBe(original.device.deviceId);
    expect(restored!.device.signingKeyPair.publicKey).toEqual(original.device.signingKeyPair.publicKey);
    expect(restored!.device.signingKeyPair.secretKey).toEqual(original.device.signingKeyPair.secretKey);
    expect(restored!.device.encryptionKeyPair?.publicKey).toEqual(original.device.encryptionKeyPair!.publicKey);
  });

  it('initState reuses existing device for same vaultId', async () => {
    const adapter = new FakeAdapter();
    const ls = new LocalState(adapter as never, '.obsidian');
    const first = await ls.initState('vault-x', 'passphrase', 1024);
    const second = await ls.initState('vault-x', 'passphrase', 1024);
    expect(second.device.deviceId).toBe(first.device.deviceId);
    expect(second.vaultId).toBe('vault-x');
  });

  it('initState reuses the device but resets metadata when vaultId changes', async () => {
    const adapter = new FakeAdapter();
    const ls = new LocalState(adapter as never, '.obsidian');
    const first = await ls.initState('vault-old', 'pass', 1024);
    await ls.saveMetadata(first.metadata);
    const second = await ls.initState('vault-new', 'pass', 1024);
    expect(second.vaultId).toBe('vault-new');
    expect(second.device.deviceId).toBe(first.device.deviceId);
    expect(second.metadata.sequence).toBe(0);
  });

  it('saveMetadata updates lastSync', async () => {
    const adapter = new FakeAdapter();
    const ls = new LocalState(adapter as never, '.obsidian');
    await ls.initState('vault-m', 'pass', 1024);
    const meta = createEmptyMetadata('vault-m', 1024);
    meta.sequence = 5;
    await ls.saveMetadata(meta);
    const loaded = await ls.load();
    expect(loaded!.metadata.sequence).toBe(5);
    expect(loaded!.lastSync).not.toBeNull();
  });
});