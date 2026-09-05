import {
  DeviceKeys,
  createDevice,
} from './crypto/key-manager';
import { VaultMetadata, createEmptyMetadata } from './sync/sync-engine';
import { bytesToBase64, base64ToBytes } from './crypto/aes';
import { DataAdapter } from 'obsidian';

/** Metadata + device state persisted to the plugin data directory */
export interface PersistedState {
  vaultId: string;
  device: DeviceKeys;
  metadata: VaultMetadata;
  lastSync: string | null;
}

/** JSON-serializable form of {@link PersistedState} with base64-encoded keys. */
export interface SerializablePersistedState extends Omit<PersistedState, 'device'> {
  device: {
    deviceId: string;
    signingKeyPair: { publicKey: string; secretKey: string };
    encryptionKeyPair?: { publicKey: string; secretKey: string };
  };
}

/**
 * Local storage adapter for device keys and metadata.
 * Uses Obsidian's plugin data directory (data.json for settings,
 * and a separate state file for keys/metadata to keep sizes small).
 */
export class LocalState {
  private adapter: DataAdapter;
  private configDir: string;

  constructor(adapter: DataAdapter, configDir: string) {
    this.adapter = adapter;
    this.configDir = configDir;
  }

  private get statePath(): string {
    return `${this.configDir}/plugins/post-quantum-webdav/state.json`;
  }

  async load(): Promise<PersistedState | null> {
    try {
      const content = await this.adapter.read(this.statePath);
      const parsed = JSON.parse(content) as unknown as SerializablePersistedState | null;
      if (!parsed?.device?.signingKeyPair) return null;
      const device: DeviceKeys = {
        deviceId: parsed.device.deviceId,
        signingKeyPair: {
          publicKey: base64ToBytes(parsed.device.signingKeyPair.publicKey),
          secretKey: base64ToBytes(parsed.device.signingKeyPair.secretKey),
        },
        ...(parsed.device.encryptionKeyPair
          ? {
              encryptionKeyPair: {
                publicKey: base64ToBytes(parsed.device.encryptionKeyPair.publicKey),
                secretKey: base64ToBytes(parsed.device.encryptionKeyPair.secretKey),
              },
            }
          : {}),
      };
      return {
        vaultId: parsed.vaultId,
        device,
        metadata: parsed.metadata,
        lastSync: parsed.lastSync ?? null,
      };
    } catch {
      return null;
    }
  }

  async save(state: PersistedState): Promise<void> {
    const serializable: SerializablePersistedState = {
      ...state,
      // Encode keys as base64 for JSON serialization
      device: {
        ...state.device,
        signingKeyPair: {
          publicKey: bytesToBase64(state.device.signingKeyPair.publicKey),
          secretKey: bytesToBase64(state.device.signingKeyPair.secretKey),
        },
        encryptionKeyPair: state.device.encryptionKeyPair && {
          publicKey: bytesToBase64(state.device.encryptionKeyPair.publicKey),
          secretKey: bytesToBase64(state.device.encryptionKeyPair.secretKey),
        },
      },
    };
    await this.adapter.write(this.statePath, JSON.stringify(serializable, null, 2));
  }

  /**
   * Initialize or load the persistent device state.
   * Creates keys if they don't exist yet.
   */
  async initState(configuredVaultId: string, passphrase: string, chunkSizeKB: number): Promise<PersistedState> {
    const existing = await this.load();

    if (existing && existing.vaultId === configuredVaultId) {
      return existing;
    }

    // New device or vault ID changed
    const vaultId = configuredVaultId || crypto.randomUUID();
    const device = existing?.device || createDevice();
    const metadata = createEmptyMetadata(vaultId, chunkSizeKB * 1024);

    const state: PersistedState = {
      vaultId,
      device,
      metadata,
      lastSync: null,
    };

    await this.save(state);
    return state;
  }

  async saveMetadata(metadata: VaultMetadata): Promise<void> {
    const state = await this.load();
    if (!state) return;
    state.metadata = metadata;
    state.lastSync = new Date().toISOString();
    await this.save(state);
  }
}
