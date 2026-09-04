import { Plugin, Notice, TFile, TAbstractFile } from 'obsidian';
import { PqcSettings, DEFAULT_SETTINGS, PqcSettingTab } from './settings';
import { LocalState, PersistedState } from './storage';
import { SyncEngine } from './sync/sync-engine';
import { WebDavClient } from './webdav/client';
import { deriveVaultMasterSecret } from './crypto/key-manager';
import { encryptFilename } from './crypto/filename';

export default class PqcWebdavPlugin extends Plugin {
  settings!: PqcSettings;
  private state: LocalState;
  private persisted!: PersistedState;
  private syncEngine: SyncEngine | null = null;
  private masterSecret: Uint8Array | null = null;
  private statusItem: HTMLElement | null = null;
  private syncInProgress = false;
  private pendingFiles = new Set<string>();

  async onload() {
    await this.loadSettings();

    // Local state adapter (Obsidian filesystem)
    const adapter = (this.app.vault as any).adapter;
    this.state = new LocalState(adapter);

    // Register settings tab
    this.addSettingTab(new PqcSettingTab(this.app, this, () => this.reconfigure()));

    // Ribbon icon for manual sync
    this.addRibbonIcon('refresh-cw', 'PQC WebDAV Sync', () => {
      void this.syncNow();
    });

    // Command palette entries
    this.addCommand({
      id: 'pqc-sync-now',
      name: 'Sync now',
      callback: () => this.syncNow(),
    });

    this.addCommand({
      id: 'pqc-sync-push',
      name: 'Push local changes',
      callback: () => this.syncNow('push'),
    });

    this.addCommand({
      id: 'pqc-sync-pull',
      name: 'Pull remote changes',
      callback: () => this.syncNow('pull'),
    });

    // Status bar
    this.statusItem = this.addStatusBarItem();
    this.setStatus('idle');

    // Watch for file changes
    this.registerEvent(
      this.app.vault.on('modify', (file: TAbstractFile) => {
        if (file instanceof TFile) this.onFileChanged(file);
      })
    );
    this.registerEvent(
      this.app.vault.on('delete', (file: TAbstractFile) => {
        if (file instanceof TFile) this.onFileDeleted(file);
      })
    );

    // Set up after layout is ready
    this.app.workspace.onLayoutReady(() => {
      void this.reconfigure();
    });
  }

  onunload() {
    this.setStatus('off');
  }

  // --- Public API used by settings ---

  async testConnection(): Promise<boolean> {
    try {
      const client = new WebDavClient({
        serverUrl: this.settings.serverUrl,
        username: this.settings.username,
        password: this.settings.password,
        basePath: this.settings.basePath,
      });
      await client.list('');
      return true;
    } catch {
      return false;
    }
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }

  private async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  // --- Orchestration ---

  private async reconfigure() {
    // Bail if not configured
    if (!this.settings.serverUrl || !this.settings.passphrase) {
      this.setStatus('config');
      return;
    }

    try {
      // Initialize state (keys, vault id)
      this.persisted = await this.state.initState(
        this.settings.vaultId,
        this.settings.passphrase,
        this.settings.chunkSizeKB
      );

      // Derive master secret from passphrase
      this.masterSecret = await deriveVaultMasterSecret(
        this.settings.passphrase,
        this.persisted.vaultId
      );

      const chunkSize = this.settings.chunkSizeKB * 1024;

      // Create sync engine
      this.syncEngine = new SyncEngine({
        webdavConfig: {
          serverUrl: this.settings.serverUrl,
          username: this.settings.username,
          password: this.settings.password,
          basePath: this.settings.basePath,
        },
        chunkSize,
        deviceId: this.persisted.device.deviceId,
        signingKeyPair: this.persisted.device.signingKeyPair,
        masterSecret: this.masterSecret,
        vaultId: this.persisted.vaultId,
      });

      // Start auto-sync timer
      this.registerInterval(
        window.setInterval(() => {
          if (this.settings.autoSync) void this.syncNow();
        }, this.settings.syncIntervalMin * 60000)
      );

      // Initial sync
      if (this.settings.autoSync) {
        void this.syncNow();
      }

      this.setStatus('ready');
    } catch (e) {
      console.error('PQC WebDAV reconfigure failed:', e);
      this.setStatus('error', e instanceof Error ? e.message : String(e));
      new Notice(`PQC Sync config error: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // --- Sync operations ---

  private setStatus(state: string, detail = '') {
    if (!this.statusItem) return;
    const icon: Record<string, string> = {
      idle: '○',
      syncing: '⟳',
      ready: '●',
      config: '⚙',
      error: '✕',
      off: '',
    };
    const label: Record<string, string> = {
      idle: 'PQC idle',
      syncing: 'PQC syncing...',
      ready: 'PQC synced',
      config: 'PQC not configured',
      error: `PQC error: ${detail}`,
      off: '',
    };
    this.statusItem.setText(`${icon[state] || ''} ${label[state] || ''}`.trim());
    this.statusItem.addClass('pqc-status');
  }

  private async getFileData(file: TFile): Promise<Uint8Array> {
    const content = await this.app.vault.read(file);
    return new TextEncoder().encode(content);
  }

  private onFileChanged(file: TFile) {
    if (!this.syncEngine || !this.settings.autoSync) return;
    // Debounce: collect files and sync after 2s
    this.pendingFiles.add(file.path);
    window.setTimeout(() => {
      if (this.pendingFiles.size > 0) {
        void this.syncNow();
        this.pendingFiles.clear();
      }
    }, 2000);
  }

  private onFileDeleted(file: TFile) {
    if (!this.syncEngine || !this.settings.autoSync) return;
    void this.syncNow();
  }

  async syncNow(mode: 'both' | 'push' | 'pull' = 'both') {
    if (!this.syncEngine || !this.masterSecret) {
      this.setStatus('config');
      return;
    }
    if (this.syncInProgress) {
      return;
    }
    this.syncInProgress = true;
    this.setStatus('syncing');

    try {
      // Load local metadata state
      const state = await this.state.load();
      if (!state) {
        return;
      }
      let meta = state.metadata;

      // Get all markdown files
      const allFiles = this.app.vault.getMarkdownFiles();
      let uploaded = 0;
      let downloaded = 0;
      let conflicts = 0;

      // Sync each markdown file (skip .obsidian internals)
      for (const file of allFiles) {
        if (file.path.startsWith('.obsidian/')) continue;

        try {
          const encPath = await encryptFilename(this.masterSecret, state.vaultId, file.path);
          const localData = await this.getFileData(file);

          const result = await this.syncEngine.syncFile(encPath, localData, meta);
          meta = result.meta;

          switch (result.action) {
            case 'uploaded':
              uploaded++;
              break;
            case 'downloaded':
              downloaded++;
              if (result.downloadedData) {
                const text = new TextDecoder().decode(result.downloadedData);
                const current = await this.app.vault.read(file);
                if (current !== text) {
                  await this.app.vault.modify(file, text);
                }
              }
              break;
            case 'conflict-resolved':
              conflicts++;
              if (result.downloadedData) {
                const text = new TextDecoder().decode(result.downloadedData);
                const current = await this.app.vault.read(file);
                if (current !== text) {
                  await this.app.vault.modify(file, text);
                }
              }
              break;
          }
        } catch (e) {
          console.warn(`PQC sync error on ${file.path}:`, e);
        }
      }

      // Save local metadata
      await this.state.saveMetadata(meta);

      // Run GC if enabled
      if (this.settings.garbageCollectDays > 0) {
        const gcResult = await this.syncEngine.garbageCollect(meta, this.settings.garbageCollectDays);
        if (gcResult.removed > 0) {
          meta = gcResult.meta;
          await this.state.saveMetadata(meta);
        }
      }

      this.setStatus('ready');
      if (uploaded + downloaded + conflicts > 0) {
        new Notice(`PQC Sync: ${uploaded}↑ ${downloaded}↓ ${conflicts}⚠`);
      }
    } catch (e) {
      console.error('PQC sync failed:', e);
      this.setStatus('error', e instanceof Error ? e.message : String(e));
      new Notice(`PQC Sync failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      this.syncInProgress = false;
    }
  }
}
