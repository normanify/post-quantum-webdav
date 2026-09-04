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

    this.addCommand({
      id: 'pqc-force-local-wins',
      name: 'Force sync: local wins',
      callback: () => this.forceFullSync('local'),
    });

    this.addCommand({
      id: 'pqc-force-remote-wins',
      name: 'Force sync: remote wins',
      callback: () => this.forceFullSync('remote'),
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
    const adapter = (this.app.vault as any).adapter;
    const buffer = await adapter.readBinary(file.path);
    return new Uint8Array(buffer);
  }

  private shouldSkip(file: TFile): boolean {
    return file.path.startsWith('.') || file.path.startsWith('.obsidian/');
  }

  private async writeFile(file: TFile, data: Uint8Array): Promise<void> {
    const adapter = (this.app.vault as any).adapter;
    await adapter.writeBinary(file.path, data.buffer);
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
      const state = await this.state.load();
      if (!state) {
        return;
      }
      let meta = state.metadata;

      const allFiles = this.app.vault.getFiles();
      const filesToSync = allFiles.filter(f => !this.shouldSkip(f));
      let uploaded = 0;
      let downloaded = 0;
      let conflicts = 0;
      let totalBytes = 0;
      const tStart = performance.now();

      console.log(`[PQC Sync] Starting sync: ${filesToSync.length} files`);

      for (let i = 0; i < filesToSync.length; i++) {
        const file = filesToSync[i];
        const label = `[${i + 1}/${filesToSync.length}] ${file.path}`;
        this.setStatus('syncing', label);

        try {
          const encPath = await encryptFilename(this.masterSecret, state.vaultId, file.path);
          const localData = await this.getFileData(file);

          const result = await this.syncEngine.syncFile(encPath, localData, meta);
          meta = result.meta;

          const sizeKB = (result.bytes || localData.length / 1024).toFixed(1);
          const speed = result.durationMs ? ((result.bytes || 0) / 1024 / (result.durationMs / 1000)).toFixed(0) : '?';

          switch (result.action) {
            case 'uploaded':
              uploaded++;
              totalBytes += result.bytes || 0;
              console.log(`  ↑ ${label}  ${sizeKB}KB  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms  ${speed}KB/s`);
              break;
            case 'downloaded':
              downloaded++;
              totalBytes += result.bytes || 0;
              console.log(`  ↓ ${label}  ${sizeKB}KB  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms  ${speed}KB/s`);
              if (result.downloadedData) {
                await this.writeFile(file, result.downloadedData);
              }
              break;
            case 'conflict-resolved':
              conflicts++;
              totalBytes += result.bytes || 0;
              console.log(`  ⚠ ${label}  ${sizeKB}KB  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms`);
              if (result.downloadedData) {
                await this.writeFile(file, result.downloadedData);
              }
              break;
            default:
              break;
          }
        } catch (e) {
          console.warn(`  ✕ ${label}  ERROR:`, e);
        }
      }

      await this.state.saveMetadata(meta);

      if (this.settings.garbageCollectDays > 0) {
        const gcResult = await this.syncEngine.garbageCollect(meta, this.settings.garbageCollectDays);
        if (gcResult.removed > 0) {
          meta = gcResult.meta;
          await this.state.saveMetadata(meta);
        }
      }

      const elapsed = ((performance.now() - tStart) / 1000).toFixed(1);
      const avgSpeed = totalBytes > 0 ? (totalBytes / 1024 / ((performance.now() - tStart) / 1000)).toFixed(0) : '0';
      this.setStatus('ready');
      console.log(`[PQC Sync] Done: ${uploaded}↑ ${downloaded}↓ ${conflicts}⚠  ${(totalBytes / 1024).toFixed(1)}KB total  ${elapsed}s  avg ${avgSpeed}KB/s`);
      if (uploaded + downloaded + conflicts > 0) {
        new Notice(`PQC Sync: ${uploaded}↑ ${downloaded}↓ ${conflicts}⚠  ${elapsed}s`);
      }
    } catch (e) {
      console.error('PQC sync failed:', e);
      this.setStatus('error', e instanceof Error ? e.message : String(e));
      new Notice(`PQC Sync failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      this.syncInProgress = false;
    }
  }

  async forceFullSync(mode: 'local' | 'remote') {
    if (!this.syncEngine || !this.masterSecret) {
      this.setStatus('config');
      return;
    }
    if (this.syncInProgress) return;
    this.syncInProgress = true;
    this.setStatus('syncing');

    try {
      const state = await this.state.load();
      if (!state) return;
      let meta = state.metadata;

      if (mode === 'local') {
        new Notice('Force sync: local wins — uploading all files to remote...');
        const allFiles = this.app.vault.getFiles();
        let uploaded = 0;
        for (const file of allFiles) {
          if (this.shouldSkip(file)) continue;
          const encPath = await encryptFilename(this.masterSecret, state.vaultId, file.path);
          const localData = await this.getFileData(file);
          const result = await this.syncEngine.forceUploadFile(encPath, localData, meta);
          meta = result.meta;
          uploaded++;
        }

        const remoteMeta = await this.syncEngine.downloadMetadata();
        for (const encPath of Object.keys(remoteMeta.files)) {
          if (!meta.files[encPath]) {
            try { await this.syncEngine.deleteFile(encPath, meta); } catch {}
          }
        }

        await this.syncEngine.uploadMetadata(meta);
        await this.state.saveMetadata(meta);
        this.setStatus('ready');
        new Notice(`Force sync (local wins): ${uploaded} files uploaded`);

      } else {
        new Notice('Force sync: remote wins — downloading all files from remote...');
        const remoteMeta = await this.syncEngine.downloadMetadata();

        const localToEnc = new Map<string, string>();
        for (const file of this.app.vault.getFiles()) {
          if (this.shouldSkip(file)) continue;
          const encPath = await encryptFilename(this.masterSecret, state.vaultId, file.path);
          localToEnc.set(file.path, encPath);
        }

        const encToLocal = new Map<string, TFile>();
        for (const [path, enc] of localToEnc) {
          const file = this.app.vault.getAbstractFileByPath(path);
          if (file instanceof TFile) encToLocal.set(enc, file);
        }

        let downloaded = 0;
        for (const [encPath, remoteEntry] of Object.entries(remoteMeta.files)) {
          const data = await this.syncEngine.forceDownloadFile(encPath, remoteMeta);
          if (data) {
            const text = new TextDecoder().decode(data);
            const localFile = encToLocal.get(encPath);
            if (localFile) {
              const current = await this.app.vault.read(localFile);
              if (current !== text) await this.app.vault.modify(localFile, text);
            } else {
              await this.app.vault.create(encPath.replace(/\//g, '--') + '.md', text);
            }
            downloaded++;
          }
        }

        for (const [path, encPath] of localToEnc) {
          if (!remoteMeta.files[encPath]) {
            const file = this.app.vault.getAbstractFileByPath(path);
            if (file instanceof TFile) await this.app.vault.delete(file);
          }
        }

        await this.syncEngine.uploadMetadata(remoteMeta);
        await this.state.saveMetadata(remoteMeta);
        this.setStatus('ready');
        new Notice(`Force sync (remote wins): ${downloaded} files downloaded`);
      }
    } catch (e) {
      console.error('PQC force sync failed:', e);
      this.setStatus('error', e instanceof Error ? e.message : String(e));
      new Notice(`Force sync failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      this.syncInProgress = false;
    }
  }
}
