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
    const configDir = (this.app.vault as any).configDir || '.obsidian';
    this.state = new LocalState(adapter, configDir);

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

      console.log(`[PQC Config] Server: ${this.settings.serverUrl}/${this.settings.basePath}`);
      console.log(`[PQC Config] Chunk: ${this.formatBytes(chunkSize)}, Timeout: ${this.settings.uploadTimeoutSec}s, Parallel: ${this.settings.parallelLimit}, Auto-sync: ${this.settings.syncIntervalMin}min`);

      // Create sync engine
      this.syncEngine = new SyncEngine({
        webdavConfig: {
          serverUrl: this.settings.serverUrl,
          username: this.settings.username,
          password: this.settings.password,
          basePath: this.settings.basePath,
          timeoutMs: this.settings.uploadTimeoutSec * 1000,
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
    const prefix = `${icon[state] || ''}`.trim();
    if (state === 'syncing' && detail) {
      this.statusItem.setText(`${prefix} ${detail}`);
    } else {
      const label: Record<string, string> = {
        idle: 'PQC idle',
        ready: 'PQC synced',
        config: 'PQC not configured',
        error: `PQC error: ${detail}`,
        off: '',
      };
      this.statusItem.setText(`${prefix} ${label[state] || ''}`.trim());
    }
    this.statusItem.addClass('pqc-status');
  }

  private async getFileData(file: TFile): Promise<Uint8Array> {
    const adapter = (this.app.vault as any).adapter;
    const buffer = await adapter.readBinary(file.path);
    return new Uint8Array(buffer);
  }

  private shouldSkip(file: TFile): boolean {
    const configDir = (this.app.vault as any).configDir || '.obsidian';
    return file.path.startsWith('.') || file.path.startsWith(configDir + '/');
  }

  private progressBar(ratio: number, width = 10): string {
    const filled = Math.round(ratio * width);
    const empty = width - filled;
    return '█'.repeat(filled) + '░'.repeat(empty);
  }

  private formatBytes(bytes: number): string {
    if (!isFinite(bytes) || bytes <= 0) return '0B';
    if (bytes < 1) return '<1B';
    if (bytes < 1024) return `${bytes.toFixed(1)}B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / 1048576).toFixed(1)}MB`;
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
      let skipped = 0;
      let errors = 0;
      let bytesTransferred = 0;
      const totalBytesAll = filesToSync.reduce((sum, f) => sum + f.stat.size, 0);
      const tStart = performance.now();

      console.log(`[PQC Sync] ═══════════════════════════════════════`);
      console.log(`[PQC Sync] Starting sync: ${filesToSync.length} files, ${this.formatBytes(totalBytesAll)} total`);
      console.log(`[PQC Sync] Settings: chunkSize=${this.formatBytes(this.settings.chunkSizeKB * 1024)}, timeout=${this.settings.uploadTimeoutSec}s, parallel=${this.settings.parallelLimit}`);

      for (let i = 0; i < filesToSync.length; i++) {
        const file = filesToSync[i];
        const fileNum = `${i + 1}/${filesToSync.length}`;
        const sizeStr = this.formatBytes(file.stat.size);
        const pct = totalBytesAll > 0 ? bytesTransferred / totalBytesAll : 0;
        const bar = this.progressBar(pct);
        const elapsed = ((performance.now() - tStart) / 1000).toFixed(0);
        const speed = bytesTransferred > 0 && (performance.now() - tStart) > 0
          ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
          : '';
        this.setStatus('syncing', `${fileNum} ${bar} ${this.formatBytes(bytesTransferred)}/${this.formatBytes(totalBytesAll)} ${speed} | ${file.path} (${sizeStr})`);

        try {
          const encPath = await encryptFilename(this.masterSecret, state.vaultId, file.path);
          const localData = await this.getFileData(file);

          const result = await this.syncEngine.syncFile(encPath, localData, meta, (chunkIdx, totalChunks, chunkBytes, totalBytes, direction) => {
            const chunkPct = totalBytesAll > 0 ? (bytesTransferred + (localData.length * chunkIdx / totalChunks)) / totalBytesAll : 0;
            const chunkBar = this.progressBar(chunkPct);
            const sp = bytesTransferred > 0 && (performance.now() - tStart) > 0
              ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
              : '';
            const action = direction === 'down' ? '↓' : '↑';
            this.setStatus('syncing', `${fileNum} ${chunkBar} ${this.formatBytes(bytesTransferred)}/${this.formatBytes(totalBytesAll)} ${sp} | ${action} ${file.path} chunk ${chunkIdx}/${totalChunks}`);
            if (chunkIdx % 20 === 0 || chunkIdx === totalChunks) {
              const chunkBytes = localData.length / totalChunks;
              const chunkElapsed = (performance.now() - tStart) / 1000;
              const chunkSpeed = chunkBytes > 0 && chunkElapsed > 0 ? this.formatBytes(chunkBytes / chunkElapsed) + '/s' : '';
              console.log(`    ${action} ${file.path} chunk ${chunkIdx}/${totalChunks}  ${this.formatBytes(chunkBytes)}  ${chunkSpeed}`);
            }
          });
          meta = result.meta;

          const speed = result.durationMs ? this.formatBytes((result.bytes || 0) / (result.durationMs / 1000)) + '/s' : '?';

          switch (result.action) {
            case 'uploaded':
              uploaded++;
              bytesTransferred += result.bytes || 0;
              console.log(`  ↑ [${fileNum}] ${file.path}  ${this.formatBytes(result.bytes || 0)}  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms  ${speed}`);
              break;
            case 'downloaded':
              downloaded++;
              bytesTransferred += result.bytes || 0;
              console.log(`  ↓ [${fileNum}] ${file.path}  ${this.formatBytes(result.bytes || 0)}  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms  ${speed}`);
              if (result.downloadedData) {
                await this.writeFile(file, result.downloadedData);
              }
              break;
            case 'conflict-resolved':
              conflicts++;
              bytesTransferred += result.bytes || 0;
              console.log(`  ⚠ [${fileNum}] ${file.path}  ${this.formatBytes(result.bytes || 0)}  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms  ${speed}  conflicts=${result.conflicts?.length}`);
              if (result.downloadedData) {
                await this.writeFile(file, result.downloadedData);
              }
              break;
            case 'unchanged':
              skipped++;
              break;
          }
        } catch (e) {
          errors++;
          console.error(`  ✕ [${fileNum}] ${file.path}  ERROR:`, e);
        }
      }

      await this.state.saveMetadata(meta);

      if (this.settings.garbageCollectDays > 0) {
        const gcResult = await this.syncEngine.garbageCollect(meta, this.settings.garbageCollectDays);
        if (gcResult.removed > 0) {
          meta = gcResult.meta;
          await this.state.saveMetadata(meta);
          console.log(`[PQC Sync] GC removed ${gcResult.removed} stale chunks`);
        }
      }

      const elapsed = ((performance.now() - tStart) / 1000).toFixed(1);
      const avgSpeed = bytesTransferred > 0 && (performance.now() - tStart) > 0
        ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
        : '';
      this.setStatus('ready');
      console.log(`[PQC Sync] ───────────────────────────────────────`);
      console.log(`[PQC Sync] Done: ${uploaded}↑ ${downloaded}↓ ${skipped}○ ${conflicts}⚠ ${errors}✕  ${this.formatBytes(bytesTransferred)} in ${elapsed}s  ${avgSpeed}`);
      if (uploaded + downloaded + conflicts + errors > 0) {
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
        const allFiles = this.app.vault.getFiles().filter(f => !this.shouldSkip(f));
        let uploaded = 0;
        let errors = 0;
        let bytesTransferred = 0;
        const totalBytesAll = allFiles.reduce((sum, f) => sum + f.stat.size, 0);
        const tStart = performance.now();
        console.log(`[PQC Force Sync] ═══════════════════════════════════════`);
        console.log(`[PQC Force Sync] Local wins: ${allFiles.length} files, ${this.formatBytes(totalBytesAll)} total`);
        console.log(`[PQC Force Sync] Settings: chunkSize=${this.formatBytes(this.settings.chunkSizeKB * 1024)}, timeout=${this.settings.uploadTimeoutSec}s`);

        for (let i = 0; i < allFiles.length; i++) {
          const file = allFiles[i];
          const fileNum = `${i + 1}/${allFiles.length}`;
          const sizeStr = this.formatBytes(file.stat.size);
          const pct = totalBytesAll > 0 ? bytesTransferred / totalBytesAll : 0;
          const bar = this.progressBar(pct);
          const elapsed = ((performance.now() - tStart) / 1000).toFixed(0);
          const speed = bytesTransferred > 0 && (performance.now() - tStart) > 0
            ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
            : '';
          this.setStatus('syncing', `${fileNum} ${bar} ${this.formatBytes(bytesTransferred)}/${this.formatBytes(totalBytesAll)} ${speed} | ↑ ${file.path} (${sizeStr})`);

          try {
            const t0 = performance.now();
            const encPath = await encryptFilename(this.masterSecret, state.vaultId, file.path);
            const localData = await this.getFileData(file);
            const result = await this.syncEngine.forceUploadFile(encPath, localData, meta, (chunkIdx, totalChunks) => {
              const chunkPct = totalBytesAll > 0 ? (bytesTransferred + (localData.length * chunkIdx / totalChunks)) / totalBytesAll : 0;
              const chunkBar = this.progressBar(chunkPct);
              const sp = bytesTransferred > 0 && (performance.now() - tStart) > 0
                ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
                : '';
              this.setStatus('syncing', `${fileNum} ${chunkBar} ${this.formatBytes(bytesTransferred)}/${this.formatBytes(totalBytesAll)} ${sp} | ↑ ${file.path} chunk ${chunkIdx}/${totalChunks}`);
              if (chunkIdx % 20 === 0 || chunkIdx === totalChunks) {
                const chunkBytes = localData.length / totalChunks;
                const chunkElapsed = (performance.now() - tStart) / 1000;
                const chunkSpeed = chunkBytes > 0 && chunkElapsed > 0 ? this.formatBytes(chunkBytes / chunkElapsed) + '/s' : '';
                console.log(`    ↑ ${file.path} chunk ${chunkIdx}/${totalChunks}  ${this.formatBytes(chunkBytes)}  ${chunkSpeed}`);
              }
            });
            meta = result.meta;
            uploaded++;
            bytesTransferred += localData.length;
            const fileSpeed = result.durationMs ? this.formatBytes(localData.length / (result.durationMs / 1000)) + '/s' : '?';
            console.log(`  ↑ [${fileNum}] ${file.path}  ${this.formatBytes(localData.length)}  ${result.chunks} chunks  ${result.durationMs?.toFixed(0)}ms  ${fileSpeed}`);
          } catch (e) {
            errors++;
            console.error(`  ✕ [${fileNum}] ${file.path}  ERROR:`, e);
          }
        }

        this.setStatus('syncing', 'Cleaning remote-only files...');
        const remoteMeta = await this.syncEngine.downloadMetadata();
        let deleted = 0;
        for (const encPath of Object.keys(remoteMeta.files)) {
          if (!meta.files[encPath]) {
            try { await this.syncEngine.deleteFile(encPath, meta); deleted++; } catch {}
          }
        }

        await this.syncEngine.uploadMetadata(meta);
        await this.state.saveMetadata(meta);
        const elapsed = ((performance.now() - tStart) / 1000).toFixed(1);
        const avgSpeed = totalBytesAll > 0 ? this.formatBytes(totalBytesAll / ((performance.now() - tStart) / 1000)) + '/s' : '0';
        this.setStatus('ready');
        console.log(`[PQC Force Sync] ───────────────────────────────────────`);
        console.log(`[PQC Force Sync] Done: ${uploaded}↑ ${deleted}✕ deleted ${errors}✕ errors  ${this.formatBytes(totalBytesAll)} in ${elapsed}s  ${avgSpeed}`);
        new Notice(`Force sync (local wins): ${uploaded} files ↑, ${deleted} deleted, ${elapsed}s`);

      } else {
        new Notice('Force sync: remote wins — downloading all files from remote...');
        const remoteMeta = await this.syncEngine.downloadMetadata();
        const remoteFiles = Object.entries(remoteMeta.files);

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
        let errors = 0;
        let bytesTransferred = 0;
        const totalBytesAll = remoteFiles.reduce((sum, [, e]) => sum + e.size, 0);
        const tStart = performance.now();
        console.log(`[PQC Force Sync] ═══════════════════════════════════════`);
        console.log(`[PQC Force Sync] Remote wins: ${remoteFiles.length} files, ${this.formatBytes(totalBytesAll)} total`);
        console.log(`[PQC Force Sync] Settings: chunkSize=${this.formatBytes(this.settings.chunkSizeKB * 1024)}, timeout=${this.settings.uploadTimeoutSec}s`);

        for (let i = 0; i < remoteFiles.length; i++) {
          const [encPath, remoteEntry] = remoteFiles[i];
          const fileNum = `${i + 1}/${remoteFiles.length}`;
          const sizeStr = this.formatBytes(remoteEntry.size);
          const pct = totalBytesAll > 0 ? bytesTransferred / totalBytesAll : 0;
          const bar = this.progressBar(pct);
          const elapsed = ((performance.now() - tStart) / 1000).toFixed(0);
          const speed = bytesTransferred > 0 && (performance.now() - tStart) > 0
            ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
            : '';
          this.setStatus('syncing', `${fileNum} ${bar} ${this.formatBytes(bytesTransferred)}/${this.formatBytes(totalBytesAll)} ${speed} | ↓ ${encPath} (${sizeStr})`);

          try {
            const t0 = performance.now();
            const totalChunks = remoteEntry.chunks.length;
            const data = await this.syncEngine.forceDownloadFile(encPath, remoteMeta, (chunkIdx, totalChunksParam) => {
              const chunkPct = totalBytesAll > 0 ? (bytesTransferred + (remoteEntry.size * chunkIdx / totalChunksParam)) / totalBytesAll : 0;
              const chunkBar = this.progressBar(chunkPct);
              const spd = bytesTransferred > 0 && (performance.now() - tStart) > 0
                ? this.formatBytes(bytesTransferred / ((performance.now() - tStart) / 1000)) + '/s'
                : '';
              this.setStatus('syncing', `${fileNum} ${chunkBar} ${this.formatBytes(bytesTransferred)}/${this.formatBytes(totalBytesAll)} ${spd} | ↓ ${encPath} chunk ${chunkIdx}/${totalChunksParam}`);
              if (chunkIdx % 20 === 0 || chunkIdx === totalChunksParam) {
                const chunkBytes = remoteEntry.size / totalChunksParam;
                const chunkElapsed = (performance.now() - tStart) / 1000;
                const chunkSpeed = chunkBytes > 0 && chunkElapsed > 0 ? this.formatBytes(chunkBytes / chunkElapsed) + '/s' : '';
                console.log(`    ↓ ${encPath} chunk ${chunkIdx}/${totalChunksParam}  ${this.formatBytes(chunkBytes)}  ${chunkSpeed}`);
              }
            });
            if (data) {
              const localFile = encToLocal.get(encPath);
              if (localFile) {
                await this.writeFile(localFile, data);
              } else {
                await this.app.vault.create(encPath.replace(/\//g, '--') + '.bin', new TextDecoder().decode(data));
              }
              downloaded++;
              bytesTransferred += data.length;
              const spd = data.length > 0 ? this.formatBytes(data.length / ((performance.now() - t0) / 1000)) + '/s' : '?';
              console.log(`  ↓ [${fileNum}] ${encPath}  ${this.formatBytes(data.length)}  ${remoteEntry.chunks.length} chunks  ${(performance.now() - t0).toFixed(0)}ms  ${spd}`);
            }
          } catch (e) {
            errors++;
            console.error(`  ✕ [${fileNum}] ${encPath}  ERROR:`, e);
          }
        }

        let deleted = 0;
        for (const [path, encPath] of localToEnc) {
          if (!remoteMeta.files[encPath]) {
            const file = this.app.vault.getAbstractFileByPath(path);
            if (file instanceof TFile) { await this.app.vault.delete(file); deleted++; }
          }
        }

        await this.syncEngine.uploadMetadata(remoteMeta);
        await this.state.saveMetadata(remoteMeta);
        const elapsed = ((performance.now() - tStart) / 1000).toFixed(1);
        const avgSpeed = totalBytesAll > 0 ? this.formatBytes(totalBytesAll / ((performance.now() - tStart) / 1000)) + '/s' : '0';
        this.setStatus('ready');
        console.log(`[PQC Force Sync] ───────────────────────────────────────`);
        console.log(`[PQC Force Sync] Done: ${downloaded}↓ ${deleted}✕ deleted ${errors}✕ errors  ${this.formatBytes(totalBytesAll)} in ${elapsed}s  ${avgSpeed}`);
        new Notice(`Force sync (remote wins): ${downloaded} files ↓, ${deleted} deleted, ${elapsed}s`);
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
