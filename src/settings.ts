import { App, Notice, PluginSettingTab, Setting } from 'obsidian';

/** Plugin settings persisted to data.json */
export interface PqcSettings {
  // WebDAV
  serverUrl: string;
  username: string;
  password: string;
  basePath: string;

  // Encryption
  passphrase: string;
  vaultId: string;

  // Sync
  autoSync: boolean;
  syncIntervalMin: number;
  chunkSizeKB: number;
  parallelLimit: number;
  uploadTimeoutSec: number;

  // Deletion
  garbageCollectDays: number;

  // Advanced
  conflictResolution: 'latest-wins' | 'manual';
}

export const DEFAULT_SETTINGS: PqcSettings = {
  serverUrl: '',
  username: '',
  password: '',
  basePath: 'obtest2',

  passphrase: '',
  vaultId: '',

  autoSync: true,
  syncIntervalMin: 5,
  chunkSizeKB: 10 * 1024,
  parallelLimit: 3,
  uploadTimeoutSec: 600,

  garbageCollectDays: 30,

  conflictResolution: 'latest-wins',
};

export class PqcSettingTab extends PluginSettingTab {
  private plugin: any;
  private onSettingsChanged: () => void;

  constructor(app: App, plugin: any, onSettingsChanged: () => void) {
    super(app, plugin);
    this.plugin = plugin;
    this.onSettingsChanged = onSettingsChanged;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    // --- WebDAV Section ---
    containerEl.createEl('h2', { text: 'WebDAV Server' });

    new Setting(containerEl)
      .setName('WebDAV Server URL')
      .setDesc('NextCloud WebDAV endpoint, e.g. https://d.manus.pp.ua/remote.php/dav/files/admin')
      .addText(text => text
        .setPlaceholder('https://...')
        .setValue(this.plugin.settings.serverUrl)
        .onChange(async value => {
          this.plugin.settings.serverUrl = value.trim();
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        }));

    new Setting(containerEl)
      .setName('Username')
      .setDesc('WebDAV account username')
      .addText(text => text
        .setPlaceholder('username')
        .setValue(this.plugin.settings.username)
        .onChange(async value => {
          this.plugin.settings.username = value.trim();
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        }));

    new Setting(containerEl)
      .setName('Password / App Token')
      .setDesc('WebDAV account password or app-specific token')
      .addText(text => {
        text.inputEl.type = 'password';
        text
          .setPlaceholder('••••••••')
          .setValue(this.plugin.settings.password)
          .onChange(async value => {
            this.plugin.settings.password = value.trim();
            await this.plugin.saveSettings();
            this.onSettingsChanged();
          });
      });

    new Setting(containerEl)
      .setName('Remote Base Path')
      .setDesc('Folder on the server where encrypted vault is stored')
      .addText(text => text
        .setPlaceholder('obtest2')
        .setValue(this.plugin.settings.basePath)
        .onChange(async value => {
          this.plugin.settings.basePath = value.trim().replace(/^\/+|\/+$/g, '');
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        }));

    // --- Encryption Section ---
    containerEl.createEl('h2', { text: 'Encryption' });

    new Setting(containerEl)
      .setName('Vault Passphrase')
      .setDesc('Used to derive the master key. All devices must share the same passphrase. Changing it will re-encrypt everything.')
      .addText(text => {
        text.inputEl.type = 'password';
        text
          .setPlaceholder('Enter passphrase')
          .setValue(this.plugin.settings.passphrase)
          .onChange(async value => {
            this.plugin.settings.passphrase = value;
            await this.plugin.saveSettings();
            this.onSettingsChanged();
          });
      });

    new Setting(containerEl)
      .setName('Vault ID')
      .setDesc('Unique identifier for this vault (auto-generated on first use)')
      .addText(text => text
        .setPlaceholder('vault-uuid')
        .setValue(this.plugin.settings.vaultId)
        .setDisabled(true));

    // --- Sync Section ---
    containerEl.createEl('h2', { text: 'Sync' });

    new Setting(containerEl)
      .setName('Auto sync')
      .setDesc('Automatically sync on a schedule')
      .addToggle(toggle => toggle
        .setValue(this.plugin.settings.autoSync)
        .onChange(async value => {
          this.plugin.settings.autoSync = value;
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        }));

    new Setting(containerEl)
      .setName('Sync interval')
      .setDesc('How often to automatically sync (minutes)')
      .addDropdown(drop => {
        for (const minutes of [1, 5, 10, 15, 30, 60]) {
          drop.addOption(String(minutes), `${minutes} min`);
        }
        drop.setValue(String(this.plugin.settings.syncIntervalMin));
        drop.onChange(async value => {
          this.plugin.settings.syncIntervalMin = Number(value);
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        });
      });

    new Setting(containerEl)
      .setName('Chunk size')
      .setDesc('Size of each encrypted chunk')
      .addDropdown(drop => {
        for (const mb of [1, 2, 5, 10, 20, 50, 100]) {
          drop.addOption(String(mb * 1024), `${mb} MB`);
        }
        drop.setValue(String(this.plugin.settings.chunkSizeKB));
        drop.onChange(async value => {
          this.plugin.settings.chunkSizeKB = Number(value);
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        });
      });

    new Setting(containerEl)
      .setName('Parallel transfers')
      .setDesc('Maximum concurrent upload/download operations')
      .addSlider(slider => slider
        .setLimits(1, 10, 1)
        .setValue(this.plugin.settings.parallelLimit)
        .setDynamicTooltip()
        .onChange(async value => {
          this.plugin.settings.parallelLimit = value;
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        }));

    new Setting(containerEl)
      .setName('Upload timeout')
      .setDesc('Maximum time in minutes for a single chunk upload before retry')
      .addDropdown(drop => {
        for (const min of [2, 5, 10, 20, 30]) {
          drop.addOption(String(min * 60), `${min} min`);
        }
        drop.setValue(String(this.plugin.settings.uploadTimeoutSec));
        drop.onChange(async value => {
          this.plugin.settings.uploadTimeoutSec = Number(value);
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        });
      });

    // --- Deletion Section ---
    containerEl.createEl('h2', { text: 'Deletion' });

    new Setting(containerEl)
      .setName('Garbage collection')
      .setDesc('Delete remote chunks N days after a file is deleted (0 = never)')
      .addDropdown(drop => {
        for (const days of [0, 7, 14, 30, 90]) {
          drop.addOption(String(days), days === 0 ? 'Never' : `${days} days`);
        }
        drop.setValue(String(this.plugin.settings.garbageCollectDays));
        drop.onChange(async value => {
          this.plugin.settings.garbageCollectDays = Number(value);
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        });
      });

    // --- Advanced Section ---
    containerEl.createEl('h2', { text: 'Advanced' });

    new Setting(containerEl)
      .setName('Conflict resolution')
      .setDesc('How to handle file conflicts between devices')
      .addDropdown(drop => {
        drop.addOption('latest-wins', 'Latest wins (automatic)');
        drop.addOption('manual', 'Manual (ask user)');
        drop.setValue(this.plugin.settings.conflictResolution);
        drop.onChange(async value => {
          this.plugin.settings.conflictResolution = value as 'latest-wins' | 'manual';
          await this.plugin.saveSettings();
          this.onSettingsChanged();
        });
      });

    new Setting(containerEl)
      .setName('Test connection')
      .setDesc('Verify WebDAV server connectivity and credentials')
      .addButton(btn => btn
        .setButtonText('Test')
        .setCta()
        .onClick(async () => {
          try {
            const result = await this.plugin.testConnection();
            new Notice(result ? 'Connection successful!' : 'Connection failed. Check your settings.');
          } catch (e) {
            new Notice(`Connection error: ${e instanceof Error ? e.message : String(e)}`);
          }
        }));

    // --- Force Sync Section ---
    containerEl.createEl('h2', { text: 'Force Full Sync' });

    new Setting(containerEl)
      .setName('Local wins (upload all)')
      .setDesc('Overwrite remote with local vault. All remote-only files will be deleted.')
      .addButton(btn => btn
        .setButtonText('Force local → remote')
        .setWarning()
        .onClick(async () => {
          await this.plugin.forceFullSync('local');
        }));

    new Setting(containerEl)
      .setName('Remote wins (download all)')
      .setDesc('Overwrite local vault with remote. All local-only files will be deleted.')
      .addButton(btn => btn
        .setButtonText('Force remote → local')
        .setWarning()
        .onClick(async () => {
          await this.plugin.forceFullSync('remote');
        }));
  }
}
