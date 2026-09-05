import { App, Notice, Plugin, PluginSettingTab, Setting, SettingDefinitionItem } from 'obsidian';

/** Plugin surface consumed by the settings tab. Kept narrow to avoid a
 *  circular dependency with the plugin class while preserving type safety. */
interface PqcPluginApi extends Plugin {
  settings: PqcSettings;
  saveSettings(): Promise<void>;
  testConnection(): Promise<boolean>;
  forceFullSync(mode: 'local' | 'remote'): Promise<void>;
}

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
  private plugin: PqcPluginApi;
  private onSettingsChanged: () => void;

  constructor(app: App, plugin: PqcPluginApi, onSettingsChanged: () => void) {
    super(app, plugin);
    this.plugin = plugin;
    this.onSettingsChanged = onSettingsChanged;
  }

  override setControlValue(key: string, value: unknown): void | Promise<void> {
    const s = this.plugin.settings;
    switch (key) {
      case 'serverUrl': s.serverUrl = String(value).trim(); break;
      case 'username': s.username = String(value).trim(); break;
      case 'basePath': s.basePath = String(value).trim().replace(/^\/+|\/+$/g, ''); break;
      case 'autoSync': s.autoSync = Boolean(value); break;
      case 'syncIntervalMin': s.syncIntervalMin = Number(value); break;
      case 'chunkSizeKB': s.chunkSizeKB = Number(value); break;
      case 'parallelLimit': s.parallelLimit = Number(value); break;
      case 'uploadTimeoutSec': s.uploadTimeoutSec = Number(value); break;
      case 'garbageCollectDays': s.garbageCollectDays = Number(value); break;
      case 'conflictResolution': s.conflictResolution = value === 'manual' ? 'manual' : 'latest-wins'; break;
      default: return;
    }
    return this.plugin.saveSettings().then(() => this.onSettingsChanged());
  }

  getSettingDefinitions(): SettingDefinitionItem[] {
    return [
      {
        type: 'group',
        heading: 'WebDAV Server',
        items: [
          {
            name: 'WebDAV Server URL',
            desc: 'NextCloud WebDAV endpoint, e.g. https://d.manus.pp.ua/remote.php/dav/files/admin',
            control: { type: 'text', key: 'serverUrl', placeholder: 'https://...' },
          },
          {
            name: 'Username',
            desc: 'WebDAV account username',
            control: { type: 'text', key: 'username', placeholder: 'username' },
          },
          {
            name: 'Password / App Token',
            desc: 'WebDAV account password or app-specific token',
            render: (setting) => this.renderSecretInput(setting, 'password', '••••••••'),
          },
          {
            name: 'Remote Base Path',
            desc: 'Folder on the server where encrypted vault is stored',
            control: { type: 'text', key: 'basePath', placeholder: 'obtest2' },
          },
        ],
      },
      {
        type: 'group',
        heading: 'Encryption',
        items: [
          {
            name: 'Vault Passphrase',
            desc: 'Used to derive the master key. All devices must share the same passphrase. Changing it will re-encrypt everything.',
            render: (setting) => this.renderSecretInput(setting, 'passphrase', 'Enter passphrase'),
          },
          {
            name: 'Vault ID',
            desc: 'Unique identifier for this vault (auto-generated on first use)',
            control: { type: 'text', key: 'vaultId', disabled: true },
          },
        ],
      },
      {
        type: 'group',
        heading: 'Sync',
        items: [
          {
            name: 'Auto sync',
            desc: 'Automatically sync on a schedule',
            control: { type: 'toggle', key: 'autoSync' },
          },
          {
            name: 'Sync interval',
            desc: 'How often to automatically sync (minutes)',
            control: {
              type: 'dropdown',
              key: 'syncIntervalMin',
              options: { '1': '1 min', '5': '5 min', '10': '10 min', '15': '15 min', '30': '30 min', '60': '60 min' },
            },
          },
          {
            name: 'Chunk size',
            desc: 'Size of each encrypted chunk',
            control: {
              type: 'dropdown',
              key: 'chunkSizeKB',
              options: { '1024': '1 MB', '2048': '2 MB', '5120': '5 MB', '10240': '10 MB', '20480': '20 MB', '51200': '50 MB', '102400': '100 MB' },
            },
          },
          {
            name: 'Parallel transfers',
            desc: 'Maximum concurrent upload/download operations',
            control: { type: 'slider', key: 'parallelLimit', min: 1, max: 10, step: 1 },
          },
          {
            name: 'Upload timeout',
            desc: 'Maximum time in minutes for a single chunk upload before retry',
            control: {
              type: 'dropdown',
              key: 'uploadTimeoutSec',
              options: { '120': '2 min', '300': '5 min', '600': '10 min', '1200': '20 min', '1800': '30 min' },
            },
          },
        ],
      },
      {
        type: 'group',
        heading: 'Deletion',
        items: [
          {
            name: 'Garbage collection',
            desc: 'Delete remote chunks N days after a file is deleted (0 = never)',
            control: {
              type: 'dropdown',
              key: 'garbageCollectDays',
              options: { '0': 'Never', '7': '7 days', '14': '14 days', '30': '30 days', '90': '90 days' },
            },
          },
        ],
      },
      {
        type: 'group',
        heading: 'Advanced',
        items: [
          {
            name: 'Conflict resolution',
            desc: 'How to handle file conflicts between devices',
            control: {
              type: 'dropdown',
              key: 'conflictResolution',
              options: { 'latest-wins': 'Latest wins (automatic)', manual: 'Manual (ask user)' },
            },
          },
          {
            name: 'Test connection',
            desc: 'Verify WebDAV server connectivity and credentials',
            render: (setting) => this.renderTestButton(setting),
          },
        ],
      },
      {
        type: 'group',
        heading: 'Force Full Sync',
        items: [
          {
            name: 'Local wins (upload all)',
            desc: 'Overwrite remote with local vault. All remote-only files will be deleted.',
            render: (setting) => this.renderForceButton(setting, 'local'),
          },
          {
            name: 'Remote wins (download all)',
            desc: 'Overwrite local vault with remote. All local-only files will be deleted.',
            render: (setting) => this.renderForceButton(setting, 'remote'),
          },
        ],
      },
    ];
  }

  private renderSecretInput(setting: Setting, key: 'password' | 'passphrase', placeholder: string): void {
    setting.addText(text => {
      text.inputEl.type = 'password';
      text.setPlaceholder(placeholder);
      text.setValue(this.plugin.settings[key]);
      text.onChange(async value => {
        this.plugin.settings[key] = key === 'passphrase' ? value : value.trim();
        await this.plugin.saveSettings();
        this.onSettingsChanged();
      });
    });
  }

  private renderTestButton(setting: Setting): void {
    setting.addButton(btn => btn
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
  }

  private renderForceButton(setting: Setting, mode: 'local' | 'remote'): void {
    setting.addButton(btn => btn
      .setButtonText(mode === 'local' ? 'Force local → remote' : 'Force remote → local')
      .setDestructive()
      .onClick(async () => {
        await this.plugin.forceFullSync(mode);
      }));
  }
}