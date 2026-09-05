# PQC WebDAV Sync

Encrypt your Obsidian vault with **post-quantum cryptography** (ML-DSA-65 / ML-KEM-768) and sync it to any WebDAV server (Nextcloud, etc.) with chunked transfer and multi-device conflict resolution.

All file names and contents are encrypted before they leave your device. The remote server only ever sees encrypted blobs — never plaintext note content or file paths.

## Features

- **Post-quantum encryption** — ML-KEM-768 key encapsulation and ML-DSA-65 digital signatures via `@noble/post-quantum`
- **Full-file encryption** — contents *and* file names are encrypted before upload
- **Chunked transfer** — large files are split into chunks for resumable, reliable upload
- **Integrity verification** — every chunk upload/download is verified (AES-GCM auth + SHA-256), and reassembled files are size-checked
- **Multi-device sync** — vector clocks + last-write-wins conflict resolution
- **Configurable** — chunk size, parallel transfers, and upload timeout are all adjustable in settings
- **Detailed progress** — per-file and per-chunk progress shown in the console and status bar
- **Force full sync** — choose "local wins" or "remote wins" for one-way synchronization

## Installation

> This plugin is listed in the Obsidian Community directory. Install it from *Settings → Community plugins* or manually (below).

### Manual install (BRAT / development)

1. Download the latest `main.js`, `manifest.json`, and `styles.css` from the [Releases](https://github.com/normanify/post-quantum-webdav/releases) page.
2. Create a folder named `post-quantum-webdav` inside your vault's `.obsidian/plugins/` directory.
3. Copy the three downloaded files into that folder.
4. Restart Obsidian and enable **PQC WebDAV Sync** under *Settings → Community plugins*.

### Install from source

```bash
git clone https://github.com/normanify/post-quantum-webdav.git
cd post-quantum-webdav
npm install
npm run build
```

Then copy `main.js`, `manifest.json`, `styles.css`, and `versions.json` into your vault's `.obsidian/plugins/post-quantum-webdav/` folder.

## Usage

1. Open *Settings → PQC WebDAV Sync*.
2. Under **WebDAV Server**, enter your server URL (e.g. `https://your-nextcloud.com/remote.php/dav/files/username`), username, and password or app token.
3. Under **Encryption**, set a **Vault Passphrase**. **All devices must share the same passphrase.** This passphrase derives the master key that encrypts your vault.
4. Tune the **Sync** settings as desired (chunk size, parallel transfers, upload timeout, auto-sync interval).
5. Click **Test connection** to verify your WebDAV credentials.
6. Sync from the ribbon icon or the command palette (*PQC WebDAV Sync: Sync now*).

### First sync

On the first sync, the plugin generates a device key pair and uploads an encrypted vault metadata + your files. All content on the server is encrypted.

### Multi-device setup

- Install the plugin on each device.
- Use the **same vault passphrase** and the **same WebDAV server + base path**.
- Each device has its own device key; conflicts are resolved automatically (last-write-wins) or manually depending on your **Conflict resolution** setting.

## Configuration

| Setting | Description |
|---------|-------------|
| WebDAV Server URL | Nextcloud/WebDAV endpoint (e.g. `https://.../remote.php/dav/files/username`) |
| Username / Password | WebDAV credentials (use an app-specific token for Nextcloud) |
| Remote Base Path | Folder on the server where the encrypted vault is stored |
| Vault Passphrase | Master secret; must be identical on every device |
| Auto sync / Interval | Scheduled background sync (minutes) |
| Chunk size | Size of each encrypted chunk (1–100 MB) |
| Parallel transfers | Max concurrent upload/download operations |
| Upload timeout | Max time per chunk upload before retry (2–30 min) |
| Garbage collection | Days to keep remote chunks after a file is deleted (0 = never) |
| Conflict resolution | `latest-wins` (automatic) or `manual` |

## License

[MIT](./LICENSE)
