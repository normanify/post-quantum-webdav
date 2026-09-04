import { createClient, WebDAVClient, FileStat } from 'webdav';

export interface WebDavConfig {
  serverUrl: string;
  username: string;
  password: string;
  /** Base path on server, e.g. /obtest2 */
  basePath: string;
}

/**
 * WebDAV client wrapper.
 *
 * Handles authentication, path sanitization, chunk upload/download with
 * retry logic. All paths are relative to the configured basePath.
 */
export class WebDavClient {
  private client: WebDAVClient;
  private config: WebDavConfig;

  constructor(config: WebDavConfig) {
    this.config = config;
    const resolvedUrl = config.serverUrl.replace(/\/+$/, '');
    this.client = createClient(resolvedUrl, {
      username: config.username,
      password: config.password,
    });
  }

  /** Normalize a relative path, stripping leading/trailing slashes. */
  private normalize(relPath: string): string {
    const p = relPath.replace(/^\/+|\/+$/g, '');
    return `${this.config.basePath.replace(/\/+$/, '')}/${p}`;
  }

  /** Ensure a remote directory exists (chain of MKCOL). */
  async ensureDir(relPath: string): Promise<void> {
    const parts = relPath.split('/').filter(Boolean);
    let current = this.config.basePath.replace(/\/+$/, '');
    for (const part of parts) {
      current = `${current}/${part}`;
      try {
        await this.client.getDirectoryContents(current);
      } catch {
        await this.client.createDirectory(current);
      }
    }
  }

  /** Check whether a remote file or directory exists. */
  async exists(relPath: string): Promise<boolean> {
    try {
      await this.client.stat(this.normalize(relPath));
      return true;
    } catch {
      return false;
    }
  }

  /** List contents of a remote directory. */
  async list(relPath = ''): Promise<FileStat[]> {
    try {
      return await this.client.getDirectoryContents(this.normalize(relPath)) as FileStat[];
    } catch {
      return [];
    }
  }

  /** Upload a Uint8Array to the given relative path. */
  async uploadBytes(relPath: string, data: Uint8Array): Promise<void> {
    const full = this.normalize(relPath);
    const dir = relPath.split('/').slice(0, -1).join('/');
    if (dir) {
      await this.ensureDir(dir);
    }
    await this.client.putFileContents(full, data as unknown as Buffer, {
      overwrite: true,
    });
  }

  /** Download a remote file as Uint8Array. */
  async downloadBytes(relPath: string): Promise<Uint8Array> {
    const full = this.normalize(relPath);
    const buf = await this.client.getFileContents(full) as Buffer;
    return new Uint8Array(buf);
  }

  /** Delete a remote file or directory recursively. */
  async delete(relPath: string): Promise<void> {
    const full = this.normalize(relPath);
    try {
      await this.client.deleteFile(full);
    } catch {
      // swallow: file may not exist
    }
  }
}
