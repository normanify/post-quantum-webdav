import { requestUrl } from 'obsidian';

export interface WebDavConfig {
  serverUrl: string;
  username: string;
  password: string;
  /** Base path on server, e.g. /obtest2 */
  basePath: string;
}

export interface FileStat {
  filename: string;
  basename: string;
  /** @deprecated Placeholder to keep interface compatibility. */
  lastmod?: string;
  size?: number;
  type: 'file' | 'directory';
  /** Path relative to base path, with leading slash. */
  path: string;
  mime?: string;
}

const b64 = (input: string): string => {
  if (typeof btoa === 'function') return btoa(input);
  const bytes = new TextEncoder().encode(input);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};

/**
 * WebDAV client backed by Obsidian's requestUrl() (main-process net stack),
 * which bypasses the renderer CORS policy that blocks fetch()/the webdav lib.
 */
export class WebDavClient {
  private url: string;
  private auth: string;

  constructor(config: WebDavConfig) {
    const base = config.serverUrl.replace(/\/+$/, '');
    this.url = `${base}/${config.basePath.replace(/^\/+|\/+$/g, '')}`;
    this.auth = `Basic ${b64(`${config.username}:${config.password}`)}`;
  }

  private resolve(relPath: string): string {
    const p = relPath.replace(/^\/+|\/+$/g, '');
    return p ? `${this.url}/${encodeURI(p)}` : this.url;
  }

  private async req(
    method: string,
    relPath: string,
    opts: { body?: string | ArrayBuffer; depth?: string; contentType?: string; allowFail?: boolean } = {}
  ): Promise<{ status: number; headers: Record<string, string>; arrayBuffer: ArrayBuffer; json: any; text: string } | undefined> {
    const headers: Record<string, string> = {
      Authorization: this.auth,
    };
    if (opts.depth) headers.Depth = opts.depth;
    if (opts.contentType) headers['Content-Type'] = opts.contentType;
    try {
      const res = await requestUrl({
        url: this.resolve(relPath),
        method,
        headers,
        body: opts.body,
        throw: false,
      });
      if (res.status >= 400 && !opts.allowFail) return res; // report via upstream
      return res;
    } catch (e) {
      if (opts.allowFail) return undefined;
      throw e;
    }
  }

  /** Ensure a remote directory exists (chain of MKCOL). */
  async ensureDir(relPath: string): Promise<void> {
    const parts = relPath.split('/').filter(Boolean);
    let cur = '';
    for (const part of parts) {
      cur = cur ? `${cur}/${part}` : part;
      await this.req('MKCOL', cur, { allowFail: true });
    }
  }

  /** Check whether a remote file or directory exists. */
  async exists(relPath: string): Promise<boolean> {
    const res = await this.req('PROPFIND', relPath, { depth: '0', allowFail: true });
    return !!res && res.status < 300;
  }

  /** List contents of a remote directory. */
  async list(relPath = ''): Promise<FileStat[]> {
    const res = await this.req('PROPFIND', relPath, { depth: '1', allowFail: true });
    if (!res || res.status >= 300) return [];
    const text = res.text || '';
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'application/xml');
    const hrefBase = this.resolve(relPath).split('?')[0];
    const ref = this.url;
    const items: FileStat[] = [];
    const rows = doc.getElementsByTagName('response');
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const hrefEl = row.getElementsByTagName('href')[0];
      if (!hrefEl) continue;
      let href = hrefEl.textContent || '';
      try {
        href = decodeURIComponent(href);
      } catch { /* keep raw */ }
      const full = href.split('?')[0];
      if (full === hrefBase || full === ref || full.endsWith('/' + relPath.replace(/^\/+|\/+$/g, ''))) continue; // self
      const isColl = row.getElementsByTagName('collection').length > 0;
      const sizeEl = row.getElementsByTagName('getcontentlength')[0];
      const size = sizeEl ? parseInt(sizeEl.textContent || '0', 10) || undefined : undefined;
      const mimeEl = row.getElementsByTagName('getcontenttype')[0];
      const basePathNorm = this.url;
      let rel = full.slice(basePathNorm.length);
      rel = rel.replace(/^\/+/, '');
      if (!rel) continue;
      const trailing = isColl ? '/' : '';
      const basename = decodeURIComponent(rel.split('/').pop() || '').replace(/\/+$/, '');
      const filename = basename + trailing;
      items.push({
        filename,
        basename,
        size,
        type: isColl ? 'directory' : 'file',
        path: '/' + rel,
        mime: mimeEl ? mimeEl.textContent || undefined : undefined,
      });
    }
    return items;
  }

  /** Upload a Uint8Array to the given relative path. */
  async uploadBytes(relPath: string, data: Uint8Array): Promise<void> {
    const dir = relPath.split('/').slice(0, -1).join('/');
    if (dir) await this.ensureDir(dir);
    const buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    const res = await this.req('PUT', relPath, { body: buffer, contentType: 'application/octet-stream' });
    if (res && res.status >= 300) {
      throw new Error(`PUT failed: HTTP ${res.status}`);
    }
  }

  /** Download a remote file as Uint8Array. */
  async downloadBytes(relPath: string): Promise<Uint8Array> {
    const res = await this.req('GET', relPath);
    if (!res || res.status >= 300) {
      throw new Error(`GET failed: HTTP ${res ? res.status : 'unknown'}`);
    }
    return new Uint8Array(res.arrayBuffer);
  }

  /** Delete a remote file or directory recursively. */
  async delete(relPath: string): Promise<void> {
    const res = await this.req('DELETE', relPath, { allowFail: true });
    if (res && res.status >= 300 && res.status !== 404) {
      throw new Error(`DELETE failed: HTTP ${res.status}`);
    }
  }
}