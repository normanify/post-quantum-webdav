/**
 * In-memory Mock WebDAV server for testing the SyncEngine without a real server.
 * Mirrors the WebDavClient interface consumed by SyncEngine.
 *
 * All instances share ONE virtual server (static state), because every
 * SyncEngine constructs its own WebDavClient — tests simulate multiple
 * devices by creating multiple SyncEngines that must see the same remote.
 *
 * Also supports fault injection (failNextUpload / failNextDownload / delayInject)
 * to test robustness under server errors.
 */

interface SharedServerState {
  files: Map<string, Uint8Array>;
  failUploads: number;
  failDownloads: number;
  failMetadata: number;
  downloadFailures: number;
  deleteLog: string[];
  uploadLog: string[];
}

export class MockWebDavClient {
  /** All instances ever created — lets tests grab the one SyncEngine constructed internally. */
  static instances: MockWebDavClient[] = [];

  private static shared: SharedServerState = {
    files: new Map<string, Uint8Array>(),
    failUploads: 0,
    failDownloads: 0,
    failMetadata: 0,
    downloadFailures: 0,
    deleteLog: [],
    uploadLog: [],
  };

  constructor() {
    MockWebDavClient.instances.push(this);
  }

  /** Reset the shared virtual server between tests. */
  static reset(): void {
    MockWebDavClient.instances.length = 0;
    const s = MockWebDavClient.shared;
    s.files.clear();
    s.failUploads = 0;
    s.failDownloads = 0;
    s.failMetadata = 0;
    s.downloadFailures = 0;
    s.deleteLog = [];
    s.uploadLog = [];
  }

  // --- Mock control (delegates to shared server state) ---

  get files(): Map<string, Uint8Array> {
    return MockWebDavClient.shared.files;
  }

  get failUploads(): number {
    return MockWebDavClient.shared.failUploads;
  }
  set failUploads(v: number) {
    MockWebDavClient.shared.failUploads = v;
  }

  get failDownloads(): number {
    return MockWebDavClient.shared.failDownloads;
  }
  set failDownloads(v: number) {
    MockWebDavClient.shared.failDownloads = v;
  }

  get failMetadata(): number {
    return MockWebDavClient.shared.failMetadata;
  }
  set failMetadata(v: number) {
    MockWebDavClient.shared.failMetadata = v;
  }

  get downloadFailures(): number {
    return MockWebDavClient.shared.downloadFailures;
  }
  set downloadFailures(v: number) {
    MockWebDavClient.shared.downloadFailures = v;
  }

  get deleteLog(): string[] {
    return MockWebDavClient.shared.deleteLog;
  }

  get uploadLog(): string[] {
    return MockWebDavClient.shared.uploadLog;
  }

  setFile(path: string, data: Uint8Array): void {
    this.files.set(path, data);
  }

  hasFile(path: string): boolean {
    return this.files.has(path);
  }

  fileSize(path: string): number {
    return this.files.get(path)?.length ?? -1;
  }

  /** All file paths on the "server" sorted. */
  listAll(): string[] {
    return [...this.files.keys()].sort();
  }

  // --- WebDavClient-compatible API ---

  async ensureDir(_relPath: string): Promise<void> {
    // no-op in memory store
  }

  async exists(relPath: string): Promise<boolean> {
    return this.files.has(relPath);
  }

  async list(_relPath = ''): Promise<unknown[]> {
    return [...this.files.keys()].map(p => ({ filename: p, basename: p, type: 'file', path: '/' + p }));
  }

  async uploadBytes(relPath: string, data: Uint8Array): Promise<void> {
    this.uploadLog.push(relPath);
    if (this.failUploads > 0) {
      this.failUploads--;
      throw new Error('Mock upload network error');
    }
    this.files.set(relPath, Uint8Array.from(data));
  }

  async downloadBytes(relPath: string): Promise<Uint8Array> {
    if (this.failDownloads > 0) {
      this.failDownloads--;
      throw new Error('Mock download network error');
    }
    const data = this.files.get(relPath);
    if (!data) throw new Error(`Mock 404: ${relPath} not found`);
    return Uint8Array.from(data);
  }

  async delete(relPath: string): Promise<void> {
    this.deleteLog.push(relPath);
    this.files.delete(relPath);
  }
}

/** Minimal typed surface used by SyncEngine tests. */
export type MockWebDavLike = MockWebDavClient;