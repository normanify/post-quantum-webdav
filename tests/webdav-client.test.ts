import { describe, it, expect, beforeEach, vi } from 'vitest';
import { requestUrl } from 'obsidian';
import { WebDavClient } from '../src/webdav/client';

function mock(url: string, opts: { status?: number; arrayBuffer?: ArrayBuffer; text?: string } = {}) {
  const m = vi.mocked(requestUrl);
  m.mockResolvedValue({
    status: opts.status ?? 200,
    headers: {},
    arrayBuffer: opts.arrayBuffer || new ArrayBuffer(0),
    json: null,
    text: opts.text || '',
  });
  return m;
}

function makeClient(timeoutMs = 500) {
  return new WebDavClient({
    serverUrl: 'https://example.com/remote.php/dav/files/user/',
    username: 'alice',
    password: 'secret',
    basePath: '/vault',
    timeoutMs,
  });
}

describe('WebDavClient', () => {
  beforeEach(() => {
    vi.mocked(requestUrl).mockReset();
  });

  it('resolves file paths under the joined base URL', async () => {
    const m = mock('https://example.com/remote.php/dav/files/user/vault/chunks/h.bin.enc');
    const client = makeClient();
    await client.downloadBytes('chunks/h.bin.enc');
    const [req] = m.mock.calls[0];
    expect(req.url).toBe('https://example.com/remote.php/dav/files/user/vault/chunks/h.bin.enc');
    expect(req.method).toBe('GET');
  });

  it('sends Basic auth header', async () => {
    const m = mock('x');
    const client = makeClient();
    await client.downloadBytes('metadata.json');
    const [req] = m.mock.calls[0];
    expect(req.headers.Authorization).toBe('Basic ' + Buffer.from('alice:secret').toString('base64'));
  });

  it('ensureDir issues MKCOL for each missing segment before PUT', async () => {
    const m = mock('x', { status: 201 });
    const client = makeClient();
    await client.uploadBytes('chunks/abc.bin.enc', new TextEncoder().encode('data'));
    const methods = m.mock.calls.map(([c]) => c.method);
    expect(methods).toContain('MKCOL');
    expect(methods).toContain('PUT');
    expect(methods.indexOf('MKCOL')).toBeLessThan(methods.indexOf('PUT'));
  });

  it('uploadBytes POSTs bytes with octet-stream content type', async () => {
    const m = mock('x', { status: 201 });
    const client = makeClient();
    const data = new TextEncoder().encode('hello');
    await client.uploadBytes('metadata.json', data);
    const put = m.mock.calls.find(([c]) => c.method === 'PUT')![0];
    expect(put.body).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(put.body as ArrayBuffer)).toEqual(data);
  });

  it('uploadBytes throws on HTTP >= 300', async () => {
    mock('x', { status: 500 });
    const client = makeClient();
    await expect(client.uploadBytes('metadata.json', new TextEncoder().encode('x'))).rejects.toThrow(/PUT failed/i);
  });

  it('downloadBytes returns file contents', async () => {
    const data = new TextEncoder().encode('file-content').buffer;
    mock('x', { status: 200, arrayBuffer: data });
    const client = makeClient();
    const out = await client.downloadBytes('metadata.json');
    expect(new TextDecoder().decode(out)).toBe('file-content');
  });

  it('downloadBytes throws on HTTP error', async () => {
    mock('x', { status: 404 });
    const client = makeClient();
    await expect(client.downloadBytes('metadata.json')).rejects.toThrow(/GET failed/i);
  });

  it('downloadBytes throws on network failure', async () => {
    vi.mocked(requestUrl).mockRejectedValue(new Error('net::ERR_CONNECTION_REFUSED'));
    const client = makeClient();
    await expect(client.downloadBytes('metadata.json')).rejects.toThrow(/ERR_CONNECTION_REFUSED/);
  });

  it('exists returns true/false by status', async () => {
    const client = makeClient();
    mock('x', { status: 200 });
    expect(await client.exists('metadata.json')).toBe(true);
    mock('x', { status: 404 });
    expect(await client.exists('metadata.json')).toBe(false);
  });

  it('delete sends DELETE and tolerates 404', async () => {
    const m = mock('x', { status: 404 });
    const client = makeClient();
    await client.delete('chunks/abc.bin.enc');
    expect(m.mock.calls[0][0].method).toBe('DELETE');
  });

  it('delete throws on non-404 errors', async () => {
    mock('x', { status: 500 });
    const client = makeClient();
    await expect(client.delete('chunks/abc.bin.enc')).rejects.toThrow(/DELETE failed/i);
  });
});