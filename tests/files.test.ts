/**
 * Unit tests for the commitFile helper. They verify that committing to an
 * existing path sends the file's sha so GitHub performs an in-place update
 * instead of returning 409 Conflict.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { webcrypto } from 'node:crypto';
import { commitFile } from '../src/files';

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
}

describe('commitFile', () => {
  const repo = 'owner/name';
  const path = 'file.txt';
  const token = 't0k3n';

  let originalFetch: typeof fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('includes sha when overwriting', async () => {
    const calls: any[] = [];
    const fetchMock = vi.fn(async (url: string, init?: any) => {
      calls.push({ url, init });

      // First call: ensureRepoExists repo lookup
      if (url.endsWith('/repos/owner/name') && (!init || init.method === undefined)) {
        return { ok: true, status: 200, json: async () => ({}) } as any;
      }

      // Second call: GET existing file
      if (url.includes('/contents/') && init?.method === undefined) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ sha: 'abc123', content: '' }),
        } as any;
      }

      // Third call: PUT updated file
      if (init?.method === 'PUT') {
        const body = JSON.parse(init.body);
        expect(body.sha).toBe('abc123');
        return { ok: true, status: 200, json: async () => ({}) } as any;
      }

      throw new Error('unexpected call');
    });
    globalThis.fetch = fetchMock as any;

    await commitFile(repo, path, 'data', 'msg', token);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('skips commit when unchanged', async () => {
    const sha = '6320cd248dd8aeaab759d5871f8781b5c0505172';
    const fetchMock = vi.fn(async (url: string, init?: any) => {
      // Repo existence check
      if (url.endsWith('/repos/owner/name') && (!init || init.method === undefined)) {
        return { ok: true, status: 200, json: async () => ({}) } as any;
      }

      // Existing file lookup
      if (url.includes('/contents/') && !init?.method) {
        return { ok: true, status: 200, json: async () => ({ sha, content: '' }) } as any;
      }

      if (init?.method === 'PUT') {
        throw new Error('should not commit identical content');
      }
      throw new Error('unexpected call');
    });
    globalThis.fetch = fetchMock as any;

    await commitFile(repo, path, 'data', 'msg', token);
    // ensure we only looked up the repo and existing file
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
