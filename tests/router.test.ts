/**
 * Integration tests for the worker router. They ensure simple routes
 * respond as expected without hitting external services.
 */
import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import worker from '../src/index';

// Provide a global `crypto` shim only when Node doesn't supply one. This avoids
// TypeErrors on recent Node versions where the property is read-only.
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
  });
}

const baseEnv = {
  GITHUB_CLIENT_ID: 'id',
  GITHUB_REDIRECT_URI: 'https://example.com/cb',
} as any;

describe('worker routes', () => {
  it('responds to /api/health', async () => {
    const req = new Request('https://host/api/health');
    const res = await worker.fetch(req, baseEnv);
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('application/json');
    const body = await res.json();
    expect(body).toEqual({ status: 'ok' });
  });

  it('starts GitHub OAuth flow', async () => {
    const req = new Request('https://host/api/auth/github', { method: 'POST' });
    const res = await worker.fetch(req, baseEnv);
    expect(res.status).toBe(302);
    const loc = res.headers.get('Location');
    expect(loc).toMatch(/github\.com\/login\/oauth\/authorize/);
    const cookie = res.headers.get('Set-Cookie');
    expect(cookie).toMatch(/oauth_state=/);
  });

  it('returns 401 when PAT decryption fails', async () => {
    const env = {
      ...baseEnv,
      ENCRYPTION_SECRET: 'secret',
      USER_PAT_STORE: { get: async () => 'bad' } as any,
      USER_REPO_STORE: { get: async () => 'owner/repo' } as any,
      SESSIONS: { get: async () => ({ id: '1', login: 'u' }) } as any,
    } as any;

    const req = new Request('https://host/api/file?path=a', {
      headers: { Cookie: 'session=x' },
    });
    const res = await worker.fetch(req, env);
    expect(res.status).toBe(401);
  });
});
