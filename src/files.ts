/**
 * File operations on the user's chosen repository.
 *
 * Functions here wrap the GitHub contents API and perform path validation so
 * the rest of the worker can simply pass user input. Each operation requires a
 * PAT with repository permissions and assumes the repo exists.
 */

import type { Env } from './index';
import { ensureRepoExists } from './repo';

// ---- Path sanitisation -----------------------------------------------------
export function sanitizePath(raw: unknown): string | null {
  const path = (typeof raw === 'string' ? raw : '').trim();
  const ok =
    path.length > 0 &&
    !path.startsWith('/') &&
    !path.includes('..') &&
    /^[\w./-]+$/.test(path);
  return ok ? path : null;
}

// ---- File write ------------------------------------------------------------
export async function commitFile(
  repo: string,
  path: string,
  content: string,
  message: string,
  token: string,
): Promise<void> {
  await ensureRepoExists(repo, token);
  const [owner, name] = repo.split('/');
  const url = `https://api.github.com/repos/${owner}/${name}/contents/${encodeURIComponent(path)}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'open-user-state',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ message, content: btoa(content) }),
  });
  if (!res.ok) throw new Error('commit failed');
}

// ---- File read -------------------------------------------------------------
export async function readFile(
  repo: string,
  path: string,
  token: string,
): Promise<string | null> {
  const [owner, name] = repo.split('/');
  const url = `https://api.github.com/repos/${owner}/${name}/contents/${encodeURIComponent(path)}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('fetch failed');
  const data = await res.json<any>();
  return atob(data.content.replace(/\n/g, ''));
}

// ---- Directory listing -----------------------------------------------------
export async function listFiles(
  repo: string,
  path: string,
  token: string,
): Promise<string[]> {
  const [owner, name] = repo.split('/');
  const url = `https://api.github.com/repos/${owner}/${name}/contents/${encodeURIComponent(path)}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
  });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error('fetch failed');
  const data = await res.json<any>();
  if (!Array.isArray(data)) return [];
  return data.map((entry: any) => entry.name as string);
}
