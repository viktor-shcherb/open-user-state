/**
 * File operations on the user's chosen repository.
 *
 * Functions here wrap the GitHub contents API and perform path validation so
 * the rest of the worker can simply pass user input. Each operation requires a
 * Personal Access Token with repository permissions and assumes the repo exists.
 *
 * The write helpers fetch existing file metadata when necessary. This allows
 * callers to update files deterministically by including the current `sha` in
 * the PUT request, avoiding a 409 Conflict response from GitHub.
 */

import type { Env } from './index';
import { ensureRepoExists } from './repo';

// Compute the git blob sha1 of the given content. GitHub's contents API
// returns this hash for existing files, so we replicate the algorithm to
// determine if a commit would introduce any changes.
async function blobSha(content: string): Promise<string> {
  const bytes = new TextEncoder().encode(content);
  const header = new TextEncoder().encode(`blob ${bytes.length}\0`);
  const data = new Uint8Array(header.length + bytes.length);
  data.set(header);
  data.set(bytes, header.length);
  const digest = await crypto.subtle.digest('SHA-1', data);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

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

  // Check if the target file already exists so we can include its `sha` when
  // updating. GitHub requires the sha to avoid a 409 Conflict and lets us skip
  // the write entirely when the content hasn't changed.
  let sha: string | null = null;
  const lookup = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
  });
  if (lookup.ok) {
    const data = await lookup.json<any>();
    sha = data.sha as string;
    const newSha = await blobSha(content);
    // Nothing to commit if the content matches the existing blob
    if (newSha === sha) return;
  } else if (lookup.status !== 404) {
    throw new Error('commit lookup failed');
  }

  const body: any = { message, content: btoa(content) };
  if (sha) body.sha = sha;

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'open-user-state',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
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
