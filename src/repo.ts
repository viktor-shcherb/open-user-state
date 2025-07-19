/**
 * Persistence helpers for user repository preferences.
 *
 * The worker stores the repository chosen by each user in a KV namespace so the
 * frontend can read and write files without repeatedly asking for the repo
 * location. Repository creation is deferred until a file operation needs it.
 */

import type { Env } from './index';

// Persist the repository selected by the user.
export async function storeRepo(userId: string, repo: string, env: Env): Promise<void> {
  await env.USER_REPO_STORE.put(userId, repo);
}

// Look up the previously stored repository for the user.
export async function getRepo(userId: string, env: Env): Promise<string | null> {
  return env.USER_REPO_STORE.get(userId);
}

// ---- GitHub Repository Helpers --------------------------------------------
/**
 * Ensure the repository exists, creating it on demand. This allows the user to
 * simply supply `owner/name` without pre-creating the repo.
 */
export async function ensureRepoExists(repo: string, token: string): Promise<void> {
  const [owner, name] = repo.split('/');
  const repoUrl = `https://api.github.com/repos/${owner}/${name}`;
  const check = await fetch(repoUrl, {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
  });
  if (check.status === 404) {
    // Lazily create the repository to keep the setup flow minimal for the user.
    const userRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
    });
    if (!userRes.ok) throw new Error('user fetch failed');
    const user = await userRes.json<any>();
    const createUrl =
      user.login === owner ? 'https://api.github.com/user/repos' : `https://api.github.com/orgs/${owner}/repos`;
    const create = await fetch(createUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'User-Agent': 'open-user-state',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name }),
    });
    if (!create.ok) throw new Error('repo create failed');
  } else if (!check.ok) {
    throw new Error('repo lookup failed');
  }
}
