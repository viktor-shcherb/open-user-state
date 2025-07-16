/**
 * Entry module for the Cloudflare Worker backend.
 *
 * The worker provides GitHub authentication endpoints and
 * persists user Personal Access Tokens (PATs) in a KV store.
 * Users can also select a repository for state storage and
 * read or commit files to that repository. All tokens are XOR
 * encrypted with a secret before storage.
 */

export interface Env {
  /** GitHub OAuth app identifier */
  GITHUB_CLIENT_ID: string;
  /** Secret used during the OAuth token exchange */
  GITHUB_CLIENT_SECRET: string;
  /** Redirect URI configured in the OAuth app */
  GITHUB_REDIRECT_URI: string;
  /** Symmetric key used to obfuscate PATs before persistence */
  ENCRYPTION_SECRET: string;
  /** KV namespace for storing encrypted PATs */
  USER_PAT_STORE: KVNamespace;
  /** KV namespace for persisting user repository preferences */
  USER_REPO_STORE: KVNamespace;
}

// ---- Cookie Utilities ------------------------------------------------------
// Minimal parser used to read session and state cookies. The implementation
// avoids allocations by splitting the header manually.
function parseCookies(header: string | null): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  const parts = header.split(';');
  for (const part of parts) {
    const [k, v] = part.trim().split('=');
    if (k && v) out[k] = v;
  }
  return out;
}

// ---- PAT Encryption --------------------------------------------------------
// PATs are not stored in plaintext. We apply a simple XOR with a secret which
// offers light obfuscation without heavy crypto dependencies. The same secret
// must be used to decrypt the value later.
function encrypt(pat: string, secret: string): string {
  const enc = new TextEncoder();
  const patBytes = enc.encode(pat);
  const secretBytes = enc.encode(secret);
  const out = new Uint8Array(patBytes.length);
  for (let i = 0; i < patBytes.length; i++) {
    out[i] = patBytes[i] ^ secretBytes[i % secretBytes.length];
  }
  return btoa(String.fromCharCode(...out));
}

// Reverses the XOR encryption when reading a PAT from storage.
function decrypt(cipher: string, secret: string): string {
  const data = Uint8Array.from(atob(cipher), c => c.charCodeAt(0));
  const secretBytes = new TextEncoder().encode(secret);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i] ^ secretBytes[i % secretBytes.length];
  }
  return new TextDecoder().decode(out);
}

// ---- Token Persistence -----------------------------------------------------
// Persist the encrypted PAT in Workers KV using the user id as a key.
async function storeToken(
  userId: string,
  encrypted: string,
  env: Env,
): Promise<void> {
  await env.USER_PAT_STORE.put(userId, encrypted);
}

// Retrieve and decrypt the PAT for the given user if it exists.
async function getToken(userId: string, env: Env): Promise<string | null> {
  const enc = await env.USER_PAT_STORE.get(userId);
  return enc ? decrypt(enc, env.ENCRYPTION_SECRET) : null;
}

// ---- Repository Preferences ------------------------------------------------
// Each user chooses a repository where their state will be stored.
async function storeRepo(userId: string, repo: string, env: Env): Promise<void> {
  await env.USER_REPO_STORE.put(userId, repo);
}

// Fetch the repository previously selected by the user.
async function getRepo(userId: string, env: Env): Promise<string | null> {
  return env.USER_REPO_STORE.get(userId);
}

// ---- GitHub File Operations ------------------------------------------------
// Creates a new file at the given path in the repository using the PAT.
async function ensureRepoExists(repo: string, token: string): Promise<void> {
  // Check if the repository already exists. If it does not, attempt to create
  // it under either the authenticated user or an organization with the same
  // name as the "owner" portion of the repo string.
  const [owner, name] = repo.split('/');
  const repoUrl = `https://api.github.com/repos/${owner}/${name}`;
  const check = await fetch(repoUrl, {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
  });
  if (check.status === 404) {
    // Determine whether the repo should be created for the user or an org by
    // comparing the repo owner to the login of the authenticated user.
    const userRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
    });
    if (!userRes.ok) throw new Error('user fetch failed');
    const user = await userRes.json<any>();
    const createUrl =
      user.login === owner
        ? 'https://api.github.com/user/repos'
        : `https://api.github.com/orgs/${owner}/repos`;
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

async function commitFile(
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

// Reads and decodes a text file from the repository using the PAT.
async function readFile(
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

// ---- GitHub OAuth ---------------------------------------------------------
// Exchanges the OAuth `code` for a GitHub access token and retrieves the user
// profile. Only the user id and login are returned for session creation.
async function authenticateWithGitHub(
  code: string,
  env: Env,
): Promise<{ id: string; login: string }> {
  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    code,
    redirect_uri: env.GITHUB_REDIRECT_URI,
  });

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json' },
    body: params,
  });
  const tokenData = await tokenRes.json<any>();
  const accessToken = tokenData.access_token;
  if (!accessToken) throw new Error('no access token');

  const userRes = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'open-user-state' },
  });
  if (!userRes.ok) throw new Error('user fetch failed');
  const user = await userRes.json<any>();
  return { id: String(user.id), login: user.login };
}

// ---- Request Router -------------------------------------------------------
// Handles all HTTP endpoints required by the frontend. The router is kept
// simple as the worker only exposes a handful of routes.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // ---- OAuth Flow: Step 1 ------------------------------------------------
    // Redirect the user to GitHub with a state parameter to prevent CSRF.
    if (url.pathname === '/api/auth/github' && request.method === 'POST') {
      const state = crypto.randomUUID();
      const redirect = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${env.GITHUB_REDIRECT_URI}&scope=user:email&state=${state}`;
      const headers = new Headers({ Location: redirect });
      headers.append('Set-Cookie', `oauth_state=${state}; HttpOnly; Path=/; Secure; SameSite=Lax`);
      return new Response(null, { status: 302, headers });
    }

    // ---- OAuth Flow: Step 2 ------------------------------------------------
    // GitHub redirects back here with the "code" which we exchange for
    // an access token and create a session cookie.
    if (url.pathname === '/api/auth/github/callback' && request.method === 'GET') {
      const params = url.searchParams;
      const code = params.get('code');
      const state = params.get('state');
      const cookies = parseCookies(request.headers.get('Cookie'));
      if (!code || !state || cookies['oauth_state'] !== state) {
        return new Response('Invalid OAuth state', { status: 400 });
      }
      try {
        const user = await authenticateWithGitHub(code, env);
        const headers = new Headers({ Location: '/' });
        headers.append('Set-Cookie', `session=${user.id}; HttpOnly; Path=/; Secure; SameSite=Lax`);
        headers.append('Set-Cookie', 'oauth_state=; Max-Age=0; Path=/; Secure; HttpOnly');
        return new Response(null, { status: 302, headers });
      } catch (err) {
        return new Response('Authentication failed', { status: 500 });
      }
    }

    // ---- Store PAT ---------------------------------------------------------
    // Accepts an encrypted PAT from the frontend and stores it in KV.
    if (url.pathname === '/api/token' && request.method === 'POST') {
      const cookies = parseCookies(request.headers.get('Cookie'));
      const userId = cookies['session'];
      if (!userId) return new Response('Unauthorized', { status: 401 });
      let body: any;
      try {
        body = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
      const pat = body?.pat;
      if (typeof pat !== 'string' || pat.length === 0) {
        return new Response('Invalid token', { status: 400 });
      }
      const encrypted = encrypt(pat, env.ENCRYPTION_SECRET);
      await storeToken(userId, encrypted, env);
      return new Response(null, { status: 204 });
    }

    // ---- Repository Selection ---------------------------------------------
    // Persists the repository where user state files will be stored.
    if (url.pathname === '/api/repository' && request.method === 'POST') {
      const cookies = parseCookies(request.headers.get('Cookie'));
      const userId = cookies['session'];
      if (!userId) return new Response('Unauthorized', { status: 401 });
      let body: any;
      try {
        body = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
      const repo = body?.repo;
      if (typeof repo !== 'string' || !repo.includes('/')) {
        return new Response('Invalid repository', { status: 400 });
      }
      await storeRepo(userId, repo, env);
      return new Response(null, { status: 204 });
    }

    if (url.pathname === '/api/repository' && request.method === 'GET') {
      const cookies = parseCookies(request.headers.get('Cookie'));
      const userId = cookies['session'];
      if (!userId) return new Response('Unauthorized', { status: 401 });
      const repo = await getRepo(userId, env);
      return new Response(JSON.stringify({ repo }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // ---- Repository File Write -------------------------------------------
    // Commits a new file with text content at the provided path.
    if (url.pathname === '/api/file' && request.method === 'POST') {
      const cookies = parseCookies(request.headers.get('Cookie'));
      const userId = cookies['session'];
      if (!userId) return new Response('Unauthorized', { status: 401 });
      const token = await getToken(userId, env);
      const repo = await getRepo(userId, env);
      if (!token || !repo) return new Response('No repository or token', { status: 400 });
      let body: any;
      try {
        body = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
      const path = body?.path;
      const content = body?.content;
      const message = body?.message ?? `Add ${path}`;
      if (typeof path !== 'string' || typeof content !== 'string') {
        return new Response('Invalid payload', { status: 400 });
      }
      try {
        await commitFile(repo, path, content, message, token);
        return new Response(null, { status: 204 });
      } catch {
        return new Response('Commit failed', { status: 500 });
      }
    }

    // ---- Repository File Read --------------------------------------------
    // Returns the raw text content of a path from the configured repository.
    if (url.pathname === '/api/file' && request.method === 'GET') {
      const cookies = parseCookies(request.headers.get('Cookie'));
      const userId = cookies['session'];
      if (!userId) return new Response('Unauthorized', { status: 401 });
      const token = await getToken(userId, env);
      const repo = await getRepo(userId, env);
      if (!token || !repo) return new Response('No repository or token', { status: 400 });
      const path = url.searchParams.get('path');
      if (!path) return new Response('Bad Request', { status: 400 });
      try {
        const text = await readFile(repo, path, token);
        return new Response(JSON.stringify({ content: text }), {
          headers: { 'Content-Type': 'application/json' },
        });
      } catch {
        return new Response('Read failed', { status: 500 });
      }
    }

    return new Response('Not Found', { status: 404 });
  },
};
