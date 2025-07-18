/**
 * Entry module for the Cloudflare Worker backend.
 *
 * The worker provides GitHub authentication endpoints and
 * persists user Personal Access Tokens (PATs) in a KV store.
 * Users can also select a repository for state storage and
 * read or commit files to that repository. Personal access tokens are
 * encrypted at rest using AES‑GCM. Keys are derived from
 * `ENCRYPTION_SECRET` via PBKDF2 so brute‑force attempts are slowed.
 */

export interface Env {
  /** GitHub OAuth app identifier */
  GITHUB_CLIENT_ID: string;
  /** Secret used during the OAuth token exchange */
  GITHUB_CLIENT_SECRET: string;
  /** Redirect URI configured in the OAuth app */
  GITHUB_REDIRECT_URI: string;
  /** Secret used to derive per-token encryption keys */
  ENCRYPTION_SECRET: string;
  /** KV namespace for storing encrypted PATs */
  USER_PAT_STORE: KVNamespace;
  /** KV namespace for persisting user repository preferences */
  USER_REPO_STORE: KVNamespace;
  /** KV namespace for keeping track of user session cookies */
  SESSIONS: KVNamespace;
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Different length ⇒ definitely not equal (length check itself leaks no
  // useful info because both values are random, same‑size UUID strings).
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];           // accumulate any differing bits
  }
  return diff === 0;               // 0 → identical, non‑zero → mismatch
}

// ---- Cookie Utilities ------------------------------------------------------
// Minimal parser used to read session and state cookies. It keeps
// allocations to a minimum by splitting the header manually instead of
// relying on a heavier cookie library.
export function parseCookies(header: string | null): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  const parts = header.split(';');
  for (const part of parts) {
    const [k, v] = part.trim().split('=');
    if (k && v) out[k] = v;
  }
  return out;
}

function withCors(request: Request, response: Response): Response {
  const origin = request.headers.get('Origin');
  // Only add CORS if the request came from a browser page
  if (origin) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.append('Vary', 'Origin');
  }
  return response;
}

/* ------------------------------------------------------------------ */
/* Helper: resolve the session cookie → user object                   */
/* ------------------------------------------------------------------ */
async function getSessionUser(
  request: Request,
  env: Env,
): Promise<{ id: string; login: string } | null> {
  const cookies   = parseCookies(request.headers.get('Cookie') || '');
  const sessionId = cookies['session'];
  if (!sessionId) return null;

  // KV lookup – returns null if the session doesn't exist / is expired.
  return await env.SESSIONS.get(sessionId, { type: 'json' });
}

/* ────────────────────────────────────────────────────────────── *
 * Path‑sanitisation helper                                       *
 *  – Returns the trimmed path when valid, otherwise null.        *
 *  – Rejects absolute paths, “..” traversal, empty strings,      *
 *    and characters outside [A‑Za‑z0‑9._‑/].                     *
 * ────────────────────────────────────────────────────────────── */
function sanitizePath(raw: unknown): string | null {
  const path = (typeof raw === 'string' ? raw : '').trim();
  const ok =
    path.length > 0 &&
    !path.startsWith('/') &&
    !path.includes('..') &&
    /^[\w./-]+$/.test(path);
  return ok ? path : null;
}

// ---- PAT Encryption --------------------------------------------------------
// Tokens are encrypted with AES-GCM to ensure both confidentiality and
// integrity. PBKDF2 is used to derive a key from the provided secret which slows
// brute-force attempts. Each token uses a fresh random salt and IV.

const SALT_LEN = 16; // 128-bit salt for PBKDF2
const IV_LEN = 12; // 96-bit nonce for AES-GCM

async function deriveKey(secret: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypts a Personal Access Token using AES-GCM and a key derived via PBKDF2.
 * AES-GCM provides confidentiality and integrity while PBKDF2 slows brute
 * force of the secret.
 */
export async function encryptPAT(pat: string, secret: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(secret, salt);
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(pat),
  );
  const out = new Uint8Array(salt.length + iv.length + cipher.byteLength);
  out.set(salt);
  out.set(iv, salt.length);
  out.set(new Uint8Array(cipher), salt.length + iv.length);
  return btoa(String.fromCharCode(...out));
}

/**
 * Decrypts a token previously encrypted with {@link encryptPAT}. Throws when
 * authentication fails so callers can respond with `401 Unauthorized`.
 */
export async function decryptPAT(data: string, secret: string): Promise<string> {
  const buf = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  if (buf.length < SALT_LEN + IV_LEN) throw new Error('cipher too short');
  const salt = buf.slice(0, SALT_LEN);
  const iv = buf.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const cipher = buf.slice(SALT_LEN + IV_LEN);
  const key = await deriveKey(secret, salt);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error('auth fail');
  }
}

// ---- Token Persistence -----------------------------------------------------
// Tokens are stored encrypted in Workers KV. The encryption occurs inside this
// helper to avoid accidentally persisting plaintext.
async function storeToken(
  userId: string,
  pat: string,
  env: Env,
): Promise<void> {
  const enc = await encryptPAT(pat, env.ENCRYPTION_SECRET);
  await env.USER_PAT_STORE.put(userId, enc);
}

// Retrieve and decrypt the PAT for the given user if it exists. Decryption
// errors bubble up so callers can return 401 Unauthorized.
async function getToken(userId: string, env: Env): Promise<string | null> {
  const enc = await env.USER_PAT_STORE.get(userId);
  return enc ? decryptPAT(enc, env.ENCRYPTION_SECRET) : null;
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

// Lists the entries under a directory in the repository. This wraps the
// GitHub contents API so the worker can expose a simple array of names to
// the frontend while still honoring authentication and error handling.
async function listFiles(
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

// ---- GitHub OAuth ---------------------------------------------------------
// Exchanges the OAuth `code` for a GitHub access token and retrieves the user
// profile. Only the user id and login are returned for session creation.
async function authenticateWithGitHub(
  code: string,
  env: Env
): Promise<{ id: string; login: string }> {
  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    code,
    redirect_uri: env.GITHUB_REDIRECT_URI,
  });

  // 1. Exchange code -> access token
  const tokenRes = await fetch(
    'https://github.com/login/oauth/access_token',
    {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params,
    }
  );

  if (!tokenRes.ok) {
    throw new Error(`token exchange failed: ${tokenRes.status}`);
  }

  const tokenData = await tokenRes.json<{
    access_token?: string;
    error?: string;
    error_description?: string;
  }>();

  if (tokenData.error || !tokenData.access_token) {
    throw new Error(`GitHub OAuth error: ${tokenData.error_description || 'unknown'}`);
  }

  // 2. Fetch the user profile
  const userRes = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${tokenData.access_token}`,
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'open-user-state',    
    },
  });

  if (!userRes.ok) {
    throw new Error(`user fetch failed: ${userRes.status}`);
  }

  const user = await userRes.json<{ id: number; login: string }>();
  return { id: String(user.id), login: user.login };
}

// ---- Request Router -------------------------------------------------------
// Handles all HTTP endpoints required by the frontend. The router is kept
// simple as the worker only exposes a handful of routes.
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/health') {
      return withCors(request, new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      }));
    }

    // Redirect the user to GitHub with a state parameter to prevent CSRF.
    // ---- OAuth Flow: Step 1 ------------------------------------------------
    // Redirect the user to GitHub with a state parameter to prevent CSRF.
    if (
      url.pathname === '/api/auth/github' &&
      (request.method === 'GET' || request.method === 'POST')
    ) {
      const state = crypto.randomUUID();
      const redirect = `https://github.com/login/oauth/authorize` +
                       `?client_id=${env.GITHUB_CLIENT_ID}` +
                       `&redirect_uri=${env.GITHUB_REDIRECT_URI}` +
                       `&scope=user:email&state=${state}`;
    
      const headers = new Headers({
        Location: redirect,
        'Set-Cookie': `oauth_state=${state}; HttpOnly; Path=/; Secure; SameSite=Lax`,
        'Cache-Control': `no-store, max-age=0`,
      });
    
      return withCors(request, new Response(null, { status: 302, headers }));
    }


    // ---- OAuth Flow: Step 2 ------------------------------------------------
    // GitHub redirects back here with the "code" which we exchange for
    // an access token and create a session cookie.
    if (url.pathname === '/api/auth/github/callback' && request.method === 'GET') {
      const params  = url.searchParams;
      const code    = params.get('code');
      const state   = params.get('state');
      const error   = params.get('error');           // <— new
      const cookies = parseCookies(request.headers.get('Cookie') || '');
    
      // 1. Handle explicit GitHub denial
      if (error) {
        return new Response(`GitHub error: ${error}`, { status: 400 });
      }
    
      // 2. Validate code & state
      if (!code || !state || !cookies.oauth_state) {
        return new Response('Missing OAuth values', { status: 400 });
      }
    
      // constant‑time compare
      const buf1 = new TextEncoder().encode(cookies.oauth_state);
      const buf2 = new TextEncoder().encode(state);
      const equal = timingSafeEqual(buf1, buf2);
    
      if (!equal) {
        return new Response('Invalid OAuth state', { status: 400 });
      }
    
      try {
        // 3. Exchange code → token → user
        const user = await authenticateWithGitHub(code, env);
    
        // 4. Create a random session ID -> store in KV/DB
        const sessionId = crypto.randomUUID();
        await env.SESSIONS.put(sessionId, JSON.stringify(user), { expirationTtl: 60 * 60 * 24 * 30 }); // 30 days
    
        // 5. Set cookies
        const headers = new Headers({
          'Set-Cookie': [
            `session=${sessionId}; HttpOnly; Path=/; Secure; SameSite=Lax`,
            `oauth_state=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`,
          ].join(', '),
        });
    
        // 6. Redirect to home
        headers.set('Location', '/');
        return withCors(request, new Response(null, { status: 303, headers }));
    
      } catch (err) {
        console.error('GitHub auth failed', err);
        return new Response('Authentication failed', { status: 500 });
      }
    }

    /* ------------------------------------------------------------------ */
    /* /api/logout – DELETE current session                               */
    /*  – Uses POST to avoid CSRF (same‑origin fetch with credentials).   */
    /*  – Clears the cookie immediately and removes the KV entry.         */
    /* ------------------------------------------------------------------ */
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      // 1. Look up the session cookie (don’t throw if missing)
      const cookies   = parseCookies(request.headers.get('Cookie') || '');
      const sessionId = cookies['session'];
    
      if (sessionId) {
        // 2. Best‑effort delete in KV (eventual consistency is fine)
        await env.SESSIONS.delete(sessionId);
      }
    
      // 3. Expire the cookie in the browser
      const headers = new Headers({
        'Set-Cookie':
          'session=; HttpOnly; Path=/; Secure; SameSite=Lax; Max-Age=0',
        'Cache-Control': 'no-store',
      });
    
      // 4. 204 No Content (you could redirect with 303 + Location: / if preferred)
      return withCors(request, new Response(null, { status: 204, headers }));
    }

    // ---- Store PAT ---------------------------------------------------------
    // Accepts an encrypted PAT from the frontend and stores it in KV.
    if (url.pathname === '/api/token' && request.method === 'POST') {
      /* 1. Authenticate the caller */
      const user = await getSessionUser(request, env);
      if (!user) return new Response('Unauthorized', { status: 401 });
    
      /* 2. Parse JSON body */
      let body: { pat?: string };
      try {
        body = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
    
      const pat = (body.pat || '').trim();
    
      /* 3. Basic syntactic validation */
      if (pat.length === 0 || pat.length > 256) {
        return new Response('Invalid token length', { status: 400 });
      }
      // Accept classic PATs (40‑hex) or fine‑grained prefixes
      if (!/^((gh[pous]_|github_pat_)[A-Za-z0-9_]{20,}|[0-9a-f]{40})$/.test(pat)) {
        return new Response('Malformed token', { status: 400 });
      }
    
      /* 4. Verify the PAT with GitHub before storing */
      const verify = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${pat}`,
          'User-Agent': 'open-user-state',
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });
    
      if (verify.status === 401) {
        return new Response('Token not authorised', { status: 401 });
      }
      if (verify.status === 403) {
        return new Response('GitHub rate limited; try later', { status: 429 });
      }
      if (!verify.ok) {
        return new Response('GitHub check failed', { status: 502 });
      }
    
      /* 5. Encrypt & persist */
      await storeToken(user.id, pat, env);
    
      /* 6. Success – 204 No Content */
      return withCors(request, new Response(null, {
        status: 204,
        headers: { 'Cache-Control': 'no-store' },
      }));
    }

    // ---- Repository Selection ---------------------------------------------
    // Persists the repository where user state files will be stored.
    
    /* ------------------------------------------------------------------ */
    /* /api/repository  –  POST  (save repository preference)             */
    /* ------------------------------------------------------------------ */
    if (url.pathname === '/api/repository' && request.method === 'POST') {
      const user = await getSessionUser(request, env);
      if (!user) return new Response('Unauthorized', { status: 401 });
    
      let body: any;
      try {
        body = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
    
      const repo = (body?.repo || '').trim();
      if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) {          // owner/repo
        return new Response('Invalid repository', { status: 400 });
      }
    
      await storeRepo(user.id, repo, env);
      return withCors(request, new Response(null, { status: 204 }));
    }
    
    /* ------------------------------------------------------------------ */
    /* /api/repository  –  GET  (fetch repository preference)             */
    /* ------------------------------------------------------------------ */
    if (url.pathname === '/api/repository' && request.method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return new Response('Unauthorized', { status: 401 });
    
      const repo = await getRepo(user.id, env);
      return withCors(request, new Response(JSON.stringify({ repo }), {
        headers: { 'Content-Type': 'application/json' },
      }));
    }

    // ---- Repository File Write -------------------------------------------
    // Commits a new file with text content at the provided path.
    if (url.pathname === '/api/file' && request.method === 'POST') {
      /* 1. Authenticate caller */
      const user = await getSessionUser(request, env);
      if (!user) return new Response('Unauthorized', { status: 401 });
    
      /* 2. Load token & repo */
      const [token, repo] = await Promise.all([
        getToken(user.id, env).catch(() => null),
        getRepo(user.id, env),
      ]);
      if (!token || !repo) return new Response('No repository or token', { status: 400 });
    
      /* 3. Parse body */
      let body: any;
      try {
        body = await request.json();
      } catch {
        return new Response('Bad Request', { status: 400 });
      }
    
      const path    = sanitizePath(body?.path);
      const content = body?.content;
      const message = (body?.message || `Add ${path}`).slice(0, 200);
    
      if (!path || typeof content !== 'string') {
        return new Response('Invalid payload', { status: 400 });
      }
    
      /* 4. Commit */
      try {
        await commitFile(repo, path, content, message, token);
        return withCors(request, new Response(null, { status: 204 }));
      } catch (err) {
        console.error('commit failed', err);
        return new Response('Commit failed', { status: 500 });
      }
    }

    // ---- Repository File Read --------------------------------------------
    // Returns the raw text content of a path from the configured repository.
    if (url.pathname === '/api/file' && request.method === 'GET') {
      /* 1. Authenticate */
      const user = await getSessionUser(request, env);
      if (!user) return new Response('Unauthorized', { status: 401 });
    
      /* 2. Load token & repo */
      const [token, repo] = await Promise.all([
        getToken(user.id, env).catch(() => null),
        getRepo(user.id, env),
      ]);
      if (!token || !repo) return new Response('No repository or token', { status: 400 });
    
      /* 3. Validate query param */
      const path = sanitizePath(url.searchParams.get('path'));
      if (!path) return new Response('Invalid path', { status: 400 });
    
      /* 4. Fetch from GitHub */
      try {
        const text = await readFile(repo, path, token);
        if (text === null) return new Response('Not Found', { status: 404 });
    
        return new Response(JSON.stringify({ content: text }), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
          },
        });
      } catch {
        return new Response('Read failed', { status: 500 });
      }
    }

    // ---- Repository File Listing ---------------------------------------
    // Returns the names of items under a directory in the configured repo.
    if (url.pathname === '/api/files' && request.method === 'GET') {
      /* 1. Authenticate via the session cookie */
      const user = await getSessionUser(request, env);
      if (!user) return new Response('Unauthorized', { status: 401 });
    
      /* 2. Grab the PAT and preferred repo in parallel */
      const [token, repo] = await Promise.all([
        getToken(user.id, env).catch(() => null),
        getRepo(user.id, env),
      ]);
      if (!token || !repo) {
        return new Response('No repository or token', { status: 400 });
      }
    
      /* 3. Validate the “path” query param (empty string = repo root) */
      const rawDir = (url.searchParams.get('path') || '').trim();
      const dir    = rawDir === '' ? '' : sanitizePath(rawDir);
      if (dir === null) return new Response('Invalid path', { status: 400 });
    
      /* 4. List files from GitHub */
      try {
        const entries = await listFiles(repo, dir, token);
        return withCors(request, new Response(JSON.stringify({ files: entries }), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store', // avoid intermediary caching
          },
        }));
      } catch (err) {
        console.error('list failed', err);
        return new Response('List failed', { status: 500 });
      }
    }

    /* ------------------------------------------------------------------ */
    /* Universal CORS pre‑flight handler                                  */
    /* ------------------------------------------------------------------ */
    if (request.method === 'OPTIONS' && url.pathname.startsWith('/api/')) {
      const origin = request.headers.get('Origin') || '*';
      const reqHdr = request.headers.get('Access-Control-Request-Headers') || '';
    
      return new Response(null, {
        status: 204,
        headers: {
          // Allow the requesting origin (required when you send cookies)
          'Access-Control-Allow-Origin': origin,
          // Allowed verbs for the API
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          // Echo requested headers so the browser can send them
          'Access-Control-Allow-Headers': reqHdr,
          // Needed for credentials: "include"
          'Access-Control-Allow-Credentials': 'true',
          // Cache this pre‑flight for 1 day
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
