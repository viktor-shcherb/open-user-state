/**
 * Cloudflare Worker entry point and HTTP router.
 *
 * The worker delegates authentication, repository persistence and
 * file operations to helpers under `src/`. Each HTTP route is handled
 * by a dedicated `handleX` function returning a `Response`. The main
 * `fetch` method dispatches to these handlers and attaches CORS headers
 * consistently via `withCors`.
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
  /** Allowed origin for all requests */
  FRONTEND_ORIGIN: string;
  /** KV namespace for storing encrypted PATs */
  USER_PAT_STORE: KVNamespace;
  /** KV namespace for persisting user repository preferences */
  USER_REPO_STORE: KVNamespace;
  /** KV namespace for keeping track of user session cookies */
  SESSIONS: KVNamespace;
}

import {
  parseCookies,
  getSessionUser,
  storeToken,
  getToken,
  authenticateWithGitHub,
  timingSafeEqual,
} from './auth';
import { storeRepo, getRepo } from './repo';
import { sanitizePath, commitFile, readFile, listFiles } from './files';
import { jsonError } from './errors';


function getFrontendOrigin(env: Env): string {
  // Trim & normalize (no trailing slash).
  return (env.FRONTEND_ORIGIN || '').replace(/\/+$/, '');
}

function isAllowedOrigin(origin: string | null, env: Env): boolean {
  if (!origin) return false;
  return origin === getFrontendOrigin(env);
}

// Validate a *relative* `next` path (no host) to prevent open redirects.
function normalizeNext(rel: string | null | undefined): string {
  if (!rel) return '/';
  // Allow path + query + hash; reject anything with protocol or //.
  if (!/^\/[A-Za-z0-9._~\-\/?#[\]=&:%+]*$/.test(rel)) return '/';
  return rel;
}

/* -------------------------------------------------------------------------- */
/* Utility to attach CORS headers to every response                           */
/* -------------------------------------------------------------------------- */
function withCors(request: Request, response: Response, env: Env): Response {
  const origin = request.headers.get('Origin');
  const allowedOrigin = getFrontendOrigin(env);

  if (origin && origin === allowedOrigin) {
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.append('Vary', 'Origin');
  }
  return response;
}

// Reject cross-origin state-changing requests. GET requests are always allowed
// so the worker can host public resources like health checks.
function enforceOrigin(request: Request, env: Env): Response | null {
  const method = request.method;
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return null;
  const origin = request.headers.get('Origin');
  if (!isAllowedOrigin(origin, env)) {
    return jsonError(403, 'BAD_ORIGIN');
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Route handlers                                                             */
/* -------------------------------------------------------------------------- */
async function handleHealth(): Promise<Response> {
  return new Response(JSON.stringify({ status: 'ok' }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

async function handleAuthStart(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const next = normalizeNext(url.searchParams.get('next'));

  const state = crypto.randomUUID();

  const redirect =
    'https://github.com/login/oauth/authorize'
    + `?client_id=${encodeURIComponent(env.GITHUB_CLIENT_ID)}`
    + `&redirect_uri=${encodeURIComponent(env.GITHUB_REDIRECT_URI)}`
    + `&scope=${encodeURIComponent('user:email')}`
    + `&state=${encodeURIComponent(state)}`;

  const headers = new Headers({
    Location: redirect,
    'Cache-Control': 'no-store, max-age=0'
  });

  // Two cookies: oauth_state + oauth_next
  headers.append(
    'Set-Cookie',
    `oauth_state=${state}; HttpOnly; Path=/; Secure; SameSite=None; Max-Age=300`
  );
  headers.append(
    'Set-Cookie',
    `oauth_next=${encodeURIComponent(next)}; HttpOnly; Path=/; Secure; SameSite=None; Max-Age=300`
  );

  return new Response(null, { status: 302, headers });
}

async function handleAuthCallback(request: Request, env: Env, url: URL): Promise<Response> {
  const params  = url.searchParams;
  const code    = params.get('code');
  const state   = params.get('state');
  const error   = params.get('error');
  const cookies = parseCookies(request.headers.get('Cookie') || '');

  if (error) {
    return jsonError(400, 'GITHUB_ERROR');
  }

  if (!code || !state || !cookies.oauth_state) {
    return jsonError(400, 'MISSING_OAUTH');
  }

  // Timing-safe compare
  const buf1 = new TextEncoder().encode(cookies.oauth_state);
  const buf2 = new TextEncoder().encode(state);
  if (!timingSafeEqual(buf1, buf2)) {
    return jsonError(400, 'INVALID_OAUTH_STATE');
  }

  try {
    const user = await authenticateWithGitHub(code, env);

    const sessionId = crypto.randomUUID();
    await env.SESSIONS.put(sessionId, JSON.stringify(user), {
      expirationTtl: 60 * 60 * 24 * 30,
    });

    const nextRel = cookies.oauth_next ? decodeURIComponent(cookies.oauth_next) : '/';
    const safeRel = normalizeNext(nextRel);
    const frontend = getFrontendOrigin(env);
    const redirectTarget = frontend + safeRel;
    
    const headers = new Headers();
    headers.append('Set-Cookie',
      `session=${sessionId}; HttpOnly; Path=/; Secure; SameSite=None; Max-Age=${60*60*24*30}`);
    headers.append('Set-Cookie',
      'oauth_state=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0');
    headers.append('Set-Cookie',
      'oauth_next=; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=0');
    headers.set('Location', redirectTarget);
    
    return new Response(null, { status: 303, headers });
  } catch (err: any) {
    return jsonError(500, 'AUTH_FAILED');
  }
}


async function handleStoreToken(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  let body: { pat?: string };
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'BAD_REQUEST');
  }

  const pat = (body.pat || '').trim();
  if (pat.length === 0 || pat.length > 256) {
    return jsonError(400, 'INVALID_TOKEN_LENGTH');
  }
  if (!/^((gh[pous]_|github_pat_)[A-Za-z0-9_]{20,}|[0-9a-f]{40})$/.test(pat)) {
    return jsonError(400, 'MALFORMED_TOKEN');
  }

  const verify = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${pat}`,
      'User-Agent': 'open-user-state',
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (verify.status === 401) return jsonError(401, 'TOKEN_UNAUTHORIZED');
  if (verify.status === 403) return jsonError(429, 'RATE_LIMIT');
  if (!verify.ok) return jsonError(502, 'GITHUB_CHECK_FAILED');

  await storeToken(user.id, pat, env);
  return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  if (cookies.session) await env.SESSIONS.delete(cookies.session);
  const headers = new Headers({
    'Set-Cookie': 'session=; HttpOnly; Path=/; Secure; SameSite=None; Max-Age=0',
    'Cache-Control': 'no-store',
  });
  return new Response(null, { status: 204, headers });
}

async function handleSetRepo(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  let body: any;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'BAD_REQUEST');
  }

  const repo = (body?.repo || '').trim();
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) {
    return jsonError(400, 'INVALID_REPO');
  }

  await storeRepo(user.id, repo, env);
  return new Response(null, { status: 204 });
}

async function handleGetRepo(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  const repo = await getRepo(user.id, env);
  return new Response(JSON.stringify({ repo }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// ---------------------------------------------------------------------------
// Return basic profile information for the authenticated user. This reaches
// out to GitHub using the stored PAT to verify the token and fetch the avatar
// URL. When no valid token is present the avatar field is empty and
// `patValid` is false. The selected repository is returned regardless.
async function handleGetProfile(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  const [token, repo] = await Promise.all([
    getToken(user.id, env),
    getRepo(user.id, env),
  ]);

  let avatar = '';
  let patValid = false;
  if (token) {
    const check = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'open-user-state' },
    });
    if (check.ok) {
      const data = await check.json<any>();
      avatar = data.avatar_url as string;
      patValid = true;
    } else if (check.status === 401 || check.status === 403) {
      patValid = false;
    } else {
      return jsonError(502, 'GITHUB_CHECK_FAILED');
    }
  }

  const body = {
    username: user.login,
    avatar,
    patValid,
    repo: repo || null,
  };

  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
}

async function handleCommitFile(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  let token: string | null = null;
  let repo: string | null = null;
  try {
    [token, repo] = await Promise.all([
      getToken(user.id, env),
      getRepo(user.id, env),
    ]);
    if (!token || !repo) return jsonError(400, 'MISSING_REPO_OR_TOKEN');
  } catch {
    return jsonError(401, 'UNAUTHORIZED');
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return jsonError(400, 'BAD_REQUEST');
  }

  const path = sanitizePath(body?.path);
  const content = body?.content;
  const message = (body?.message || `Add ${path}`).slice(0, 200);
  if (!path || typeof content !== 'string') {
    return jsonError(400, 'INVALID_PAYLOAD');
  }

  try {
    await commitFile(repo, path, content, message, token);
    return new Response(null, { status: 204 });
  } catch (err) {
    return jsonError(500, 'COMMIT_FAILED');
  }
}

async function handleReadFile(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  let token: string | null = null;
  let repo: string | null = null;
  try {
    [token, repo] = await Promise.all([
      getToken(user.id, env),
      getRepo(user.id, env),
    ]);
    if (!token || !repo) return jsonError(400, 'MISSING_REPO_OR_TOKEN');
  } catch {
    return jsonError(401, 'UNAUTHORIZED');
  }

  const path = sanitizePath(url.searchParams.get('path'));
  if (!path) return jsonError(400, 'INVALID_PATH');

  try {
    const text = await readFile(repo, path, token);
    if (text === null) return jsonError(404, 'NOT_FOUND');
    return new Response(JSON.stringify({ content: text }), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  } catch (err) {
    return jsonError(500, 'READ_FAILED'); 
  }
}

async function handleListFiles(request: Request, env: Env, url: URL): Promise<Response> {
  const user = await getSessionUser(request, env);
  if (!user) return jsonError(401, 'UNAUTHORIZED');

  let token: string | null = null;
  let repo: string | null = null;
  try {
    [token, repo] = await Promise.all([
      getToken(user.id, env),
      getRepo(user.id, env),
    ]);
    if (!token || !repo) return jsonError(400, 'MISSING_REPO_OR_TOKEN');
  } catch {
    return jsonError(401, 'UNAUTHORIZED');
  }

  const rawDir = (url.searchParams.get('path') || '').trim();
  const dir = rawDir === '' ? '' : sanitizePath(rawDir);
  if (dir === null) return jsonError(400, 'INVALID_PATH');

  try {
    const entries = await listFiles(repo, dir, token);
    return new Response(JSON.stringify({ files: entries }), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  } catch {
    return jsonError(500, 'LIST_FAILED');
  }
}

function handlePreflight(request: Request, env: Env): Response {
  const origin = request.headers.get('Origin');
  const allowed = isAllowedOrigin(origin, env) ? origin : '';
  if (!allowed) {
    return new Response(null, { status: 403 });
  }
  const reqHdr = request.headers.get('Access-Control-Request-Headers') || '';
  const allowHeaders = reqHdr ? reqHdr : 'Content-Type';
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': allowed,
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': allowHeaders,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '600',
      'Vary': 'Origin',
    },
  });
}

/* -------------------------------------------------------------------------- */
/* Router                                                                     */
/* -------------------------------------------------------------------------- */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    let pathname = url.pathname;
    if (pathname !== '/' && pathname.endsWith('/')) {
      pathname = pathname.replace(/\/+$/, '');
    }
    
    const method = request.method;
    const hdrTag = 'X-Worker-Build';
    const buildStamp = 'build-2025-07-18a';

    let res: Response | null = null;

    // do not enforce origin for auth
    if (
      ['POST','PUT','PATCH','DELETE'].includes(method) &&
      !pathname.startsWith('/api/auth/')
    ) {
      const originErr = enforceOrigin(request, env);
      if (originErr) return withCors(request, originErr, env);
    }

    if (pathname === '/api/health' && (method === 'GET' || method === 'HEAD')) {
      res = await handleHealth();
      if (method === 'HEAD') {
        res = new Response(null, res); // strip body
      }
    } else if (pathname === '/api/auth/github' && (method === 'GET' || method === 'POST')) {
      res = await handleAuthStart(request, env);
    } else if (pathname === '/api/auth/github/callback' && method === 'GET') {
      res = await handleAuthCallback(request, env, url);
    } else if (pathname === '/api/token' && method === 'POST') {
      res = await handleStoreToken(request, env);
    } else if (pathname === '/api/logout' && method === 'POST') {
      res = await handleLogout(request, env);
    } else if (pathname === '/api/repository' && method === 'POST') {
      res = await handleSetRepo(request, env);
    } else if (pathname === '/api/repository' && method === 'GET') {
      res = await handleGetRepo(request, env);
    } else if (pathname === '/api/profile' && method === 'GET') {
      res = await handleGetProfile(request, env);
    } else if (pathname === '/api/file' && method === 'POST') {
      res = await handleCommitFile(request, env);
    } else if (pathname === '/api/file' && method === 'GET') {
      res = await handleReadFile(request, env, url);
    } else if (pathname === '/api/files' && method === 'GET') {
      res = await handleListFiles(request, env, url);
    } else if (method === 'OPTIONS' && pathname.startsWith('/api/')) {
      res = handlePreflight(request, env);
    }

    if (!res) {
      res = jsonError(404, 'NOT_FOUND');
    }
    res.headers.set(hdrTag, buildStamp);
    return withCors(request, res, env);
  },
};
