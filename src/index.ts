/**
 * Entry module for the Cloudflare Worker backend.
 *
 * The worker provides GitHub authentication endpoints and
 * persists user Personal Access Tokens (PATs) in a KV store.
 * All tokens are XOR encrypted with a secret before storage.
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

// ---- Token Persistence -----------------------------------------------------
// Persist the encrypted PAT in Workers KV using the user id as a key.
async function storeToken(
  userId: string,
  encrypted: string,
  env: Env,
): Promise<void> {
  await env.USER_PAT_STORE.put(userId, encrypted);
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

    return new Response('Not Found', { status: 404 });
  },
};
