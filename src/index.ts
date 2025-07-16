export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  GITHUB_REDIRECT_URI: string;
  ENCRYPTION_SECRET: string;
}

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

async function storeToken(userId: string, encrypted: string): Promise<void> {
  // Placeholder for secure storage implementation
  // Implement secure persistence such as Workers KV or a database.
  // Intentionally left blank in this example.
}

async function authenticateWithGitHub(code: string, env: Env): Promise<{ id: string; login: string }> {
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (url.pathname === '/api/auth/github' && request.method === 'POST') {
      const state = crypto.randomUUID();
      const redirect = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${env.GITHUB_REDIRECT_URI}&scope=user:email&state=${state}`;
      const headers = new Headers({ Location: redirect });
      headers.append('Set-Cookie', `oauth_state=${state}; HttpOnly; Path=/; Secure; SameSite=Lax`);
      return new Response(null, { status: 302, headers });
    }

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
      await storeToken(userId, encrypted);
      return new Response(null, { status: 204 });
    }

    return new Response('Not Found', { status: 404 });
  },
};
