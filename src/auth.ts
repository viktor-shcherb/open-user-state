/**
 * Authentication and token helpers for the Cloudflare Worker.
 *
 * This module encapsulates GitHub OAuth handling, session retrieval and
 * encryption of personal access tokens. Keeping these concerns separate from
 * the request router keeps `index.ts` focused on HTTP orchestration while this
 * file deals with security related logic.
 *
 * Tokens are encrypted using AES-GCM with keys derived via PBKDF2. Sessions are
 * stored in Workers KV under the `SESSIONS` binding.
 */

import type { Env } from './index';

// ---- Cookie Utilities ------------------------------------------------------
// Tiny parser used only for the session and OAuth state cookies.
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

// Compare two byte arrays without leaking early mismatch information.
// This avoids timing attacks when validating OAuth state.
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/* ------------------------------------------------------------------ */
/* Session lookup helper                                              */
/* ------------------------------------------------------------------ */
export async function getSessionUser(
  request: Request,
  env: Env,
): Promise<{ id: string; login: string } | null> {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionId = cookies['session'];
  if (!sessionId) return null;
  return await env.SESSIONS.get(sessionId, { type: 'json' });
}

// ---- PAT Encryption --------------------------------------------------------
const SALT_LEN = 16;
const IV_LEN = 12;

async function deriveKey(secret: string, salt: Uint8Array): Promise<CryptoKey> {
  // Stretch the shared secret using PBKDF2 so compromised
  // data in KV can't be decrypted with a simple brute force.
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

export async function encryptPAT(pat: string, secret: string): Promise<string> {
  // Each token is encrypted with a unique salt and IV so repeating
  // the same PAT produces different ciphertext.
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
    // Return a generic failure so callers don't learn anything about the secret.
    throw new Error('auth fail');
  }
}

// ---- Token Persistence -----------------------------------------------------
export async function storeToken(
  userId: string,
  pat: string,
  env: Env,
): Promise<void> {
  const enc = await encryptPAT(pat, env.ENCRYPTION_SECRET);
  await env.USER_PAT_STORE.put(userId, enc);
}

// Remove the stored PAT for the given user. The worker keeps no
// other reference so deleting the KV entry fully revokes backend
// access until a new token is supplied.
export async function deleteToken(userId: string, env: Env): Promise<void> {
  await env.USER_PAT_STORE.delete(userId);
}

export async function getToken(userId: string, env: Env): Promise<string | null> {
  const enc = await env.USER_PAT_STORE.get(userId);
  return enc ? decryptPAT(enc, env.ENCRYPTION_SECRET) : null;
}

// ---- GitHub OAuth ---------------------------------------------------------
export async function authenticateWithGitHub(
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
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });

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

  const userRes = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: 'application/vnd.github+json',
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

