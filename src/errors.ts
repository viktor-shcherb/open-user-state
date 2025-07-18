/**
 * Minimal response helper used by the router.
 *
 * The Cloudflare Worker returns many small error messages. To make
 * them machine readable and language agnostic the frontend expects a
 * standard `{ error: string }` envelope. Centralising the creation of
 * these responses keeps each handler lean and ensures headers like
 * `Content-Type` are applied uniformly.
 */
export function jsonError(code: number, key: string): Response {
  const body = JSON.stringify({ error: key });
  const headers = { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' };
  return new Response(body, { status: code, headers });
}
