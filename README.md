# Open User State Backend

This project hosts a Cloudflare Worker that serves as a backend for
[frontend](https://github.com/viktor-shcherb/viktor-shcherb.github.io). The aim
is to authenticate users via GitHub and sync editor state to a repository using
a Personal Access Token (PAT).

## Development

Install dependencies and start a local dev server:

```bash
npm install
npm run dev
```

`/api/health` returns a simple JSON payload which can be used by the frontend to
check whether the backend is running.

## API Endpoints

The worker exposes a small set of routes used by the frontend to authenticate
with GitHub and store a Personal Access Token (PAT).

### `POST /api/auth/github`

Initiates the OAuth login flow. The backend responds with a redirect to
GitHub. From the browser you can trigger the flow with:

```ts
await fetch('/api/auth/github', { method: 'POST', credentials: 'include' })
  .then(res => {
    if (res.redirected) window.location.href = res.url;
  });
```

### `GET /api/auth/github/callback`

GitHub redirects back to this route after the user approves the OAuth request.
The worker exchanges the `code` parameter for a short‑lived access token,
creates a session cookie, and then redirects the user to `/`.
This endpoint is handled automatically as part of the OAuth redirect and does
not need to be called manually from the frontend.

### `POST /api/token`

Stores a fine‑grained PAT for the authenticated user. The request must include
the session cookie set during OAuth login.

```ts
await fetch('/api/token', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ pat }),
});
```

The token will be encrypted and stored securely using the worker's storage
mechanism.
