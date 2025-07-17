<!--
  This README describes the Cloudflare Worker backend for Open User State.
  It explains local development steps and documents the REST API used by the frontend.
-->
# Open User State Backend

[![Coverage](https://codecov.io/gh/viktor-shcherb/open-user-state/branch/master/graph/badge.svg)](https://codecov.io/gh/viktor-shcherb/open-user-state)
[![Backend Status](https://img.shields.io/website?url=https%3A%2F%2Fopen-user-state-personal-website.viktoroo-sch.workers.dev%2Fapi%2Fhealth)](https://open-user-state-personal-website.viktoroo-sch.workers.dev/api/health)

This project hosts a Cloudflare Worker that serves as a backend for
[frontend](https://github.com/viktor-shcherb/viktor-shcherb.github.io). The aim
is to authenticate users via GitHub and sync editor state to a repository using
a Personal Access Token (PAT).
<!--
  Development instructions demonstrate how to run the worker locally
  and execute tests so contributors can verify changes quickly.
-->

## Development

Install dependencies and start a local dev server:

```bash
npm install
npm run dev
```

Run the test suite with coverage:

```bash
npm run coverage
```

<!--
  The API Endpoints section catalogs each HTTP route exposed by the worker
  so the frontend knows how to authenticate and store user state.
-->

## API Endpoints

The worker exposes a small set of routes used by the frontend to authenticate
with GitHub, store a Personal Access Token (PAT) and manage the repository
where user state is kept.
### `GET /api/health`

Returns a small JSON payload `{ status: 'ok' }` which can be used by the frontend to verify that the backend is running.


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

The token will be encrypted and stored securely in the worker's `user-pat-store`
KV namespace.

### `POST /api/repository`

Persists the GitHub repository where user state files will be written. The body
must include `{ repo: 'owner/name' }` and the request requires a valid session
cookie.

### `GET /api/repository`

Returns the currently selected repository for the authenticated user in the form
`{ repo: string }`.

### `POST /api/file`

Commits a new text file to the selected repository. The JSON payload should
include `path`, `content` and optionally a `message` used as the commit
message. If the repository does not exist, it will be created automatically
before committing the file.

### `GET /api/file`

Retrieves the raw text at the given `path` from the selected repository. The
path is provided as a query parameter. When the file or repository is missing
`content` will be `null` in the response.

### `GET /api/files`

Lists the files under a directory in the selected repository. Pass the
`path` query parameter to specify the directory (or omit for the repo root).
The response is an array like `{ files: string[] }` containing the entry names.
