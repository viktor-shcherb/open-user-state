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

The code is split into small modules under `src/`:
`auth.ts` handles OAuth and token encryption, `repo.ts` manages repository
preferences and `files.ts` wraps the GitHub file APIs. `index.ts` wires these
together and exposes the HTTP routes.
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

Vitest expects a Node runtime that exposes the standard `webcrypto` API on
`globalThis.crypto` (Node 18+). When running on older versions the tests will
shim the API automatically.

## OAuth & State Storage

Users authenticate via GitHub OAuth. The worker stores a short session
identifier in `SESSIONS` once the callback exchange succeeds. Subsequent
requests use this cookie to look up the GitHub `login` and numeric `id`.

A separate `POST /api/token` call persists a fine grained PAT encrypted in the
`USER_PAT_STORE` namespace. Repository preferences are saved per user in
`USER_REPO_STORE`. Editor state is committed as plain text files; each file is
written individually and overwrites any existing blob at that path.

<!--
  The API Endpoints section catalogs each HTTP route exposed by the worker
  so the frontend knows how to authenticate and store user state.
-->

## API Endpoints

The worker exposes a small set of routes used by the frontend to authenticate
with GitHub, store a Personal Access Token (PAT) and manage the repository
where user state is kept.
### `GET /api/health`

Returns a small JSON payload `{ status: 'ok' }` which can be used by the
frontend to verify that the backend is running. A `HEAD` request returns the
same headers without the body.


### `GET|POST /api/auth/github`

Initiates the OAuth login flow. The backend responds with a redirect to GitHub
and accepts both `GET` and `POST` methods. From the browser you can trigger the
flow with:

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

### `DELETE /api/token`

Removes the stored PAT for the current session. Subsequent file or repository
operations will fail until a new token is provided.

### `POST /api/logout`

Clears the active session cookie on the server so subsequent requests are
unauthenticated.

### `POST /api/repository`

Persists the GitHub repository where user state files will be written. The body
must include `{ repo: 'owner/name' }` and the request requires a valid session
cookie.

### `GET /api/repository`

Returns the currently selected repository for the authenticated user in the form
`{ repo: string }`.

### `GET /api/profile`

Returns `{ username, avatar, patValid, repo }` for the authenticated user.
`patValid` indicates whether the stored PAT successfully fetches the account
information from GitHub.

### `POST /api/file`

Commits a text file to the selected repository. The JSON payload should include
`path`, `content` and optionally a commit `message`. The file is created if it
does not exist or overwritten when the contents differ. The repository will be
created automatically if missing.

### `GET /api/file`

Retrieves the raw text at the given `path` from the selected repository. The
path is provided as a query parameter. When the file or repository is missing
the response is `404`.

### `GET /api/files`

Lists the entries under a directory in the selected repository. Pass the `path`
query parameter to specify the directory (or omit for the repo root). The
response is an array like `{ files: string[] }` containing file and folder
names.

## Error Codes

All error responses use the JSON shape `{ "error": "CODE" }`. Consult
[docs/errors.md](docs/errors.md) for a list of possible codes and the routes
that may produce them.
