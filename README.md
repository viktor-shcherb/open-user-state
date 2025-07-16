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
