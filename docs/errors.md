# API Error Codes

Every API request may return a JSON body of the form `{ "error": "CODE" }`.
The code identifies what went wrong while the HTTP status shows whether the
problem is on the client side (4xx) or the server (5xx).

The table below lists all error codes and which routes can emit them.

| Code | Meaning | Routes |
| ---- | ------- | ------ |
| BAD_ORIGIN | `Origin` header did not match `FRONTEND_ORIGIN` | any stateful route (non-GET/HEAD) |
| GITHUB_ERROR | GitHub returned an error during OAuth callback | `/api/auth/github/callback` |
| MISSING_OAUTH | OAuth callback lacked `code`/`state` or cookie | `/api/auth/github/callback` |
| INVALID_OAUTH_STATE | OAuth `state` mismatch, possible tampering | `/api/auth/github/callback` |
| AUTH_FAILED | Unexpected failure fetching user info from GitHub | `/api/auth/github/callback` |
| UNAUTHORIZED | Missing or invalid session | most routes requiring auth |
| BAD_REQUEST | Malformed JSON payload | token/repo/file routes |
| INVALID_TOKEN_LENGTH | PAT outside accepted length range | `/api/token` |
| MALFORMED_TOKEN | PAT fails format checks | `/api/token` |
| TOKEN_UNAUTHORIZED | GitHub rejected the PAT with 401 | `/api/token` |
| RATE_LIMIT | GitHub responded 403 when verifying PAT | `/api/token` |
| GITHUB_CHECK_FAILED | Unknown response from GitHub while verifying PAT or avatar | `/api/token`, `/api/profile` |
| INVALID_REPO | Repository string not of the form `owner/name` | `/api/repository` (POST) |
| MISSING_REPO_OR_TOKEN | Repo or PAT missing for file access | `/api/file*` routes |
| INVALID_PAYLOAD | Missing path or content in commit request | `/api/file` (POST) |
| COMMIT_FAILED | GitHub rejected the commit | `/api/file` (POST) |
| INVALID_PATH | Path contained illegal characters | `/api/file` (GET/POST), `/api/files` |
| NOT_FOUND | Resource does not exist | `/api/file` (GET) |
| READ_FAILED | GitHub returned an error while reading | `/api/file` (GET) |
| LIST_FAILED | GitHub returned an error while listing | `/api/files` |

