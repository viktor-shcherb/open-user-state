# AGENTS.md

## Documentation
guidelines:
  - **File/Module Headers**  
    - Add or enrich a top‑of‑file comment that describes:
      - the overall purpose of this module  
      - its place in the system’s architecture  
      - key design decisions or patterns used
  - **High‑Level Sections**  
    - Before each major section or logical block, insert a brief comment summarizing:
      - the problem being solved in this block  
      - why this approach was chosen (performance, clarity, reusability, etc.)
  - **Types & Classes**  
    - For each class or type definition, explain:
      - its role in the domain model  
      - any invariants or assumptions  
      - how it interacts with others
  - **Inline Comments**
    - For any non‑trivial algorithm, transformation, or conditional:
      - write a short inline note on **why** it’s needed
      - describe any trade‑offs or edge cases handled
  - **Avoid “What”**
    - Don’t restate code semantics or syntax
    - Assume a reader can read the code; focus on rationale, context, and intent.

## Repository Structure

High‑level overview of notable files. **Update this list whenever files are added, removed or modified.**

- `AGENTS.md` – contributor guidelines and repo structure.
- `README.md` – project overview, development instructions and API description.
- `LICENSE` – license terms.
- `docs/security.md` – security considerations for handling Personal Access Tokens.
- `src/index.ts` – Cloudflare Worker entry point that wires together the helper modules.
- `src/auth.ts` – OAuth flow, session lookup and PAT encryption helpers.
- `src/repo.ts` – persistence of user repository preferences and repo creation.
- `src/files.ts` – wrappers around the GitHub contents API.
- `src/errors.ts` – helper for structured JSON error responses.
- `tests/cookie.test.ts` – unit tests for `parseCookies` from `src/auth.ts`.
- `tests/encryption.test.ts` – tests `encryptPAT` and `decryptPAT` helpers from `src/auth.ts`.
- `tests/router.test.ts` – integration tests for the worker routes defined in `src/index.ts`.
- `tests/files.test.ts` – tests `commitFile` overwrite logic from `src/files.ts`.
- `package.json` / `package-lock.json` – Node.js dependencies and npm scripts.
- `tsconfig.json` – TypeScript compiler settings shared across source and tests.
- `wrangler.toml` – Cloudflare Worker deployment configuration.

## Development Notes

Testing relies on Node's built-in `webcrypto` implementation. Use Node 18 or
newer so `globalThis.crypto` is available without additional shims.
