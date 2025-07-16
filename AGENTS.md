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
- `src/index.ts` – Cloudflare Worker entry point; orchestrates routes and uses helpers from `src/github.ts`.
- `src/github.ts` – GitHub API stubs invoked by `src/index.ts` for authentication and repository operations.
- `tests/cookie.test.ts` – unit tests for `parseCookies` from `src/index.ts`.
- `tests/encryption.test.ts` – tests `encryptPAT` and `decryptPAT` helpers from `src/index.ts`.
- `tests/router.test.ts` – integration tests for the worker routes defined in `src/index.ts`.
- `package.json` / `package-lock.json` – Node.js dependencies and npm scripts.
- `tsconfig.json` – TypeScript compiler settings shared across source and tests.
- `wrangler.toml` – Cloudflare Worker deployment configuration.
