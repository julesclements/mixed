# Security Policy

## Node.js October 2026 Security Releases

Reference: <https://nodejs.org/en/blog/vulnerability/october-2026-security-releases>

### Exposure summary

This is a browser-only SPA built with Vite and deployed as static files (Netlify). Node.js is used only for local development, build, tests and CI. No application code runs on Node in production.

Reviewed: `src/`, `scripts/`, `package.json`, `netlify.toml`, `.github/workflows/test-coverage.yml`.

| CVE | Issue | Affects | Exposed? | Reason |
| --- | --- | --- | --- | --- |
| CVE-2026-111497 | Brotli decoder out-of-bounds write (RCE) | Node 22.x, 24.x, 26.x | No (toolchain only, not reachable) | No use of `node:zlib` or Brotli in `src/` or `scripts/`. The only `node:` imports are `node:fs` and `node:path` in `scripts/generate-coverage-summary.ts`. The app has no Node server that accepts Brotli request bodies or fetches Brotli responses. Browser `fetch()` calls (`src/App.tsx`, `src/lib/tokenExchange.ts`) use the browser's decoder, not Node's. |
| CVE-2026-105483 | TLS hostname bypass (fullwidth-digit IP) | Node 24.x, 26.x | No | No Node-side TLS client code. Browser requests use the browser's TLS stack. |
| CVE-2026-106069 | TLS hostname bypass (non-canonical IPv4 literal) | Node 22.x, 24.x, 26.x | No | Same as above. Tooling connects to named hosts (npm registry, GitHub), not IP literals. |
| CVE-2026-105482 | `dns.resolve*()` truncates names containing NUL | Node 22.x, 24.x, 26.x | No | No use of `dns` or `dns.resolve*()`. |

### Pre-branch state (`main`)

`main` did not pin a patched Node.js version. `package.json` had no `engines` field, the README said "Node.js v14 or higher", and CI used `node-version: 24`. Developer machines and CI could therefore run an affected Node build. This was a latent toolchain exposure only. None of the vulnerable code paths above are used by this project.

### Mitigation on this branch

All four CVEs are fixed in Node.js 26.12.1 (also 24.22.1 and 22.23.4).

- `package.json` `engines.node` is `>=26.12.1`.
- `.nvmrc` pins `26.12.1`.
- CI (`.github/workflows/test-coverage.yml`) uses Node `26.12.1`.

Notes:

- `engines` is advisory unless `engine-strict=true` is set in `.npmrc`. The repo has no `.npmrc`.
- `netlify.toml` does not set `NODE_VERSION`. Netlify builds rely on `.nvmrc`.
