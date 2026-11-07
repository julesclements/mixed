# Security Assessment

## Node.js October 2026 Security Releases

Reference: <https://nodejs.org/en/blog/vulnerability/october-2026-security-releases>
(published 2026-10-21). The advisory lists ten CVEs across the 22.x, 24.x and
26.x lines. The fixed releases are 22.23.4, 24.22.1 and 26.12.1. The advisory
does not map individual CVEs to fixed versions.

### Where Node.js runs

- **Build, test and CI:** Parcel and Vitest run on Node.js.
- **GitHub Pages:** `.github/workflows/client-deploy.yml` publishes the static
  `docs/` output. No Node.js runs in this deployment.
- **Docker:** `.github/workflows/client-docker-build.yml` publishes the
  `ping-client` image. Its runtime stage runs the `serve` static file server on
  Node.js (`node:26.13.0-alpine`).

The application code runs in the browser and uses the browser's `fetch`, TLS
and decompression, not Node's. `serve` 14.2.7 handles inbound HTTP `GET`
requests for static files. It does not decode request bodies, and its
`compression` dependency only *compresses* responses (Brotli, gzip). On startup
it also checks the npm registry for updates over HTTPS. The image sets
`NO_UPDATE_CHECK=1`, so the container makes no outbound requests.

Reviewed: `lib.js`, `script.js`, `package.json`, `Dockerfile`, both client
workflows and the `serve` 14.2.7 package.

### Exposure assessment

| CVE | Severity | Issue | Exposed? | Reason |
| --- | --- | --- | --- | --- |
| CVE-2026-111497 | High | Brotli decoder out-of-bounds write (RCE) | No | Neither `serve` nor the build tooling decodes untrusted Brotli input. `serve` only encodes responses. |
| CVE-2026-105483 | High | TLS hostname bypass (fullwidth-digit IP) | No | The production container makes no outbound TLS connections (`NO_UPDATE_CHECK=1`). Build tooling connects to named hosts (npm registry, GitHub), not IP literals. |
| CVE-2026-106069 | High | TLS hostname bypass (host loosely resolves to an IP) | No | Same as above. |
| CVE-2026-106072 | Medium | DNS SANs accepted for non-canonical IPv4 hostnames | No | Same as above. |
| CVE-2026-105482 | High | `dns.resolve*()` truncates names containing NUL | No | No use of `dns.resolve*()`. |
| CVE-2026-105481 | Medium | Keep-alive socket processes a response written before the request | No | No outbound Node HTTP client in production. |
| CVE-2026-106074 | Medium | `randomUUID()`/`randomInt()` entropy cached in startup snapshots and SEAs | No | No startup snapshots or single executable applications. |
| CVE-2026-106070 | Low | `ZipFile` returns prefix bytes after failed header validation | No | No ZIP handling. |
| CVE-2026-106071 | Low | Permission Model filesystem over-grant | No | The Permission Model (`--permission`) is not used. |
| CVE-2026-106073 | Low | Permission Model bypass with `fs.realpathSync` | No | Same as above. |

Before this change, the image built on `node:24-slim` and ran on
`node:20-alpine`, and the GitHub Pages build used Node 22. Node 20 is end-of-life and the advisory says end-of-life
versions are affected and receive no fix. None of the vulnerable code paths
above are used, so this was a latent exposure rather than an exploitable one.

### Mitigation

Node.js is pinned to exactly `26.13.0`, which includes all of the fixes:

- `Dockerfile` uses `node:26.13.0-slim` (build) and `node:26.13.0-alpine` (runtime).
- Both client workflows use `node-version: '26.13.0'`.
- The runtime `serve` package is pinned to `14.2.7`.

To change the Node version, follow the upgrade checklist in the
[local-pipelines skill](../.github/skills/local-pipelines/SKILL.md).
