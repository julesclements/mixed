---
name: local-pipelines
description: 'Run and maintain local build/test pipelines for this repository. Use when verifying BFF, client, or SPA builds, running coverage tests, switching to the pinned Node.js version with NVM, upgrading Node.js (security patch release or new LTS major), bumping pinned tool versions (NVM, serve), building local Docker images, or addressing dependency and build warnings. Excludes image delivery, runtime startup, and Azure deployment.'
---

# Local pipeline verification

## Scope and safety

- Verify the BFF, JavaScript client, React/TypeScript SPA, and client Pages build.
- Run builds and tests only. Exclude the Azure workflow entirely.
- Never log into a registry, push images, start containers or servers, or deploy
  runtimes as part of local verification.
- Keep GitHub-hosted delivery workflows unchanged unless explicitly requested.
  A requested Node.js upgrade counts as such a request, but only for the
  `node-version` and comment changes listed in the upgrade checklist below.

## Procedure

1. Read the [runner documentation](../../scripts/README.md) and inspect the
   current workflow commands if changing the runner.
2. Run `bash .github/scripts/run-pipelines-local.sh` from the repository root.
   The [runner](../../scripts/run-pipelines-local.sh) installs NVM if missing,
   verifies its installer checksum, then installs and uses the pinned Node.js
   version (26.13.0). It does not switch Node in the calling terminal.
3. Use `--skip-docker` only for explicitly partial validation. Application npm
   builds and coverage tests still run with that option.
4. Review all four pipeline statuses, logs, and coverage in the timestamped
   local results directory. Failed checks must not be reported as passes.
5. When changing runner behavior, run
   `bash .github/scripts/test-local-runner.sh` to execute the
   [offline control-flow tests](../../scripts/test-local-runner.sh).

## Upgrading Node.js

Node is pinned to the exact `major.minor.patch` version that the software is
built and tested on (currently **26.13.0**). Never use a bare major (`26`,
`node:26-slim`) or a moving selector (`lts/*`, `--lts`, `node:lts-slim`,
`node:lts-alpine`). This applies to patch and minor releases, such as a Node
security release, as well as to new majors. Only move to a new major once it is
an even-numbered release in Active LTS.

Pick the version with `nvm ls-remote <major>`, and check that both Docker tags
exist (`docker manifest inspect node:<version>-slim` and `node:<version>-alpine`).
Change every location below in the same commit:

1. `NODE_VERSION` in [run-pipelines-local.sh](../../scripts/run-pipelines-local.sh).
2. The `nvm install <version>` and `nvm use <version>` assertions in
   [test-local-runner.sh](../../scripts/test-local-runner.sh).
3. `node-version: '<version>'` in all five workflows under `.github/workflows/`
   (including `main_mixed.yml`, even though the local runner excludes it; that
   file uses CRLF line endings, so keep them).
4. `FROM node:<version>-slim` and `FROM node:<version>-alpine` in
   `bff/Dockerfile`, `client/Dockerfile` and `spa/Dockerfile`.
5. `engines.node` (`>=<version>`) in `bff/package.json` and `spa/package.json`,
   then `npm install --package-lock-only` in each to refresh the lockfile.
6. The `pull: true` comments in the Docker workflows, and every mention of the
   version in this skill, the [runner README](../../scripts/README.md), the BFF
   readme, `spa/README.md` and the component security documents.

Then confirm nothing was missed:

```bash
grep -rnE "lts/\*|--lts|node:lts|node:[0-9.]+-|node-version|NODE_VERSION|nvm (install|use)|\"node\": \"" \
  .github bff/Dockerfile client/Dockerfile spa/Dockerfile bff/package.json spa/package.json
```

Apart from this skill's own examples of moving selectors, every hit must name
the new full version. Then run the offline runner tests and the
full local pipelines (not `--skip-docker`). Native modules such as `@swc/core`,
`lmdb`, `msgpackr-extract`, `@parcel/watcher` and `esbuild` may need
newer versions for a new Node major: refresh them within their ranges, re-review
their install scripts, and re-pin `allowScripts` with `npm approve-scripts`.

### Other pinned versions

Bump these deliberately too, never by switching to a floating version:

- **NVM:** update `NVM_VERSION` and `NVM_INSTALL_SHA256` in the runner
  together. Compute the hash from the tagged installer
  (`curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/<tag>/install.sh | sha256sum`)
  and also check it against a second download before committing.
- **serve:** update `serve@<version>` in both the client and SPA Dockerfiles,
  and check that the `-s` and `-l` flags still behave the same.

## Learned maintenance rules

- All component Dockerfiles install from committed lockfiles using `npm ci`.
  The BFF image installs production dependencies only with `--omit=dev`.
- Each Docker context must exclude host dependencies, env files, coverage, and
  generated build output. Otherwise `COPY . .` can overwrite container-installed
  dependencies or include secrets and inflate images.
- The exact Node version is pinned and must move everywhere at once; follow
  [Upgrading Node.js](#upgrading-nodejs). Moving `lts` and bare-major tags were
  removed on purpose so that no Node change arrives without a code change.
- Docker builds refresh the pinned base image tags with `--pull`, load images only
  into the local daemon, and retain `ping-{bff,client,spa}:local-test` tags.
- The runtime `serve` package is version-pinned in the client and SPA images.
- The SPA Dockerfile declares `VITE_*` build args; `.env*` files never reach
  the Docker context.
- Coverage output is gitignored and deleted before each local run so failed
  runs never report stale coverage.
- Native install-script approvals in client/SPA manifests are version-pinned
  (npm currently enforces them advisorily). Re-review scripts and re-pin with
  `npm approve-scripts <pkg>` when versions change; never blanket-approve.
- The SPA lints with ESLint 10 flat config (`npm run lint`, zero warnings).
  ESLint 10 and typescript-eslint 8 require `minimatch@^10`, which is affected by
  GHSA-g3hv-75wg-m249 (fixed only in 11.0.1). `spa/package.json` therefore uses
  `overrides.minimatch` (`^11.0.5`); they only use `Minimatch#match`, `.pattern`
  and `minimatch()`, which 11 keeps. Remove the override once ESLint and
  typescript-eslint depend on `minimatch@^11` directly.
- Suppress lint rules per line with a reason, never project-wide. The single
  `react-hooks/set-state-in-effect` exception in `spa/src/App.tsx` covers the
  one-time OAuth callback URL read on mount.
- The BFF application uses CommonJS. Its Vitest config uses an explicit ESM
  extension rather than changing the application's module type.
- Dependency tools can use a different npm than the persistent terminal.
  Re-source NVM and select `26.13.0` before using npm-specific commands such
  as `npm install-scripts ls`.
- Refresh vulnerable dependencies within compatible version ranges when
  possible, regenerate lockfiles, re-audit all three components, and rerun the
  full local checks. Do not force unrelated major framework upgrades.
- Refresh Browserslist data in lockfiles rather than suppressing stale-data
  warnings. Fix config-loader warnings rather than hiding them.
- npm funding and newer-major-version notices are informational. Keep npm
  bundled with Node LTS unless a separate npm upgrade is requested.

## Historical verification evidence

The final run on 2026-11-07 passed all four local checks: BFF 50 tests, client
16 tests in each of its two checks, and SPA 53 tests. All three npm audits
reported zero vulnerabilities, and no build warnings remained. This is a
historical baseline, not a guarantee about future dependencies or executions.