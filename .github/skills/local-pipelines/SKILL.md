---
name: local-pipelines
description: 'Run and maintain local build/test pipelines for this repository. Use when verifying BFF, client, or SPA builds, running coverage tests, switching to the pinned Node LTS major with NVM, upgrading Node.js to a new LTS major, bumping pinned tool versions (NVM, serve), building local Docker images, or addressing dependency and build warnings. Excludes image delivery, runtime startup, and Azure deployment.'
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
   major (26). It does not switch Node in the calling terminal.
3. Use `--skip-docker` only for explicitly partial validation. Application npm
   builds and coverage tests still run with that option.
4. Review all four pipeline statuses, logs, and coverage in the timestamped
   local results directory. Failed checks must not be reported as passes.
5. When changing runner behavior, run
   `bash .github/scripts/test-local-runner.sh` to execute the
   [offline control-flow tests](../../scripts/test-local-runner.sh).

## Upgrading Node.js to a new LTS major

Node is pinned to an explicit major (currently **26**); never switch back to
moving selectors such as `lts/*`, `--lts`, `node:lts-slim` or `node:lts-alpine`.
Only upgrade to an even-numbered major once it has entered Active LTS. Change
every location below in the same commit:

1. `NODE_MAJOR` in [run-pipelines-local.sh](../../scripts/run-pipelines-local.sh).
2. The `nvm install <major>` and `nvm use <major>` assertions in
   [test-local-runner.sh](../../scripts/test-local-runner.sh).
3. `node-version: '<major>'` in all five workflows under `.github/workflows/`
   (including `main_mixed.yml`, even though the local runner excludes it).
4. `FROM node:<major>-slim` and `FROM node:<major>-alpine` in
   `bff/Dockerfile`, `client/Dockerfile` and `spa/Dockerfile`.
5. The `pull: true` comments in the Docker workflows, and every mention of the
   major in this skill and the [runner README](../../scripts/README.md).

Then confirm nothing was missed:

```bash
grep -rnE "lts/\*|--lts|node:lts|node:[0-9]+-|node-version|NODE_MAJOR|nvm (install|use)" \
  .github bff/Dockerfile client/Dockerfile spa/Dockerfile
```

Apart from this skill's own examples of moving selectors, every hit must name
the new major. Then run the offline runner tests and the
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
- The Node major is pinned and must move everywhere at once; follow
  [Upgrading Node.js](#upgrading-nodejs-to-a-new-lts-major). Moving `lts`
  tags were removed on purpose so that a new major never arrives without a code change.
- Docker builds refresh pinned-major base images with `--pull`, load images only
  into the local daemon, and retain `ping-{bff,client,spa}:local-test` tags.
- The runtime `serve` package is version-pinned in the client and SPA images.
- The SPA Dockerfile declares `VITE_*` build args; `.env*` files never reach
  the Docker context.
- Coverage output is gitignored and deleted before each local run so failed
  runs never report stale coverage.
- Native install-script approvals in client/SPA manifests are version-pinned
  (npm currently enforces them advisorily). Re-review scripts and re-pin with
  `npm approve-scripts <pkg>` when versions change; never blanket-approve.
- The BFF application uses CommonJS. Its Vitest config uses an explicit ESM
  extension rather than changing the application's module type.
- Dependency tools can use a different npm than the persistent terminal.
  Re-source NVM and select `26` before using LTS npm-specific commands such
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