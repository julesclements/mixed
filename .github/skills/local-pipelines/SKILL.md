---
name: local-pipelines
description: 'Run and maintain local build/test pipelines for this repository. Use when verifying BFF, client, or SPA builds, running coverage tests, switching to latest Node LTS with NVM, building local Docker images, or addressing dependency and build warnings. Excludes image delivery, runtime startup, and Azure deployment.'
---

# Local pipeline verification

## Scope and safety

- Verify the BFF, JavaScript client, React/TypeScript SPA, and client Pages build.
- Run builds and tests only. Exclude the Azure workflow entirely.
- Never log into a registry, push images, start containers or servers, or deploy
  runtimes as part of local verification.
- Keep GitHub-hosted delivery workflows unchanged unless explicitly requested.

## Procedure

1. Read the [runner documentation](../../scripts/README.md) and inspect the
   current workflow commands if changing the runner.
2. Run `bash .github/scripts/run-pipelines-local.sh` from the repository root.
   The [runner](../../scripts/run-pipelines-local.sh) installs NVM if missing,
   then installs and uses the latest Node.js LTS. It does not switch Node in
   the calling terminal.
3. Use `--skip-docker` only for explicitly partial validation. Application npm
   builds and coverage tests still run with that option.
4. Review all four pipeline statuses, logs, and coverage in the timestamped
   local results directory. Failed checks must not be reported as passes.
5. When changing runner behavior, run
   `bash .github/scripts/test-local-runner.sh` to execute the
   [offline control-flow tests](../../scripts/test-local-runner.sh).

## Learned maintenance rules

- All component Dockerfiles install from committed lockfiles using `npm ci`.
  The BFF image installs production dependencies only with `--omit=dev`.
- Each Docker context must exclude host dependencies, env files, coverage, and
  generated build output. Otherwise `COPY . .` can overwrite container-installed
  dependencies or include secrets and inflate images.
- Docker builds refresh moving LTS base images with `--pull`, load images only
  into the local daemon, and retain `ping-{bff,client,spa}:local-test` tags.
- Native install-script approvals in client/SPA manifests are version-pinned.
  Re-review scripts when those versions change; never blanket-approve packages.
- The BFF application uses CommonJS. Its Vitest config uses an explicit ESM
  extension rather than changing the application's module type.
- Dependency tools can use a different npm than the persistent terminal.
  Re-source NVM and select `--lts` before using LTS npm-specific commands such
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