# Local pipeline checks

Repository-specific agent guidance and learned maintenance rules live in the
[local-pipelines skill](../skills/local-pipelines/SKILL.md).

Run `bash .github/scripts/run-pipelines-local.sh` from the repository root, or
invoke the script by absolute path from any directory. Use `--skip-docker` for
explicitly partial npm-only checks, or `--help` for usage without side effects.

The runner installs NVM v0.40.3 if missing, then installs/uses **latest Node.js
LTS** via `nvm install --lts` and `nvm use --lts`. It respects `NVM_DIR`, does
not edit shell profiles, and only switches Node within the script process (the
calling terminal is unchanged). NVM may create a default alias on first install.
All workflows use `lts/*`; Docker build/runtime stages use `lts-slim` and
`lts-alpine`. These moving selectors follow future LTS releases automatically.

Prerequisites: Bash, curl when installing NVM, and Docker with a running daemon
and Buildx. Internet access is required for Node/npm and base-image downloads.
No cloud credentials are needed. Docker builds use `--pull` to refresh base images.

Only the four application build/test checks below run locally. The Azure workflow
is excluded entirely; no root npm job, image delivery, or Azure runtime is attempted.
The GitHub-hosted workflows themselves are unchanged by this local-only exclusion.

| Workflow | Local checks |
| --- | --- |
| BFF Docker | `npm ci`, coverage tests, syntax build, Buildx image build/load |
| Client Docker | `npm ci`, coverage tests, Parcel build, Buildx image build/load |
| SPA Docker | `npm ci`, advisory production audit, coverage, summary generation, TypeScript/Vite build, Buildx image build/load |
| Client Pages | `npm ci`, coverage tests, Parcel build, local Pages artifact |

With `--skip-docker`, all application npm builds and tests still run. Images are
loaded only into the local Docker daemon, never pushed, and no containers are started.

Set `VITE_STAFF_CLIENT_ID` and `VITE_PING_BASE_URL` in the environment to mirror
SPA repository variables. They are passed as Docker build args, as in CI; the
current SPA Dockerfile does not declare/use them, so this does not guarantee
that they appear in built assets.

Each pipeline stops on its first blocking failure; remaining pipelines still
run. The final exit code is nonzero if any pipeline failed. The SPA audit is
non-blocking, matching CI. No lockfiles are generated as a fallback for `npm ci`.

Logs, a Markdown summary, coverage copies (including pre-existing reports on
failure), and the Pages artifact go to the ignored local results directory.
Set `LOCAL_PIPELINES_RESULTS_DIR` to override its timestamped location. npm checks
update dependencies, coverage, and build outputs; Docker images are retained
as `ping-{bff,client,spa}:local-test`.

This checks local build/test portions, **not** GitHub-hosted actions, triggers,
permissions, caches, artifact transfer, registry authentication/push, Pages
deployment, or Azure OIDC/deployment. No production resources are modified.
Keep this runner in sync when workflow commands change.

Run `bash .github/scripts/test-local-runner.sh` for offline control-flow tests
using an isolated temporary repository and mocked NVM/npm/Docker commands.

## Dependency warning maintenance

Dependency manifests and lockfiles include compatible security patches. Keep
the lockfiles committed: Docker builds now use `npm ci`, not floating installs.
Each Docker context excludes host dependencies, coverage, build output, and env
files, so container dependencies cannot be overwritten by a local installation.

Client and SPA manifests explicitly approve the reviewed native-build scripts
using version-pinned `allowScripts` entries. When those packages change, review
their scripts again and update the pins; do not approve all packages globally.
Browserslist data was refreshed in the lockfiles rather than hiding stale-data
warnings. The BFF test config uses an explicit ESM extension for native loading.

npm's messages about funding or a newer npm major version are informational,
not build warnings. The runner intentionally retains npm bundled with Node LTS.