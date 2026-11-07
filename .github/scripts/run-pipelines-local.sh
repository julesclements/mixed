#!/usr/bin/env bash
# Exercise application build/test steps locally; exclude Azure, pushes, and deployments.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SKIP_DOCKER=false
usage() {
    cat <<'EOF'
Usage: bash .github/scripts/run-pipelines-local.sh [--skip-docker] [--help]

Installs NVM if missing, then installs and switches to latest Node.js LTS.
Runs four application build/test checks independently; exits nonzero if any fails.
The Azure workflow is excluded. No image delivery or runtime deployment is attempted.
Docker builds are local only. --skip-docker enables partial npm-only checks.
Set VITE_STAFF_CLIENT_ID and VITE_PING_BASE_URL to mirror SPA workflow vars.
Set LOCAL_PIPELINES_RESULTS_DIR to override the timestamped log directory.
EOF
}
for arg in "$@"; do
    case "$arg" in
        --skip-docker) SKIP_DOCKER=true ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
    esac
done

RESULTS="${LOCAL_PIPELINES_RESULTS_DIR:-$ROOT/.local-pipelines/$(date +%Y%m%d-%H%M%S)-$$}"
mkdir -p -- "$RESULTS"
RESULTS="$(cd -- "$RESULTS" && pwd)"
export CI=true
export GITHUB_STEP_SUMMARY="$RESULTS/summary.md"
printf '# Local pipeline results\n\n' > "$GITHUB_STEP_SUMMARY"

setup_node() {
    # NVM shell functions are not nounset-safe across all releases.
    set +u
    export NVM_DIR="${NVM_DIR:-${XDG_CONFIG_HOME:-$HOME}/.nvm}"
    if [[ ! -s "$NVM_DIR/nvm.sh" ]]; then
        command -v curl >/dev/null || { echo 'curl is required to install NVM.' >&2; return 1; }
        local installer
        installer="$(mktemp)"
        # Pin NVM's installer, but dynamically resolve latest Node LTS.
        if ! curl --fail --silent --show-error --location \
            https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh -o "$installer"; then
            rm -f -- "$installer"
            return 1
        fi
        if ! PROFILE=/dev/null METHOD=script bash "$installer"; then
            rm -f -- "$installer"
            return 1
        fi
        rm -f -- "$installer"
    fi
    # shellcheck source=/dev/null
    source "$NVM_DIR/nvm.sh" --no-use
    nvm install --lts
    nvm use --lts
    set -u
    printf 'Using Node %s, npm %s\n' "$(node --version)" "$(npm --version)"
}
setup_node

install_dependencies() {
    if [[ ! -f package-lock.json && ! -f npm-shrinkwrap.json ]]; then
        echo 'npm ci requires a committed lockfile; no npm install fallback is performed.' >&2
        return 1
    fi
    npm ci
}

save_coverage() {
    # Match always() artifact steps, including reports already on disk on failure.
    if [[ -d coverage ]]; then
        mkdir -p -- "$RESULTS/$PIPELINE"
        cp -R coverage "$RESULTS/$PIPELINE/"
    fi
    if [[ -f coverage/coverage-summary.json ]]; then
        node --input-type=commonjs - <<'JS' >> "$GITHUB_STEP_SUMMARY"
const fs = require('fs');
const data = JSON.parse(fs.readFileSync('coverage/coverage-summary.json', 'utf8'));
console.log('\n| File | Lines | Statements | Functions | Branches |');
console.log('|---|---|---|---|---|');
for (const [file, metrics] of Object.entries(data)) {
    const fmt = m => `${m.pct}% (${m.covered}/${m.total})`;
    console.log(`| ${file.split('/').slice(-2).join('/')} | ${fmt(metrics.lines)} | ${fmt(metrics.statements)} | ${fmt(metrics.functions)} | ${fmt(metrics.branches)} |`);
}
JS
    fi
}

build_image() {
    local service="$1"
    if [[ "$SKIP_DOCKER" == true ]]; then
        echo "Docker build for $service explicitly skipped (partial validation)."
        return
    fi
    command -v docker >/dev/null || { echo 'Docker is required; install it or use --skip-docker.' >&2; return 1; }
    docker info >/dev/null
    docker buildx version
    local args=(--pull --load --tag "ping-$service:local-test" --file "$ROOT/$service/Dockerfile")
    if [[ "$service" == spa ]]; then
        args+=(--build-arg "VITE_STAFF_CLIENT_ID=${VITE_STAFF_CLIENT_ID:-}"
               --build-arg "VITE_PING_BASE_URL=${VITE_PING_BASE_URL:-}")
    fi
    docker buildx build "${args[@]}" "$ROOT/$service"
}

docker_pipeline() {
    local service="$1"
    cd -- "$ROOT/$service"
    trap 'save_coverage' EXIT
    install_dependencies
    if [[ "$service" == spa ]]; then
        # Advisory in the workflow, not a blocking check.
        npm audit --omit=dev --audit-level=high || echo 'WARNING: SPA audit failed (non-blocking, as in CI).'
        npm run coverage
        npx --no-install tsx scripts/generate-coverage-summary.ts
    else
        npm run test:coverage
    fi
    # Validate host builds too, including when Docker builds are skipped.
    npm run build
    build_image "$service"
}

pages_pipeline() {
    cd -- "$ROOT/client"
    trap 'save_coverage' EXIT
    install_dependencies
    npm run test:coverage
    npm run build
    [[ -s docs/index.html ]] || { echo 'Pages build is missing docs/index.html.' >&2; return 1; }
    mkdir -p -- "$RESULTS/$PIPELINE"
    cp -R docs "$RESULTS/$PIPELINE/"
    echo 'Pages artifact prepared locally; deployment is not executed.'
}

FAILED=0
run_pipeline() {
    local name="$1" status
    local -a statuses
    shift
    printf '\n=== %s ===\n' "$name"
    printf '\n## %s\n' "$name" >> "$GITHUB_STEP_SUMMARY"
    # A standalone subshell preserves errexit inside functions (unlike an if).
    # Continue independent workflows without masking failed installs/tests.
    set +e
    ( set -e; PIPELINE="$name"; "$@" ) 2>&1 | tee "$RESULTS/$name.log"
    statuses=("${PIPESTATUS[@]}")
    status=${statuses[0]}
    set -e
    if [[ "$status" -eq 0 && "${statuses[1]}" -eq 0 ]]; then
        printf '%s: PASS\n' "$name" | tee -a "$GITHUB_STEP_SUMMARY"
    else
        printf '%s: FAIL (pipeline exit %s, log exit %s)\n' "$name" "$status" "${statuses[1]}" | tee -a "$GITHUB_STEP_SUMMARY"
        FAILED=$((FAILED + 1))
    fi
}

run_pipeline bff-docker-build docker_pipeline bff
run_pipeline client-docker-build docker_pipeline client
run_pipeline spa-docker-build docker_pipeline spa
run_pipeline client-deploy pages_pipeline

printf '\nResults: %s\nFailed pipelines: %s\n' "$RESULTS" "$FAILED"
if [[ "$SKIP_DOCKER" == true ]]; then
    echo 'Partial validation: Docker builds were explicitly skipped.'
fi
echo 'Azure workflow excluded. No registry login/push, runtime launch, or cloud deployment is attempted.'
[[ "$FAILED" -eq 0 ]]