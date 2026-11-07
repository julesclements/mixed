#!/usr/bin/env bash
# Offline control-flow tests: no real installs, containers, or repo build output.
set -euo pipefail
SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
mkdir -p "$FIXTURE/repo/.github/scripts" "$FIXTURE/bin" "$FIXTURE/nvm"
cp "$SOURCE/run-pipelines-local.sh" "$FIXTURE/repo/.github/scripts/"
for service in bff client spa; do
    mkdir -p "$FIXTURE/repo/$service"
    printf '{}\n' > "$FIXTURE/repo/$service/package.json"
    printf '{}\n' > "$FIXTURE/repo/$service/package-lock.json"
done
cat > "$FIXTURE/nvm/nvm.sh" <<'SH'
nvm() {
    printf 'nvm %s\n' "$*" >> "$CALLS"
    if [[ "${FAIL_NVM:-false}" == true ]]; then return 9; fi
}
SH
cat > "$FIXTURE/bin/npm" <<'SH'
#!/usr/bin/env bash
printf '%s npm %s\n' "${PWD##*/}" "$*" >> "$CALLS"
if [[ "$*" == --version ]]; then echo '11.0.0'; fi
if [[ "${FAIL_BFF:-false}" == true && "${PWD##*/}" == bff && "$*" == 'run test:coverage' ]]; then exit 42; fi
if [[ "$1" == audit ]]; then exit 1; fi
if [[ "${PWD##*/}" == client && "$*" == 'run build' ]]; then
    mkdir -p docs; printf '<html>fixture</html>\n' > docs/index.html
fi
SH
cat > "$FIXTURE/bin/node" <<'SH'
#!/usr/bin/env bash
echo 'v24.0.0'
SH
cat > "$FIXTURE/bin/docker" <<'SH'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$CALLS"
case "$*" in
    info|'buildx version') ;;
    'buildx build '*)
        if [[ "$*" == *--push* || "$*" == *type=registry* ]]; then exit 99; fi
        ;;
    *) echo 'Unexpected Docker delivery/runtime command' >&2; exit 99 ;;
esac
SH
cat > "$FIXTURE/bin/npx" <<'SH'
#!/usr/bin/env bash
printf 'npx %s\n' "$*" >> "$CALLS"
SH
chmod +x "$FIXTURE/bin/"*
export PATH="$FIXTURE/bin:$PATH" NVM_DIR="$FIXTURE/nvm" CALLS="$FIXTURE/calls"
RUNNER="$FIXTURE/repo/.github/scripts/run-pipelines-local.sh"

run_case() {
    local name="$1" expected="$2" status
    shift 2
    export LOCAL_PIPELINES_RESULTS_DIR="$FIXTURE/results-$name"
    : > "$CALLS"
    set +e
    bash "$RUNNER" "$@" > "$FIXTURE/output" 2>&1
    status=$?
    set -e
    if [[ "$status" != "$expected" ]]; then
        cat "$FIXTURE/output"; echo "$name: expected $expected, got $status" >&2; exit 1
    fi
    echo "$name: PASS"
}

run_case missing-root 0
if grep -q 'main_mixed:' "$FIXTURE/output"; then exit 1; fi
[[ "$(grep -c ': PASS' "$FIXTURE/output")" -eq 4 ]]
if grep -q '^repo npm install\|^repo npm run' "$CALLS"; then exit 1; fi
grep -q 'nvm install 26.13.0' "$CALLS"
grep -q 'nvm use 26.13.0' "$CALLS"
[[ "$(grep -c 'docker buildx build' "$CALLS")" -eq 3 ]]
grep -q -- '--pull --load' "$CALLS"
grep -q 'npx --no-install tsx' "$CALLS"
printf '{}\n' > "$FIXTURE/repo/package.json"
run_case all-pass 0
[[ "$(grep -c ': PASS' "$FIXTURE/output")" -eq 4 ]]
if grep -q '^repo npm install\|^repo npm run' "$CALLS"; then exit 1; fi
grep -q 'WARNING: SPA audit failed' "$FIXTURE/output"
[[ -s "$LOCAL_PIPELINES_RESULTS_DIR/client-deploy/docs/index.html" ]]
mkdir -p "$FIXTURE/repo/bff/coverage"
printf '{}\n' > "$FIXTURE/repo/bff/coverage/coverage-summary.json"
export FAIL_BFF=true
run_case failed-test 1
[[ ! -e "$FIXTURE/repo/bff/coverage" ]]
[[ ! -e "$LOCAL_PIPELINES_RESULTS_DIR/bff-docker-build/coverage" ]]
grep -q 'bff-docker-build: FAIL (pipeline exit 42' "$FIXTURE/output"
if grep -q 'docker buildx build.*ping-bff' "$CALLS"; then exit 1; fi
grep -q 'client-deploy: PASS' "$FIXTURE/output"
unset FAIL_BFF
run_case skip-docker 0 --skip-docker
if grep -q '^docker ' "$CALLS"; then exit 1; fi
for service in bff client spa; do
    grep -q "^$service npm run build" "$CALLS"
done
grep -q 'Partial validation' "$FIXTURE/output"
run_case help 0 --help
[[ ! -s "$CALLS" ]]
run_case unknown-option 2 --unknown
[[ ! -s "$CALLS" ]]
export FAIL_NVM=true
run_case nvm-failure 9
if grep -q 'npm ' "$CALLS"; then exit 1; fi
echo 'All offline runner tests passed.'