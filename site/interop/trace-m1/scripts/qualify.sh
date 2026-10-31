#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
if [[ -L results || -e results/replay-r1 || -L results/replay-r1 || \
    -e results/native-artifacts.tar.gz || -L results/native-artifacts.tar.gz ]]; then
    printf '%s\n' 'Existing result paths must be preserved. Use a fresh checkout.' >&2
    exit 2
fi
mkdir -p results
if ! mkdir results/qualification; then
    printf '%s\n' 'The qualification directory already exists or cannot be reserved.' >&2
    exit 2
fi

run_gate() {
    local trace_gate="$1"
    shift
    local trace_exit=0
    "$@" > "results/qualification/${trace_gate}.stdout" \
        2> "results/qualification/${trace_gate}.stderr" || trace_exit=$?
    printf '%s\n' "$trace_exit" > "results/qualification/${trace_gate}.exit"
    if (( trace_exit != 0 )); then
        cat "results/qualification/${trace_gate}.stdout" "results/qualification/${trace_gate}.stderr"
        exit "$trace_exit"
    fi
}

run_gate sync uv sync --locked --group dev
run_gate fetch uv run --locked python src/fetch_inputs.py
run_gate lint uv run --locked ruff check src tests
run_gate format uv run --locked ruff format --check src tests
run_gate controls uv run --locked coverage run -m pytest -q
run_gate coverage-report uv run --locked coverage report --show-missing
run_gate coverage-json uv run --locked coverage json -o results/qualification/coverage.json
run_gate per-file-coverage uv run --locked python scripts/check_coverage.py
run_gate replay uv run --locked python src/replay.py --out results/replay-r1
run_gate export tar -czf results/native-artifacts.tar.gz results/qualification results/replay-r1
printf '%s\n' 'Pinned fetch, controls, per-file coverage and twelve-case replay passed.'
