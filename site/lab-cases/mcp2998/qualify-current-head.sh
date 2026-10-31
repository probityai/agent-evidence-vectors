#!/usr/bin/env bash
set -euo pipefail

base=b022522089a0c8b632595c6e7b536453945ed5a9
head=cccc1091873f730455f8d5f8f4c5e9fe5244b0ab
scratch=$(mktemp -d /tmp/mcp-current-head.XXXXXX)
trap 'rm -rf "$scratch"' EXIT

run_phase() {
  local label=$1 code
  shift
  echo "PHASE_START $label"
  set +e
  "$@"
  code=$?
  set -e
  echo "PHASE_END $label $code"
  [ "$code" -eq 0 ] || exit "$code"
}

check_fixture() {
  printf '%s\n' \
    '2754e5959d016f44900499728d8f75ed5180d24ecb9e214818b001676dab8e23  lab-cases/mcp2998/consumer.test.mjs' \
    '359aa6ece939fec523fb60aa72d61e23df74be3e6b626537e1fb3b958588447e  lab-cases/mcp2998/server.mjs' | sha256sum --check --strict
}

pnpm() { "$scratch/tooling/node_modules/.bin/pnpm" "$@"; }
run_phase runtime node --version
run_phase source-fixture check_fixture
run_phase freeze-fixture tar -czf "$scratch/cases.tgz" lab-cases/mcp2998/consumer.test.mjs lab-cases/mcp2998/server.mjs
run_phase install-pinned-tools npm install --prefix "$scratch/tooling" --no-audit --no-fund pnpm@10.26.1 c8@12.0.0
run_phase pnpm-version pnpm --version
run_phase fetch-current-head git fetch origin "$head"

for revision in base head; do
  ref=$base
  [ "$revision" = head ] && ref=$head
  run_phase "checkout-$revision" git checkout --detach "$ref"
  run_phase "restore-fixture-$revision" tar -xzf "$scratch/cases.tgz"
  run_phase "fixture-source-$revision" check_fixture
  echo "SDK_REVISION $revision $(git rev-parse HEAD)"
  run_phase "save-workspace-policy-$revision" cp pnpm-workspace.yaml "$scratch/workspace-original.yaml"
  run_phase "name-redundant-lefthook-postinstall-$revision" python3 - <<'POLICY'
from pathlib import Path
p = Path("pnpm-workspace.yaml")
s = p.read_text()
needle = "ignoredBuiltDependencies:\n    - unrs-resolver"
assert s.count(needle) == 1
s = s.replace(needle, needle + "\n    # Task-local: postinstall repeats root prepare's explicit lefthook install.\n    - lefthook")
p.write_text(s)
POLICY
  run_phase "install-$revision" pnpm --filter @modelcontextprotocol/client... install --frozen-lockfile
  run_phase "installed-pre-push-hook-$revision" test -x "$(git rev-parse --git-path hooks/pre-push)"
  run_phase "restore-workspace-policy-$revision" cp "$scratch/workspace-original.yaml" pnpm-workspace.yaml
  run_phase "workspace-policy-exact-$revision" git diff --quiet -- pnpm-workspace.yaml
  run_phase "build-$revision" pnpm --filter @modelcontextprotocol/client... run build
  run_phase "consumer-$revision" env CALLED_TOOL_REVISION="$revision" "$scratch/tooling/node_modules/.bin/c8" --reporter=text --reporter=json-summary --reports-dir "$scratch/coverage-$revision" --include='lab-cases/mcp2998/*.mjs' --exclude='**/node_modules/**' --all --src lab-cases/mcp2998 --check-coverage --per-file --lines=80 --functions=80 --branches=80 node --test --test-concurrency=1 lab-cases/mcp2998/consumer.test.mjs
  run_phase "coverage-report-$revision" cat "$scratch/coverage-$revision/coverage-summary.json"
done

run_phase focused-upstream pnpm --filter @modelcontextprotocol/client exec vitest run --maxWorkers=1 test/client/lazyOutputValidator.test.ts test/client/lazyOutputValidator.transports.test.ts test/client/productionCatalogColdEntry.test.ts
run_phase typecheck pnpm --filter @modelcontextprotocol/client run typecheck
run_phase lint pnpm --filter @modelcontextprotocol/client run lint
run_phase fixture-format pnpm exec prettier --check lab-cases/mcp2998/consumer.test.mjs lab-cases/mcp2998/server.mjs
run_phase diff-check git diff --check
run_phase final-fixture-source check_fixture
echo "QUALIFICATION_COMPLETE $base $head"
