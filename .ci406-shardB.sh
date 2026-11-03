#!/usr/bin/env bash
set +e
export UV_PYTHON=3.13
export CI=true GITHUB_ACTIONS=true RUNNER_TEMP=/tmp/rt GITHUB_WORKSPACE=$PWD
mkdir -p /tmp/rt ci406out
rm -f ci406out/*
export PATH=$HOME/.cargo/bin:/usr/local/go/bin:$HOME/go/bin:$PATH
summ(){ echo "STEP $1 rc=$2 $3"; }
cat > ci406out/029-python-2.sh <<'__EOS__'
uv sync --locked --extra dev --extra generators
__EOS__
timeout 1500 bash -e ci406out/029-python-2.sh > ci406out/029-python-2.sh.log 2>&1; summ 029-python-2 $? 'sync toolchain'
cat > ci406out/030-python-3.sh <<'__EOS__'
uv pip install --no-deps .
__EOS__
timeout 1500 bash -e ci406out/030-python-3.sh > ci406out/030-python-3.sh.log 2>&1; summ 030-python-3 $? 'Install checkout wheel for distribution imports'
cat > ci406out/116-python-89.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-completion-confirmation/tests -q
__EOS__
timeout 1500 bash -e ci406out/116-python-89.sh > ci406out/116-python-89.sh.log 2>&1; summ 116-python-89 $? 'completion-confirmation cases regenerate and force every check'
cat > ci406out/117-python-90.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-chunked-export/tests -q
__EOS__
timeout 1500 bash -e ci406out/117-python-90.sh > ci406out/117-python-90.sh.log 2>&1; summ 117-python-90 $? 'chunked-export cases regenerate and force every check'
cat > ci406out/118-python-91.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-done-receipt/tests -q
__EOS__
timeout 1500 bash -e ci406out/118-python-91.sh > ci406out/118-python-91.sh.log 2>&1; summ 118-python-91 $? 'done corpora regenerate, are judged clean and force every rule'
cat > ci406out/119-python-92.sh <<'__EOS__'
rev=$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['tool']['uv']['sources']['probity-verify']['rev'])")
probity="${RUNNER_TEMP:-$(mktemp -d)}/probity-at-pin"
git clone --quiet --filter=blob:none --no-checkout https://github.com/probityai/probity "$probity"
git -C "$probity" checkout --quiet "$rev" -- packages/probity-verify/examples/done-receipt
uv run --locked --extra dev --group crosscheck python corpora/vectors-done-receipt/crosscheck_probity_verify.py \
  vectors-done-contract vectors-done-receipt vectors-spoofed-tool-output \
  vectors-test-tampering vectors-grader-isolation vectors-done-probes \
  --examples "$probity/packages/probity-verify/examples/done-receipt"

__EOS__
timeout 1500 bash -e ci406out/119-python-92.sh > ci406out/119-python-92.sh.log 2>&1; summ 119-python-92 $? 'the done readers agree with probity-verify on every member'
cat > ci406out/120-python-93.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-trace-anchor/tests -q
__EOS__
timeout 1500 bash -e ci406out/120-python-93.sh > ci406out/120-python-93.sh.log 2>&1; summ 120-python-93 $? 'TRACE registry anchor cases regenerate and force every check'
cat > ci406out/121-python-94.sh <<'__EOS__'
set -euo pipefail
uv run --extra dev pytest corpora/vectors-agent-payment-mandate/tests -q
uv run python corpora/vectors-agent-payment-mandate/check_vectors.py
uv run python corpora/vectors-agent-payment-mandate/mutation_check.py

__EOS__
timeout 1500 bash -e ci406out/121-python-94.sh > ci406out/121-python-94.sh.log 2>&1; summ 121-python-94 $? 'vectors-agent-payment-mandate cases regenerate, agree and every rule is load-bearing'
cat > ci406out/122-python-95.sh <<'__EOS__'
set -euo pipefail
uv run --extra dev pytest corpora/vectors-connector-scope/tests -q
uv run python corpora/vectors-connector-scope/check_vectors.py
uv run python corpora/vectors-connector-scope/mutation_check.py

__EOS__
timeout 1500 bash -e ci406out/122-python-95.sh > ci406out/122-python-95.sh.log 2>&1; summ 122-python-95 $? 'vectors-connector-scope cases regenerate, agree and every rule is load-bearing'
cat > ci406out/123-python-96.sh <<'__EOS__'
set -euo pipefail
uv run --extra dev pytest corpora/vectors-grade-floor/tests -q
uv run python corpora/vectors-grade-floor/check_vectors.py
uv run python corpora/vectors-grade-floor/mutation_check.py

__EOS__
timeout 1500 bash -e ci406out/123-python-96.sh > ci406out/123-python-96.sh.log 2>&1; summ 123-python-96 $? 'grade-floor cases regenerate, agree and every rule is load-bearing'
cat > ci406out/124-python-97.sh <<'__EOS__'
set -euo pipefail
uv run --extra dev pytest corpora/vectors-agent-change-admission/tests -q
uv run python corpora/vectors-agent-change-admission/check_vectors.py
uv run python corpora/vectors-agent-change-admission/mutation_check.py

__EOS__
timeout 1500 bash -e ci406out/124-python-97.sh > ci406out/124-python-97.sh.log 2>&1; summ 124-python-97 $? 'change-admission cases regenerate, agree and every rule is load-bearing'
cat > ci406out/125-python-98.sh <<'__EOS__'
set -euo pipefail
uv run --extra dev pytest corpora/vectors-agentic-process-evidence/tests -q
uv run python corpora/vectors-agentic-process-evidence/check_vectors.py
uv run python corpora/vectors-agentic-process-evidence/mutation_check.py

__EOS__
timeout 1500 bash -e ci406out/125-python-98.sh > ci406out/125-python-98.sh.log 2>&1; summ 125-python-98 $? 'agentic-process-evidence cases regenerate, agree and every rule is load-bearing'
cat > ci406out/126-python-99.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-delegation-lifecycle/tests -q
__EOS__
timeout 1500 bash -e ci406out/126-python-99.sh > ci406out/126-python-99.sh.log 2>&1; summ 126-python-99 $? 'delegation-lifecycle cases regenerate and their digest recomputes'
cat > ci406out/127-python-100.sh <<'__EOS__'
set -euo pipefail
uv run --extra dev pytest corpora/vectors-restart-records/tests -q
uv run python corpora/vectors-restart-records/check_vectors.py

__EOS__
timeout 1500 bash -e ci406out/127-python-100.sh > ci406out/127-python-100.sh.log 2>&1; summ 127-python-100 $? 'restart-records members regenerate, every rule is forced and the checker agrees'
cat > ci406out/128-python-101.sh <<'__EOS__'
python3 corpora/vectors-a2a-jcs-v01/upstream.py check
__EOS__
timeout 1500 bash -e ci406out/128-python-101.sh > ci406out/128-python-101.sh.log 2>&1; summ 128-python-101 $? 'the vendored a2a-jcs-v01 corpus matches its source lock'
cat > ci406out/129-python-102.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-a2a-jcs-v01/tests -q
__EOS__
timeout 1500 bash -e ci406out/129-python-102.sh > ci406out/129-python-102.sh.log 2>&1; summ 129-python-102 $? 'the a2a-jcs-v01 corpus replays under its verifier contract'
cat > ci406out/130-python-103.sh <<'__EOS__'
uv run python corpora/vectors-mcp-owasp/gen_vectors.py --check
uv run python scripts/mcp-owasp-reader-test.py

__EOS__
timeout 1500 bash -e ci406out/130-python-103.sh > ci406out/130-python-103.sh.log 2>&1; summ 130-python-103 $? 'OWASP MCP drafts regenerate and every rule owns its reject'
cat > ci406out/131-python-104.sh <<'__EOS__'
mkdir -p .build
uv run python packaging/run_vectors.py \
  --corpus vectors-source-coverage \
  --verifier "uv run --no-project --python 3.13 --with probity-verify==0.1.1 probity-verify" \
  --report .build/probity-source-coverage.json

__EOS__
timeout 1500 bash -e ci406out/131-python-104.sh > ci406out/131-python-104.sh.log 2>&1; summ 131-python-104 $? 'probity-verify checks source coverage'
cat > ci406out/132-python-105.sh <<'__EOS__'
uv run --extra generators python corpora/vectors-observed-effect/mutation_check.py
__EOS__
timeout 1500 bash -e ci406out/132-python-105.sh > ci406out/132-python-105.sh.log 2>&1; summ 132-python-105 $? 'every observed-effect rule is load-bearing'
cat > ci406out/133-python-106.sh <<'__EOS__'
uv run --extra generators python corpora/vectors-agent-audit-record/check_vectors.py
__EOS__
timeout 1500 bash -e ci406out/133-python-106.sh > ci406out/133-python-106.sh.log 2>&1; summ 133-python-106 $? 'the agent-audit-record corpus behaves as its manifest claims'
cat > ci406out/134-python-107.sh <<'__EOS__'
uv run mypy --strict scripts/auditrecord-aggregation-test.py
uv run python scripts/auditrecord-aggregation-test.py

__EOS__
timeout 1500 bash -e ci406out/134-python-107.sh > ci406out/134-python-107.sh.log 2>&1; summ 134-python-107 $? 'producer aggregation preserves source pairs at representable boundaries'
cat > ci406out/135-python-108.sh <<'__EOS__'
uv run mypy --strict scripts/auditrecord-issuedat-test.py
uv run python scripts/auditrecord-issuedat-test.py

__EOS__
timeout 1500 bash -e ci406out/135-python-108.sh > ci406out/135-python-108.sh.log 2>&1; summ 135-python-108 $? 'issuedAt must parse and must not be earlier than sealedAt'
cat > ci406out/136-python-109.sh <<'__EOS__'
uv run --extra generators python corpora/vectors-agent-decision/check_vectors.py
__EOS__
timeout 1500 bash -e ci406out/136-python-109.sh > ci406out/136-python-109.sh.log 2>&1; summ 136-python-109 $? 'the agent-decision corpus behaves as its manifest claims'
cat > ci406out/137-python-110.sh <<'__EOS__'
uv run --extra dev --extra generators pytest corpora/vectors-w3c-intake/tests -q
__EOS__
timeout 1500 bash -e ci406out/137-python-110.sh > ci406out/137-python-110.sh.log 2>&1; summ 137-python-110 $? 'the W3C intake corpus and records behave as claimed'
cat > ci406out/138-python-111.sh <<'__EOS__'
uv run --extra generators python corpora/vectors-ietf-agent-record-drafts/check_vectors.py
__EOS__
timeout 1500 bash -e ci406out/138-python-111.sh > ci406out/138-python-111.sh.log 2>&1; summ 138-python-111 $? 'the IETF agent-record drafts corpus behaves as its manifest claims'
cat > ci406out/139-python-112.sh <<'__EOS__'
uv run --extra generators python scripts/indeterminate-readers-test.py
__EOS__
timeout 1500 bash -e ci406out/139-python-112.sh > ci406out/139-python-112.sh.log 2>&1; summ 139-python-112 $? 'indeterminate members are scored on their readings'
cat > ci406out/140-python-113.sh <<'__EOS__'
uv run --extra generators python scripts/write-chain-replay-test.py
__EOS__
timeout 1500 bash -e ci406out/140-python-113.sh > ci406out/140-python-113.sh.log 2>&1; summ 140-python-113 $? 'each comparison of the write-chain replay has its own member'
cat > ci406out/141-python-114.sh <<'__EOS__'
uv run --extra generators python scripts/audit-record-dating-rows-test.py
__EOS__
timeout 1500 bash -e ci406out/141-python-114.sh > ci406out/141-python-114.sh.log 2>&1; summ 141-python-114 $? 'each revision-01 dating rule is pinned by its own retained member'
cat > ci406out/142-python-115.sh <<'__EOS__'
python3 scripts/indeterminate-scoring-gate.py
python3 scripts/indeterminate-scoring-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/142-python-115.sh > ci406out/142-python-115.sh.log 2>&1; summ 142-python-115 $? 'no corpus pins a verdict on an open member'
cat > ci406out/143-python-116.sh <<'__EOS__'
python3 packaging/run_vectors.py --self-test
__EOS__
timeout 1500 bash -e ci406out/143-python-116.sh > ci406out/143-python-116.sh.log 2>&1; summ 143-python-116 $? 'the reference rail clears its own oracle'
cat > ci406out/144-python-117.sh <<'__EOS__'
python3 packaging/run_vectors.py
__EOS__
timeout 1500 bash -e ci406out/144-python-117.sh > ci406out/144-python-117.sh.log 2>&1; summ 144-python-117 $? 'replay every vector on the Python rail (must be 288/288)'
cat > ci406out/145-python-118.sh <<'__EOS__'
python3 scripts/harness-output-contract-test.py
__EOS__
timeout 1500 bash -e ci406out/145-python-118.sh > ci406out/145-python-118.sh.log 2>&1; summ 145-python-118 $? 'the harness refuses a rail that answers nothing'
cat > ci406out/146-python-119.sh <<'__EOS__'
python3 scripts/stage-column-test.py
__EOS__
timeout 1500 bash -e ci406out/146-python-119.sh > ci406out/146-python-119.sh.log 2>&1; summ 146-python-119 $? 'a stage the verifier never reached is not printed as FAIL'
cat > ci406out/147-python-120.sh <<'__EOS__'
python3 scripts/starhint-test.py
__EOS__
timeout 1500 bash -e ci406out/147-python-120.sh > ci406out/147-python-120.sh.log 2>&1; summ 147-python-120 $? 'the star hint stays quiet in CI, beside JSON and after its first showing'
cat > ci406out/148-python-121.sh <<'__EOS__'
python3 scripts/verifier-must-run-test.py
__EOS__
timeout 1500 bash -e ci406out/148-python-121.sh > ci406out/148-python-121.sh.log 2>&1; summ 148-python-121 $? 'a named verifier runs, or the harness says it did not'
cat > ci406out/149-python-122.sh <<'__EOS__'
python3 scripts/wheel-jcs-bytes-test.py
__EOS__
timeout 1500 bash -e ci406out/149-python-122.sh > ci406out/149-python-122.sh.log 2>&1; summ 149-python-122 $? 'the wheel ships the JCS byte cases at the path the package names'
cat > ci406out/150-python-123.sh <<'__EOS__'
python3 scripts/wheel-corpora-gate-test.py
rm -rf "$RUNNER_TEMP/corpora-dist"
uv build --out-dir "$RUNNER_TEMP/corpora-dist"
python3 scripts/wheel-corpora-gate.py "$RUNNER_TEMP/corpora-dist"/agent_evidence_vectors-*.whl "$RUNNER_TEMP/corpora-dist"/agent_evidence_vectors-*.tar.gz

__EOS__
timeout 1500 bash -e ci406out/150-python-123.sh > ci406out/150-python-123.sh.log 2>&1; summ 150-python-123 $? 'the wheel and the sdist carry every corpus the signed list names'
cat > ci406out/151-python-124.sh <<'__EOS__'
python3 scripts/report-provenance-test.py
__EOS__
timeout 1500 bash -e ci406out/151-python-124.sh > ci406out/151-python-124.sh.log 2>&1; summ 151-python-124 $? 'a report names the corpus release and digest it ran'
cat > ci406out/152-python-125.sh <<'__EOS__'
uv run python scripts/action-retention-test.py
__EOS__
timeout 1500 bash -e ci406out/152-python-125.sh > ci406out/152-python-125.sh.log 2>&1; summ 152-python-125 $? 'the actions report retention is an input'
cat > ci406out/153-python-126.sh <<'__EOS__'
uv run python scripts/action-build-pin-test.py
__EOS__
timeout 1500 bash -e ci406out/153-python-126.sh > ci406out/153-python-126.sh.log 2>&1; summ 153-python-126 $? 'the action builds on a pinned interpreter and a locked backend'
cat > ci406out/154-python-127.sh <<'__EOS__'
uv run --group crosscheck python scripts/action-reference-stage-test.py
__EOS__
timeout 1500 bash -e ci406out/154-python-127.sh > ci406out/154-python-127.sh.log 2>&1; summ 154-python-127 $? 'the actions reference stage counts, prints and cannot be switched off'
cat > ci406out/155-python-128.sh <<'__EOS__'
python3 scripts/verify-release-tag-test.py
__EOS__
timeout 1500 bash -e ci406out/155-python-128.sh > ci406out/155-python-128.sh.log 2>&1; summ 155-python-128 $? 'the release tag check refuses a tag the pinned key did not sign'
cat > ci406out/156-python-129.sh <<'__EOS__'
python3 scripts/oracle-every-corpus-test.py
__EOS__
timeout 1500 bash -e ci406out/156-python-129.sh > ci406out/156-python-129.sh.log 2>&1; summ 156-python-129 $? 'a perfect verifier passes every corpus that runs one'
cat > ci406out/157-python-130.sh <<'__EOS__'
python3 scripts/admission-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/157-python-130.sh > ci406out/157-python-130.sh.log 2>&1; summ 157-python-130 $? 'the two admission rails agree'
cat > ci406out/158-python-131.sh <<'__EOS__'
python3 scripts/approval-binding-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/158-python-131.sh > ci406out/158-python-131.sh.log 2>&1; summ 158-python-131 $? 'the approval-binding readers agree'
cat > ci406out/159-python-132.sh <<'__EOS__'
uv run --locked --extra generators python scripts/self-reported-record-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/159-python-132.sh > ci406out/159-python-132.sh.log 2>&1; summ 159-python-132 $? 'the two self-reported-record rails agree'
cat > ci406out/160-python-133.sh <<'__EOS__'
uv run --locked --extra generators python corpora/vectors-self-reported-record/check_vectors.py
uv run --locked --extra generators python corpora/vectors-self-reported-record/mutation_check.py

__EOS__
timeout 1500 bash -e ci406out/160-python-133.sh > ci406out/160-python-133.sh.log 2>&1; summ 160-python-133 $? 'the self-reported-record reference verifier and its mutation check pass'
cat > ci406out/161-python-134.sh <<'__EOS__'
uv run python scripts/predicate-uri-gate.py
uv run python scripts/predicate-uri-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/161-python-134.sh > ci406out/161-python-134.sh.log 2>&1; summ 161-python-134 $? 'every predicate URI the tree names has a page on the site'
echo SWEEPDONE
