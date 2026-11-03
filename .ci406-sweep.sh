#!/usr/bin/env bash
set +e
export UV_PYTHON=3.13
export CI=true GITHUB_ACTIONS=true RUNNER_TEMP=/tmp/rt GITHUB_WORKSPACE=$PWD
mkdir -p /tmp/rt ci406out
rm -f ci406out/*
export PATH=$HOME/.cargo/bin:/usr/local/go/bin:$HOME/go/bin:$PATH
summ(){ echo "STEP $1 rc=$2 $3"; }
cat > ci406out/001-installed-wheel-3.sh <<'__EOS__'
rm -rf dist
uv build
go build -o "$RUNNER_TEMP/aee-verify-installed" ./cmd/aee-verify

__EOS__
timeout 1500 bash -e ci406out/001-installed-wheel-3.sh > ci406out/001-installed-wheel-3.sh.log 2>&1; summ 001-installed-wheel-3 $? 'build the wheel and the directory reader'
cat > ci406out/002-installed-wheel-4.sh <<'__EOS__'
scripts/installed-wheel-replay.sh "$(ls "$PWD"/dist/agent_evidence_vectors-*.whl)" "$RUNNER_TEMP/aee-verify-installed"
__EOS__
timeout 1500 bash -e ci406out/002-installed-wheel-4.sh > ci406out/002-installed-wheel-4.sh.log 2>&1; summ 002-installed-wheel-4 $? 'the wheel runs from outside the checkout and replays every corpus'
cat > ci406out/003-installed-wheel-5.sh <<'__EOS__'
uv run --locked --extra dev python scripts/corpus-registry.py --check
__EOS__
timeout 1500 bash -e ci406out/003-installed-wheel-5.sh > ci406out/003-installed-wheel-5.sh.log 2>&1; summ 003-installed-wheel-5 $? 'the corpus registry is valid and its derived files are current'
cat > ci406out/004-installed-wheel-6.sh <<'__EOS__'
python3 scripts/adopter-pins-test.py --wheel "$(ls "$PWD"/dist/agent_evidence_vectors-*.whl)"
__EOS__
timeout 1500 bash -e ci406out/004-installed-wheel-6.sh > ci406out/004-installed-wheel-6.sh.log 2>&1; summ 004-installed-wheel-6 $? 'every name and path an adopter pins still resolves, in the tree and the wheel'
cat > ci406out/005-go-2.sh <<'__EOS__'
unformatted=$(gofmt -l aee cmd corpusreaders observedeffect witnessattestor)
if [ -n "$unformatted" ]; then
  echo "gofmt needs to run on:"; echo "$unformatted"; exit 1
fi

__EOS__
timeout 1500 bash -e ci406out/005-go-2.sh > ci406out/005-go-2.sh.log 2>&1; summ 005-go-2 $? 'gofmt (no diffs)'
cat > ci406out/006-go-3.sh <<'__EOS__'
go build ./aee/... ./cmd/... ./corpusreaders/... ./observedeffect/...
(cd witnessattestor && go build ./...)

__EOS__
timeout 1500 bash -e ci406out/006-go-3.sh > ci406out/006-go-3.sh.log 2>&1; summ 006-go-3 $? 'build'
cat > ci406out/007-go-4.sh <<'__EOS__'
go vet ./aee/... ./cmd/... ./corpusreaders/... ./observedeffect/...
(cd witnessattestor && go vet ./...)

__EOS__
timeout 1500 bash -e ci406out/007-go-4.sh > ci406out/007-go-4.sh.log 2>&1; summ 007-go-4 $? 'vet'
cat > ci406out/008-go-5.sh <<'__EOS__'
go test ./aee/... ./cmd/... ./corpusreaders/... ./observedeffect/... -race -count=1 -timeout 30m
(cd witnessattestor && go test ./... -race -count=1 -timeout 30m)

__EOS__
timeout 1500 bash -e ci406out/008-go-5.sh > ci406out/008-go-5.sh.log 2>&1; summ 008-go-5 $? 'test (race)'
cat > ci406out/009-go-7.sh <<'__EOS__'
node corpora/jcs-byte-vectors/check.mjs
__EOS__
timeout 1500 bash -e ci406out/009-go-7.sh > ci406out/009-go-7.sh.log 2>&1; summ 009-go-7 $? 'check canonical JSON transcript bytes'
cat > ci406out/010-go-9.sh <<'__EOS__'
uv sync --locked --extra generators
__EOS__
timeout 1500 bash -e ci406out/010-go-9.sh > ci406out/010-go-9.sh.log 2>&1; summ 010-go-9 $? 'sync the Python readers generator dependencies'
cat > ci406out/011-go-10.sh <<'__EOS__'
uv run --locked --extra generators python scripts/external-rail-gate.py scripts/forcing-gate.py scripts/forcing-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/011-go-10.sh > ci406out/011-go-10.sh.log 2>&1; summ 011-go-10 $? 'the shipped CLI clears the published corpus as an external rail'
cat > ci406out/012-go-11.sh <<'__EOS__'
rustup toolchain install 1.90.0 --profile minimal --component clippy,rustfmt
echo "RUSTUP_TOOLCHAIN=1.90.0" >> "$GITHUB_ENV"

__EOS__
timeout 1500 bash -e ci406out/012-go-11.sh > ci406out/012-go-11.sh.log 2>&1; summ 012-go-11 $? 'install the Rust toolchain the third W3C reader builds with'
cat > ci406out/013-go-12.sh <<'__EOS__'
cargo fmt --manifest-path readers/w3c-report-rs/Cargo.toml --check
cargo clippy --locked --manifest-path readers/w3c-report-rs/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path readers/w3c-report-rs/Cargo.toml

__EOS__
timeout 1500 bash -e ci406out/013-go-12.sh > ci406out/013-go-12.sh.log 2>&1; summ 013-go-12 $? 'the Rust W3C reader is formatted, lint-clean and tested'
cat > ci406out/014-go-13.sh <<'__EOS__'
uv run --locked --extra generators python scripts/w3c-rails-parity-test.py
__EOS__
timeout 1500 bash -e ci406out/014-go-13.sh > ci406out/014-go-13.sh.log 2>&1; summ 014-go-13 $? 'the three W3C report readers print the same bytes'
cat > ci406out/015-go-14.sh <<'__EOS__'
cargo run --locked --release --manifest-path readers/w3c-report-rs/Cargo.toml -- \
  --report corpora/vectors-w3c-report/observed/aee-v0.12.0/report.json

__EOS__
timeout 1500 bash -e ci406out/015-go-14.sh > ci406out/015-go-14.sh.log 2>&1; summ 015-go-14 $? 'the Rust reader validates the published emitter run and re-writes it byte for byte'
cat > ci406out/016-go-15.sh <<'__EOS__'
uv run --locked --extra generators python scripts/receipt-signature-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/016-go-15.sh > ci406out/016-go-15.sh.log 2>&1; summ 016-go-15 $? 'the two receipt-signature readers print the same bytes'
cat > ci406out/017-go-16.sh <<'__EOS__'
uv run --locked --extra generators python scripts/delegation-lifecycle-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/017-go-16.sh > ci406out/017-go-16.sh.log 2>&1; summ 017-go-16 $? 'the two delegation-lifecycle readers derive the same outcomes'
cat > ci406out/018-go-17.sh <<'__EOS__'
uv run --locked --extra generators python scripts/w3c-intake-parity-test.py
__EOS__
timeout 1500 bash -e ci406out/018-go-17.sh > ci406out/018-go-17.sh.log 2>&1; summ 018-go-17 $? 'the two W3C intake readers print the same bytes'
cat > ci406out/019-go-18.sh <<'__EOS__'
uv run --locked --extra generators python scripts/regenerate-derived.py --check
__EOS__
timeout 1500 bash -e ci406out/019-go-18.sh > ci406out/019-go-18.sh.log 2>&1; summ 019-go-18 $? 'every derived file is what a fresh run writes (intake records, digest list, source lock)'
cat > ci406out/020-go-19.sh <<'__EOS__'
python3 scripts/regenerate-derived-test.py
__EOS__
timeout 1500 bash -e ci406out/020-go-19.sh > ci406out/020-go-19.sh.log 2>&1; summ 020-go-19 $? 'derived files are marked, checked together and resolved by regeneration'
cat > ci406out/021-go-20.sh <<'__EOS__'
uv run --locked --extra generators python scripts/a2a-jcs-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/021-go-20.sh > ci406out/021-go-20.sh.log 2>&1; summ 021-go-20 $? 'the two a2a-jcs readers agree and the conformance API catches a wrong canonicalizer'
cat > ci406out/022-go-21.sh <<'__EOS__'
uv run --locked --extra generators python scripts/predicate-state-gate.py
__EOS__
timeout 1500 bash -e ci406out/022-go-21.sh > ci406out/022-go-21.sh.log 2>&1; summ 022-go-21 $? 'both rails read the three empty predicate states identically'
cat > ci406out/023-go-22.sh <<'__EOS__'
set -euo pipefail
uv run --locked --extra generators python scripts/rail-parity-gate.py --check
uv run --locked --extra generators python scripts/rail-parity-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/023-go-22.sh > ci406out/023-go-22.sh.log 2>&1; summ 023-go-22 $? 'the two first-party rails agree, member by member'
cat > ci406out/024-go-23.sh <<'__EOS__'
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
binary="$RUNNER_TEMP/aee-verify"
go build -o "$binary" ./cmd/aee-verify
status=0
for dir in vectors*/ corpora/vectors*/; do
  [ -f "${dir}MANIFEST.json" ] || continue
  echo "== ${dir%/}"
  rc=0
  "$binary" "${dir%/}" || rc=$?
  case "$rc" in
    0) ;;
    # 2 is the reader saying it cannot judge this suite yet, and it says
    # so rather than reporting a corpus nothing read as clean. That is
    # only acceptable while the corpus is judged by its own checker, so
    # the absence of one is a failure here: it is the state where a
    # corpus is covered by nothing at all and every exit status still
    # looks fine.
    2)
      if [ -f "${dir}check_vectors.py" ]; then
        # "runs in the python job" was a sentence, not a check. A corpus
        # arrived with a checker, a mutation sweep and no step invoking
        # either, and this branch reported it as judged while nothing
        # judged it: the Go reader exits 2, the checker exists, and the
        # loop said so approvingly. The claim is now verified against
        # this file, so a corpus whose checker no step runs fails here.
        if grep -q "${dir}check_vectors.py" .github/workflows/ci.yml; then
          echo "   no Go reader yet; ${dir}check_vectors.py judges this corpus and a step in this workflow runs it"
        else
          echo "   ${dir}check_vectors.py exists and no step in this workflow runs it: judged by nothing" >&2
          status=1
        fi
      else
        echo "   no Go reader and no ${dir}check_vectors.py: this corpus is judged by nothing" >&2
        status=1
      fi
      ;;
    *) status=1 ;;
  esac
done
exit "$status"

__EOS__
timeout 1500 bash -e ci406out/024-go-23.sh > ci406out/024-go-23.sh.log 2>&1; summ 024-go-23 $? 'one harness judges every corpus'
cat > ci406out/025-go-24.sh <<'__EOS__'
uv run --locked --extra generators python scripts/uncited-obligations-proof.py
uv run --locked --extra generators python scripts/uncited-obligations-proof-test.py

__EOS__
timeout 1500 bash -e ci406out/025-go-24.sh > ci406out/025-go-24.sh.log 2>&1; summ 025-go-24 $? 'every newly cited obligation is paid for by a rail that gets it wrong'
cat > ci406out/026-go-25.sh <<'__EOS__'
go test ./aee/... ./cmd/... ./corpusreaders/... ./observedeffect/... -coverprofile=core.cov -count=1
(cd witnessattestor && go test ./... -coverprofile=../wa.cov -count=1)
# The aee-witness-demo command is a runnable library-mode example; its
# attest lifecycle is covered by the attestor tests, so it is excluded.
uv run --locked --extra generators python scripts/coverage-gate.py --threshold 80 \
  --exclude cmd/aee-witness-demo core.cov wa.cov

__EOS__
timeout 1500 bash -e ci406out/026-go-25.sh > ci406out/026-go-25.sh.log 2>&1; summ 026-go-25 $? 'coverage (per-file 80% minimum)'
cat > ci406out/027-go-26.sh <<'__EOS__'
go install honnef.co/go/tools/cmd/staticcheck@latest
"$(go env GOPATH)/bin/staticcheck" ./aee/... ./cmd/... ./corpusreaders/... ./observedeffect/...
(cd witnessattestor && "$(go env GOPATH)/bin/staticcheck" ./...)

__EOS__
timeout 1500 bash -e ci406out/027-go-26.sh > ci406out/027-go-26.sh.log 2>&1; summ 027-go-26 $? 'staticcheck'
cat > ci406out/028-go-27.sh <<'__EOS__'
# Pinned, unlike staticcheck@latest above: this tool's numeric output
# is committed in the table, so an upstream change to how complexity
# is counted would fail an unrelated PR. Bump deliberately, then run
# the gate with --sync.
go install github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0
uv run --locked --extra generators python scripts/complexity-table-gate.py --rail go \
  --gocyclo "$(go env GOPATH)/bin/gocyclo"

__EOS__
timeout 1500 bash -e ci406out/028-go-27.sh > ci406out/028-go-27.sh.log 2>&1; summ 028-go-27 $? 'accepted-complexity table matches the source'
cat > ci406out/029-python-2.sh <<'__EOS__'
uv sync --locked --extra dev --extra generators
__EOS__
timeout 1500 bash -e ci406out/029-python-2.sh > ci406out/029-python-2.sh.log 2>&1; summ 029-python-2 $? 'sync toolchain'
cat > ci406out/030-python-3.sh <<'__EOS__'
uv pip install --no-deps .
__EOS__
timeout 1500 bash -e ci406out/030-python-3.sh > ci406out/030-python-3.sh.log 2>&1; summ 030-python-3 $? 'Install checkout wheel for distribution imports'
cat > ci406out/031-python-4.sh <<'__EOS__'
uv run mypy packaging/run_vectors.py packaging/agent_evidence_vectors/w3creport.py packaging/agent_evidence_vectors/observedeffect.py packaging/agent_evidence_vectors/auditrecord.py packaging/agent_evidence_vectors/runmetrics.py packaging/agent_evidence_vectors/contextdiscovery.py corpora/vectors-w3c-report/gen_vectors.py corpora/vectors-w3c-report/origin/derive_pairs.py scripts/w3c-rails-parity-test.py scripts/w3c-reader-differential.py scripts/w3c-report-rules-test.py scripts/json-encoding-differential-test.py packaging/agent_evidence_vectors/receiptsignature.py packaging/agent_evidence_vectors/a2ajcs.py scripts/a2a-jcs-rails-test.py packaging/agent_evidence_vectors/changeadmission.py packaging/agent_evidence_vectors/agenticprocess.py scripts/receipt-signature-rails-test.py packaging/agent_evidence_vectors/delegationlifecycle.py scripts/delegation-lifecycle-rails-test.py corpora/vectors-delegation-lifecycle/mutate.py corpora/vectors-receipt-signature/digest.py corpora/vectors-receipt-signature/tools/veritasacta-verify.py scripts/gen-w3c-appendix.py vectors/reject/gen_invalid_vectors.py vectors/accept/gen_valid_vectors.py vectors/gen_manifest.py scripts/spec-drift-gate.py scripts/interpretation-registry-gate.py scripts/interpretation-registry-gate-test.py scripts/coverage-matrix-gate.py scripts/complexity-table-gate.py scripts/specpins.py scripts/spec-anchor-gate.py scripts/spec-anchor-gate-test.py scripts/code-contract-gate.py scripts/code-contract-gate-test.py scripts/consumer-lag-gate.py scripts/consumer-lag-gate-test.py scripts/independent-runs-gate.py scripts/suite-commit-gate.py scripts/suite-commit-gate-test.py scripts/condition-registry-gate.py scripts/condition-registry-gate-test.py scripts/condition-forcing-gate.py scripts/condition-forcing-gate-test.py scripts/condition-forcing-crosscheck.py scripts/condition-forcing-crosscheck-test.py scripts/external-rail-gate.py scripts/predicate-state-gate.py scripts/forcing-gate.py scripts/forcing-gate-test.py scripts/countcensus.py scripts/countcensus-sparse-test.py scripts/count-gate.py scripts/count-gate-test.py scripts/distribution-gate.py scripts/distribution-gate-test.py scripts/test_doc_gate_migration.py scripts/test_site_navigation.py docs/site/build.py scripts/regenerability-gate.py scripts/mutationdiff.py scripts/accept-anchor-gate.py scripts/accept-anchor-gate-test.py scripts/liveness-probe.py scripts/liveness-probe-test.py scripts/citation-metadata-gate.py scripts/citation-metadata-gate-test.py scripts/expectation-slack-gate.py scripts/expectation-slack-gate-test.py scripts/observed-code-closure-gate.py scripts/observed-code-closure-gate-test.py scripts/uncited-crosscheck-gate.py scripts/reading-differential.py scripts/reading-differential-test.py scripts/vendor-remap-test.py scripts/vector-distinctness-gate.py scripts/vector-distinctness-gate-test.py scripts/surface-leakage-gate.py scripts/surface-leakage-gate-test.py scripts/harness-output-contract-test.py scripts/stage-column-test.py scripts/starhint-test.py packaging/agent_evidence_vectors/starhint.py scripts/verifier-must-run-test.py scripts/report-provenance-test.py scripts/action-retention-test.py scripts/action-build-pin-test.py scripts/verify-release-tag.py scripts/verify-release-tag-test.py scripts/workflow-steps-gate.py scripts/workflow-steps-gate-test.py scripts/readme-lint.py scripts/readme-lint-test.py scripts/action-download-budget.py scripts/action-download-budget-test.py scripts/runner-labels-gate.py scripts/runner-labels-gate-test.py scripts/_go_selector.py scripts/go-selector-test.py scripts/_lockfile.py scripts/_lockfile-test.py scripts/manifest-revision-test.py scripts/statement-layer-test.py scripts/independent-runs-gate-test.py scripts/indeterminate-readers-test.py scripts/write-chain-replay-test.py scripts/audit-record-dating-rows-test.py scripts/indeterminate-scoring-gate.py scripts/indeterminate-scoring-gate-test.py interop/action-tuple-framed-v1/reader.py packaging/agent_evidence_vectors/heldout.py scripts/heldout-runner-test.py scripts/predicate-uri-gate.py scripts/predicate-uri-gate-test.py scripts/oracle-verifier.py scripts/oracle-every-corpus-test.py packaging/agent_evidence_vectors/admission.py scripts/admission-rails-test.py packaging/agent_evidence_vectors/w3cintake.py scripts/w3c-intake-parity-test.py scripts/gen-intake-records.py scripts/badge-grants-gate.py scripts/badge-grants-gate-test.py packaging/agent_evidence_vectors/selfreportedrecord.py scripts/self-reported-record-rails-test.py packaging/agent_evidence_vectors/approvalbinding.py scripts/approval-binding-rails-test.py
__EOS__
timeout 1500 bash -e ci406out/031-python-4.sh > ci406out/031-python-4.sh.log 2>&1; summ 031-python-4 $? 'mypy --strict'
cat > ci406out/032-python-5.sh <<'__EOS__'
uv run mypy interop/gemara-method-link
__EOS__
timeout 1500 bash -e ci406out/032-python-5.sh > ci406out/032-python-5.sh.log 2>&1; summ 032-python-5 $? 'strict Gemara reader and test types'
cat > ci406out/033-python-6.sh <<'__EOS__'
uv run mypy corpora/vectors-w3c-intake/gen_vectors.py corpora/vectors-w3c-intake/tests/test_corpus.py
__EOS__
timeout 1500 bash -e ci406out/033-python-6.sh > ci406out/033-python-6.sh.log 2>&1; summ 033-python-6 $? 'strict W3C intake generator and test types'
cat > ci406out/034-python-7.sh <<'__EOS__'
uv run python scripts/typecheck-gate.py
__EOS__
timeout 1500 bash -e ci406out/034-python-7.sh > ci406out/034-python-7.sh.log 2>&1; summ 034-python-7 $? 'type-check every python file'
cat > ci406out/035-python-8.sh <<'__EOS__'
uv run ruff check packaging vectors corpora/vectors-* scripts interop/*/
__EOS__
timeout 1500 bash -e ci406out/035-python-8.sh > ci406out/035-python-8.sh.log 2>&1; summ 035-python-8 $? 'ruff'
cat > ci406out/036-python-9.sh <<'__EOS__'
python3 scripts/retain-timestamp-candidate-test.py
__EOS__
timeout 1500 bash -e ci406out/036-python-9.sh > ci406out/036-python-9.sh.log 2>&1; summ 036-python-9 $? 'timestamp candidate custody and refusal controls'
cat > ci406out/037-python-10.sh <<'__EOS__'
uv run python -m pytest -q interop/aps-priorseal-e2-2026-09-30/test_reproduction.py
__EOS__
timeout 1500 bash -e ci406out/037-python-10.sh > ci406out/037-python-10.sh.log 2>&1; summ 037-python-10 $? 'E2 compatibility tests in the shared development environment'
cat > ci406out/038-python-11.sh <<'__EOS__'
PYTHONPATH=packaging uv run python interop/ws4-prior-witness-candidate/gen_fixture.py --check
PYTHONPATH=packaging uv run python -m unittest discover -s interop/ws4-prior-witness-candidate -p 'test_profile.py'

__EOS__
timeout 1500 bash -e ci406out/038-python-11.sh > ci406out/038-python-11.sh.log 2>&1; summ 038-python-11 $? 'WS4 prior witness candidate cases'
cat > ci406out/039-python-12.sh <<'__EOS__'
PYTHONPATH=packaging uv run python interop/agentavow-live-mcp/build_cases.py --check
PYTHONPATH=packaging uv run python interop/agentavow-live-mcp/run.py
PYTHONPATH=packaging uv run python -m unittest discover -s interop/agentavow-live-mcp -p 'test_definition_pin.py'

__EOS__
timeout 1500 bash -e ci406out/039-python-12.sh > ci406out/039-python-12.sh.log 2>&1; summ 039-python-12 $? 'Live MCP named-tool definition cases'
cat > ci406out/040-python-13.sh <<'__EOS__'
cd interop/aps-priorseal-e2-2026-09-30
sh fetch_inputs.sh
uv run python check_reproduction.py

__EOS__
timeout 1500 bash -e ci406out/040-python-13.sh > ci406out/040-python-13.sh.log 2>&1; summ 040-python-13 $? 'E2 reports reproduce in the shared development environment'
cat > ci406out/041-python-14.sh <<'__EOS__'
uv run python scripts/complexity-table-gate.py --rail python
__EOS__
timeout 1500 bash -e ci406out/041-python-14.sh > ci406out/041-python-14.sh.log 2>&1; summ 041-python-14 $? 'accepted-complexity rationales match the source'
cat > ci406out/042-python-15.sh <<'__EOS__'
python3 scripts/spec-drift-gate.py
__EOS__
timeout 1500 bash -e ci406out/042-python-15.sh > ci406out/042-python-15.sh.log 2>&1; summ 042-python-15 $? 'spec/corpus non-drift gate'
cat > ci406out/043-python-16.sh <<'__EOS__'
python3 vectors/accept/gen_valid_vectors.py
python3 vectors/reject/gen_invalid_vectors.py

__EOS__
timeout 1500 bash -e ci406out/043-python-16.sh > ci406out/043-python-16.sh.log 2>&1; summ 043-python-16 $? 'the generator identifier maps the anchor gate resolves rows through'
cat > ci406out/044-python-17.sh <<'__EOS__'
python3 scripts/vendor-remap-test.py --synthetic
__EOS__
timeout 1500 bash -e ci406out/044-python-17.sh > ci406out/044-python-17.sh.log 2>&1; summ 044-python-17 $? 'the vendor remap keeps every anchor on its own prose'
cat > ci406out/045-python-18.sh <<'__EOS__'
python3 scripts/spec-anchor-gate.py
python3 scripts/spec-anchor-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/045-python-18.sh > ci406out/045-python-18.sh.log 2>&1; summ 045-python-18 $? 'spec anchor gate'
cat > ci406out/046-python-19.sh <<'__EOS__'
python3 scripts/uncited-crosscheck-gate.py
__EOS__
timeout 1500 bash -e ci406out/046-python-19.sh > ci406out/046-python-19.sh.log 2>&1; summ 046-python-19 $? 'the uncited-obligation ledger and the document about it agree'
cat > ci406out/047-python-20.sh <<'__EOS__'
python3 scripts/interpretation-registry-gate.py
python3 scripts/interpretation-registry-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/047-python-20.sh > ci406out/047-python-20.sh.log 2>&1; summ 047-python-20 $? 'interpretation-decision registry gate'
cat > ci406out/048-python-21.sh <<'__EOS__'
python3 scripts/condition-registry-gate.py
python3 scripts/condition-registry-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/048-python-21.sh > ci406out/048-python-21.sh.log 2>&1; summ 048-python-21 $? 'condition-registry gate'
cat > ci406out/049-python-22.sh <<'__EOS__'
python3 scripts/code-contract-gate.py
python3 scripts/code-contract-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/049-python-22.sh > ci406out/049-python-22.sh.log 2>&1; summ 049-python-22 $? 'failure-code contract gate'
cat > ci406out/050-python-23.sh <<'__EOS__'
python3 scripts/expectation-slack-gate.py
python3 scripts/expectation-slack-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/050-python-23.sh > ci406out/050-python-23.sh.log 2>&1; summ 050-python-23 $? 'no reject expectation is satisfied by more than one emitted code'
cat > ci406out/051-python-24.sh <<'__EOS__'
python3 scripts/observed-code-closure-gate.py
python3 scripts/observed-code-closure-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/051-python-24.sh > ci406out/051-python-24.sh.log 2>&1; summ 051-python-24 $? 'the reference rail emits no code the corpus declares nowhere'
cat > ci406out/052-python-25.sh <<'__EOS__'
python3 scripts/accept-anchor-gate.py
python3 scripts/accept-anchor-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/052-python-25.sh > ci406out/052-python-25.sh.log 2>&1; summ 052-python-25 $? 'every refusal ships beside a vector that must be accepted'
cat > ci406out/053-python-26.sh <<'__EOS__'
uv run python scripts/liveness-probe.py --require-demonstrated \
  --key 496cbe15e391eccd3a0864f2709df0eeb4f5b6c1bad750c95cc80ee49bceae62 \
  vectors/statements/vda285efc96ac6e75.json
uv run python scripts/liveness-probe-test.py

__EOS__
timeout 1500 bash -e ci406out/053-python-26.sh > ci406out/053-python-26.sh.log 2>&1; summ 053-python-26 $? 'per-channel detector liveness, and each arm of it switched off'
cat > ci406out/054-python-27.sh <<'__EOS__'
python3 scripts/coverage-matrix-gate.py --check
__EOS__
timeout 1500 bash -e ci406out/054-python-27.sh > ci406out/054-python-27.sh.log 2>&1; summ 054-python-27 $? 'requirement-coverage matrix is current'
cat > ci406out/055-python-28.sh <<'__EOS__'
python3 scripts/condition-forcing-gate.py --check
python3 scripts/condition-forcing-gate-test.py --without-history
python3 scripts/condition-forcing-crosscheck.py
python3 scripts/condition-forcing-crosscheck-test.py --without-history

__EOS__
timeout 1500 bash -e ci406out/055-python-28.sh > ci406out/055-python-28.sh.log 2>&1; summ 055-python-28 $? 'the published weak-spot figure follows from the forcing baseline'
cat > ci406out/056-python-29.sh <<'__EOS__'
python3 scripts/independent-runs-gate.py
python3 scripts/independent-runs-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/056-python-29.sh > ci406out/056-python-29.sh.log 2>&1; summ 056-python-29 $? 'the independence column is the run ledger'
cat > ci406out/057-python-30.sh <<'__EOS__'
python3 scripts/suite-commit-gate.py
python3 scripts/suite-commit-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/057-python-30.sh > ci406out/057-python-30.sh.log 2>&1; summ 057-python-30 $? 'every commit an outside record cites is reachable in a clone'
cat > ci406out/058-python-31.sh <<'__EOS__'
uv run --extra dev python scripts/citation-metadata-gate.py
__EOS__
timeout 1500 bash -e ci406out/058-python-31.sh > ci406out/058-python-31.sh.log 2>&1; summ 058-python-31 $? 'the citation metadata parses and agrees with itself'
cat > ci406out/059-python-32.sh <<'__EOS__'
uv run --extra dev python scripts/citation-metadata-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/059-python-32.sh > ci406out/059-python-32.sh.log 2>&1; summ 059-python-32 $? 'the citation gate refuses a wrong figure'
cat > ci406out/060-python-33.sh <<'__EOS__'
python3 scripts/archived-repo-gate.py
__EOS__
timeout 1500 bash -e ci406out/060-python-33.sh > ci406out/060-python-33.sh.log 2>&1; summ 060-python-33 $? 'no live reference to the archived agent-evidence repository'
cat > ci406out/061-python-34.sh <<'__EOS__'
python3 scripts/archived-repo-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/061-python-34.sh > ci406out/061-python-34.sh.log 2>&1; summ 061-python-34 $? 'the archived-repository gate refuses a live reference'
cat > ci406out/062-python-35.sh <<'__EOS__'
python3 scripts/vector-distinctness-gate.py
python3 scripts/vector-distinctness-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/062-python-35.sh > ci406out/062-python-35.sh.log 2>&1; summ 062-python-35 $? 'no two vector identifiers address one statement'
cat > ci406out/063-python-36.sh <<'__EOS__'
uv run python scripts/surface-leakage-gate.py
uv run python scripts/surface-leakage-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/063-python-36.sh > ci406out/063-python-36.sh.log 2>&1; summ 063-python-36 $? 'the corpus is not scoreable from its surface'
cat > ci406out/064-python-37.sh <<'__EOS__'
python3 scripts/consumer-lag-gate.py --check
__EOS__
timeout 1500 bash -e ci406out/064-python-37.sh > ci406out/064-python-37.sh.log 2>&1; summ 064-python-37 $? 'consumers carry the corpus the latest release publishes, and the report says so'
cat > ci406out/065-python-38.sh <<'__EOS__'
python3 scripts/regen.py --audit
python3 scripts/regen-test.py

__EOS__
timeout 1500 bash -e ci406out/065-python-38.sh > ci406out/065-python-38.sh.log 2>&1; summ 065-python-38 $? 'every comparing gate declares how to repair it'
cat > ci406out/066-python-39.sh <<'__EOS__'
python3 scripts/consumer-lag-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/066-python-39.sh > ci406out/066-python-39.sh.log 2>&1; summ 066-python-39 $? 'the lag gate refuses a real lag and only a real lag'
cat > ci406out/067-python-40.sh <<'__EOS__'
python3 scripts/_lockfile-test.py
__EOS__
timeout 1500 bash -e ci406out/067-python-40.sh > ci406out/067-python-40.sh.log 2>&1; summ 067-python-40 $? 'the gate lock refuses only what it confirmed, and frees itself'
cat > ci406out/068-python-41.sh <<'__EOS__'
python3 scripts/scitt-digest-isolation-test.py
__EOS__
timeout 1500 bash -e ci406out/068-python-41.sh > ci406out/068-python-41.sh.log 2>&1; summ 068-python-41 $? 'the digest check runs with no third-party package'
cat > ci406out/069-python-42.sh <<'__EOS__'
python3 scripts/count-gate.py
python3 scripts/count-gate-test.py
python3 scripts/countcensus-sparse-test.py

__EOS__
timeout 1500 bash -e ci406out/069-python-42.sh > ci406out/069-python-42.sh.log 2>&1; summ 069-python-42 $? 'every published count is derived, and no new one is hand-written'
cat > ci406out/070-python-43.sh <<'__EOS__'
python3 scripts/manifest-counts-gate.py
python3 scripts/manifest-counts-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/070-python-43.sh > ci406out/070-python-43.sh.log 2>&1; summ 070-python-43 $? 'every corpus manifest carries counts that match its entries'
cat > ci406out/071-python-44.sh <<'__EOS__'
python3 scripts/distribution-gate.py
python3 scripts/distribution-gate-test.py
uv run --extra dev python -m pytest -q scripts/test_doc_gate_migration.py

__EOS__
timeout 1500 bash -e ci406out/071-python-44.sh > ci406out/071-python-44.sh.log 2>&1; summ 071-python-44 $? 'check distribution metadata and release recipe'
cat > ci406out/072-python-45.sh <<'__EOS__'
python3 scripts/badge-grants-gate.py
python3 scripts/badge-grants-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/072-python-45.sh > ci406out/072-python-45.sh.log 2>&1; summ 072-python-45 $? 'every Verified by Probity grant still meets the evidence rule'
cat > ci406out/073-python-46.sh <<'__EOS__'
.venv/bin/python -B scripts/workflow-steps-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/073-python-46.sh > ci406out/073-python-46.sh.log 2>&1; summ 073-python-46 $? 'the local pre-push mirror agrees with this workflows shell'
cat > ci406out/074-python-47.sh <<'__EOS__'
.venv/bin/python -B scripts/runner-labels-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/074-python-47.sh > ci406out/074-python-47.sh.log 2>&1; summ 074-python-47 $? 'an unreadable account is inconclusive, not a refused runner label'
cat > ci406out/075-python-48.sh <<'__EOS__'
.venv/bin/python -B scripts/workflow-concurrency-gate.py
.venv/bin/python -B scripts/workflow-concurrency-gate-test.py

__EOS__
timeout 1500 bash -e ci406out/075-python-48.sh > ci406out/075-python-48.sh.log 2>&1; summ 075-python-48 $? 'every workflow cancels superseded runs and every required check can report'
cat > ci406out/076-python-49.sh <<'__EOS__'
.venv/bin/python -B scripts/release-procedure-test.py
__EOS__
timeout 1500 bash -e ci406out/076-python-49.sh > ci406out/076-python-49.sh.log 2>&1; summ 076-python-49 $? 'the release procedure runs only the leak tier locally'
cat > ci406out/077-python-50.sh <<'__EOS__'
.venv/bin/python -B scripts/publish-gate-test.py
.venv/bin/python -B scripts/publish-gate-selftest.py

__EOS__
timeout 1500 bash -e ci406out/077-python-50.sh > ci406out/077-python-50.sh.log 2>&1; summ 077-python-50 $? 'every publish job sits behind the approved release'
cat > ci406out/078-python-51.sh <<'__EOS__'
.venv/bin/python -B scripts/readme-lint.py README.md
.venv/bin/python -B scripts/readme-lint-test.py

__EOS__
timeout 1500 bash -e ci406out/078-python-51.sh > ci406out/078-python-51.sh.log 2>&1; summ 078-python-51 $? 'the README stays one screen and every link in it resolves'
cat > ci406out/079-python-52.sh <<'__EOS__'
python3 scripts/action-download-budget.py
python3 scripts/action-download-budget-test.py

__EOS__
timeout 1500 bash -e ci406out/079-python-52.sh > ci406out/079-python-52.sh.log 2>&1; summ 079-python-52 $? 'the archive every Action job downloads stays under its budget'
cat > ci406out/080-python-53.sh <<'__EOS__'
python3 scripts/sync-install-pins.py --check
python3 scripts/sync-install-pins-test.py

__EOS__
timeout 1500 bash -e ci406out/080-python-53.sh > ci406out/080-python-53.sh.log 2>&1; summ 080-python-53 $? 'the install pins on the inbound pages match the published release'
cat > ci406out/081-python-54.sh <<'__EOS__'
python3 scripts/probity-bridge-test.py
__EOS__
timeout 1500 bash -e ci406out/081-python-54.sh > ci406out/081-python-54.sh.log 2>&1; summ 081-python-54 $? 'the Action summary and every spec README carry the Probity bridge line'
cat > ci406out/082-python-55.sh <<'__EOS__'
.venv/bin/python -B scripts/pre-push-pool-test.py
__EOS__
timeout 1500 bash -e ci406out/082-python-55.sh > ci406out/082-python-55.sh.log 2>&1; summ 082-python-55 $? 'the pool venue retains source-bound native results and refuses incomplete runs'
cat > ci406out/083-python-56.sh <<'__EOS__'
bash scripts/prepush-commit-msg-test.sh
__EOS__
timeout 1500 bash -e ci406out/083-python-56.sh > ci406out/083-python-56.sh.log 2>&1; summ 083-python-56 $? 'the pre-push hook refuses a pushed commit message the commit-msg hook never saw'
cat > ci406out/084-python-57.sh <<'__EOS__'
bash scripts/prepush-own-scanner-test.sh --mutate
__EOS__
timeout 1500 bash -e ci406out/084-python-57.sh > ci406out/084-python-57.sh.log 2>&1; summ 084-python-57 $? 'the pre-push hook runs the pushed commits own identity scanner and rules'
cat > ci406out/085-python-58.sh <<'__EOS__'
.venv/bin/python -B scripts/native-provider-test.py
__EOS__
timeout 1500 bash -e ci406out/085-python-58.sh > ci406out/085-python-58.sh.log 2>&1; summ 085-python-58 $? 'required native providers bind real tools and refuse unsafe archives'
cat > ci406out/086-python-59.sh <<'__EOS__'
.venv/bin/python -B scripts/go-selector-test.py
__EOS__
timeout 1500 bash -e ci406out/086-python-59.sh > ci406out/086-python-59.sh.log 2>&1; summ 086-python-59 $? 'setup-go selects the declared workspace file before dependent commands'
cat > ci406out/087-python-60.sh <<'__EOS__'
uv run python scripts/regenerability-gate.py
__EOS__
timeout 1500 bash -e ci406out/087-python-60.sh > ci406out/087-python-60.sh.log 2>&1; summ 087-python-60 $? 'every generated file regenerates byte-identically'
cat > ci406out/088-python-61.sh <<'__EOS__'
uv run python scripts/regenerability-gate-test.py
__EOS__
timeout 1500 bash -e ci406out/088-python-61.sh > ci406out/088-python-61.sh.log 2>&1; summ 088-python-61 $? 'the regenerability gate counts only tracked files as committed'
cat > ci406out/089-python-62.sh <<'__EOS__'
python3 scripts/w3c-report-rules-test.py
__EOS__
timeout 1500 bash -e ci406out/089-python-62.sh > ci406out/089-python-62.sh.log 2>&1; summ 089-python-62 $? 'the v0.1 report readers tree-shape rules'
cat > ci406out/090-python-63.sh <<'__EOS__'
python3 scripts/json-encoding-differential-test.py
__EOS__
timeout 1500 bash -e ci406out/090-python-63.sh > ci406out/090-python-63.sh.log 2>&1; summ 090-python-63 $? 'the shared JSON encoding table holds against the Python encoders'
cat > ci406out/091-python-64.sh <<'__EOS__'
python3 scripts/manifest-revision-test.py
__EOS__
timeout 1500 bash -e ci406out/091-python-64.sh > ci406out/091-python-64.sh.log 2>&1; summ 091-python-64 $? 'the manifests suite revision is the changelogs'
cat > ci406out/092-python-65.sh <<'__EOS__'
python3 scripts/statement-layer-test.py
__EOS__
timeout 1500 bash -e ci406out/092-python-65.sh > ci406out/092-python-65.sh.log 2>&1; summ 092-python-65 $? 'the recorded Statement-layer verdicts are the executed ones'
cat > ci406out/093-python-66.sh <<'__EOS__'
uv run --extra dev python -m pytest tools/artifact-binding/tests -q
__EOS__
timeout 1500 bash -e ci406out/093-python-66.sh > ci406out/093-python-66.sh.log 2>&1; summ 093-python-66 $? 'the artifact-binding tool holds its properties'
cat > ci406out/094-python-67.sh <<'__EOS__'
uv run --extra artifact-binding ./demo/four-arms.sh
__EOS__
timeout 1500 bash -e ci406out/094-python-67.sh > ci406out/094-python-67.sh.log 2>&1; summ 094-python-67 $? 'the four-arm demonstration reaches the contract outcomes'
cat > ci406out/095-python-68.sh <<'__EOS__'
uv run python corpora/vectors-scitt-cose/check_vectors.py
__EOS__
timeout 1500 bash -e ci406out/095-python-68.sh > ci406out/095-python-68.sh.log 2>&1; summ 095-python-68 $? 'the SCITT/COSE corpus behaves as its manifest claims'
cat > ci406out/096-python-69.sh <<'__EOS__'
uv run --extra artifact-binding python corpora/vectors-artifact-binding/check_vectors.py
__EOS__
timeout 1500 bash -e ci406out/096-python-69.sh > ci406out/096-python-69.sh.log 2>&1; summ 096-python-69 $? 'the artifact-binding corpus carries exactly the faults it names'
cat > ci406out/097-python-70.sh <<'__EOS__'
uv run --extra artifact-binding python corpora/vectors-artifact-binding/check_vectors.py vectors-dependency-selection
__EOS__
timeout 1500 bash -e ci406out/097-python-70.sh > ci406out/097-python-70.sh.log 2>&1; summ 097-python-70 $? 'the dependency-selection corpus carries exactly the faults it names'
cat > ci406out/098-python-71.sh <<'__EOS__'
uv run --extra generators python corpora/vectors-observed-effect/check_vectors.py
__EOS__
timeout 1500 bash -e ci406out/098-python-71.sh > ci406out/098-python-71.sh.log 2>&1; summ 098-python-71 $? 'the observed-effect corpus behaves as its manifest claims'
cat > ci406out/099-python-72.sh <<'__EOS__'
uv run --extra generators python examples/mcp-receipts/check_examples.py
__EOS__
timeout 1500 bash -e ci406out/099-python-72.sh > ci406out/099-python-72.sh.log 2>&1; summ 099-python-72 $? 'the MCP receipt examples verify and link'
cat > ci406out/100-python-73.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-source-coverage/tests -q
__EOS__
timeout 1500 bash -e ci406out/100-python-73.sh > ci406out/100-python-73.sh.log 2>&1; summ 100-python-73 $? 'source-coverage fixtures regenerate and refuse invalid replays'
cat > ci406out/101-python-74.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-open-weight-art53/tests -q
__EOS__
timeout 1500 bash -e ci406out/101-python-74.sh > ci406out/101-python-74.sh.log 2>&1; summ 101-python-74 $? 'open-weight cases regenerate and force every condition'
cat > ci406out/102-python-75.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-anchored-chain/tests -q
__EOS__
timeout 1500 bash -e ci406out/102-python-75.sh > ci406out/102-python-75.sh.log 2>&1; summ 102-python-75 $? 'anchored-chain cases regenerate and force every check'
cat > ci406out/103-python-76.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-receipt-chain-end/tests -q
__EOS__
timeout 1500 bash -e ci406out/103-python-76.sh > ci406out/103-python-76.sh.log 2>&1; summ 103-python-76 $? 'receipt-chain-end cases regenerate and force every check'
cat > ci406out/104-python-77.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-identity-binding/tests -q
__EOS__
timeout 1500 bash -e ci406out/104-python-77.sh > ci406out/104-python-77.sh.log 2>&1; summ 104-python-77 $? 'identity-binding cases regenerate and force every check'
cat > ci406out/105-python-78.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-authority-at-dispatch/tests -q
__EOS__
timeout 1500 bash -e ci406out/105-python-78.sh > ci406out/105-python-78.sh.log 2>&1; summ 105-python-78 $? 'authority-at-dispatch cases regenerate and force every check'
cat > ci406out/106-python-79.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-approval-binding/tests -q
__EOS__
timeout 1500 bash -e ci406out/106-python-79.sh > ci406out/106-python-79.sh.log 2>&1; summ 106-python-79 $? 'approval-binding cases regenerate and force every check'
cat > ci406out/107-python-80.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-dispatch-fence/tests -q
__EOS__
timeout 1500 bash -e ci406out/107-python-80.sh > ci406out/107-python-80.sh.log 2>&1; summ 107-python-80 $? 'dispatch-fence cases regenerate and force every check'
cat > ci406out/108-python-81.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-refund-connected/tests -q
__EOS__
timeout 1500 bash -e ci406out/108-python-81.sh > ci406out/108-python-81.sh.log 2>&1; summ 108-python-81 $? 'refund-connected runs are judged from their bytes and each mutation turns the reader red'
cat > ci406out/109-python-82.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-aggregate-accounting/tests -q
__EOS__
timeout 1500 bash -e ci406out/109-python-82.sh > ci406out/109-python-82.sh.log 2>&1; summ 109-python-82 $? 'aggregate-accounting cases regenerate and force every check'
cat > ci406out/110-python-83.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-uncertain-effect/tests -q
__EOS__
timeout 1500 bash -e ci406out/110-python-83.sh > ci406out/110-python-83.sh.log 2>&1; summ 110-python-83 $? 'uncertain-effect cases regenerate, force every check and fail a blind retry'
cat > ci406out/111-python-84.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-agent-card-receipt/tests -q
__EOS__
timeout 1500 bash -e ci406out/111-python-84.sh > ci406out/111-python-84.sh.log 2>&1; summ 111-python-84 $? 'agent-card-receipt cases regenerate and force every check'
cat > ci406out/112-python-85.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-credential-release/tests -q
__EOS__
timeout 1500 bash -e ci406out/112-python-85.sh > ci406out/112-python-85.sh.log 2>&1; summ 112-python-85 $? 'credential-release cases regenerate and force every check'
cat > ci406out/113-python-86.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-converted-argument-binding/tests -q
__EOS__
timeout 1500 bash -e ci406out/113-python-86.sh > ci406out/113-python-86.sh.log 2>&1; summ 113-python-86 $? 'converted-argument-binding cases regenerate and force every check'
cat > ci406out/114-python-87.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-delegator-right/tests -q
__EOS__
timeout 1500 bash -e ci406out/114-python-87.sh > ci406out/114-python-87.sh.log 2>&1; summ 114-python-87 $? 'delegator-right cases regenerate and force every check'
cat > ci406out/115-python-88.sh <<'__EOS__'
uv run --extra dev pytest corpora/vectors-badge-vc-verify/tests -q
__EOS__
timeout 1500 bash -e ci406out/115-python-88.sh > ci406out/115-python-88.sh.log 2>&1; summ 115-python-88 $? 'badge-vc-verify cases regenerate and force every check'
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
