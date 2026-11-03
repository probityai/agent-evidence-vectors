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
echo SWEEPDONE
