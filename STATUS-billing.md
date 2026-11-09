# STATUS: billing-finality corpus (issue 485)

Branch `feat/billing-finality-corpus-1109`, worktree `~/Documents/wt-aev-billing-1109`.
This file is scratch and is removed from the branch before the PR is opened.

## Source pin
agent-evidence-lab `8db9989` (descendant of `7e3c6de`): X1 clarification (7e3c6de) plus
the v0.2-proposal decision that `dispatch_state` is a required output (8db9989). The
merged proposal doc already names 8db9989. Extracted copy:
`~/.claude_tmp/.../scratchpad/p04-8db9989/collaborations/open-evidence-lab/p04-execution-billing/`.
Ledger `upstream/exposure_ledger.py` is MIT, Mohammed Messaoudene, blob 3b9599c4.

## Design (decided)
- Corpus `corpora/vectors-execution-billing-finality`, suite `execution-billing-finality/v1`,
  contractId `.../predicate/v1/execution-billing-finality`, verifierContract
  `verifier record.json --json; exit 0 allow, 1 deny`, runtimeContract
  `runtime scenario.json --json; prints the record; see executionbilling_runtime`.
- Record (camelCase): contractId, scenario {budget,id,probes,steps}, initial, steps[],
  observed, reopened, probes[], end, endReopened, externalEffect, mustNotClaim.
  State keys: availableMicroUsd, billingFinality, dispatchState, executionOutcome, frozen,
  heldMicroUsd, knownSpendMicroUsd, unbounded. Action = {exception, return, state}.
- Checks in order: contract_id_missing, contract_id_unknown, record_malformed,
  dispatch_state_missing, claim_boundary_dropped, reopen_changed_state,
  execution_outcome_without_observation, held_released_before_final_billing,
  same_attempt_redispatched, dispatch_state_reserved_after_billing,
  invoice_replay_refinalized. Allow reason `finality_held`.
- Allow cases (from the unmutated vendored ledger via the reference adapter): F01, F03,
  F04, F05 (F01 control), F14 (first-dispatch positive control), X1 (3 probes:
  dispatch, replayed invoice-1, cost 1).
- Deny from mutants: F01+success_releases_exposure, F04+invoice_implies_execution,
  F03+M1, F04+M2, X1+M5, X1+M4 (dispatch_state). M3 equivalent: generator asserts its
  records equal baseline on every scenario; recorded in manifest `mutants`.
- Deny by edit: contract id missing/unknown, money as boolean, dispatchState missing and
  null, externalEffect established, a claim boundary dropped, reopen differs, invoice
  replay refinalized.
- Files: packaging/agent_evidence_vectors/executionbilling.py (+ _runtime.py),
  corpusreaders/executionbilling.go (+ _test.go), corpus gen_vectors.py,
  check_vectors.py, README.md, tests/billing_adapter.py, tests/p04/ (vendored ledger,
  LICENSE, SOURCE.json), tests/test_corpus.py.
- Registration: REGISTRY.toml then `scripts/corpus-registry.py`; run_vectors.py suite +
  runtime runner; ci.yml pytest step; independent-run.yml; DISTRIBUTION.md;
  docs/guides/corpora.md; docs/reference/corpus-readers.md; spec/predicates/REGISTRY.md;
  scripts/oracle-every-corpus-test.py, regenerability-gate.py, release-digests.py,
  test_site_navigation.py; then regenerate CORPUS-DIGESTS, intake records,
  reference-coverage on the box.

## State
No corpus code committed yet. The Python reader draft was refused by the turn budget
gate before it was written; rewrite it from the design above.

## Next
1. Write the files above; commit each testable step.
2. `~/.claude/scripts/box_run.sh quint-testrunner-3 -- uv run --extra dev pytest corpora/vectors-execution-billing-finality/tests -q`
3. Regenerate derived files, open PR (Closes #485), `~/.claude/bin/pr-green probityai/agent-evidence-vectors <N> --wait 240`, then `gh pr merge <N> -R probityai/agent-evidence-vectors --squash`.
