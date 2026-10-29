#!/usr/bin/env python3
"""Write ``fixtures/cases.json`` and ``fixtures/MANIFEST.json`` from this file.

Every digest in the corpus is computed here, so a case cannot be written by
hand with a ref that does not recompute. Run from the example directory::

    python3 scripts/generate_cases.py

The preimages are the only inputs a human edits. ``ref`` values are always
derived: ``sha256(JCS(preimage))`` with ``JCS`` as RFC 8785 canonical JSON.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "request-effect-fixture-v1"
#: SHA-256(JCS(profile_doc)) for jcs-rfc8785-v1, published by the selected
#: execution-join contract. The alias resolves to this value.
PROFILE = "f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d"
PROFILE_UNKNOWN = "jcs-rfc8785-v2-draft"

INPUT_A = "sha256:" + "7f353fcc5bd01b84b3d7fb209f62246e2c05e2f913afdc68584a1e6c47776b91"
INPUT_B = "sha256:" + "cdbe1b66420f474d1f621cc108444d2d6b9806f7ceb0961c8514b521c89fa9b3"
T0 = 1791557046000
T1 = 1791557046500
T2 = 1791557047000

MISSING = object()


def jcs(value: object) -> bytes:
    """RFC 8785 canonical JSON for the value shapes this fixture uses."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def ref(preimage: dict) -> str:
    """Return ``sha256:<hex>`` over the canonical preimage bytes."""
    return "sha256:" + hashlib.sha256(jcs(preimage)).hexdigest()


def action(scope: str, input_hash: str, ts_ms: int) -> dict:
    """Return an action object with its derived ref."""
    preimage = {
        "actor_id": "svc-payments",
        "input_hash": input_hash,
        "scope": scope,
        "ts_ms": ts_ms,
        "version": VERSION,
    }
    return {"ref": ref(preimage), "preimage": preimage}


def decision(action_ref: str, outcome: str, ts_ms: int, profile: str = PROFILE) -> dict:
    """Return a decision object covering ``action_ref``, with its derived ref."""
    preimage = {
        "action_ref": action_ref,
        "canonicalization_profile_id": profile,
        "outcome": outcome,
        "policy_id": "fixture-policy-A",
        "ts_ms": ts_ms,
        "version": VERSION,
    }
    return {"ref": ref(preimage), "preimage": preimage}


def attempt(action_ref: str, ts_ms: int) -> dict:
    """Return an attempt object for ``action_ref``, with its derived ref."""
    preimage = {
        "action_ref": action_ref,
        "attempt_seq": 1,
        "executor_id": "fixture-dispatcher",
        "ts_ms": ts_ms,
        "version": VERSION,
    }
    return {"ref": ref(preimage), "preimage": preimage}


def result(attempt_ref: str, output_hash: str, ts_ms: int, outcome: str = "completed") -> dict:
    """Return a terminal result for ``attempt_ref``, with its derived ref."""
    preimage = {
        "attempt_id": attempt_ref,
        "outcome": outcome,
        "output_hash": output_hash,
        "ts_ms": ts_ms,
        "version": VERSION,
    }
    return {"ref": ref(preimage), "preimage": preimage}


def observation(scope: str, content_sha256: str, observed_at_ms: int | None = None) -> dict:
    """Return a later file read. It carries no ref of its own."""
    return {
        "target_scope": scope,
        "content_sha256": content_sha256,
        "observed_at_ms": observed_at_ms,
        "observer_id": "fixture-observer",
    }


def base(case_id: str, source: dict) -> dict:
    """Return the case shape every entry shares: one approved call, one permit."""
    approved = action("transfer_funds:/work/acct-2.txt", INPUT_A, T0)
    return {
        "case_id": case_id,
        "contract": "request-effect-join-fixture/v1",
        "source": source,
        "approved": approved,
        "effective": json.loads(json.dumps(approved)),
        "decision": decision(approved["ref"], "permit", T0),
        "covering_decision": None,
        "attempt": None,
        "result": None,
        "later_observation": None,
    }


def joined(case: dict) -> dict:
    """Attach the attempt and result that complete the join in ``case``."""
    case["attempt"] = attempt(case["effective"]["ref"], T1)
    case["result"] = result(case["attempt"]["ref"], INPUT_A, T2)
    return case


def rewritten(case: dict) -> dict:
    """Dispatch a changed call instead of the approved one."""
    case["effective"] = action("transfer_funds:/work/acct-3.txt", INPUT_B, T1)
    return case


def cases() -> list[dict]:
    """Return the ten cases in the order the contract's table names them."""
    corpus: list[dict] = []

    corpus.append(joined(base("S-00", {
        "producer_vector": "AR-00",
        "frequency_row": "AR-00 (authorized, current effect confirmed)",
        "note": "The approved call is the dispatched call; no later read is supplied.",
    })))

    corpus.append(joined(rewritten(base("S-01", {
        "producer_vector": "AR-01",
        "frequency_row": None,
        "note": "Arguments rewritten after approval, no decision covers the rewritten ref.",
    }))))

    case = joined(rewritten(base("S-02", {
        "producer_vector": "APPROVED-REWRITE",
        "frequency_row": None,
        "note": "Same rewrite as S-01; a permit decision covers the effective ref.",
    })))
    case["covering_decision"] = decision(case["effective"]["ref"], "permit", T1)
    corpus.append(case)

    case = joined(rewritten(base("S-03", {
        "producer_vector": "COVERING-DENY",
        "frequency_row": None,
        "note": "A decision binds the effective ref and says deny: coverage without permission.",
    })))
    case["covering_decision"] = decision(case["effective"]["ref"], "deny", T1)
    corpus.append(case)

    case = joined(base("S-04", {
        "producer_vector": "AR-05",
        "frequency_row": "AR-05 (execution reported, current effect contradicted)",
        "note": "A later read sees different bytes than the committed output.",
    }))
    case["later_observation"] = observation("transfer_funds:/work/acct-2.txt", INPUT_B, T2 + 1000)
    corpus.append(case)

    case = joined(base("S-05", {
        "producer_vector": "MISSING-OBSERVATION",
        "frequency_row": None,
        "note": "The later-read key is present and null: no read was supplied.",
    }))
    case["later_observation"] = None
    corpus.append(case)

    case = joined(base("S-06", {
        "producer_vector": None,
        "frequency_row": None,
        "note": "Identical to S-05 except the later-read key is absent, not null.",
    }))
    del case["later_observation"]
    corpus.append(case)

    case = joined(base("S-07", {
        "producer_vector": "CHANGED-PREIMAGE",
        "frequency_row": None,
        "note": "The claimed effective ref does not recompute from its own preimage.",
    }))
    case["effective"]["ref"] = "sha256:" + "11" * 32
    corpus.append(case)

    case = joined(rewritten(base("S-08", {
        "producer_vector": "COVERING-UNSUPPORTED-PROFILE",
        "frequency_row": None,
        "note": "The covering decision names a canonicalization profile this contract does not implement.",
    })))
    case["covering_decision"] = decision(case["effective"]["ref"], "permit", T1, PROFILE_UNKNOWN)
    corpus.append(case)

    case = base("S-09", {
        "producer_vector": None,
        "frequency_row": "AR-01 to AR-04 (refusal rows; nearest, not equivalent)",
        "note": "The decision denies, nothing is dispatched, and no later read is supplied.",
    })
    case["decision"] = decision(case["approved"]["ref"], "deny", T0)
    corpus.append(case)

    return corpus


def write(corpus: list[dict]) -> None:
    """Write the corpus and the manifest that pins it."""
    fixtures = ROOT / "fixtures"
    fixtures.mkdir(exist_ok=True)
    cases_path = fixtures / "cases.json"
    cases_path.write_text(json.dumps({"contract": "request-effect-join-fixture/v1",
                                      "cases": corpus}, indent=2, ensure_ascii=False) + "\n")
    digests = {}
    for name in ("cases.json", "expected.json"):
        path = fixtures / name if name == "cases.json" else ROOT / name
        digests[name] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    (fixtures / "MANIFEST.json").write_text(
        json.dumps({"contract": "request-effect-join-fixture/v1",
                    "sha256": dict(sorted(digests.items()))}, indent=2) + "\n")
    for name, digest in sorted(digests.items()):
        print(f"{digest}  {name}")


def main() -> int:
    """Generate the corpus and report every pinned digest."""
    corpus = cases()
    write(corpus)
    print(f"{len(corpus)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
