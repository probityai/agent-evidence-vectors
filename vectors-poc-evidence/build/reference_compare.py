#!/usr/bin/env python3
"""Run every corpus case through the specification's own reference code.

The reference is the validator and Verifier pinned at build/spec-93d0e28. The
output, REFERENCE-RESULTS.json, lists every case where the reference does not
give the corpus's expected answer. Those are the findings: a vector attached to
a requirement, with the reference's actual behaviour beside it.

    python3 build/reference_compare.py            # write REFERENCE-RESULTS.json
    python3 build/reference_compare.py --check    # exit 1 if the file would change
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = HERE / "spec-93d0e28"
sys.path.insert(0, str(SPEC / "impl"))
sys.path.insert(0, str(SPEC / "schema"))
sys.path.insert(0, str(ROOT / "package"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

import validate as V  # noqa: E402
from poc import Verifier, TransparencyLog  # noqa: E402
from poc.merkle import leaf_hash, verify_consistency, verify_inclusion  # noqa: E402
from poc_evidence_vectors.run_vectors import load_cases, passes  # noqa: E402

OUT = ROOT / "REFERENCE-RESULTS.json"


def judge_reference(case: dict) -> dict:
    k = case["kind"]
    try:
        if k == "token":
            tok = V.load_token(case["text"])
            V.validate(tok, case.get("public_key"))
            return {"result": "accept"}
        if k == "inclusion":
            ok = verify_inclusion(
                case["index"],
                case["tree_size"],
                leaf_hash(bytes.fromhex(case["record_hex"])),
                [bytes.fromhex(p) for p in case["proof"]],
                bytes.fromhex(case["root"]),
            )
            return (
                {"result": "accept"}
                if ok
                else {"result": "reject", "code": "not-included"}
            )
        if k == "consistency":
            ok = verify_consistency(
                case["old_size"],
                case["new_size"],
                bytes.fromhex(case["old_root"]),
                bytes.fromhex(case["new_root"]),
                [bytes.fromhex(p) for p in case["proof"]],
            )
            return (
                {"result": "accept"}
                if ok
                else {"result": "reject", "code": "not-consistent"}
            )
        if k == "chain":
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(case["public_key"]))
            anchor = None
            if case["anchor"] is not None:
                anchor = TransparencyLog("a")
                anchor.entries.append(
                    {
                        "root": case["anchor"]["root"],
                        "index": case["anchor"]["index"],
                        "t": 0,
                    }
                )
            ok, msg = Verifier(pk, case["measurement"]).verify_chain(
                case["records"], anchor
            )
            if ok:
                return {"result": "accept"}
            for needle, code in (
                ("invalid signature", "signature"),
                ("measurement", "measurement"),
                ("sequence gap", "sequence-gap"),
                ("chain break", "chain-break"),
                ("truncation", "truncation"),
                ("history rewritten", "history-rewritten"),
            ):
                if needle in msg:
                    return {"result": "reject", "code": code}
            return {"result": "reject", "code": "other: " + msg}
        if k == "canonical":
            got = hashlib.sha256(V.jcs(V.load_token(case["text"]))).hexdigest()
            return (
                {"result": "accept"}
                if got == case["canonical_sha256"]
                else {"result": "reject", "code": "canonical-digest"}
            )
    except V.ValidationError as e:
        return {"result": "reject", "code": e.code}
    except Exception as e:  # noqa: BLE001 - the crash IS the observation
        return {"result": "reject", "code": f"crash:{type(e).__name__}"}
    raise ValueError(k)


def compute() -> dict:
    rows, diverge = [], []
    for c in load_cases():
        got = judge_reference(c)
        ok = passes(c, got)
        rows.append(c["id"])
        if not ok:
            diverge.append(
                {
                    "id": c["id"],
                    "kind": c["kind"],
                    "class": c["class"],
                    "requirements": c["requirements"],
                    "expect": c["expect"],
                    "reference": got,
                    "note": c["note"],
                }
            )
    return {
        "spec_commit": "93d0e282fc177d5df741de4cdd6a0d0dacf1955a",
        "cases_run": len(rows),
        "divergences": diverge,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = json.dumps(compute(), indent=2, sort_keys=True) + "\n"
    if args.check:
        return 0 if OUT.exists() and OUT.read_text() == text else 1
    OUT.write_text(text)
    d = json.loads(text)
    print(f"{d['cases_run']} cases, {len(d['divergences'])} divergences")
    for x in d["divergences"]:
        print(
            f"  {x['id']}: expected {x['expect'].get('code', 'accept')}, reference {x['reference']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
