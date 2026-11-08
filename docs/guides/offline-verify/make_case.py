#!/usr/bin/env python3
"""Write a case file per record and one policy file, for agent-evidence-verify.

Standard library only, so it runs on the offline machine before anything is
installed. Each record becomes ``<out>/<stem>.case.json``, which names the record
by path, length and SHA-256. ``<out>/policy.json`` holds one assessment per case:
the claim type and the substrate observation keys taken from the key-set file.
With ``--keys`` omitted the policy pins no key, which is the reading of a party
that holds the record and nothing else.

    python3 make_case.py --out cases [--keys keys.json] records/*.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

CLAIM = "adversarial_execution_evidence/v1"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--keys", type=Path, help="key set: {substrateObservationKeys: [...]}")
    parser.add_argument("records", type=Path, nargs="+")
    args = parser.parse_args()
    keys: list[str] = []
    if args.keys:
        keyset = json.loads(args.keys.read_text(encoding="utf-8"))
        keys = [k["publicKeyHex"] for k in keyset["substrateObservationKeys"]]
    args.out.mkdir(parents=True, exist_ok=True)
    assessments = {}
    for record in args.records:
        data = record.read_bytes()
        case_id = record.stem
        case = {"schema_version": "probity-case/v1", "case_id": case_id,
                "artifacts": {"statement": {"path": record.name, "length": len(data),
                                            "sha256": hashlib.sha256(data).hexdigest()}}}
        (args.out / f"{case_id}.case.json").write_text(json.dumps(case, indent=1) + "\n")
        assessments[case_id] = {"claim_type": CLAIM, "statement": "statement",
                                "substrate_observation_keys": keys}
    policy = {"schema_version": "probity-policy/v1", "assessments": assessments}
    (args.out / "policy.json").write_text(json.dumps(policy, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
