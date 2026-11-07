"""Judge the committed control-decision members and prove each rule is load-bearing.

1. Every committed member file reads back to the verdict and code MANIFEST.json declares.
2. The corpus digest recomputes.
3. Every rule's code is produced by at least one member, so no rule is decorative.

    uv run --extra generators python corpora/vectors-acs-decision-record/check_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from digest import corpus_digest
from record import ACCEPTED, RULES, Refusal, judge

HERE = Path(__file__).resolve().parent


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    key = bytes.fromhex(manifest["keys"]["producer"]["publicKey"])
    failures, seen = [], set()
    for entry in manifest["vectors"]:
        member = json.loads((HERE / entry["path"]).read_text(encoding="utf-8"))
        try:
            got, code = (
                judge(member["envelope"], member["disclosed"], key, member["replayedVerdict"]),
                None,
            )
        except Refusal as refusal:
            got, code = "refused", refusal.code
        want = entry["expected"]
        seen.add(code)
        if (want["verdict"] == "accept") != (got == ACCEPTED) or code != want["code"]:
            failures.append(f"{entry['id']}: read {got} {code}, declared {want}")
    if corpus_digest(manifest, str(HERE)) != manifest["corpusDigest"]:
        failures.append("corpusDigest does not recompute")
    for rule, code in RULES:
        if code not in seen:
            failures.append(f"rule {rule} ({code}) is produced by no member")
    for line in failures:
        print(f"FAIL {line}")
    print(f"control-decision: {len(manifest['vectors'])} members, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
