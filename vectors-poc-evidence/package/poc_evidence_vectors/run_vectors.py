"""Run the corpus against a verifier. Standard library only.

    python -m poc_evidence_vectors.run_vectors                      # the bundled twin
    python -m poc_evidence_vectors.run_vectors --verifier "CMD"     # your verifier

A verifier command reads one case (JSON) on stdin and prints one JSON line:
{"result": "accept"} or {"result": "reject", "code": "<reason>"}. A reject
counts only when its code is one of the case's accepted reasons: rejecting for
the wrong reason is not a pass.

Conformant means passing this corpus at a pinned version: the manifest digest
printed on the last line is the thing to pin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from . import __version__, twin

CORPUS = Path(__file__).resolve().parent / "corpus"
MANIFEST = Path(__file__).resolve().parent / "CORPUS-MANIFEST.json"


def load_cases() -> list[dict]:
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(CORPUS.rglob("*.json"))
    ]


def judge_twin(case: dict) -> dict:
    """What the bundled twin says about one case."""
    k = case["kind"]
    code = None
    if k == "token":
        code = twin.check_token(case["text"], case.get("public_key"))
    elif k == "inclusion":
        code = twin.check_inclusion(
            case["index"],
            case["tree_size"],
            twin.leaf_hash(bytes.fromhex(case["record_hex"])),
            [bytes.fromhex(p) for p in case["proof"]],
            bytes.fromhex(case["root"]),
        )
    elif k == "consistency":
        code = twin.check_consistency(
            case["old_size"],
            case["new_size"],
            bytes.fromhex(case["old_root"]),
            bytes.fromhex(case["new_root"]),
            [bytes.fromhex(p) for p in case["proof"]],
        )
    elif k == "chain":
        code = twin.check_chain(
            case["records"], case["public_key"], case["measurement"], case["anchor"]
        )
    elif k == "canonical":
        got = hashlib.sha256(twin.jcs(twin.parse(case["text"]))).hexdigest()
        code = None if got == case["canonical_sha256"] else "canonical-digest"
    else:
        raise ValueError(f"unknown kind {k}")
    return {"result": "accept"} if code is None else {"result": "reject", "code": code}


def judge_command(cmd: str):
    def run(case: dict) -> dict:
        out = subprocess.run(
            cmd,
            shell=True,
            input=json.dumps(case),
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        try:
            return json.loads(out.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {
                "result": "error",
                "code": f"unparseable output rc={out.returncode}",
            }

    return run


def passes(case: dict, got: dict) -> bool:
    want = case["expect"]
    if want["result"] == "accept":
        return got.get("result") == "accept"
    return got.get("result") == "reject" and got.get("code") in want["code"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--verifier", help="command that judges one case (see above)")
    ap.add_argument("--json", action="store_true", help="print one JSON line per case")
    args = ap.parse_args(argv)
    judge = judge_command(args.verifier) if args.verifier else judge_twin
    cases = load_cases()
    failed = 0
    for c in cases:
        got = judge(c)
        ok = passes(c, got)
        failed += not ok
        if args.json:
            print(json.dumps({"id": c["id"], "ok": ok, "got": got}))
        elif not ok:
            print(f"FAIL {c['id']}: expected {c['expect']}, got {got}")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    print(
        f"poc-evidence-vectors {__version__}: {len(cases) - failed} passed, "
        f"{failed} failed, corpus_sha256={manifest['corpus_sha256']}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
