#!/usr/bin/env python3
"""A verifier that answers every member exactly as its corpus MANIFEST declares.

It reads no statement. It finds the MANIFEST above the file it is handed, looks
the member up by identifier, and prints the answer the manifest records, in the
shape of whichever external-verifier contract the harness is driving:

* the generic contract (``packaging/run_vectors.py``): exit 0 for ``valid``,
  1 otherwise, and one JSON line carrying ``verdict``, ``codes``, ``result``,
  the tier column for the key policy in ``AEE_SUBSTRATE_KEYS`` (the pinned
  column when it is set, the no-key column when it is not), and for an
  indeterminate member one declared reading's condition as ``primaryCode``;
* the receipt-signature contract: exit 0, 1 or 2 and one JSON line carrying
  ``verdict`` and ``code``, answering the with-windows or without-windows
  expectation according to which published key set ``AEV_RECEIPT_JWKS`` names;
* the case-directory contract (``<member file> [--policy <file>] --json``): the
  member's ``expected`` object, with the exit status its reader binds to the
  decision;
* the A2A canonicalization contract (``<target> <vector>``): the expected
  canonical bytes as ``canonical_utf8_hex``, or exit 1 where none exist;
* the admission contract: exit 0 when the member pairing this statement with
  the policy ``AEE_CONSUMER_POLICY`` names is admitted, 1 when it is not, and
  one JSON line carrying ``admitted`` and ``policyCodes``.

It exists to test the harness, not a verifier. A perfect verifier must score a
perfect run: any failure or suite-level refusal this program draws is a defect
in the harness or in a corpus, never in the program under test.
``scripts/oracle-every-corpus-test.py`` runs it over every corpus.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import sys
from typing import Any

EXIT = {"valid": 0, "invalid": 1}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_manifest(path: str) -> tuple[str, dict[str, Any]]:
    here = os.path.dirname(os.path.abspath(path))
    while True:
        candidate = os.path.join(here, "MANIFEST.json")
        if os.path.isfile(candidate):
            with open(candidate, encoding="utf-8") as f:
                return here, json.load(f)
        parent = os.path.dirname(here)
        if parent == here:
            raise SystemExit(f"no MANIFEST.json above {path}")
        here = parent


def member(manifest: dict[str, Any], path: str) -> dict[str, Any]:
    stem = os.path.basename(path).split(".", 1)[0]
    for entry in manifest.get("vectors") or []:
        if entry.get("id") == stem:
            return dict(entry)
    raise SystemExit(f"no MANIFEST row names {stem}")


def member_for_file(manifest: dict[str, Any], path: str) -> dict[str, Any]:
    """The member whose identifier is the file's stem, else the first member
    declaring that file (a receipt shared by members that differ in context)."""
    stem = os.path.basename(path).split(".", 1)[0]
    for entry in manifest.get("vectors") or []:
        if entry.get("id") == stem:
            return dict(entry)
    for entry in manifest.get("vectors") or []:
        if os.path.basename(str(entry.get("file"))).split(".", 1)[0] == stem:
            return dict(entry)
    raise SystemExit(f"no MANIFEST row names {stem}")


def reading_for(manifest: dict[str, Any], row: dict[str, Any]) -> str | None:
    """One reading, the same one for every member of the row's family.

    The harness refuses a rail that answers two members of one family under
    different readings, so the choice is made per family: the first reading
    name, in sorted order, that every member of the family declares. With
    ``ORACLE_READING=accept`` the choice is restricted to readings that predict
    acceptance where the family declares one, which is the other answer a
    conforming rail may give; by default it is restricted to readings that
    predict a condition.
    """
    want_valid = os.environ.get("ORACLE_READING") == "accept"
    expected = row.get("expected") or {}
    family = expected.get("family")
    if not family:
        return None
    names: set[str] | None = None
    for entry in manifest.get("vectors") or []:
        exp = entry.get("expected") or {}
        if exp.get("family") != family:
            continue
        readings = exp.get("readings") or {}
        declared = {n for n, code in readings.items() if (code == "valid") == want_valid}
        if want_valid and not declared:
            declared = {n for n, code in readings.items() if code != "valid"}
        names = declared if names is None else names & declared
    for name in sorted(names or ()):
        return str(expected["readings"][name])
    return None


def generic(manifest: dict[str, Any], row: dict[str, Any]) -> int:
    expected = row.get("expected") or {}
    verdict = str(expected.get("verdict"))
    out: dict[str, Any] = {"verdict": verdict, "codes": list(expected.get("codes") or [])}
    code = reading_for(manifest, row)
    if code == "valid":
        verdict = "valid"
        out = {"verdict": verdict, "codes": []}
    elif code is not None:
        verdict = "invalid"
        out = {"verdict": verdict, "codes": [code], "primaryCode": code}
    if verdict == "valid":
        if "result" in expected:
            out["result"] = expected["result"]
        column = "tierWithPinnedKey" if os.environ.get("AEE_SUBSTRATE_KEYS") else "tierWithoutKey"
        if column in expected:
            out["tiers"] = list(expected[column])
    print(json.dumps(out))
    return EXIT.get(verdict, 1)


def receipt(suite_dir: str, manifest: dict[str, Any], row: dict[str, Any]) -> int:
    keys_path = os.environ.get("AEV_RECEIPT_JWKS", "")
    with open(keys_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    sets = manifest.get("keySets") or {}
    without = (sets.get("withoutWindows") or {}).get("sha256")
    answer = row.get("expectedWithoutWindows") if digest == without else row.get("expected")
    answer = answer or {}
    verdict = str(answer.get("verdict"))
    print(json.dumps({"verdict": verdict, "code": answer.get("code")}))
    return {"valid": 0, "invalid": 1}.get(verdict, 2)


def suite_exit_codes(suite: str) -> dict[str, int]:
    """The decision-to-exit mapping a case-directory corpus's own reader holds.

    Each of those corpora writes its contract into its README and its reader in
    this package keeps the same mapping as ``EXIT_FOR``; a corpus whose reader
    keeps none expects exit 0 for every answered case.
    """
    sys.path.insert(0, os.path.join(ROOT, "packaging"))
    import importlib
    import pkgutil

    import agent_evidence_vectors as pkg

    for info in pkgutil.iter_modules(pkg.__path__):
        module = importlib.import_module(f"agent_evidence_vectors.{info.name}")
        if getattr(module, "SUITE", None) == suite:
            return dict(getattr(module, "EXIT_FOR", {}))
    raise SystemExit(f"no reader in this package names the suite {suite!r}")


def case_directory(case_path: str) -> int:
    """``<verifier> <cases/<id>/<member file>> [--policy <file>] --json``.

    The case-directory corpora hand a verifier one case file and read one JSON
    object back whose fields are compared with the member's ``expected``, with
    the exit status bound to the decision.
    """
    _, manifest = find_manifest(case_path)
    stem = os.path.basename(os.path.dirname(os.path.abspath(case_path)))
    for entry in manifest.get("vectors") or []:
        if entry.get("id") == stem:
            expected = dict(entry.get("expected") or {})
            print(json.dumps(expected))
            codes = suite_exit_codes(str(manifest.get("suite")))
            return codes.get(str(expected.get("decision")), 0)
    raise SystemExit(f"no MANIFEST row names {stem}")


def a2a_reader() -> Any:
    sys.path.insert(0, os.path.join(ROOT, "packaging"))
    from agent_evidence_vectors import a2ajcs

    return a2ajcs


def signatures_exclusion_clause() -> str:
    return str(a2a_reader().SIGNATURES_EXCLUSION_CLAUSE)


def canonical_bytes(target: str, vector_path: str) -> int:
    """``<verifier> <target> <vector file>`` for the A2A canonicalization corpus.

    The harness writes only the member's input, named for the member, so the
    member is found by that name in the corpus. A member with a canonical form
    is answered with its expected bytes; one without is refused with exit 1.
    """
    stem = os.path.basename(vector_path).split(".", 1)[0]
    vector: dict[str, Any] | None = None
    for corpus in sorted(glob.glob(os.path.join(ROOT, "vectors-a2a-jcs-*"))):
        for candidate in glob.glob(os.path.join(corpus, "*", f"{stem}.json")):
            with open(candidate, encoding="utf-8") as f:
                vector = json.load(f)
    if vector is None:
        raise SystemExit(f"no canonicalization member is named {stem}")
    hex_bytes = (vector.get("expected") or {}).get("canonical_utf8_hex")
    if hex_bytes is None and vector.get("clause") == signatures_exclusion_clause():
        # The member declares only that the presented bytes are not the card's
        # signing bytes, so the answer is the signing bytes themselves, computed
        # by the corpus's own reference reader from the input it was handed.
        with open(vector_path, encoding="utf-8", errors="surrogatepass") as f:
            answered, produced = a2a_reader().reference_answer(target, f.read())
        if answered != "bytes" or produced is None:
            return 1
        hex_bytes = produced.hex()
    if hex_bytes is None:
        return 1
    print(json.dumps({"canonical_utf8_hex": hex_bytes}))
    return 0


def admission(manifest: dict[str, Any], statement: str, policy: str) -> int:
    """The admission contract: the member is the (statement, policy) pair."""
    pair = (os.path.basename(statement), os.path.basename(policy))
    for entry in manifest.get("vectors") or []:
        if (os.path.basename(entry["file"]), os.path.basename(entry["policy"])) == pair:
            expected = entry["expected"]
            print(
                json.dumps(
                    {"admitted": expected["admitted"], "policyCodes": expected["policyCodes"]}
                )
            )
            return 0 if expected["admitted"] else 1
    raise SystemExit(f"no MANIFEST row pairs {pair}")


def contract_member_file(path: str) -> str | None:
    """The member file a case-directory corpus hands its verifier.

    Each such corpus writes its contract as ``verifier <file> [...] --json``
    in its MANIFEST; the file is ``case.json`` for most and ``record.json``
    for the authority-at-dispatch corpus, so it is read, not assumed. A
    corpus that writes no contract (the trace-anchor corpus) hands
    ``case.json``, the harness's default for this contract.
    """
    try:
        _, manifest = find_manifest(path)
    except SystemExit:
        return None
    words = str(manifest.get("verifierContract") or "").split()
    if len(words) > 1 and words[0] == "verifier":
        return words[1]
    return "case.json"


def main(argv: list[str]) -> int:
    args = argv[1:]
    if "--json" in args and args and os.path.basename(args[0]) == contract_member_file(args[0]):
        return case_directory(args[0])
    if len(args) == 2 and not args[0].endswith(".json"):
        return canonical_bytes(args[0], args[1])
    if len(args) != 1:
        print("usage: oracle-verifier.py <member-file>", file=sys.stderr)
        return 2
    suite_dir, manifest = find_manifest(args[0])
    if os.environ.get("AEE_CONSUMER_POLICY"):
        return admission(manifest, args[0], os.environ["AEE_CONSUMER_POLICY"])
    row = member_for_file(manifest, args[0])
    if os.environ.get("AEV_RECEIPT_JWKS"):
        # Several receipt members share one receipt file and differ only in the
        # context the harness hands over, whose file is named for the member.
        context = os.environ.get("AEV_RECEIPT_CONTEXT")
        if context:
            row = member(manifest, os.path.basename(context).split(".", 1)[0])
        return receipt(suite_dir, manifest, row)
    return generic(manifest, row)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
