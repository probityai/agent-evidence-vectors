#!/usr/bin/env python3
"""The Action's second stage: replay the corpus's members through the reference verifier.

This is the body of the "Check against the reference verifier" step of
`action.yml`. It runs after the candidate verifier's replay and cannot be
switched off. It reads the corpus the report names, hands every member that the
reference verifier (probity-verify) can judge to the same comparison the
repository's cross-check uses (`vectors-done-receipt/crosscheck_probity_verify.py`),
or, for the Adversarial Execution Evidence corpus (`vectors`, the default), to the
reference verifier's `adversarial_execution_evidence/v1` claim type, and prints
one line:

    reference-checked conformance N of M

N is the count of members whose every declared verdict the reference verifier
reached too. M is every member of the corpus, including those no reference route
covers, so a corpus the reference verifier cannot judge reads `0 of M` and never
a quiet pass. `FULL-RELEASE` is printed only when M is above zero and N equals M.

The stage records what it found in the report (`reference.verifier.id`,
`reference.checked`, `reference.total`, `reference.fullRelease`), so the
identifier of the verifier that checked sits inside the bytes the consumer's own
pipeline uploads. It does not change the candidate's `result` output: the
candidate verdict and the reference count are two facts, and each is reported.

Variables, all required but the last two:

    REPORT                the report JSON the replay wrote
    CORPUS_DIR            directory holding the corpus MANIFEST.json
    GITHUB_STEP_SUMMARY   the job summary, appended to
    GITHUB_OUTPUT         the step's outputs, appended to
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CROSSCHECK = HERE.parent / "vectors-done-receipt" / "crosscheck_probity_verify.py"
MAX_ROWS = 20

# A member's check: how many verdicts were compared and which disagreed.
Check = Callable[[dict[str, Any], Path], tuple[int, list[str]]]


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"action-reference-stage: ${name} is not set; refusing to report nowhere.")
    return value


def load_crosscheck() -> Any:
    """The cross-check module, loaded from this action's own checkout by path."""
    spec = importlib.util.spec_from_file_location("aev_crosscheck", CROSSCHECK)
    if spec is None or spec.loader is None:
        sys.exit(f"action-reference-stage: cannot load {CROSSCHECK}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def member_check(crosscheck: Any, entry: dict[str, Any]) -> Check | None:
    """The comparison the reference verifier has for this done-corpus member, or none."""
    expected = entry.get("expected", {})
    if "contract" in expected:
        return crosscheck.compare_contract  # type: ignore[no-any-return]
    if "checks" in expected or "integrity" in expected:
        return crosscheck.compare_member  # type: ignore[no-any-return]
    return None


# The Adversarial Execution Evidence corpus (`vectors`, the default). Every member
# kind it declares has a route through the reference verifier's
# adversarial_execution_evidence/v1 claim type; a kind left out of AEE_KINDS is
# counted in M and never in N.
AEE_PREDICATE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
AEE_CLAIM = "adversarial_execution_evidence/v1"
AEE_KINDS = ("accept", "reject", "indeterminate")


def aee_test_key(role: str = "substrate-observation-test") -> str:
    """A key of the corpus's published recipe (vectors/keys/README.md), as hex.

    seed = SHA-256("in-toto-aee-test-key/<role>/v1"); the key is that seed's
    Ed25519 public key. The recipe is corpus data, published for every rail.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def aee_decide(entry: dict[str, Any], root: Path, keys: list[str]) -> dict[str, Any]:
    """The reference verifier's own judgment of one member, read from its bytes only."""
    from probity_verify import adjudicate  # pyright: ignore[reportMissingImports]

    data = (root / entry["file"]).read_bytes()
    case = {"schema_version": "probity-case/v1", "case_id": entry["id"],
            "artifacts": {"statement": {"path": entry["file"], "length": len(data),
                                        "sha256": hashlib.sha256(data).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {entry["id"]: {"claim_type": AEE_CLAIM, "statement": "statement",
                                            "substrate_observation_keys": keys}}}
    return dict(adjudicate(case, policy, root)["checks"][0])


def aee_problems(entry: dict[str, Any], found: dict[str, Any], pinned: bool) -> list[str]:
    """How the reference verifier departs from what the corpus declares for a member."""
    expected = entry["expected"]
    label = f"{entry['id']} ({'pinned key' if pinned else 'no key'})"
    if found["verdict"] != expected["verdict"]:
        return [f"{label}: verdict {found['verdict']}, the corpus declares {expected['verdict']}"]
    problems = []
    if entry["kind"] == "accept":
        if found.get("result") != expected.get("result"):
            problems.append(f"{label}: result {found.get('result')}")
        tiers = expected.get("tierWithPinnedKey" if pinned else "tierWithoutKey")
        if tiers and found.get("tiers") != tiers:
            problems.append(f"{label}: tiers {found.get('tiers')}")
    elif entry["kind"] == "reject":
        if found["primary_code"] not in expected.get("codes", []):
            problems.append(f"{label}: primary code {found['primary_code']}")
    elif found["primary_code"] not in expected.get("readings", {}).values():
        problems.append(f"{label}: primary code {found['primary_code']} is no declared reading")
    return problems


def aee_family_notes(
    entries: list[dict[str, Any]], agreed: set[str], primary: dict[str, str]
) -> list[str]:
    """Drop from `agreed` every indeterminate family no single declared reading explains."""
    families: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if entry.get("kind") == "indeterminate" and entry["id"] in agreed:
            families.setdefault(entry["expected"].get("family", ""), []).append(entry)
    notes = []
    for family, members in families.items():
        readings = members[0]["expected"].get("readings", {})
        if not any(all(m["expected"]["readings"].get(r) == primary[m["id"]] for m in members)
                   for r in readings):
            notes.append(f"family {family}: no declared reading explains every member")
            agreed -= {m["id"] for m in members}
    return notes


def aee_tally(entries: list[dict[str, Any]], root: Path) -> tuple[int, int, list[str]]:
    """N, M and the disagreements over an AEE corpus, each member judged on its own."""
    keys = [aee_test_key()]
    agreed: set[str] = set()
    notes: list[str] = []
    primary: dict[str, str] = {}
    for entry in entries:
        if entry.get("kind") not in AEE_KINDS:
            continue
        try:
            problems = []
            for pinned in (True, False):
                found = aee_decide(entry, root, keys if pinned else [])
                problems += aee_problems(entry, found, pinned)
                if pinned:
                    primary[entry["id"]] = str(found.get("primary_code"))
        except Exception as exc:  # noqa: BLE001 -- one member's failure must not hide the rest
            notes.append(f"{entry.get('id')}: the reference verifier could not run: {exc!r}")
            continue
        notes.extend(problems)
        if not problems:
            agreed.add(entry["id"])
    notes.extend(aee_family_notes(entries, agreed, primary))
    return len(agreed), len(entries), notes


def tally(
    entries: list[dict[str, Any]], root: Path, crosscheck: Any
) -> tuple[int, int, list[str]]:
    """N, M and the disagreements, over every member of a done-corpus manifest."""
    checked, notes = 0, []
    for entry in entries:
        check = member_check(crosscheck, entry)
        if check is None:
            continue
        member = root / entry["path"]
        try:
            compared, problems = check(entry, member)
        except Exception as exc:  # noqa: BLE001 -- one member's failure must not hide the rest
            notes.append(f"{entry.get('id')}: the reference verifier could not run: {exc!r}")
            continue
        if compared and not problems:
            checked += 1
        notes.extend(problems)
    return checked, len(entries), notes


def line(checked: int, total: int) -> str:
    return f"reference-checked conformance {checked} of {total}"


def full_release(checked: int, total: int) -> bool:
    return total > 0 and checked == total


def reference_id() -> str:
    from probity_verify.core import REFERENCE_VERIFIER_ID  # pyright: ignore[reportMissingImports]

    return str(REFERENCE_VERIFIER_ID)


def main() -> int:
    report_path = Path(required("REPORT"))
    corpus_dir = Path(required("CORPUS_DIR"))
    summary_path = required("GITHUB_STEP_SUMMARY")
    output_path = required("GITHUB_OUTPUT")
    verifier_id = reference_id()

    notes: list[str] = []
    manifest = corpus_dir / "MANIFEST.json"
    if manifest.is_file():
        document = json.loads(manifest.read_text(encoding="utf-8"))
        entries = document.get("vectors", [])
        if document.get("predicateType") == AEE_PREDICATE:
            checked, total, notes = aee_tally(entries, corpus_dir)
        else:
            checked, total, notes = tally(entries, corpus_dir, load_crosscheck())
    else:
        # No manifest to walk: the corpus is judged by a reader this stage has no
        # route into. The member count still comes from the report, and N is zero.
        checked = 0
        total = 0
        if report_path.is_file():
            total = json.loads(report_path.read_text(encoding="utf-8"))["totals"]["vectors"]
        notes.append(f"{corpus_dir} holds no MANIFEST.json, so no member was routed.")

    full = full_release(checked, total)
    text = line(checked, total)
    print(text)
    if full:
        print("FULL-RELEASE")
    print(f"reference.verifier.id {verifier_id}")

    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["reference"] = {
            "verifier": {"id": verifier_id},
            "checked": checked,
            "total": total,
            "fullRelease": full,
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    rows = [f"## agent-evidence-vectors: {text}\n\n", f"Reference verifier `{verifier_id}`.\n\n"]
    if full:
        rows.append("**FULL-RELEASE**\n\n")
    if notes:
        rows.append("| reference disagreement |\n| --- |\n")
        rows.extend(f"| {note[:300]} |\n" for note in notes[:MAX_ROWS])
        if len(notes) > MAX_ROWS:
            rows.append(f"\n{len(notes) - MAX_ROWS} more are in the step log.\n")
        for note in notes:
            print(note)
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("".join(rows))
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(
            f"reference-checked={checked}\nreference-total={total}\n"
            f"full-release={'true' if full else 'false'}\n"
            f"reference-verifier-id={verifier_id}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
