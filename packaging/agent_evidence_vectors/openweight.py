"""Check what a model release must carry to claim the Article 53(2) exemption.

The EU AI Act, Article 53(2), lifts the obligations of Article 53(1),
points (a) and (b), from "providers of AI models that are released under a free
and open-source licence that allows for the access, usage, modification, and
distribution of the model, and whose parameters, including the weights, the
information on the model architecture, and the information on model usage, are
made publicly available". It adds that "this exception shall not apply to
general-purpose AI models with systemic risks". Recital 103 adds that a release
monetised through conditions such as personal data collected for reasons other
than security, compatibility or interoperability does not benefit.

A reader asking whether a release qualifies has nothing to run today. This
module reads a release record, a small JSON file of public locators, and says
which of six conditions the record evidences. It does not judge the licence in
law, fetch a URL, or decide whether a model has systemic risk: it reports what
the record carries, and a condition the record does not carry is
``not-established``, never a pass. Nothing here is legal advice.

The checks run in a fixed order and the first finding of the most severe class
names the reason. ``not-exempt`` outranks ``not-established``:

1. ``licence``: an SPDX identifier from the pinned list below, which grants
   access, use, modification and distribution with no field-of-use or
   non-commercial restriction (``licence_restricts_use`` for the restricted
   list, ``licence_not_recognised`` for an identifier on neither list);
2. ``weights``: ``access`` is ``public`` and the record binds the weights by
   URL and SHA-256 (``weights_not_public`` for ``private``,
   ``weights_access_gated`` for ``gated``, ``weights_not_evidenced`` when the
   record does not say, ``weights_not_digest_bound``);
3. ``architecture``: a public URL (``architecture_not_evidenced``);
4. ``usage``: a public URL (``usage_information_not_evidenced``);
5. ``monetisation``: an explicit empty list of monetisation conditions
   (``monetised_release``, ``monetisation_not_stated``);
6. ``systemic_risk``: a stated training compute at or below 10^25 floating
   point operations and no Commission designation, or a recorded Commission
   decision that the model is not systemic (``systemic_risk_designated``,
   ``systemic_risk_presumed``, ``training_compute_not_stated``).

When every condition holds the decision is ``exempt`` with reason
``all_conditions_evidenced``. The exemption reaches Article 53(1)(a) and (b)
only. The copyright policy of 53(1)(c) and the public training-content summary
of 53(1)(d) still apply, so the answer lists whether the record carries them.

The external-verifier contract: ``<verifier> <case-dir>/case.json --json``
prints one JSON object carrying ``decision`` and ``reason`` and exits 0
whenever it produced an answer, 2 on a record it could not read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

SUITE = "open-weight-art53/v1"
EXEMPT, NOT_EXEMPT, NOT_ESTABLISHED = "exempt", "not-exempt", "not-established"
RELEASE_SCHEMA = "open-weight-release/v1"
CASE_SCHEMA = "open-weight-case/v1"
# Article 51(2): a presumption of high impact capabilities above this training compute.
COMPUTE_THRESHOLD_FLOP = 1e25
# The pinned list. A consumer replaces it with its own; the checker never fetches a licence.
OPEN_LICENCES = frozenset({
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "MPL-2.0", "CC-BY-4.0",
    "CC-BY-SA-4.0", "GPL-3.0-only", "LGPL-3.0-only", "AGPL-3.0-only", "ISC", "Unlicense",
})
RESTRICTED_LICENCES = frozenset({"CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-NC-ND-4.0",
                                 "CC-BY-ND-4.0"})
CONDITIONS = ("licence", "weights", "architecture", "usage", "monetisation", "systemic_risk")
REMAINING = (("copyright_policy", "Article 53(1)(c)"),
             ("training_summary", "Article 53(1)(d)"))
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-open-weight-art53" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-open-weight-art53")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _url(node: Any) -> bool:
    return isinstance(node, dict) and str(node.get("url", "")).startswith("https://")


def _licence(release: dict[str, Any]) -> tuple[str, str] | None:
    spdx = (release.get("licence") or {}).get("spdx")
    if spdx in RESTRICTED_LICENCES:
        return NOT_EXEMPT, "licence_restricts_use"
    if spdx not in OPEN_LICENCES:
        return NOT_ESTABLISHED, "licence_not_recognised"
    return None


def _weights(release: dict[str, Any]) -> tuple[str, str] | None:
    weights = release.get("weights") or {}
    access = weights.get("access")
    if access == "private":
        return NOT_EXEMPT, "weights_not_public"
    if access == "gated":
        return NOT_ESTABLISHED, "weights_access_gated"
    if access != "public":
        return NOT_ESTABLISHED, "weights_not_evidenced"
    digest = str(weights.get("sha256", ""))
    if not _url(weights) or len(digest) != 64 or set(digest) - set("0123456789abcdef"):
        return NOT_ESTABLISHED, "weights_not_digest_bound"
    return None


def _architecture(release: dict[str, Any]) -> tuple[str, str] | None:
    return None if _url(release.get("architecture")) else (
        NOT_ESTABLISHED, "architecture_not_evidenced")


def _usage(release: dict[str, Any]) -> tuple[str, str] | None:
    return None if _url(release.get("usage")) else (
        NOT_ESTABLISHED, "usage_information_not_evidenced")


def _monetisation(release: dict[str, Any]) -> tuple[str, str] | None:
    conditions = release.get("monetisation")
    if not isinstance(conditions, list):
        return NOT_ESTABLISHED, "monetisation_not_stated"
    return (NOT_EXEMPT, "monetised_release") if conditions else None


def _systemic_risk(release: dict[str, Any]) -> tuple[str, str] | None:
    risk = release.get("systemic_risk") or {}
    if risk.get("commission_designation"):
        return NOT_EXEMPT, "systemic_risk_designated"
    if _url({"url": risk.get("commission_decision_not_systemic")}):
        return None
    compute = (release.get("training") or {}).get("compute_flop")
    if isinstance(compute, bool) or not isinstance(compute, (int, float)) or compute <= 0:
        return NOT_ESTABLISHED, "training_compute_not_stated"
    return (NOT_EXEMPT, "systemic_risk_presumed") if compute > COMPUTE_THRESHOLD_FLOP else None


_STEPS = (("licence", _licence), ("weights", _weights), ("architecture", _architecture),
          ("usage", _usage), ("monetisation", _monetisation), ("systemic_risk", _systemic_risk))


def assess(release: dict[str, Any]) -> dict[str, Any]:
    """Judge one release record and list every finding, not only the first.

    Returns ``decision`` and ``reason`` (the contract), the per-condition
    ``findings``, and ``remaining``: whether the record carries what Article
    53(1)(c) and (d) still ask of an exempt provider.
    """
    findings = {name: step(release) for name, step in _STEPS}
    failed = [(name, hit) for name, hit in findings.items() if hit]
    worst = next((cls for cls in (NOT_EXEMPT, NOT_ESTABLISHED)
                  if any(hit[0] == cls for _, hit in failed)), EXEMPT)
    reason = next((hit[1] for _, hit in failed if hit[0] == worst), "all_conditions_evidenced")
    return {
        "decision": worst, "reason": reason,
        "findings": {name: (hit[1] if hit else "evidenced") for name, hit in findings.items()},
        "remaining": {label: _url(release.get(key)) for key, label in REMAINING},
    }


def verify(case_path: Path) -> dict[str, Any]:
    """Read ``case.json``, load the release it names and judge it."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    release = json.loads((case_path.parent / case["release"]).read_text(encoding="utf-8"))
    if release.get("schema_version") != RELEASE_SCHEMA:
        raise ValueError(f"release is not {RELEASE_SCHEMA}")
    return assess(release)


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], case_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if result.returncode:
        return True, f"exit {result.returncode} for an answered case"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader.

    Returns the number of cases answered and every disagreement.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory / "case.json")
            observed = {key: observed[key] for key in ("decision", "reason")}
        else:
            ran, observed = _external_answer(command, directory / "case.json")
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("target", nargs="?",
                        help="a release.json (or case.json) to judge with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument("--require-exempt", action="store_true",
                        help="exit 1 unless the decision is exempt (for a CI job)")
    parser.add_argument("--verifier", help="run every corpus case through this verifier instead")
    args = parser.parse_args(argv)
    if args.target:
        try:
            path = Path(args.target)
            data = json.loads(path.read_text(encoding="utf-8"))
            answer = verify(path) if data.get("schema_version") == CASE_SCHEMA else assess(data)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"cannot read the release record: {exc}")
            return 2
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return 1 if args.require_exempt and answer["decision"] != EXEMPT else 0
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
