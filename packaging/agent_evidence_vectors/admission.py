"""The admission corpus: its Python reader and its external-verifier contract.

``vectors-admission/`` pairs an Adversarial Execution Evidence statement with a
consumer policy and requires the ADMISSION answer: whether the consumer may act
on the statement under the pins it supplied. This module is the second rail
beside the Go reader in ``corpora/admission.go``. It derives validity, the
result and the tier column from this package's reference rail, under the
policy's own keys, and computes the admission conjunction itself, so the two
rails share no code below the statement.

The conjunction, in the order the codes are raised:

* ``substrate-row-unattested``: a basis: substrate row whose covering records do
  not all verify under a pinned key;
* the three anchors: corpus, substrate and subject digest, each pinned and
  equal, or declined by ``allowUnpinnedAnchors`` (an absent pin only); the
  subject is compared on ``subject[0].digest.sha256`` and nothing else;
* the scope: ``demandedClasses`` all assessed, or declined by
  ``allowUnpinnedScope``;
* the threshold: ``acceptedResults`` absent is ``["pass"]``; the only other
  admissible value is ``["pass", "pass_indirect"]``, which must say what it
  requires of a clean row; declining the row rule under ``["pass"]`` is refused
  as unreachable;
* time: ``maxIssuanceLagSeconds`` and ``maxEvidenceAgeSeconds`` against the
  armedAt of every arming record that verifies under a pinned key and commits
  to the run, never against issuedAt; a bounded policy with no such record
  refuses.

The external contract: ``<cmd> <statement-file>`` with the policy's path in
``AEE_CONSUMER_POLICY``; exit 0 admitted, 1 not, 2 could not answer; the last
stdout line a JSON object whose ``admitted`` agrees with the exit status and
whose ``policyCodes`` is a list of strings.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SUITE = "adversarial-execution-evidence-admission"
POLICY_ENV = "AEE_CONSUMER_POLICY"
EXIT_ANSWERS = {0: True, 1: False}

POLICY_MEMBERS = {
    "substrateObservationKeys",
    "expectedCorpusDigest",
    "expectedSubstrateDigest",
    "expectedSubjectDigest",
    "allowUnpinnedAnchors",
    "demandedClasses",
    "allowUnpinnedScope",
    "acceptedResults",
    "admitUninterceptedCleanRows",
    "maxIssuanceLagSeconds",
    "maxEvidenceAgeSeconds", "allowPublishedTestKeys",
}
#: The roles whose seed the corpus publishes; a key derived from one signs for
#: anybody who read the recipe.
PUBLISHED_TEST_KEY_ROLES = (
    "substrate-observation-test", "wrong-signer-test", "statement-test", "no-pae-verify",
)
THRESHOLD_PASS = {"pass"}
THRESHOLD_INDIRECT = {"pass", "pass_indirect"}


def _rail() -> Any:
    """The reference rail, imported where it lives in the wheel or in a checkout.

    Imported when first needed rather than at the top, because the rail imports
    this module and a top-level import each way is a cycle.
    """
    try:
        return importlib.import_module("agent_evidence_vectors.run_vectors")
    except ImportError:
        return importlib.import_module("run_vectors")


def load_policy(raw: bytes) -> dict[str, Any]:
    """A consumer policy document, refused on any member this contract does not
    define, a key that is not 32 bytes of hex, or a time bound that is not a
    positive number, because a misspelt pin that reads as absent is a pin that
    silently stopped being enforced."""
    doc = json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError("a consumer policy is a JSON object")
    unknown = sorted(set(doc) - POLICY_MEMBERS)
    if unknown:
        raise ValueError(f"unknown policy members {unknown}")
    for key in doc.get("substrateObservationKeys") or []:
        hexed = key.get("publicKeyHex") if isinstance(key, dict) else None
        if not isinstance(hexed, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", hexed):
            raise ValueError("publicKeyHex must be an Ed25519 public key in hex")
    for name in ("maxIssuanceLagSeconds", "maxEvidenceAgeSeconds"):
        value = doc.get(name)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0
        ):
            raise ValueError(f"{name} must be a positive number of seconds")
    return doc


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _verified_armed_at(rv: Any, verifier: Any, stmt: dict[str, Any]) -> list[datetime]:
    """armedAt of every arming record verifying under a pinned key and carrying
    this statement's run binding."""
    if not verifier.pinned_pubs:
        return []
    pred = stmt.get("predicate") or {}
    env = pred.get("observationEnvironment") or {}
    binding = rv._sfa_derived_binding(stmt, env)
    out = []
    for i, rec in enumerate(pred.get("observationRecords") or []):
        view = rv.RecordView(i, rec)
        payload = view.payload if isinstance(view.payload, dict) else {}
        if payload.get("aeeKind") != "arming" or payload.get("aeeRunBinding") != binding:
            continue
        if not verifier._record_verifies(view):
            continue
        at = _instant(payload.get("armedAt"))
        if at is not None:
            out.append(at)
    return sorted(out)


def _published_test_keys(rv: Any) -> set[bytes]:
    import hashlib  # noqa: PLC0415 -- used by this derivation alone

    return {
        rv.ed25519_public_key(hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest())
        for role in PUBLISHED_TEST_KEY_ROLES
    }


def _anchor_codes(stmt: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    env = (stmt.get("predicate") or {}).get("observationEnvironment") or {}
    subject = ((stmt.get("subject") or [{}])[0].get("digest") or {}).get("sha256")
    pins = (
        (
            "expectedCorpusDigest",
            ((env.get("corpus") or {}).get("digest") or {}).get("sha256"),
            "corpus",
        ),
        (
            "expectedSubstrateDigest",
            ((env.get("substrate") or {}).get("digest") or {}).get("sha256"),
            "substrate",
        ),
        ("expectedSubjectDigest", subject, "subject"),
    )
    codes = []
    for member, carried, name in pins:
        expected = policy.get(member) or ""
        if not expected and not policy.get("allowUnpinnedAnchors"):
            codes.append(f"{name}-anchor-unpinned")
        elif expected and expected != carried:
            codes.append(f"{name}-anchor-mismatch")
    return codes


def _scope_codes(stmt: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    demanded = policy.get("demandedClasses") or []
    if not demanded:
        return [] if policy.get("allowUnpinnedScope") else ["scope-unpinned"]
    assessed = set(
        ((stmt.get("predicate") or {}).get("coverage") or {}).get("assessedClasses") or []
    )
    return [] if all(c in assessed for c in demanded) else ["demanded-class-unassessed"]


def _clean_row_unintercepted(stmt: dict[str, Any]) -> bool:
    pred = stmt.get("predicate") or {}
    vocab = (pred.get("observationEnvironment") or {}).get("observationVocabulary") or {}
    labels, caught = set(vocab.get("labels") or []), set(vocab.get("caught") or [])
    for row in pred.get("attackResults") or []:
        label = row.get("containmentObserved")
        if label not in labels or label in caught:
            continue
        if row.get("basis") != "substrate" or row.get("method") != "intercepted":
            return True
    return False


def _threshold_codes(stmt: dict[str, Any], result: str, policy: dict[str, Any]) -> list[str]:
    declared = policy.get("acceptedResults")
    threshold = set(declared) if isinstance(declared, list) else THRESHOLD_PASS
    if declared is not None and (
        not isinstance(declared, list)
        or len(set(declared)) != len(declared)
        or threshold not in (THRESHOLD_PASS, THRESHOLD_INDIRECT)
    ):
        return ["accepted-results-malformed"]
    relaxed = threshold == THRESHOLD_INDIRECT
    gate = policy.get("admitUninterceptedCleanRows")
    row_declared = isinstance(gate, bool)
    declined = gate is True
    codes = []
    if relaxed and not row_declared:
        codes.append("row-gate-undeclared")
    elif declined and not relaxed:
        codes.append("row-gate-decline-unreachable")
    if not (declined and relaxed) and _clean_row_unintercepted(stmt):
        codes.append("clean-row-unintercepted")
    if result not in threshold:
        codes.append("result-not-accepted")
    return codes


def _time_codes(
    stmt: dict[str, Any], policy: dict[str, Any], armed: list[datetime], now: datetime
) -> list[str]:
    lag, age = policy.get("maxIssuanceLagSeconds"), policy.get("maxEvidenceAgeSeconds")
    if lag is None and age is None:
        return []
    if not armed:
        return ["observed-instant-absent"]
    issued = _instant((stmt.get("predicate") or {}).get("issuedAt"))
    codes = []
    if (
        lag is not None
        and issued is not None
        and any((issued - a).total_seconds() > lag for a in armed)
    ):
        codes.append("issuance-lag-exceeded")
    if age is not None and any((now - a).total_seconds() > age for a in armed):
        codes.append("evidence-age-exceeded")
    return codes


def _seals_verify(rv: Any, verifier: Any, stmt: dict[str, Any]) -> bool:
    """Every sealed record verifies under a pinned key, whether or not a row resolves it.

    Only a statement carrying a basis: substrate row owes a seal. A row's tier reads
    the records the row resolves, and a caught row resolves interception records, so
    the seal's own signature is checked here in every case.
    """
    pred = stmt.get("predicate") or {}
    if not any(r.get("basis") == "substrate" for r in pred.get("attackResults") or []):
        return True
    if not verifier.pinned_pubs:
        return False
    for i, rec in enumerate(pred.get("observationRecords") or []):
        view = rv.RecordView(i, rec)
        payload = view.payload if isinstance(view.payload, dict) else {}
        if payload.get("aeeKind") == "sealed" and not verifier._record_verifies(view):
            return False
    return True


def admit(raw: bytes, policy: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """The reference admission answer for one statement under one policy."""
    rv = _rail()
    keys = [bytes.fromhex(k["publicKeyHex"]) for k in policy.get("substrateObservationKeys") or []]
    verifier = rv.ReferenceVerifier(keys)
    stmt, _faithful = rv._load_statement(raw)
    out = verifier.verify(stmt, raw)
    if out.codes:
        return {
            "verdict": "invalid",
            "codes": sorted(set(out.codes)),
            "admitted": False,
            "policyCodes": [],
        }
    tiers = out.tiers_with_key or []
    rows = (stmt.get("predicate") or {}).get("attackResults") or []
    codes = []
    if any(
        r.get("basis") == "substrate" and t != "attested" for r, t in zip(rows, tiers, strict=False)
    ) or not _seals_verify(rv, verifier, stmt):
        codes.append("substrate-row-unattested")
    if not policy.get("allowPublishedTestKeys") and set(keys) & _published_test_keys(rv):
        codes.append("observation-key-published")
    codes += _anchor_codes(stmt, policy)
    codes += _scope_codes(stmt, policy)
    codes += _threshold_codes(stmt, str(out.result), policy)
    codes += _time_codes(
        stmt, policy, _verified_armed_at(rv, verifier, stmt), now or datetime.now(UTC)
    )
    return {
        "verdict": "valid",
        "result": out.result,
        "tiers": tiers,
        "admitted": not codes,
        "policyCodes": codes,
    }


@dataclass
class Judged:
    """One pass of this reader over the corpus: per-member findings and the corpus's own."""

    members: list[tuple[str, str, list[str]]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.findings and all(not f for _, _, f in self.members)


def _load(directory: str) -> dict[str, Any]:
    with open(os.path.join(directory, "MANIFEST.json"), encoding="utf-8") as fh:
        loaded: dict[str, Any] = json.load(fh)
    return loaded


def _read(directory: str, rel: str) -> bytes:
    with open(os.path.join(directory, rel), "rb") as fh:
        return fh.read()


def _corpus_findings(directory: str, manifest: dict[str, Any]) -> list[str]:
    import hashlib  # noqa: PLC0415 -- used by this check alone

    findings = []
    vectors = manifest.get("vectors") or []
    digest = hashlib.sha256(
        b"".join(
            _read(directory, v["file"]) + _read(directory, v["policy"])
            for v in sorted(vectors, key=lambda v: v["id"])
        )
    ).hexdigest()
    if digest != manifest.get("corpusDigest"):
        findings.append(
            f"corpus digest over the files on disk is {digest}, the manifest "
            f"publishes {manifest.get('corpusDigest')}"
        )
    counts: dict[str, int] = {}
    kinds: dict[str, set[str]] = {}
    for v in vectors:
        counts[v["kind"]] = counts.get(v["kind"], 0) + 1
        for c in v.get("conditions") or []:
            kinds.setdefault(c, set()).add(v["kind"])
            if c not in (manifest.get("conditions") or {}):
                findings.append(f"member {v['id']} cites undefined condition {c}")
    if counts != manifest.get("counts"):
        findings.append(f"counts {manifest.get('counts')} disagree with the members {counts}")
    root = os.path.dirname(os.path.abspath(directory))
    for name, cond in sorted((manifest.get("conditions") or {}).items()):
        if kinds.get(name, set()) != {"accept", "reject"}:
            findings.append(
                f"condition {name} is not carried by both an admitted and a refused member"
            )
        try:
            with open(os.path.join(root, cond["file"]), encoding="utf-8") as fh:
                text = re.sub(r"\s+", " ", fh.read())
        except OSError as exc:
            findings.append(
                f"condition {name} rests on {cond['file']}, which cannot be read: {exc}"
            )
            continue
        if re.sub(r"\s+", " ", cond["quote"]) not in text:
            findings.append(f"condition {name} quotes a sentence {cond['file']} no longer carries")
    return findings


def judge(directory: str) -> Judged:
    manifest = _load(directory)
    judged = Judged(findings=_corpus_findings(directory, manifest))
    for v in manifest.get("vectors") or []:
        findings = []
        try:
            policy = load_policy(_read(directory, v["policy"]))
            answer = admit(_read(directory, v["file"]), policy)
        except (OSError, ValueError) as exc:
            judged.members.append((v["id"], v["kind"], [f"could not judge: {exc}"]))
            continue
        want = v.get("expected") or {}
        if answer["verdict"] != "valid":
            findings.append(f"statement is invalid ({answer.get('codes')})")
        if answer["admitted"] != want.get("admitted"):
            findings.append(
                f"admitted={answer['admitted']}, the manifest declares {want.get('admitted')}"
            )
        if sorted(answer["policyCodes"]) != sorted(want.get("policyCodes") or []):
            findings.append(
                f"policy codes {sorted(answer['policyCodes'])}, the manifest declares "
                f"{sorted(want.get('policyCodes') or [])}"
            )
        judged.members.append((v["id"], v["kind"], findings))
    return judged


def render(judged: Judged, suite: str) -> str:
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts: dict[str, int] = {}
    for _, kind, _ in judged.members:
        counts[kind] = counts.get(kind, 0) + 1
    lines += [f"  {kind}: {n}" for kind, n in sorted(counts.items())]
    for mid, _, findings in judged.members:
        lines += [f"FAIL {mid}: {f}" for f in findings]
    lines += [f"FAIL corpus: {f}" for f in judged.findings]
    lines.append(
        "verdict: every member behaves as MANIFEST.json declares"
        if judged.ok()
        else "verdict: the corpus does not judge clean"
    )
    return "\n".join(lines) + "\n"


def ask(cmd: list[str], statement: str, policy: str) -> tuple[dict[str, Any] | None, str | None]:
    """One invocation through the contract: (the answer, or None; why it is not one)."""
    env = dict(os.environ)
    env.pop("AEE_SUBSTRATE_KEYS", None)
    env[POLICY_ENV] = policy
    try:
        proc = subprocess.run(
            [*cmd, statement], capture_output=True, timeout=120, env=env, check=False
        )
    except subprocess.TimeoutExpired:
        return None, "the verifier did not terminate"
    except OSError as exc:
        return None, f"the verifier could not run: {exc}"
    answer = EXIT_ANSWERS.get(proc.returncode)
    if answer is None:
        return (
            None,
            f"the verifier exited {proc.returncode}, which the contract gives no admission meaning",
        )
    lines = [ln for ln in proc.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]
    try:
        line = json.loads(lines[-1]) if lines else None
    except ValueError:
        line = None
    if not isinstance(line, dict):
        return None, "the verifier's last stdout line is not a JSON object"
    if line.get("admitted") is not answer:
        return None, (
            f"the exit status says admitted={answer} and the report says "
            f"admitted={line.get('admitted')!r}"
        )
    codes = line.get("policyCodes") or []
    if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
        return None, "policyCodes is not a list of strings"
    return {"admitted": answer, "policyCodes": sorted(codes)}, None


def run_external(directory: str, cmd: list[str], report_path: str, rail_note: str) -> int:
    """Run a named verifier over every member, write the report, return the exit."""
    manifest = _load(directory)
    judged = judge(directory)
    notes = (
        []
        if judged.ok()
        else ["the corpus does not judge clean:", *render(judged, SUITE).splitlines()]
    )
    rows = []
    for v in manifest.get("vectors") or []:
        answer, why = ask(
            cmd,
            os.path.abspath(os.path.join(directory, v["file"])),
            os.path.abspath(os.path.join(directory, v["policy"])),
        )
        want = v.get("expected") or {}
        row: dict[str, Any] = {
            "id": v["id"],
            "kind": v["kind"],
            "label": v.get("label"),
            "verifierRan": answer is not None,
            "reasons": [],
            "parity": [],
        }
        if answer is None:
            row["status"], row["reasons"] = "FAIL", [str(why)]
        else:
            row["answer"] = answer
            if answer["admitted"] != want.get("admitted"):
                row["reasons"].append(
                    f"admitted={answer['admitted']}, expected {want.get('admitted')}"
                )
            if answer["policyCodes"] != sorted(want.get("policyCodes") or []):
                row["parity"].append(
                    f"policy codes {answer['policyCodes']}, the reference names "
                    f"{sorted(want.get('policyCodes') or [])}"
                )
            row["status"] = "FAIL" if row["reasons"] else "PASS"
        rows.append(row)
    executed = sum(1 for r in rows if r["verifierRan"])
    if executed != len(rows):
        notes.append(f"the verifier {shlex.join(cmd)!r} ran on {executed} of {len(rows)} vectors")
    refusals = (0 if judged.ok() else 1) + (0 if executed == len(rows) else 1)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    failed = len(rows) - passed
    report = {
        "suite": os.path.basename(os.path.normpath(directory)),
        "rail": "external",
        "railNote": rail_note,
        "verifier": {"command": shlex.join(cmd), "vectorsExecuted": executed, "vectors": len(rows)},
        "totals": {
            "vectors": len(rows),
            "pass": passed,
            "fail": failed,
            "conform": passed,
            "reasonParityMismatch": sum(1 for r in rows if r["parity"]),
            "suiteRefusals": refusals,
            "notExercised": 0,
        },
        "notes": notes,
        "vectors": rows,
    }
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    for r in rows:
        print(f"{r['id']:<20} {r['kind']:<8} {r['status']:<5} {r.get('label') or ''}")
        for reason in r["reasons"] + r["parity"]:
            print(f"    {'!' if r['status'] == 'FAIL' else '-'} {reason}")
    for note in notes:
        print(f"note: {note}")
    print(
        f"totals: {len(rows)} vectors, {passed} pass, {failed} fail; "
        f"report written to {report_path}"
    )
    print(f"verifier: {shlex.join(cmd)} ran on {executed} of {len(rows)} vectors")
    if executed == 0:
        return 2
    return 1 if failed or refusals else 0


def main(argv: list[str] | None = None) -> int:
    import argparse  # noqa: PLC0415 -- the command line alone needs it

    parser = argparse.ArgumentParser(prog="admission", description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("directory")
    parser.add_argument("--verifier")
    parser.add_argument("--report", default="admission-report.json")
    args = parser.parse_args(argv)
    if args.verifier:
        return run_external(
            args.directory,
            shlex.split(args.verifier),
            args.report,
            f"external verifier: {args.verifier}",
        )
    judged = judge(args.directory)
    sys.stdout.write(render(judged, SUITE))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
