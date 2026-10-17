#!/usr/bin/env python3
"""Regenerate the admission corpus byte-identically.

    python3 gen_vectors.py            # write statements/, policies/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The subject under test is the ADMISSION decision a verifier reports for an
Adversarial Execution Evidence statement under a consumer's policy: the one
consumer-facing result the specification asks verification surfaces to expose,
conjoining validity, tier-policy satisfaction and the consumer's pins. The
reference corpus in ../vectors judges validity and the tier column and never
admission, so a verifier could pass all of it and still report "admitted" for a
statement nothing independent stands behind. Each member here is one statement
and one consumer policy, and the answer is admitted or not, with the policy
conditions that decided it.

Every statement is either a member of ../vectors, copied byte for byte, or one
of those with a field the run binding does not cover rewritten. No record is
re-signed: the rewrites are exactly the ones a party holding only the envelope
key can make, which is the point of them.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCE = os.path.join(ROOT, "vectors")
SPEC = "spec/predicates/adversarial-execution-evidence.md"
PROFILE = "spec/v1/statement.md"
VERIFICATION = "spec/predicates/adversarial-execution-evidence/verification.md"

sys.path.insert(0, os.path.join(ROOT, "packaging"))
import run_vectors  # noqa: E402  -- the reference rail derives the published test key


def _load_digest_of() -> Any:
    """The preimage lives in digest.py beside this file, loaded by path."""
    spec = importlib.util.spec_from_file_location(
        "admission_digest", os.path.join(HERE, "digest.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.digest_of


digest_of = _load_digest_of()

SUITE = "adversarial-execution-evidence-admission"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"

#: The test key a consumer pins, derived from the recipe in ../vectors/keys.
OBSERVATION_KEY_HEX = run_vectors.derive_test_keys()["substrate-observation-test"]["public"].hex()

#: A digest standing for an artifact other than the one a statement was issued
#: for: the production payments agent a relabelled statement claims to be about.
OTHER_ARTIFACT = hashlib.sha256(b"payments-agent-prod artifact bytes").hexdigest()

#: The conditions, each with the text it rests on. ``quote`` is verbatim from
#: ``file`` (whitespace-normalised), and the readers refuse a manifest whose
#: quotation is not in the file, so a condition cannot outlive its basis.
CONDITIONS: dict[str, dict[str, str]] = {
    "adm-c-0": {
        "requires": "A verifier reports success only for a statement it admitted. A consumer "
        "that supplied no policy pinned nothing, and nothing is admitted to it.",
        "file": VERIFICATION,
        "quote": "A verification surface MUST NOT report success for a statement it did not "
        "admit",
    },
    "adm-c-8": {
        "requires": "An observation key whose seed the suite publishes attests nothing, so a "
        "verifier does not admit under one unless the consumer declines by name.",
        "file": VERIFICATION,
        "quote": "a surface does not admit under one unless the consumer declines that refusal "
        "by name",
    },
    "adm-c-1": {
        "requires": "A statement is admitted only when the consumer has pinned the corpus, "
        "the substrate and the subject digest it expects, or has declined the pins by name. "
        "Silence is not a decline.",
        "file": SPEC,
        "quote": "A consumer MUST pin, out of band, the corpus digest and the substrate digest "
        "it expects for the deployment it is admitting into",
    },
    "adm-c-2": {
        "requires": "A statement is admitted only when the consumer has pinned the classes it "
        "demands and every one is assessed, or has declined the demand by name.",
        "file": SPEC,
        "quote": "A consumer that demands no class MUST record that decision explicitly rather "
        "than reach it by omission",
    },
    "adm-c-3": {
        "requires": "A substrate row is credited only when its covering records verify under a "
        "key the consumer pinned, so a consumer that pinned none admits no substrate row.",
        "file": SPEC,
        "quote": "A consumer with no policy-pinned substrate root MUST treat every `basis: "
        "substrate` row as `unattested`",
    },
    "adm-c-4": {
        "requires": "The subject is matched by the sha256 digest the observer's records bind, "
        "never by its name, which no observer signs.",
        "file": PROFILE,
        "quote": "A verifier admitting a statement matches the subject by "
        "`subject[0].digest.sha256` and by nothing else",
    },
    "adm-c-5": {
        "requires": "A bound on when a run happened is evaluated against the armedAt a verified "
        "arming record carries, never against issuedAt, and a bounded consumer handed no such "
        "record refuses.",
        "file": SPEC,
        "quote": "`issuedAt` is producer-asserted, sits outside every substrate signature, and is "
        "not among the run binding digest's inputs",
    },
    "adm-c-6": {
        "requires": "Only the result tokens the consumer accepts are admitted: `pass` by default, "
        "`pass` and `pass_indirect` when widened, and nothing else.",
        "file": SPEC,
        "quote": "a policy relaxed to admit `pass_indirect` MUST keep the rule",
    },
    "adm-c-7": {
        "requires": "A clean row is admitted only as a live substrate interception unless the "
        "consumer declines that obligation by name, under a threshold that makes the decline "
        "reachable.",
        "file": SPEC,
        "quote": "an admission rule that needs a live observation keys on `method: intercepted` "
        "as well as the tier",
    },
}


def canonical(obj: Any) -> bytes:
    """The byte form every statement in ../vectors is written in."""
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def policy_bytes(policy: dict[str, Any]) -> bytes:
    return canonical(policy)


def content_id(data: bytes) -> str:
    return "v" + hashlib.sha256(data).hexdigest()[:16]


def load_source(vid: str) -> dict[str, Any]:
    with open(os.path.join(SOURCE, "statements", f"{vid}.json"), encoding="utf-8") as fh:
        loaded: dict[str, Any] = json.load(fh)
    return loaded


def relabelled(source: dict[str, Any]) -> dict[str, Any]:
    """The rewrite case 7 of the public demonstration made: a new name, a new date.

    Neither field is a run binding input, so every record still verifies. The
    subject digest is left alone; rewriting it breaks the binding and is caught
    by validity.
    """
    out: dict[str, Any] = json.loads(json.dumps(source))
    out["subject"][0]["name"] = "payments-agent-prod"
    out["predicate"]["issuedAt"] = "2026-09-26T00:00:00Z"
    return out


def full_policy(statement: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Every pin a consumer owes, matching this statement, then the changes."""
    env = statement["predicate"]["observationEnvironment"]
    policy: dict[str, Any] = {
        "substrateObservationKeys": [{"publicKeyHex": OBSERVATION_KEY_HEX}],
        "expectedCorpusDigest": env["corpus"]["digest"]["sha256"],
        "expectedSubstrateDigest": env["substrate"]["digest"]["sha256"],
        "expectedSubjectDigest": statement["subject"][0]["digest"]["sha256"],
        "demandedClasses": sorted(statement["predicate"]["coverage"]["assessedClasses"]),
        # Every key in this corpus is a published test key, so every policy that
        # pins one declines that refusal by name; the adm-c-8 members are the
        # ones that do not.
        "allowPublishedTestKeys": True,
    }
    for key, value in changes.items():
        if value is None:
            policy.pop(key, None)
        else:
            policy[key] = value
    return policy


UNPINNED = [
    "corpus-anchor-unpinned",
    "scope-unpinned",
    "subject-anchor-unpinned",
    "substrate-anchor-unpinned",
]


def members() -> list[dict[str, Any]]:
    """The members, in the order the table in README.md reads them."""
    flagship = load_source("vcc938c6038536dcb")  # pass, one clean row, arming + sealed
    relabel = relabelled(flagship)
    failed = load_source("vcf20eae7df4f1f1b")  # fail, caught and attested, no arming record
    indirect = load_source("vc2782e6c3cbdb9b7")  # pass_indirect, one reconstructed artifact row
    unattested = load_source("v550c91df0d36a218")  # fail, row unattested under the pinned key
    keys_only = {
        "substrateObservationKeys": [{"publicKeyHex": OBSERVATION_KEY_HEX}],
        "allowPublishedTestKeys": True,
    }
    day = 86400
    rows: list[tuple[str, dict[str, Any], dict[str, Any], bool, list[str], list[str]]] = [
        (
            "no consumer policy at all",
            flagship,
            {},
            False,
            [*UNPINNED, "substrate-row-unattested"],
            ["adm-c-0", "adm-c-1", "adm-c-2", "adm-c-3"],
        ),
        (
            "every pin supplied and matching",
            flagship,
            full_policy(flagship),
            True,
            [],
            ["adm-c-0", "adm-c-1", "adm-c-2", "adm-c-3", "adm-c-4", "adm-c-6", "adm-c-8"],
        ),
        (
            "every pin supplied, the observation key is a published test key",
            flagship,
            full_policy(flagship, allowPublishedTestKeys=None),
            False,
            ["observation-key-published"],
            ["adm-c-8"],
        ),
        (
            "the observation key pinned and nothing else",
            flagship,
            keys_only,
            False,
            UNPINNED,
            ["adm-c-1", "adm-c-2"],
        ),
        (
            "the observation key pinned, the anchors and the scope declined by name",
            flagship,
            {**keys_only, "allowUnpinnedAnchors": True, "allowUnpinnedScope": True},
            True,
            [],
            ["adm-c-1", "adm-c-2"],
        ),
        (
            "every anchor pinned, no observation key",
            flagship,
            full_policy(flagship, substrateObservationKeys=None),
            False,
            ["substrate-row-unattested"],
            ["adm-c-3"],
        ),
        (
            "a wrong corpus pinned",
            flagship,
            full_policy(flagship, expectedCorpusDigest=OTHER_ARTIFACT),
            False,
            ["corpus-anchor-mismatch"],
            ["adm-c-1"],
        ),
        (
            "subject renamed and redated, the consumer pins the artifact it deploys",
            relabel,
            full_policy(relabel, expectedSubjectDigest=OTHER_ARTIFACT),
            False,
            ["subject-anchor-mismatch"],
            ["adm-c-4"],
        ),
        (
            "subject renamed and redated, the consumer pins the digest the observer bound",
            relabel,
            full_policy(relabel),
            True,
            [],
            ["adm-c-4"],
        ),
        (
            "subject renamed and redated, the consumer bounds issuance lag at one day",
            relabel,
            full_policy(relabel, maxIssuanceLagSeconds=day),
            False,
            ["issuance-lag-exceeded"],
            ["adm-c-5"],
        ),
        (
            "the statement as issued, the same one-day bound",
            flagship,
            full_policy(flagship, maxIssuanceLagSeconds=day),
            True,
            [],
            ["adm-c-5"],
        ),
        (
            "a fail result, every pin matching",
            failed,
            full_policy(failed),
            False,
            ["result-not-accepted"],
            ["adm-c-6"],
        ),
        (
            "a fail result carrying no arming record, under an issuance-lag bound",
            failed,
            full_policy(failed, maxIssuanceLagSeconds=day),
            False,
            ["observed-instant-absent", "result-not-accepted"],
            ["adm-c-5", "adm-c-6"],
        ),
        (
            "an artifact-only pass_indirect, default threshold",
            indirect,
            full_policy(indirect),
            False,
            ["clean-row-unintercepted", "result-not-accepted"],
            ["adm-c-6", "adm-c-7"],
        ),
        (
            "an artifact-only pass_indirect, threshold widened, row rule kept",
            indirect,
            full_policy(
                indirect,
                acceptedResults=["pass", "pass_indirect"],
                admitUninterceptedCleanRows=False,
            ),
            False,
            ["clean-row-unintercepted"],
            ["adm-c-7"],
        ),
        (
            "an artifact-only pass_indirect, threshold widened, row rule declined",
            indirect,
            full_policy(
                indirect,
                acceptedResults=["pass", "pass_indirect"],
                admitUninterceptedCleanRows=True,
            ),
            True,
            [],
            ["adm-c-6", "adm-c-7"],
        ),
        (
            "threshold widened with the row rule left unsaid",
            indirect,
            full_policy(indirect, acceptedResults=["pass", "pass_indirect"]),
            False,
            ["clean-row-unintercepted", "row-gate-undeclared"],
            ["adm-c-7"],
        ),
        (
            "the row rule declined under a pass-only threshold",
            flagship,
            full_policy(flagship, admitUninterceptedCleanRows=True),
            False,
            ["row-gate-decline-unreachable"],
            ["adm-c-7"],
        ),
        (
            "an accepted-results list that names no threshold",
            flagship,
            full_policy(flagship, acceptedResults=["pass", "degraded"]),
            False,
            ["accepted-results-malformed"],
            ["adm-c-6"],
        ),
        (
            "a demanded class the run did not assess",
            flagship,
            full_policy(flagship, demandedClasses=["XA", "XZ"]),
            False,
            ["demanded-class-unassessed"],
            ["adm-c-2"],
        ),
        (
            "a substrate row unattested under the pinned key",
            unattested,
            full_policy(unattested),
            False,
            ["result-not-accepted", "substrate-row-unattested"],
            ["adm-c-3", "adm-c-6"],
        ),
    ]
    out = []
    for label, statement, policy, admitted, codes, conditions in rows:
        sbytes = canonical(statement)
        pbytes = policy_bytes(policy)
        sid, pid = content_id(sbytes), content_id(pbytes)
        mid = content_id(sid.encode() + b"\0" + pid.encode())
        out.append(
            {
                "id": mid,
                "kind": "accept" if admitted else "reject",
                "label": label,
                "file": f"statements/{sid}.json",
                "policy": f"policies/{pid}.json",
                "conditions": conditions,
                "expected": {"admitted": admitted, "policyCodes": sorted(codes)},
                "_bytes": {f"statements/{sid}.json": sbytes, f"policies/{pid}.json": pbytes},
            }
        )
    return out


def quote_found(rel: str, quote: str) -> bool:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        text = re.sub(r"\s+", " ", fh.read())
    return re.sub(r"\s+", " ", quote) in text


def build() -> dict[str, bytes]:
    for cid, cond in CONDITIONS.items():
        if not quote_found(cond["file"], cond["quote"]):
            raise SystemExit(f"{cid}: the quotation is not in {cond['file']}")
    entries = members()
    files: dict[str, bytes] = {}
    for entry in entries:
        files.update(entry.pop("_bytes"))
    ids = [e["id"] for e in entries]
    if len(set(ids)) != len(ids):
        raise SystemExit("two members share an identifier")
    counts = {
        "accept": sum(e["kind"] == "accept" for e in entries),
        "reject": sum(e["kind"] == "reject" for e in entries),
    }
    manifest = {
        "suite": SUITE,
        "predicateType": PREDICATE_TYPE,
        "specPath": SPEC,
        "contract": "README.md",
        "comparisonSurface": {
            "normative": ["admitted"],
            "measured": ["policyCodes"],
            "note": "A rail conforms when its admission answer matches this manifest. The "
            "policy codes are the reference verifier's own vocabulary, compared as a set: a "
            "rail naming a different code for the same member has produced a reason-parity "
            "datum rather than a failure.",
        },
        "keyRecipe": 'seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1"), role '
        "substrate-observation-test, as ../vectors/keys/README.md publishes it",
        "conditions": CONDITIONS,
        "counts": counts,
        "corpusDigest": digest_of(entries, lambda rel: files[rel]),
        "vectors": sorted(entries, key=lambda e: e["id"]),
    }
    files["MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    files["INDEX.md"] = index(entries, manifest).encode()
    return files


def index(entries: list[dict[str, Any]], manifest: dict[str, Any]) -> str:
    lines = [
        "# Admission corpus index",
        "",
        "Generated by `gen_vectors.py`; do not edit. One row per member: the statement, the "
        "consumer policy, and the admission answer the member requires.",
        "",
        "| member | kind | case | admitted | policy codes |",
        "|---|---|---|---|---|",
    ]
    for e in entries:
        codes = ", ".join(f"`{c}`" for c in e["expected"]["policyCodes"]) or "none"
        lines.append(
            f"| `{e['id']}` | {e['kind']} | {e['label']} | "
            f"{str(e['expected']['admitted']).lower()} | {codes} |"
        )
    counts = manifest["counts"]
    lines += [
        "",
        f"This corpus is {counts['accept'] + counts['reject']} vectors, of which "
        f"{counts['accept']} a conformant verifier must not fail closed on and "
        f"{counts['reject']} it must reject. Here, not failing closed means admitting "
        "the statement under the member's policy.",
        "",
        f"Corpus digest `{manifest['corpusDigest']}`.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="refuse when the tree differs")
    args = parser.parse_args()
    files = build()
    drift = []
    for rel, data in sorted(files.items()):
        path = os.path.join(HERE, rel)
        if args.check:
            try:
                with open(path, "rb") as fh:
                    if fh.read() != data:
                        drift.append(rel)
            except FileNotFoundError:
                drift.append(rel)
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    for sub in ("statements", "policies"):
        on_disk = (
            set(os.listdir(os.path.join(HERE, sub)))
            if os.path.isdir(os.path.join(HERE, sub))
            else set()
        )
        stray = sorted(on_disk - {os.path.basename(r) for r in files if r.startswith(sub + "/")})
        if not args.check:
            for name in stray:
                os.remove(os.path.join(HERE, sub, name))
            continue
        drift += [f"{sub}/{name} (not generated)" for name in stray]
    if drift:
        print("the tree differs from the generator:\n  " + "\n  ".join(drift), file=sys.stderr)
        return 1
    print(
        f"{len([r for r in files if r.startswith('statements/') or r.startswith('policies/')])} "
        f"files, {json.loads(files['MANIFEST.json'])['counts']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
