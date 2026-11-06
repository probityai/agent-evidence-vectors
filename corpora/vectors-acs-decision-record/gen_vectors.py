"""Build the control-decision corpus from the recorded run of agent-control-spec 0.4.0a4.

Reads ``observed/run-acs-0.4.0a4.json`` (written by ``run/run_acs.py``), signs one
control-decision record per case with the published test key, derives the reject
members by one edit each, judges every member with ``record.judge`` and refuses to
write a member whose verdict differs from the one it declares. Writes
``members/*.json``, ``MANIFEST.json`` and ``INDEX.md``; the same run file gives the
same bytes on every machine.

    uv run --extra generators python corpora/vectors-acs-decision-record/gen_vectors.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from digest import corpus_digest
from record import (
    ACCEPTED,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    RULES,
    STATEMENT_TYPE,
    Refusal,
    canonical,
    digest,
    judge,
    pae,
)

HERE = Path(__file__).resolve().parent
RUN = HERE / "observed" / "run-acs-0.4.0a4.json"
KEY_SEED = b"agent-evidence-control-decision-test-key/producer/v1"
KEY_RECIPE = 'sha256("agent-evidence-control-decision-test-key/producer/v1")'


def producer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED).digest())


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def statement(run: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    context_digest = digest(canonical(case["context"]))
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": f"{run['interventionPoint']}:{case['context']['tool_call']['id']}",
                "digest": {"sha256": context_digest.removeprefix("sha256:")},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "interventionPoint": run["interventionPoint"],
            "decisionPoint": {
                "specification": run["runtime"]["distribution"],
                "version": run["runtime"]["version"],
                "repository": run["runtime"]["repository"],
            },
            "input": {"canonicalization": "rfc8785", "digest": context_digest},
            "policy": {
                "manifestDigest": digest(run["manifest"].encode("utf-8")),
                "bundleDigest": digest(canonical(run["policyBundle"])),
            },
            "verdict": case["verdict"],
        },
    }


def envelope(stmt: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    payload = canonical(stmt)
    sig = key.sign(pae(PAYLOAD_TYPE, payload))
    keyid = hashlib.sha256(public_bytes(key)).hexdigest()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def disclosed(run: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    return {
        "context": copy.deepcopy(case["context"]),
        "manifest": run["manifest"],
        "policyBundle": copy.deepcopy(run["policyBundle"]),
    }


Edit = Callable[[dict[str, Any], dict[str, Any]], None]


def drop(path: tuple[str, ...]) -> Edit:
    def edit(stmt: dict[str, Any], _disc: dict[str, Any]) -> None:
        node = stmt
        for part in path[:-1]:
            node = node[part]
        del node[path[-1]]

    return edit


def set_verdict(verdict: dict[str, Any]) -> Edit:
    def edit(stmt: dict[str, Any], _disc: dict[str, Any]) -> None:
        stmt["predicate"]["verdict"] = verdict

    return edit


def disclose_args(args: dict[str, Any]) -> Edit:
    def edit(_stmt: dict[str, Any], disc: dict[str, Any]) -> None:
        disc["context"]["tool_call"]["args"] = args
        disc["context"]["target"] = args

    return edit


def disclose_policy(source: str) -> Edit:
    def edit(_stmt: dict[str, Any], disc: dict[str, Any]) -> None:
        disc["policyBundle"] = {"modules": {"tool_gate.rego": source}}

    return edit


def wrong_predicate_type(stmt: dict[str, Any], _disc: dict[str, Any]) -> None:
    stmt["predicateType"] = PREDICATE_TYPE.replace("/v1/", "/v0/")


#: slug, case, edit (None for an accept member), code, what the member shows.
REJECTS: tuple[tuple[str, str, Edit | str, str, str], ...] = (
    (
        "input-args-changed",
        "delete-denied",
        disclose_args({"branch": "feature"}),
        "input-digest-mismatch",
        "the disclosed tool arguments are not the ones the record's input digest names",
    ),
    (
        "input-args-amount-lowered",
        "payment-escalated",
        disclose_args({"amount": 40, "currency": "USD"}),
        "input-digest-mismatch",
        "a lowered payment amount disclosed under the escalated record",
    ),
    (
        "verdict-flipped-to-allow",
        "delete-denied",
        set_verdict({"decision": "allow", "reason": "tool_permitted"}),
        "verdict-mismatch",
        "the record says allow; replaying the bound input and policy denies",
    ),
    (
        "verdict-approval-dropped",
        "payment-escalated",
        set_verdict({"decision": "deny", "reason": "payment_needs_approval"}),
        "verdict-mismatch",
        "the record drops the approval block, so a liftable deny reads as final",
    ),
    (
        "verdict-reason-changed",
        "read-allowed",
        set_verdict({"decision": "allow", "reason": "operator_override"}),
        "verdict-mismatch",
        "same decision, a reason the policy never returned",
    ),
    (
        "policy-bundle-digest-missing",
        "read-allowed",
        drop(("predicate", "policy", "bundleDigest")),
        "policy-digest-missing",
        "the record names no policy bundle digest",
    ),
    (
        "policy-manifest-digest-missing",
        "delete-denied",
        drop(("predicate", "policy", "manifestDigest")),
        "policy-digest-missing",
        "the record names no manifest digest",
    ),
    (
        "policy-bundle-swapped",
        "delete-denied",
        disclose_policy(
            "package tool_gate\n\n"
            'default verdict := {"decision": "deny", "reason": "destructive_tool"}\n'
        ),
        "policy-digest-mismatch",
        "the disclosed policy is not the one the record's bundle digest names",
    ),
    (
        "verdict-decision-unknown",
        "read-allowed",
        set_verdict({"decision": "permit"}),
        "verdict-malformed",
        "a decision outside allow, deny and transform",
    ),
    (
        "predicate-type-wrong",
        "read-allowed",
        wrong_predicate_type,
        "statement-malformed",
        "the Statement names another predicate type",
    ),
    (
        "signature-other-key",
        "read-allowed",
        "other-key",
        "signature-invalid",
        "signed by a key the consumer did not name",
    ),
)


def build() -> list[dict[str, Any]]:
    run = json.loads(RUN.read_text(encoding="utf-8"))
    cases = {case["name"]: case for case in run["cases"]}
    key = producer_key()
    other = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"not-the-producer").digest())
    members = []
    for case in run["cases"]:
        members.append(
            {
                "slug": f"accept-{case['name']}",
                "case": case["name"],
                "expected": {"verdict": "accept", "code": None},
                "shows": (
                    f"the recorded run's {case['verdict']['decision']} verdict, "
                    "bound to its input and policy"
                ),
                "envelope": envelope(statement(run, case), key),
                "disclosed": disclosed(run, case),
                "replayedVerdict": case["verdict"],
            }
        )
    for slug, name, edit, code, shows in REJECTS:
        case = cases[name]
        stmt, disc = statement(run, case), disclosed(run, case)
        signer = key
        if edit == "other-key":
            signer = other
        else:
            assert callable(edit)
            edit(stmt, disc)
        members.append(
            {
                "slug": f"reject-{slug}",
                "case": name,
                "expected": {"verdict": "reject", "code": code},
                "shows": shows,
                "envelope": envelope(stmt, signer),
                "disclosed": disc,
                "replayedVerdict": case["verdict"],
            }
        )
    pub = public_bytes(key)
    for m in members:
        try:
            got = judge(m["envelope"], m["disclosed"], pub, m["replayedVerdict"])
            code = None
        except Refusal as refusal:
            got, code = "refused", refusal.code
        want = m["expected"]
        if (want["verdict"] == "accept") != (got == ACCEPTED) or code != want["code"]:
            raise SystemExit(
                f"{m['slug']}: the reader gave {got} {code}, the member declares {want}"
            )
    return members


def member_bytes(member: dict[str, Any]) -> bytes:
    body = {k: member[k] for k in ("envelope", "disclosed", "replayedVerdict")}
    return json.dumps(body, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def main() -> int:
    members = build()
    out = HERE / "members"
    out.mkdir(exist_ok=True)
    for stale in out.glob("*.json"):
        stale.unlink()
    entries = []
    for m in members:
        path = f"members/{m['slug']}.json"
        (HERE / path).write_bytes(member_bytes(m))
        entries.append(
            {
                "id": m["slug"],
                "path": path,
                "case": m["case"],
                "expected": m["expected"],
                "shows": m["shows"],
            }
        )
    run_bytes = RUN.read_bytes()
    run = json.loads(run_bytes)
    runtime = run["runtime"]
    key = producer_key()
    manifest: dict[str, Any] = {
        "suite": "control-decision-conformance",
        "predicateType": PREDICATE_TYPE,
        "payloadType": PAYLOAD_TYPE,
        "rules": [{"rule": rule, "code": code} for rule, code in RULES],
        "acceptedReason": ACCEPTED,
        "keyRecipe": KEY_RECIPE,
        "keys": {"producer": {"publicKey": public_bytes(key).hex()}},
        "keyNote": (
            "PUBLISHED TEST KEY, derived from a fixed seed in gen_vectors.py. "
            "It signs every member except the one that shows a foreign key."
        ),
        "trustInputs": (
            "the consumer supplies the producer key and the verdict it got by replaying the "
            "disclosed context, manifest and bundle through the named runtime; neither is "
            "read from the record"
        ),
        "observedRuns": [
            {
                "ran": (
                    f"{runtime['distribution']}=={runtime['version']} "
                    f"(agent-hooks-sdk {runtime['agentHooksSdk']}), "
                    f"ActivatedPolicy.from_memory, evaluate at {run['interventionPoint']}"
                ),
                "against": (
                    "the four contexts, the manifest and the Rego bundle in "
                    "observed/run-acs-0.4.0a4.json"
                ),
                "environment": "run/pyproject.toml with run/uv.lock",
                "command": "uv run python run_acs.py ../observed/run-acs-0.4.0a4.json",
                "output": "observed/run-acs-0.4.0a4.json",
                "outputSha256": hashlib.sha256(run_bytes).hexdigest(),
                "verdicts": {case["name"]: case["verdict"] for case in run["cases"]},
                "use": (
                    "every accept member is that run's context, policy and verdict; every "
                    "member's replayedVerdict is that run's verdict for its case"
                ),
            }
        ],
        "counts": {
            "accept": sum(1 for e in entries if e["expected"]["verdict"] == "accept"),
            "reject": sum(1 for e in entries if e["expected"]["verdict"] == "reject"),
        },
        "vectors": entries,
    }
    manifest["corpusDigest"] = corpus_digest(manifest, str(HERE))
    (HERE / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    rows = ["| Member | Verdict | Code | Shows |", "| --- | --- | --- | --- |"]
    rows += [
        f"| `{e['id']}` | {e['expected']['verdict']} "
        f"| {e['expected']['code'] or ''} | {e['shows']} |"
        for e in entries
    ]
    (HERE / "INDEX.md").write_text(
        "# Members\n\nGenerated by `gen_vectors.py`; do not edit.\n\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(entries)} members: {manifest['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
