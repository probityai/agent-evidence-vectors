"""Build the decision-record corpus from the format's published cases and our own break cases.

Reads ``source/cases.json`` and ``source/vectors.json``, the published test data of the
action-binding format (``dps-action-binding`` 0.3.0), after checking them against the digests in
``source/SOURCE.json``. Writes three groups of members:

* ``baseline-*``: one member per published binding case, the case's attachment with its patch
  applied, written as the published cases write documents (JSON with no whitespace, UTF-8). The
  member's expected dimensions are the case's own expected values; its verdict is ``reject`` when
  one of them failed and ``accept`` otherwise.
* ``baseline-sig-*``: the published signed attachments under the published trust policy, and the
  ways a seal or a document fails.
* ``strict-*``: attachments signed with this corpus's own test key, read with every source a
  relying party holds, where exactly one strict check refuses. Each is one case the format's text
  accepts and a relying party should not: an approval by the drafting role or the executor, one
  request observed to succeed twice, an unconfirmed person, an authority no source grants,
  consistently backdated stages, an older attachment, and a removed signature; and the shapes of a
  missing or mismatched observation (a source the relying party does not hold reads ``not_checked``
  and the strict profile refuses it; a key's retirement is read against the stated sealing time).

Writes ``members/*.json``, ``MANIFEST.json`` and ``INDEX.md``; the same sources give the same bytes.

    uv run --extra generators python corpora/vectors-decision-record/gen_vectors.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from digest import corpus_digest

HERE = Path(__file__).resolve().parent
SUITE = "decision-record/v1"
BINDING = ("specification_digests", "specification_statements", "record_statements", "action_binding",
           "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")
KEY_SEED_TEXT = "agent-evidence-vectors decision-record test key corpus-seal-1"
KEY_REF = "corpus-seal-1"


def sources() -> tuple[dict, dict]:
    pins = json.loads((HERE / "source" / "SOURCE.json").read_text(encoding="utf-8"))
    out = []
    for name in ("cases.json", "vectors.json"):
        raw = (HERE / "source" / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pins["files"][name]["sha256"]:
            raise SystemExit(f"source/{name} is not the pinned published file")
        out.append(json.loads(raw))
    return out[0], out[1]


def compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def pointer(doc: Any, path: str) -> tuple[Any, str]:
    parts = [p.replace("~1", "/").replace("~0", "~") for p in path.split("/")[1:]]
    node = doc
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node, parts[-1]


def apply_patch(doc: Any, patch: list[dict]) -> Any:
    """The published cases' patch operations: set, insert, remove, move."""
    for op in patch:
        if "set" in op or "insert" in op:
            node, key = pointer(doc, op.get("set", op.get("insert")))
            if isinstance(node, list) and "insert" in op:
                node.insert(len(node) if key == "-" else int(key), op["value"])
            elif isinstance(node, list):
                node[int(key)] = op["value"]
            else:
                node[key] = op["value"]
        elif "remove" in op:
            node, key = pointer(doc, op["remove"])
            del node[int(key) if isinstance(node, list) else key]
        else:
            node, key = pointer(doc, op["move"])
            value = node.pop(int(key) if isinstance(node, list) else key)
            target, where = pointer(doc, op["to"])
            if isinstance(target, list):
                target.insert(int(where), value)
            else:
                target[where] = value
    return doc


def first_failed(dimensions: dict[str, str]) -> str | None:
    for name in ("structural_validity", *BINDING, "issuer_signature"):
        if dimensions.get(name) == "failed":
            return f"{name}:failed"
    return None


def baseline_members(cases: dict, vectors: dict) -> list[dict]:
    out = []
    for case in cases["binding_cases"]:
        doc = apply_patch(copy.deepcopy(vectors["attachments"][case["attachment"]]), case["patch"])
        want = case["expected"]
        dims = {name: want.get(name, "verified") for name in BINDING}
        record = cases["records"][case["record"]] if case["record"] else None
        member = {"attachment": compact(doc), "record": record, "profile": "baseline"}
        code = first_failed(dims)
        out.append({"slug": f"baseline-{case['id'].lower()}", "member": member, "source_case": case["id"],
                    "expected": {"verdict": "reject" if code else "accept", "code": code,
                                 "dimensions": dims},
                    "shows": case["description"]})
    return out


def signature_members(cases: dict, vectors: dict) -> list[dict]:
    policy = vectors["trust_policy"]
    a0 = compact(vectors["attachments"]["A0"])
    without_seal = copy.deepcopy(policy)
    without_seal["keys"] = [k for k in policy["keys"] if k["key_ref"] != "org-seal-1"]
    twice = copy.deepcopy(policy)
    seal = next(k for k in twice["keys"] if k["key_ref"] == "org-seal-1")
    twice["keys"].append({**seal, "key_ref": "org-seal-1-listed-again"})
    def with_key(**changes: str) -> dict:
        changed = copy.deepcopy(policy)
        next(k for k in changed["keys"] if k["key_ref"] == "org-seal-1").update(changes)
        return changed

    rows = [
        ("baseline-sig-a0-stated-time", a0, policy, "verified", None,
         "the published signed attachment, its seal checked on the stated time under the published policy"),
        ("baseline-sig-b0", compact(vectors["attachments"]["B0"]), policy, "verified", None,
         "the published attachment whose copy is the signatures profile's seal, byte for byte"),
        ("baseline-sig-result-changed", a0.replace('"observed":"succeeded"', '"observed":"indeterminate"'),
         policy, "failed", "issuer_signature:failed", "a result changed after the attachment was signed"),
        ("baseline-sig-key-not-in-policy", a0, without_seal, "failed", "issuer_signature:failed",
         "a key the relying party's policy does not list"),
        ("baseline-sig-policy-lists-key-twice", a0, twice, "failed", "issuer_signature:failed",
         "a policy listing one public key under two references is refused, and the seal with it"),
        ("baseline-sig-key-superseded-before-sealing", a0,
         with_key(revoked_at="2026-09-30T00:00:00Z", revocation_reason="superseded"),
         "failed", "issuer_signature:failed", "a key the policy supersedes the day before the stated sealing time"),
        ("baseline-sig-key-expired-before-sealing", a0, with_key(not_after="2026-09-30T23:59:59Z"),
         "failed", "issuer_signature:failed", "a key whose validity in the policy ended before the stated sealing time"),
        ("baseline-sig-key-in-another-role", a0, with_key(role="person"),
         "failed", "issuer_signature:failed", "a key the policy lists for a person, presented as the organisation's seal"),
    ]
    out = []
    for slug, text, pol, status, code, shows in rows:
        record = None if slug == "baseline-sig-b0" else cases["records"]["R0"]
        member = {"attachment": text, "record": record, "trust_policy": pol, "profile": "baseline"}
        out.append({"slug": slug, "member": member, "source_case": None,
                    "expected": {"verdict": "reject" if code else "accept", "code": code,
                                 "dimensions": {"issuer_signature": status}}, "shows": shows})
    dup = vectors["texts"]["dup_decision_id"]["attachment_text"]
    out.append({"slug": "baseline-sig-member-named-twice",
                "member": {"attachment": dup, "record": None, "trust_policy": policy, "profile": "baseline"},
                "source_case": None,
                "expected": {"verdict": "reject", "code": "structural_validity:failed",
                             "dimensions": {"structural_validity": "failed"}},
                "shows": "decision_id named twice: not read, though a reader keeping the last member verifies the seal"})
    return out


# --- the strict members ---------------------------------------------------------------------------

def corpus_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED_TEXT.encode("utf-8")).digest())


def corpus_policy() -> dict:
    public = corpus_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0",
            "policy_ref": "urn:example:trust-policy:decision-record-corpus",
            "keys": [{"key_ref": KEY_REF, "holder": "Corpus issuer (test only)", "role": "organisation",
                      "algorithm": "Ed25519", "public_key_hex": public,
                      "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"}]}


def lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def sign(doc: dict, sealed_at: str = "2026-10-01T10:00:00Z") -> str:
    """The attachment's text with an organisation seal copy made with this corpus's key."""
    placeholder = "A" * 88
    doc = copy.deepcopy(doc)
    doc["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": KEY_REF,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal",
                               "sealed_at": sealed_at, "value_b64": placeholder}
    text = compact(doc)
    sealed = hashlib.sha256(text.encode("utf-8")).digest()
    fields = [b"dps-signatures", b"0.2.0", b"organisation_seal", KEY_REF.encode(), b"attachment",
              doc["decision_id"].encode(), sealed, sealed_at.encode()]
    signed = b"DPS-SIG\x00" + b"".join(lp(f) for f in fields)
    value = base64.b64encode(corpus_key().sign(signed)).decode("ascii")
    return text.replace(f'"value_b64":"{placeholder}"', f'"value_b64":"{value}"')


def relying_party(doc: dict, text: str) -> dict:
    """Every source a relying party could hold, each confirming what the attachment says."""
    stages = doc["stages"]
    actors = sorted({s[k] for s in stages for k in ("reviewer_ref", "actor_ref")
                     if k in s and s.get("kind") != "proposal"})
    grants = [{"actor_ref": s["actor_ref"], "authority_ref": s["authority"]["authority_ref"]}
              for s in stages if s.get("kind") in ("outcome", "standing_approval", "change_authorisation")
              and "authority" in s]
    observed = {s["stage_id"]: s["at"] for s in stages
                if s.get("kind") in ("outcome", "standing_approval", "change_authorisation", "attempt")}
    return {"identities": {a: {"status": "verified", "source": "urn:example:directory:corpus"} for a in actors},
            "authority_grants": grants,
            "independent_times": {"tolerance_seconds": 60, "observed": observed},
            "latest": {doc["decision_id"]: hashlib.sha256(text.encode("utf-8")).hexdigest()}}


SECOND_SUCCESS = [
    {"insert": "/stages/7", "value": {"stage_id": "c2", "kind": "recheck", "at": "2026-10-01T09:20:00Z",
                                      "request_ref": "q1", "result": "authorised",
                                      "authority_source_ref": "urn:example:permission-service:snapshot-101-2"}},
    {"insert": "/stages/8", "value": {"stage_id": "x2", "kind": "attempt", "at": "2026-10-01T09:20:05Z",
                                      "request_ref": "q1", "recheck_ref": "c2", "spec_digest": "",
                                      "executor_ref": "urn:example:service:payment-executor"}},
    {"insert": "/stages/9", "value": {"stage_id": "r2", "kind": "result", "at": "2026-10-01T09:20:09Z",
                                      "attempt_ref": "x2", "observed": "succeeded", "basis": "target_response"}}]


def _strict_rows(cases: dict, vectors: dict) -> list[tuple]:
    """(slug, attachment patch, record patch, source change, dimension, status, shows)."""
    second = copy.deepcopy(SECOND_SUCCESS)
    second[1]["value"]["spec_digest"] = vectors["attachments"]["A0"]["stages"][0]["spec_digest"]
    drafting = "urn:example:role:payables-drafting"
    executor = "urn:example:service:payment-executor"
    requester = "urn:example:service:payables"
    l69 = next(c for c in cases["binding_cases"] if c["id"] == "L69")
    return [
        ("strict-all-sources-confirm", [], [], None, None, "verified",
         "a signed attachment every source the relying party holds confirms"),
        ("strict-approved-by-drafting-role",
         [{"set": "/stages/1/reviewer_ref", "value": drafting}, {"set": "/stages/2/actor_ref", "value": drafting}],
         [{"set": "/affirmation_record/actor_identity", "value": drafting}], None,
         "approver_independence", "failed", "the AI worker's own role reviews and approves its proposal"),
        ("strict-approved-by-executor",
         [{"set": "/stages/1/reviewer_ref", "value": executor}, {"set": "/stages/2/actor_ref", "value": executor}],
         [{"set": "/affirmation_record/actor_identity", "value": executor}], None,
         "approver_independence", "failed", "the executing service reviews and approves the action"),
        ("strict-one-request-succeeds-twice", second, [], None, "single_effect_per_request", "failed",
         "one approval and one request, the action attempted twice and observed to succeed twice"),
        ("strict-retry-after-indeterminate", [{"set": "/stages/6/observed", "value": "indeterminate"}] + second,
         [], None, "single_effect_per_request", "not_checked",
         "a retry after an indeterminate attempt, with no observation at the target of how many effects it saw"),
        ("strict-person-not-confirmed", [], [], ("identity", "owner-example-1"), "identity_independent", "failed",
         "the approver named is not confirmed by the relying party's identity source"),
        ("strict-change-by-unnamed-service", l69["patch"], [], ("grants", None), "authority_independent",
         "failed", "a change authorised by a service the attachment does not name, which no source grants"),
        ("strict-stages-backdated", [], [], ("time", "x1"), "time_independent", "failed",
         "every stage dated consistently, the attempt observed independently two hours later"),
        ("strict-older-attachment", [], [], ("latest", None), "latest_attachment", "failed",
         "an attachment of the decision older than the one the relying party holds"),
        ("strict-signature-removed", [], [], ("unsigned", None), "signature_required", "failed",
         "the attachment presented with its issuer signature removed"),
        ("strict-approved-by-requester",
         [{"set": "/stages/1/reviewer_ref", "value": requester}, {"set": "/stages/2/actor_ref", "value": requester}],
         [{"set": "/affirmation_record/actor_identity", "value": requester}], None,
         "approver_independence", "failed", "the service that requested the action reviews and approves it"),
        ("strict-authority-granted-for-another-charter", [], [], ("grants-other", None), "authority_independent",
         "failed", "the approver holds a grant, but under another charter than the one the approval cites"),
        ("strict-identity-source-says-failed", [], [], ("identity", "owner-example-1", "failed"),
         "identity_independent", "failed", "the relying party's identity source reports the approver as failed"),
        ("strict-person-absent-from-identity-source", [], [], ("identity-absent", "owner-example-1"),
         "identity_independent", "failed", "the approver named is unknown to the relying party's identity source"),
        ("strict-approval-observed-after-execution", [], [], ("approved-late", "o1"), "time_independent", "failed",
         "the issuer dates the approval before the attempt; the independent clock puts it after the attempt ran"),
        ("strict-no-identity-source", [], [], ("drop", "identities"), "identity_independent", "not_checked",
         "the relying party holds no identity source, so the approver's identity was never observed"),
        ("strict-no-authority-source", [], [], ("drop", "authority_grants"), "authority_independent",
         "not_checked", "the relying party holds no authority source, so no grant was observed"),
        ("strict-no-independent-clock", [], [], ("drop", "independent_times"), "time_independent",
         "not_checked", "the relying party holds no independent observation of when the stages happened"),
        ("strict-latest-attachment-unknown", [], [], ("drop", "latest"), "latest_attachment", "not_checked",
         "the relying party holds no record of which attachment of the decision is the latest"),
        ("strict-no-trust-policy", [], [], ("no-policy", None), "signature_required", "failed",
         "a signed attachment read with no trust policy, so no key is held for its signature"),
        ("strict-seal-key-compromised-backdated", [], [], ("key-compromised", None), "signature_required",
         "failed", "a key later revoked as compromised signs a time before the revocation; only an independent "
                   "timestamp can say when it signed, and none is read"),
    ]


def strict_members(cases: dict, vectors: dict) -> list[dict]:
    out = []
    for slug, patch, record_patch, change, dimension, status, shows in _strict_rows(cases, vectors):
        doc = apply_patch(copy.deepcopy(vectors["attachments"]["A0"]), copy.deepcopy(patch))
        doc.pop("issuer_signature", None)
        record = compact(apply_patch(json.loads(cases["records"]["R0"]), record_patch))
        text = compact(doc) if change and change[0] == "unsigned" else sign(doc)
        party = relying_party(doc, text)
        policy = corpus_policy()
        if change and change[0] == "identity":
            party["identities"][change[1]] = {"status": change[2] if len(change) > 2 else "not_verified",
                                              "source": "urn:example:directory:corpus"}
        elif change and change[0] == "identity-absent":
            del party["identities"][change[1]]
        elif change and change[0] == "grants-other":
            party["authority_grants"] = [{**g, "authority_ref": g["authority_ref"] + "-other"}
                                         for g in party["authority_grants"]]
        elif change and change[0] == "approved-late":
            party["independent_times"]["tolerance_seconds"] = 3600
            party["independent_times"]["observed"][change[1]] = "2026-10-01T09:40:00Z"
        elif change and change[0] == "drop":
            del party[change[1]]
        elif change and change[0] == "key-compromised":
            policy["keys"][0].update({"revoked_at": "2026-10-01T12:00:00Z", "revocation_reason": "compromised"})
        elif change and change[0] == "grants":
            party["authority_grants"] = [g for g in party["authority_grants"]
                                         if g["actor_ref"] == "owner-example-1"]
        elif change and change[0] == "time":
            party["independent_times"]["observed"][change[1]] = "2026-10-01T11:16:05Z"
        elif change and change[0] == "latest":
            party["latest"] = {doc["decision_id"]: hashlib.sha256(b"a later attachment").hexdigest()}
        member = {"attachment": text, "record": record, "trust_policy": policy,
                  "relying_party": party, "profile": "strict"}
        if change and change[0] == "no-policy":
            del member["trust_policy"]
        code = None if dimension is None else f"{dimension}:{status}"
        dims = {"strict": {dimension: status}} if dimension else {"strict": {}}
        out.append({"slug": slug, "member": member, "source_case": None,
                    "expected": {"verdict": "reject" if code else "accept", "code": code, "dimensions": dims},
                    "shows": shows})
    return out


def build() -> list[dict]:
    cases, vectors = sources()
    return baseline_members(cases, vectors) + signature_members(cases, vectors) + strict_members(cases, vectors)


def main() -> int:
    members = build()
    out = HERE / "members"
    out.mkdir(exist_ok=True)
    for stale in out.glob("*.json"):
        stale.unlink()
    entries = []
    for m in members:
        path = f"members/{m['slug']}.json"
        (HERE / path).write_text(json.dumps(m["member"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        entry = {"id": m["slug"], "path": path, "profile": m["member"]["profile"], "expected": m["expected"],
                 "shows": m["shows"]}
        if m["source_case"]:
            entry["sourceCase"] = m["source_case"]
        entries.append(entry)
    pins = json.loads((HERE / "source" / "SOURCE.json").read_text(encoding="utf-8"))
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "format": {"profile": "dps-action-binding", "profile_version": "0.3.0"},
        "source": {"repository": pins["repository"], "commit": pins["commit"], "path": pins["path"],
                   "files": pins["files"]},
        "profiles": {
            "baseline": "refuses a structure, binding dimension or issuer signature that failed; "
                        "not_checked and unavailable stay as reported",
            "strict": "also requires every binding dimension, the issuer signature and each strict "
                      "dimension verified, against sources the relying party holds",
        },
        "keyRecipe": f'sha256("{KEY_SEED_TEXT}")',
        "keyNote": "PUBLISHED TEST KEY, derived from a fixed seed in gen_vectors.py. It signs the strict "
                   "members; the baseline members carry the format's own published test signatures.",
        "counts": {
            "accept": sum(1 for e in entries if e["expected"]["verdict"] == "accept"),
            "reject": sum(1 for e in entries if e["expected"]["verdict"] == "reject"),
        },
        "vectors": entries,
    }
    manifest["corpusDigest"] = corpus_digest(manifest, str(HERE))
    (HERE / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                                        encoding="utf-8")
    rows = ["| Member | Profile | Verdict | Code | Shows |", "| --- | --- | --- | --- | --- |"]
    rows += [f"| `{e['id']}` | {e['profile']} | {e['expected']['verdict']} | {e['expected']['code'] or ''} "
             f"| {e['shows'].replace('|', '/')} |" for e in entries]
    (HERE / "INDEX.md").write_text("# Members\n\nGenerated by `gen_vectors.py`; do not edit.\n\n"
                                   + "\n".join(rows) + "\n", encoding="utf-8")
    print(f"wrote {len(entries)} members: {manifest['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
