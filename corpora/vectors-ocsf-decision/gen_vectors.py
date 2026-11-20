"""Build the OCSF decision-record corpus from the format's published samples and our own break cases.

Reads ``source/SAMPLE-OUTPUT*.md``, the published sample outputs of the Praxis Policy Engine's
``ocsf-audit`` sink that AID-EMIT-1 names as its conformance vectors, after checking them against the
digests in ``source/SOURCE.json``. Writes members of two profiles:

* ``baseline-*``: the published records as emitted (the signed pair under the published demo key, the
  nine unchained decision records), a chain this generator emits over the published decision records
  with this corpus's test key, and each way a stream breaks: a member named twice riding a valid seal,
  a swapped or unknown key id, a record re-signed under a retired key or a key of another authority,
  a dropped tail with an independent head, a deleted record, changed content, a fingerprint recomputed
  without a new signature, a fork, a substituted uid, a stream gap, ``emission_seq`` disorder, a ruling
  that reads two ways, a suppressed deny no flag reports, and a policy that lists one key twice. One
  member keeps a dropped tail with no head, which the format cannot show: it reads ``not_checked``.
* ``strict-*``: what a relying party should also require: a complete signed chain with an independent
  head, and refusals for two live keys of one authority, no head, an unsigned chain rewritten end to
  end, an integer a double cannot hold, and a chain whose opening is not supplied.

The emitter here is this corpus's own implementation of the published rule; it does not import the
reader that judges it. Writes ``members/*.json``, ``MANIFEST.json`` and ``INDEX.md``; the same sources
give the same bytes (ECDSA signatures are deterministic, RFC 6979).

    uv run --extra generators python corpora/vectors-ocsf-decision/gen_vectors.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from digest import corpus_digest

HERE = Path(__file__).resolve().parent
SUITE = "ocsf-decision/v1"
PAYLOAD_TYPE = b"application/vnd.ocsf.event+json"
AUTHORITY = "org-f3576cf6"
KEY_SEED_TEXT = "agent-evidence-vectors ocsf-decision test key corpus-key-1"
RETIRED_SEED_TEXT = "agent-evidence-vectors ocsf-decision test key corpus-key-0"
FP = {"algorithm": "SHA-256", "algorithm_id": 3, "encoding": "Hex", "encoding_id": 1,
      "serialization": "JCS", "serialization_id": 2}
SIG = [{"algorithm": "ECDSA", "algorithm_id": 3, "serialization": "DSSE", "serialization_id": 5}]
CHAIN_UID = "gw-1-corpus"


# --- sources --------------------------------------------------------------------------------------

def published(name: str) -> list[dict]:
    pins = json.loads((HERE / "source" / "SOURCE.json").read_text(encoding="utf-8"))["files"]
    raw = (HERE / "source" / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins[name]["sha256"]:
        raise SystemExit(f"source/{name} is not the pinned published file")
    out = []
    for block in re.findall(r"```(?:jsonc|text)\n(.*?)```", raw.decode("utf-8"), re.S):
        for part in re.split(r"^// =====.*$", block, flags=re.M):
            body = "\n".join(line for line in part.splitlines() if not line.startswith("//")).strip()
            if body.startswith("{"):
                out.append(json.loads(body))
    return out


# --- the published rule, as this corpus implements it ---------------------------------------------

def canon(value: Any) -> str:
    """RFC 8785 bytes with integers written exactly; these records carry no non-integer number."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canon(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canon(value[k]) for k in keys) + "}"
    raise TypeError(f"{type(value).__name__} is outside these records")


def covered(event: dict) -> bytes:
    """The bytes the fingerprint and signature cover: the record minus the four unsigned members."""
    event = copy.deepcopy(event)
    att = event["attestation_list"][0]
    att.pop("fingerprint", None)
    att.pop("signatures", None)
    un = event.get("unmapped", {})
    un.pop("signature_b64", None)
    un.pop("signature_key_id", None)
    if "unmapped" in event and not un:
        del event["unmapped"]
    return canon(event).encode("utf-8")


def pae(data: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE), PAYLOAD_TYPE, len(data), data)


def key(seed: str) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big"), ec.SECP256R1())


DEMO = ec.derive_private_key(int.from_bytes(b"\x42" * 32, "big"), ec.SECP256R1())
CORPUS, RETIRED = key(KEY_SEED_TEXT), key(RETIRED_SEED_TEXT)


def seal(event: dict, signer: ec.EllipticCurvePrivateKey | None, kid: str | None) -> dict:
    att = event["attestation_list"][0]
    att.pop("fingerprint", None)
    att.pop("signatures", None)
    un = event.setdefault("unmapped", {})
    un.pop("signature_b64", None)
    un.pop("signature_key_id", None)
    data = covered(event)
    att["fingerprint"] = {**FP, "value": hashlib.sha256(data).hexdigest()}
    if signer is not None:
        att["signatures"] = copy.deepcopy(SIG)
        sig = signer.sign(pae(data), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        un["signature_b64"] = base64.b64encode(sig).decode("ascii")
        if kid is not None:
            un["signature_key_id"] = kid
    if not un:
        del event["unmapped"]
    return event


def emit(bodies: list[dict], signer=CORPUS, kid: str | None = "corpus-key-1") -> list[dict]:
    out: list[dict] = []
    for i, body in enumerate(bodies):
        event = copy.deepcopy(body)
        event.setdefault("metadata", {})["uid"] = f"{CHAIN_UID}-{i:06d}"
        profiles = event["metadata"].setdefault("profiles", [])
        if "record_integrity" not in profiles:
            profiles.append("record_integrity")
        att = {"uid": f"{CHAIN_UID}-att-{i:06d}", "chain_uid": CHAIN_UID, "authority_uid": AUTHORITY}
        if out:
            att["prev_event"] = {"uid": out[-1]["metadata"]["uid"], "type_uid": out[-1]["type_uid"],
                                 "fingerprint": copy.deepcopy(out[-1]["attestation_list"][0]["fingerprint"])}
        event["attestation_list"] = [att]
        out.append(seal(event, signer, kid))
    return out


def jwk(signer: ec.EllipticCurvePrivateKey, kid: str, authority: str = AUTHORITY, **window: str) -> dict:
    n = signer.public_key().public_numbers()

    def enc(v: int) -> str:
        return base64.urlsafe_b64encode(v.to_bytes(32, "big")).decode("ascii").rstrip("=")

    return {"kty": "EC", "crv": "P-256", "kid": kid, "x": enc(n.x), "y": enc(n.y), "authority_uid": authority,
            **window}


def head(record: dict) -> dict:
    return {"chain_uid": record["attestation_list"][0]["chain_uid"], "uid": record["metadata"]["uid"],
            "fingerprint": record["attestation_list"][0]["fingerprint"]["value"]}


def lines(records: list[dict]) -> str:
    return "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records)


DEMO_POLICY = {"keys": [jwk(DEMO, "demo-key-2026-07")]}
POLICY = {"keys": [jwk(CORPUS, "corpus-key-1", not_before="2026-01-01T00:00:00Z"),
                   jwk(RETIRED, "corpus-key-0", not_before="2025-01-01T00:00:00Z",
                       not_after="2025-12-31T23:59:59Z")]}


# --- members --------------------------------------------------------------------------------------

def members() -> list[dict]:
    pair = published("SAMPLE-OUTPUT.md")
    decisions = published("SAMPLE-OUTPUT-DECISIONS.md") + published("SAMPLE-OUTPUT-PROVENANCE.md")
    chain = emit(decisions)
    opened = copy.deepcopy(decisions)
    for i, body in enumerate(opened):
        body["unmapped"]["aid.stream"].update(stream_seq=i, emission_seq=i)
    full = emit(opened)
    out: list[dict] = []

    def add(slug, records, expected, shows, *, trust=POLICY, heads=None, profile="baseline", raw=None):
        member = {"records": raw if raw is not None else lines(records), "trust_policy": trust,
                  "relying_party": {"heads": heads} if heads is not None else None, "profile": profile}
        code = expected.pop("code", None)
        out.append({"slug": slug, "member": member,
                    "expected": {"verdict": "reject" if code else "accept", "code": code, "dimensions": expected},
                    "shows": shows})

    add("baseline-published-signed-pair", pair, {"fingerprint": "verified", "signature": "verified",
        "key_binding": "verified", "chain_links": "verified", "tail": "not_checked"},
        "the two published signed records, under the published demo key", trust=DEMO_POLICY)
    add("baseline-published-decisions-unchained", decisions, {"fingerprint": "unavailable",
        "signature": "unavailable", "stream_sequence": "verified", "decision_consistency": "verified"},
        "the nine published decision records: unchained and unsigned, one dense stream from stream_seq 41",
        trust=None)
    sealed = json.dumps(pair[0], separators=(",", ":"))
    add("baseline-published-duplicate-member-rides-seal", None,
        {"code": "structural_validity:failed", "structural_validity": "failed"},
        "an earlier disposition Blocked injected into the published signed record; a last-wins reader "
        "recomputes the sealed fingerprint and the signature verifies, a first-wins reader sees Blocked",
        trust=DEMO_POLICY, raw=sealed.replace('"disposition":"Logged"',
                                              '"disposition":"Blocked","disposition_id":2,"disposition":"Logged"', 1)
        + "\n")
    add("baseline-published-duplicate-member-escaped", None,
        {"code": "structural_validity:failed", "structural_validity": "failed"},
        "the same injection with the member name spelled \\u0061ction", trust=DEMO_POLICY,
        raw=sealed.replace('"action":"Observed"', '"\\u0061ction":"Denied","action":"Observed"', 1) + "\n")
    add("baseline-chain-as-emitted", chain, {"fingerprint": "verified", "signature": "verified",
        "key_binding": "verified", "tail": "verified"},
        "a signed chain over the published decision records, with the head the relying party holds",
        heads=[head(chain[-1])])

    swapped = copy.deepcopy(chain)
    swapped[2]["unmapped"]["signature_key_id"] = "corpus-key-0"
    add("baseline-key-id-swapped", swapped, {"code": "key_binding:failed", "signature": "verified",
        "key_binding": "failed"}, "the unsigned key id names the retired key; the current key verified")
    unknown = copy.deepcopy(chain)
    unknown[0]["unmapped"]["signature_key_id"] = "kid-nobody-holds"
    add("baseline-key-id-unknown", unknown, {"code": "key_binding:failed"},
        "the unsigned key id names a key the relying party does not hold")
    retired = copy.deepcopy(chain)
    retired[-1] = seal(retired[-1], RETIRED, "corpus-key-0")
    add("baseline-resigned-under-retired-key", retired, {"code": "key_binding:failed", "signature": "verified"},
        "the last record re-signed under the retired key, its key id naming that key; the key's window "
        "ended before the record's time")
    add("baseline-key-of-another-authority", chain, {"code": "key_binding:failed"},
        "the only key that verifies belongs to another authority than the signed authority_uid",
        trust={"keys": [jwk(CORPUS, "corpus-key-1", "org-someone-else")]})
    add("baseline-policy-lists-key-twice", chain, {"code": "trust_policy:failed", "signature": "not_checked"},
        "a relying-party policy listing one public key under two key ids",
        trust={"keys": [jwk(CORPUS, "corpus-key-1"), jwk(CORPUS, "corpus-key-1b")]})

    add("baseline-tail-dropped-with-head", chain[:-3], {"code": "tail:failed", "tail": "failed"},
        "the last three records deleted; the relying party holds the head independently", heads=[head(chain[-1])])
    add("baseline-tail-dropped-no-head", chain[:-3], {"tail": "not_checked", "chain_links": "verified"},
        "the last three records deleted with no independent head: the format cannot show it, so the tail "
        "reads not_checked and never verified")
    add("baseline-record-deleted", chain[:4] + chain[5:], {"code": "chain_gaps:failed",
        "stream_sequence": "failed"}, "one record deleted from the middle of the chain")
    changed = copy.deepcopy(chain)
    changed[2]["unmapped"]["aid.decision"]["steps"][0]["detail"]["reason"] = "granted"
    add("baseline-content-changed", changed, {"code": "fingerprint:failed"},
        "a denying step's reason changed after sealing")
    refp = copy.deepcopy(changed)
    refp[2]["attestation_list"][0]["fingerprint"]["value"] = hashlib.sha256(covered(refp[2])).hexdigest()
    add("baseline-refingerprinted-not-resigned", refp, {"code": "signature:failed", "fingerprint": "verified"},
        "the changed record with its fingerprint recomputed and the old signature kept")
    fork = copy.deepcopy(chain[1])
    fork["unmapped"]["aid.span"]["span_id"] = "00f067aa0ba9ffff"
    fork["unmapped"]["aid.stream"].update(stream_seq=99, emission_seq=99)
    fork["metadata"]["uid"] = f"{CHAIN_UID}-000099"
    fork["attestation_list"][0]["uid"] = f"{CHAIN_UID}-att-000099"
    add("baseline-chain-fork", chain + [seal(fork, CORPUS, "corpus-key-1")], {"code": "chain_links:failed"},
        "a second signed record naming the same predecessor")
    sub = copy.deepcopy(chain[3])
    sub["unmapped"]["aid.span"]["span_id"] = "00f067aa0ba9eeee"
    add("baseline-uid-substituted", chain + [seal(sub, CORPUS, "corpus-key-1")],
        {"code": "record_uniqueness:failed"}, "two signed records claim one uid with different content")
    add("baseline-stream-gap", decisions[:2] + decisions[3:], {"code": "stream_sequence:failed"},
        "stream_seq 43 missing between records that are supplied", trust=None)
    disorder = copy.deepcopy(decisions)
    disorder[4]["unmapped"]["aid.stream"]["emission_seq"] = 1
    add("baseline-emission-disorder", disorder, {"code": "stream_sequence:failed"},
        "emission_seq goes back while stream_seq advances", trust=None)
    twoway = copy.deepcopy(decisions)
    twoway[2]["disposition"] = "Allowed"
    add("baseline-ruling-reads-two-ways", twoway, {"code": "decision_consistency:failed"},
        "disposition says Allowed while disposition_id, action and the verdict say a deny", trust=None)
    unflagged = copy.deepcopy(decisions)
    del unflagged[3]["unmapped"]["aid.decision"]["deny_ignored"]
    add("baseline-suppressed-deny-unflagged", unflagged, {"code": "decision_consistency:failed"},
        "a deny_ignored step with no flat deny_ignored flag, so the SIEM query for suppressed denies misses it",
        trust=None)

    add("strict-chain-complete", full, {"strict": {name: "verified" for name in (
        "signature_required", "key_named_by_signed_bytes", "tail_anchored", "opening_supplied",
        "numbers_interoperable")}}, "a signed chain from its genesis and stream_seq 0, one key of the "
        "authority, with an independent head", heads=[head(full[-1])], profile="strict")
    add("strict-published-pair-with-head", pair, {}, "the published signed pair with an independent head",
        trust=DEMO_POLICY, heads=[head(pair[-1])], profile="strict")
    add("strict-two-live-keys", full, {"code": "key_named_by_signed_bytes:unavailable"},
        "two keys of the authority valid at the records' time: which one signed rests on the unsigned key id",
        trust={"keys": [jwk(CORPUS, "corpus-key-1"), jwk(RETIRED, "corpus-key-0")]},
        heads=[head(full[-1])], profile="strict")
    add("strict-no-head", full, {"code": "tail_anchored:not_checked"},
        "a complete signed chain with no independent head", profile="strict")
    rewritten = copy.deepcopy(opened)
    deny = rewritten[2]
    deny.update(action="Allowed", action_id=1, disposition="Allowed", disposition_id=1)
    for member in ("status_id", "status_code", "status_detail"):
        deny.pop(member, None)
    deny["unmapped"]["aid.decision"]["verdict"] = "allow"
    deny["unmapped"]["aid.decision"]["steps"][0]["action"] = "allowed"
    del deny["unmapped"]["aid.decision"]["steps"][0]["detail"]
    unsigned = emit(rewritten, signer=None)
    add("strict-unsigned-chain-rewritten", unsigned, {"code": "signature_required:unavailable"},
        "an unsigned chain with a deny rewritten to an allow and every fingerprint recomputed: baseline "
        "accepts it, as the format's default signing: none allows", heads=[head(unsigned[-1])], profile="strict")
    wide = copy.deepcopy(opened)
    for body in wide:
        body["unmapped"]["aid.stream"]["epoch"] = 1755648000123456789
    wide_chain = emit(wide)
    add("strict-epoch-a-double-cannot-hold", wide_chain, {"code": "numbers_interoperable:failed"},
        "a nanosecond epoch past 2**53 that no double holds: a double-based verifier recomputes another "
        "fingerprint", heads=[head(wide_chain[-1])], profile="strict")
    add("strict-opening-not-supplied", full[2:], {"code": "opening_supplied:unavailable"},
        "the chain's first two records not supplied", heads=[head(full[-1])], profile="strict")
    return out


def main() -> int:
    built = members()
    out = HERE / "members"
    out.mkdir(exist_ok=True)
    for stale in out.glob("*.json"):
        stale.unlink()
    entries = []
    for m in built:
        path = f"members/{m['slug']}.json"
        (HERE / path).write_text(json.dumps(m["member"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        entries.append({"id": m["slug"], "path": path, "profile": m["member"]["profile"],
                        "expected": m["expected"], "shows": m["shows"]})
    pins = json.loads((HERE / "source" / "SOURCE.json").read_text(encoding="utf-8"))
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "format": {"class_uid": 6003, "rule": "AID-EMIT-1 record_integrity",
                   "payload_type": PAYLOAD_TYPE.decode("ascii")},
        "source": {"repository": pins["repository"], "commit": pins["commit"], "path": pins["path"],
                   "files": pins["files"]},
        "profiles": {
            "baseline": "refuses a record or stream dimension that failed; not_checked and unavailable "
                        "stay as reported",
            "strict": "also requires every record signed, the key named by the signed bytes and the "
                      "relying party's key set, an anchored tail, the opening supplied and interoperable numbers",
        },
        "keyRecipe": f'P-256 scalar sha256("{KEY_SEED_TEXT}"); retired key sha256("{RETIRED_SEED_TEXT}")',
        "keyNote": "PUBLISHED TEST KEYS, derived from fixed seeds in gen_vectors.py. The published pair is "
                   "signed with the format's own demo key, the scalar of 32 bytes 0x42.",
        "counts": {
            "accept": sum(1 for e in entries if e["expected"]["verdict"] == "accept"),
            "reject": sum(1 for e in entries if e["expected"]["verdict"] == "reject"),
        },
        "vectors": entries,
    }
    manifest["corpusDigest"] = corpus_digest(manifest, str(HERE))
    (HERE / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rows = ["| Member | Profile | Verdict | Code | Shows |", "| --- | --- | --- | --- | --- |"]
    rows += [f"| `{e['id']}` | {e['profile']} | {e['expected']['verdict']} | {e['expected']['code'] or ''} "
             f"| {e['shows'].replace('|', '/')} |" for e in entries]
    (HERE / "INDEX.md").write_text("# Members\n\nGenerated by `gen_vectors.py`; do not edit.\n\n"
                                   + "\n".join(rows) + "\n", encoding="utf-8")
    print(f"wrote {len(entries)} members: {manifest['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
