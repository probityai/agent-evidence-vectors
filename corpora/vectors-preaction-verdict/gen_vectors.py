"""Build the pre-action verdict cases byte-identically.

Every case is a directory with one ``case.json``: a signed verdict (a Nostr event signed with
BIP-340), the keys the relying party trusts, what the relying party knows about the action,
and, for the authenticated-time cases, the block headers it holds and the anchor that goes
with the record. Each denied case departs from a conformant case in one place. Keys come from
fixed seeds and the signer uses a fixed auxiliary value, so the corpus regenerates byte for
byte. No key here signs anything outside this corpus.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import preactionverdict as reader  # noqa: E402

SUITE = reader.SUITE
SCHEMA_TAG = reader.SCHEMA_TAG
BASE_TIME = 1_790_000_000
CREATED = BASE_TIME + 10_000
BEACON_TIME = CREATED - 600
EXECUTED = CREATED + 3_600
ANCHOR_TIME = CREATED + 600
PREIMAGE_FIELDS = ["artifact_hash", "verdict", "rationale_hash", "private_note"]
CREDITS = [{
    "name": "babyblueviper1",
    "for": "the record shape, the eight-step reader and the key-binding negative",
    "source": ("https://github.com/babyblueviper1/preaction-governance-conformance/tree/"
               "641c0684698b236d8a4d350aa30bdad900f34167/vectors/preaction-verdict"),
}]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _seckey(label: str) -> int:
    return int.from_bytes(hashlib.sha256(f"preaction-verdict/v1 seed {label}".encode()).digest(),
                          "big") % (reader.N - 1) + 1


def _pubkey(secret: int) -> str:
    point = reader.point_mul(reader.G, secret)
    assert point is not None
    return point[0].to_bytes(32, "big").hex()


SECRETS = {name: _seckey(name) for name in ("issuer-1", "issuer-2", "test", "stranger")}
PUBKEYS = {name: _pubkey(secret) for name, secret in SECRETS.items()}


def schnorr_sign(message: bytes, secret: int) -> bytes:
    """BIP-340 signing with an all-zero auxiliary value, so signatures are deterministic."""
    point = reader.point_mul(reader.G, secret)
    assert point is not None
    d = secret if point[1] % 2 == 0 else reader.N - secret
    px = point[0].to_bytes(32, "big")
    aux = reader.tagged_hash("BIP0340/aux", bytes(32))
    t = (d ^ int.from_bytes(aux, "big")).to_bytes(32, "big")
    k0 = int.from_bytes(reader.tagged_hash("BIP0340/nonce", t + px + message), "big") % reader.N
    r_point = reader.point_mul(reader.G, k0)
    assert r_point is not None
    k = k0 if r_point[1] % 2 == 0 else reader.N - k0
    rx = r_point[0].to_bytes(32, "big")
    e = int.from_bytes(reader.tagged_hash("BIP0340/challenge", rx + px + message), "big")
    sig = rx + ((k + e % reader.N * d) % reader.N).to_bytes(32, "big")
    assert reader.schnorr_verify(message, bytes.fromhex(px.hex()), sig)
    return sig


def action_hash(label: str = "action-1") -> str:
    return _sha(f"preaction-verdict/v1 action {label}".encode())


def header(label: str, stamped: int, root: bytes | None = None) -> bytes:
    """An 80-byte block header at ``stamped``; the root is a labelled hash unless given."""
    merkle = root if root is not None else hashlib.sha256(f"root {label}".encode()).digest()
    return ((0x20000000).to_bytes(4, "little") + hashlib.sha256(f"prev {label}".encode()).digest()
            + merkle + stamped.to_bytes(4, "little") + (0x207FFFFF).to_bytes(4, "little")
            + (0).to_bytes(4, "little"))


BEACON_HEADER = header("beacon", BEACON_TIME)


def base_content(artifact: str, signer: str = "issuer-1", **changes: Any) -> dict[str, Any]:
    """The conformant content object; ``None`` removes a member. ``decision_ref`` is set last."""
    body: dict[str, Any] = {
        "artifact_hash": artifact,
        "confidence_pct": 90,
        "decision_ref_preimage_fields": list(PREIMAGE_FIELDS),
        "freshness_beacon": {"block_time": BEACON_TIME,
                             "hash": reader.header_hash(BEACON_HEADER), "height": 5},
        "key_id": PUBKEYS[signer],
        "rationale_hash": _sha(b"rationale"),
        "verdict": "approve",
        "verifier_pubkey": PUBKEYS[signer],
    }
    for key, value in changes.items():
        if value is None:
            body.pop(key, None)
        else:
            body[key] = value
    if "decision_ref" not in changes:
        body["decision_ref"] = reader.decision_ref(body)
    return body


def serialise(content: dict[str, Any]) -> str:
    return json.dumps(content, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sign_record(content: dict[str, Any] | str, signer: str = "issuer-1",
                created: int = CREATED, tags: list[list[str]] | None = None) -> dict[str, Any]:
    """A signed record over ``content`` (a dict, or text taken as given)."""
    record: dict[str, Any] = {
        "content": content if isinstance(content, str) else serialise(content),
        "created_at": created, "kind": 30078, "pubkey": PUBKEYS[signer],
        "tags": [list(SCHEMA_TAG)] if tags is None else tags,
    }
    record["id"] = reader.event_id(record)
    record["sig"] = schnorr_sign(bytes.fromhex(record["id"]), SECRETS[signer]).hex()
    return record


def anchor_for(record: dict[str, Any], stamped: int = ANCHOR_TIME,
               commitment: str | None = None) -> tuple[dict[str, Any], bytes]:
    """An anchor that commits the record's id, and the header it folds into."""
    commit = commitment or record["id"]
    path = [{"hash": _sha(b"sibling 1"), "side": "right"},
            {"hash": _sha(b"sibling 2"), "side": "left"}]
    stamp = header("anchor", stamped, reader.fold(commit, path))
    return {"commitment": commit, "header": stamp.hex(), "path": path}, stamp


def case(record: dict[str, Any], *, keys: list[str] | None = None, action: str | None = None,
         executed: int = EXECUTED, max_age: int | None = None,
         headers: list[bytes] | None = None, anchor: dict[str, Any] | None = None,
         contract: str | None = reader.CONTRACT_ID) -> dict[str, Any]:
    """One case; every argument is a departure from the conformant case."""
    party: dict[str, Any] = {
        "actionHash": action or json.loads(record["content"]).get("artifact_hash", action_hash()),
        "executedAt": executed,
    }
    if max_age is not None:
        party["maxAgeSeconds"] = max_age
    if headers is not None:
        party["trustedHeaders"] = [h.hex() for h in headers]
    body: dict[str, Any] = {
        "keySet": keys if keys is not None else [PUBKEYS["issuer-1"]],
        "record": record, "relyingParty": party,
    }
    if anchor is not None:
        body["anchor"] = anchor
    if contract is not None:
        body["contractId"] = contract
    return body


def issuer_clock(name: str = "base", **changes: Any) -> dict[str, Any]:
    """A conformant record checked by the issuer's clock alone."""
    return case(sign_record(base_content(action_hash(name), **changes)), action=action_hash(name))


def authenticated(name: str, content: dict[str, Any] | None = None, **overrides: Any
                  ) -> dict[str, Any]:
    """A conformant record whose time is shown by headers the relying party holds."""
    artifact = action_hash(name)
    record = sign_record(content or base_content(artifact))
    anchor, stamp = anchor_for(record)
    arguments: dict[str, Any] = {"action": artifact, "headers": [BEACON_HEADER, stamp],
                                 "anchor": anchor}
    arguments.update(overrides)
    return case(record, **arguments)


Case = tuple[str, dict[str, Any], str, str, str]
ISSUER = reader.REASON_ISSUER_CLOCK
ANCHORED = reader.REASON_ANCHORED


def _allow() -> list[Case]:
    second = sign_record(base_content(action_hash("second"), "issuer-2"), "issuer-2")
    unicode_content = base_content(action_hash("unicode"), rationale="café ✓")
    explicit_null = base_content(action_hash("null"), private_note=None)
    explicit_null["private_note"] = None
    explicit_null["decision_ref"] = reader.decision_ref(explicit_null)
    fake_beacon = base_content(action_hash("fake-beacon"), freshness_beacon={
        "block_time": 1, "hash": "00" * 32, "height": 1})
    return [
        ("allow-issuer-clock", issuer_clock("plain"), "allow", ISSUER,
         "control: a conformant record, credited by the issuer's clock alone"),
        ("allow-anchored", authenticated("anchored"), "allow", ANCHORED,
         "control: the beacon and the anchor both name headers the relying party holds"),
        ("allow-second-issuer-key",
         case(second, keys=[PUBKEYS["issuer-1"], PUBKEYS["issuer-2"]],
              action=action_hash("second")), "allow", ISSUER,
         "control: the issuer's second key signs and names itself"),
        ("allow-within-max-age",
         case(sign_record(base_content(action_hash("age"))), action=action_hash("age"),
              max_age=3_600), "allow", ISSUER,
         "control: the verdict is exactly as old as the relying party allows"),
        ("allow-non-ascii-content",
         case(sign_record(unicode_content), action=action_hash("unicode")), "allow", ISSUER,
         "control: non-ASCII characters in content stay unescaped in the signed array"),
        ("allow-explicit-null-in-preimage",
         case(sign_record(explicit_null), action=action_hash("null")), "allow", ISSUER,
         "control: a preimage field present as null gives the same reference as an absent one"),
        ("allow-fabricated-beacon-by-issuer-clock",
         case(sign_record(fake_beacon), action=action_hash("fake-beacon")), "allow", ISSUER,
         "an unauthenticated beacon (block time 1, a zero hash) is credited when the "
         "relying party holds no headers: the issuer's clock is all this mode trusts"),
    ]


def _shape_denials() -> list[Case]:
    base = issuer_clock("shape")
    not_hex = copy.deepcopy(base)
    not_hex["record"]["pubkey"] = "not-a-key"
    not_json = copy.deepcopy(base)
    not_json["record"]["content"] = "{not json"
    return [
        ("contract-id-missing", case(base["record"], contract=None, action=action_hash("shape")),
         "deny", "contract_id_missing", "the case names no contract"),
        ("contract-id-unknown",
         case(base["record"], contract=reader.CONTRACT_ID.replace("/v1", "/v0"),
              action=action_hash("shape")), "deny", "contract_id_unknown",
         "the case names a contract version that does not exist"),
        ("malformed-pubkey-not-hex", not_hex, "deny", "malformed_case",
         "the record's pubkey is not 64 hex characters"),
        ("malformed-content-not-json", not_json, "deny", "malformed_case",
         "the record's content is not a JSON object"),
    ]


def _integrity_denials() -> list[Case]:
    tampered = issuer_clock("tampered")
    changed = json.loads(tampered["record"]["content"])
    changed["confidence_pct"] = 99
    tampered["record"]["content"] = serialise(changed)
    escaped = sign_record(base_content(action_hash("escaped"), rationale="café"))
    array = [0, escaped["pubkey"], escaped["created_at"], escaped["kind"], escaped["tags"],
             escaped["content"]]
    escaped["id"] = _sha(json.dumps(array, separators=(",", ":"), ensure_ascii=True).encode())
    escaped["sig"] = schnorr_sign(bytes.fromhex(escaped["id"]), SECRETS["issuer-1"]).hex()
    flipped = issuer_clock("flipped")
    sig = flipped["record"]["sig"]
    flipped["record"]["sig"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    return [
        ("event-id-content-edited-after-signing", tampered, "deny", "event_id",
         "confidence_pct changed after signing; the id and the signature were kept"),
        ("event-id-over-ascii-escaped-array",
         case(escaped, action=action_hash("escaped")), "deny", "event_id",
         "the id was computed over the array with non-ASCII characters escaped"),
        ("signature-last-digit-changed", flipped, "deny", "signature",
         "one hex digit of the signature changed"),
    ]


def _key_denials() -> list[Case]:
    wrong = sign_record(base_content(action_hash("wrong")), "stranger")
    outsider = sign_record(base_content(action_hash("outsider"), "stranger"), "stranger")
    return [
        ("wrong-key-names-issuer", case(wrong, action=action_hash("wrong")), "deny",
         "key_not_in_set", "re-signed by a key outside the key set, content still names the issuer"),
        ("outsider-key-names-itself", case(outsider, action=action_hash("outsider")), "deny",
         "key_not_in_set",
         "an outsider signs and its content names that same outsider key, so the binding "
         "check agrees; only the key set refuses it"),
    ]


def _binding_denials() -> list[Case]:
    bound = sign_record(base_content(action_hash("bound")), "test")
    untagged = sign_record(base_content(action_hash("untagged")), tags=[])
    return [
        ("key-binding-trusted-key-names-the-issuer",
         case(bound, keys=[PUBKEYS["issuer-1"], PUBKEYS["test"]], action=action_hash("bound")),
         "deny", "key_binding",
         "signed by a second key the relying party trusts while the content names the "
         "issuer: a signature check plus the key set credits it"),
        ("schema-tag-removed", case(untagged, action=action_hash("untagged")), "deny", "schema",
         "correctly signed and bound, with the schema tag removed"),
    ]


def _commitment_denials() -> list[Case]:
    artifact = action_hash("decision")
    mismatch = base_content(artifact, decision_ref="sha256:" + "0" * 64)
    omitted = base_content(artifact)
    short = {name: omitted.get(name) for name in PREIMAGE_FIELDS if name in omitted}
    omitted["decision_ref"] = "sha256:" + _sha(reader._rail().jcs_dumps(short))
    return [
        ("decision-ref-mismatch", case(sign_record(mismatch), action=artifact), "deny",
         "decision_ref", "decision_ref no longer matches its preimage"),
        ("decision-ref-omits-absent-field", case(sign_record(omitted), action=artifact), "deny",
         "decision_ref",
         "the reference was computed with the absent field left out instead of set to null"),
        ("action-hash-is-a-neighbouring-action",
         case(sign_record(base_content(action_hash("one"))), action=action_hash("two")), "deny",
         "action_unbound", "the verdict is about one action and the relying party ran another"),
    ]


def _timing_denials() -> list[Case]:
    early = sign_record(base_content(action_hash("early")))
    late_beacon = sign_record(base_content(action_hash("late-beacon"), freshness_beacon={
        "block_time": CREATED + 5, "hash": reader.header_hash(BEACON_HEADER), "height": 5}))
    old = sign_record(base_content(action_hash("old")))
    return [
        ("executed-before-the-verdict-was-signed",
         case(early, action=action_hash("early"), executed=CREATED - 60), "deny",
         "not_pre_action", "the action ran 60 seconds before created_at"),
        ("beacon-time-after-created-at",
         case(late_beacon, action=action_hash("late-beacon")), "deny", "not_pre_action",
         "the beacon is later than the record that claims to follow it"),
        ("verdict-signed-100-days-before-the-action",
         case(old, action=action_hash("old"), executed=CREATED + 100 * 86_400,
              max_age=86_400), "deny", "stale_verdict",
         "the relying party allows one day and the verdict is 100 days old"),
    ]


def _authenticated_denials() -> list[Case]:
    fake = base_content(action_hash("fabricated"), freshness_beacon={
        "block_time": 1, "hash": "00" * 32, "height": 1})
    untrusted = authenticated("stranger-header")
    untrusted["relyingParty"]["trustedHeaders"] = [BEACON_HEADER.hex()]
    foreign_record = sign_record(base_content(action_hash("commits-another")))
    foreign, foreign_stamp = anchor_for(foreign_record, commitment=_sha(b"another record"))
    forked = authenticated("path-broken")
    forked["anchor"]["path"][0]["hash"] = _sha(b"a different sibling")
    absent = authenticated("no-anchor")
    del absent["anchor"]
    late_case = authenticated("late")
    late_case["anchor"], stamp = anchor_for(late_case["record"], stamped=EXECUTED + 60)
    late_case["relyingParty"]["trustedHeaders"] = [BEACON_HEADER.hex(), stamp.hex()]
    return [
        ("beacon-is-not-a-header-the-relying-party-holds",
         authenticated("fabricated", content=fake), "deny", "beacon_untrusted",
         "the beacon is block time 1 with a zero hash and no held header matches it"),
        ("beacon-names-a-header-with-another-time",
         authenticated("beacon-time", content=base_content(
             action_hash("beacon-time"), freshness_beacon={
                 "block_time": BEACON_TIME - 5, "hash": reader.header_hash(BEACON_HEADER),
                 "height": 5})), "deny", "beacon_untrusted",
         "the beacon hash is a held header and the beacon time is not that header's time"),
        ("anchor-absent-where-time-must-be-shown", absent, "deny", "anchor_missing",
         "the relying party holds headers and the record comes with no anchor"),
        ("anchor-commits-a-different-record",
         authenticated("commits-another", anchor=foreign,
                       headers=[BEACON_HEADER, foreign_stamp]) | {"record": foreign_record},
         "deny", "anchor_commitment",
         "the anchor commits another record's id, though its path folds to its own header"),
        ("anchor-path-does-not-reach-the-header-root", forked, "deny", "anchor_commitment",
         "a sibling hash on the path was replaced, so the fold misses the merkle root field"),
        ("anchor-header-is-not-held", untrusted, "deny", "anchor_header_untrusted",
         "the anchor folds into a header the relying party does not hold"),
        ("anchor-stamped-after-the-action", late_case, "deny", "anchor_after_action",
         "the anchor header's time is 60 seconds after the action ran"),
    ]


def cases() -> list[Case]:
    """Every case: id, case.json body, decision, reason, departure."""
    return copy.deepcopy([
        *_allow(), *_shape_denials(), *_integrity_denials(), *_key_denials(),
        *_binding_denials(), *_commitment_denials(), *_timing_denials(),
        *_authenticated_denials(),
    ])


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "case.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"case.json": _sha(data)}, "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)),
        "credits": CREDITS, "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
