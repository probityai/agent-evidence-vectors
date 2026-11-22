"""Build the revocation-list cases byte-identically.

A case is what one verifier sees: the root key ids it pins (``roots.json``) and the
signed lists it is handed, in order (``list-01.json`` and on), each exactly the
published form ``{"body": BODY, "sig": base64(Ed25519 over DOMAIN || JCS(BODY))}``.

Two sources feed it. The shared vectors every reader of the one revocation list
answers (``aee/testdata/revocation-list.json``, pinned by SHA-256) become one case
each. The minted cases add one refusal per check the shared set does not reach on
its own, so a reader that skips any single check, or answers it with another detail,
disagrees with at least one case.

Every case states its decision, the full refusal text (code, or code:detail) and the
index of the refused list, the list in force when the verdict was reached, and the
ListDigest of every list file. The state is computed here, by a model of the chain
rules that shares no code with any reader, and checked against the shared vectors'
own expected states before anything is written.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild every
signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO / "packaging"))

import run_vectors as rail  # noqa: E402

SUITE = "revocation-list/v1"
SHARED = REPO / "aee" / "testdata" / "revocation-list.json"
SHARED_SHA256 = "d762714623703accce51db2adedf9d3abeb9f4db568f1749b1754c833f8a4441"
SEED_PREFIX = "agent-evidence-vectors/revocation-list/v1/"
DOMAIN = b"probity-revocation-v1\x00"
TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list"
KINDS = ("agent", "build", "grant", "key", "permit", "sponsor", "stream")
LIST_ID = "example-revocations"
T1, T2, T3 = "2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z", "2026-06-03T00:00:00Z"
MAX_EXACT = 2**53 - 1

# Each shared vector's case id and the full refusal its reader gives: the code the
# shared vector states, and the detail naming which check refused it.
SHARED_CASES: dict[str, tuple[str, str]] = {
    "RL01": ("empty-first-list", "in_force"),
    "RL02": ("three-lists-in-force", "in_force"),
    "RL03": ("root-rotation-in-force", "in_force"),
    "RL04": ("single-list-in-force", "in_force"),
    "RL05": ("unknown-kind", "revocation_list_shape:entry_kind_unknown"),
    "RL06": ("entries-out-of-order", "revocation_list_shape:entries_not_strictly_ascending"),
    "RL07": ("duplicate-entry", "revocation_list_shape:entries_not_strictly_ascending"),
    "RL08": ("identifier-not-ascii", "revocation_list_shape:entry_id_form:agent"),
    "RL09": ("identifier-with-space", "revocation_list_shape:entry_id_form:agent"),
    "RL10": ("identifier-513-characters", "revocation_list_shape:entry_id_form:agent"),
    "RL11": ("extra-body-member", "revocation_list_shape:body_members"),
    "RL12": ("seq-boolean", "revocation_list_shape:seq_not_a_positive_exact_integer"),
    "RL13": ("seq-beyond-exact-integers", "revocation_list_shape:signed_list_unreadable"),
    "RL14": ("time-with-offset", "revocation_list_shape:issuedAt_not_a_utc_second"),
    "RL15": ("time-not-a-calendar-day", "revocation_list_shape:issuedAt_not_a_calendar_instant"),
    "RL16": ("issuer-key-noncanonical-base64", "revocation_list_shape:issuerKey_not_base64"),
    "RL17": ("grant-digest-upper-case", "revocation_list_shape:entry_id_form:grant"),
    "RL18": ("successor-on-agent-entry", "revocation_list_shape:successor_on_non_key_entry"),
    "RL19": ("extra-top-level-member", "revocation_list_shape:signed_list_members"),
    "RL20": ("another-type", "revocation_list_shape:type"),
    "RL21": ("signer-not-a-root", "revocation_list_signer_not_a_root"),
    "RL22": ("entries-edited-after-signing", "revocation_list_signature_unverified"),
    "RL23": ("root-key-over-another-signature", "revocation_list_signature_unverified"),
    "RL24": ("signature-bit-flipped", "revocation_list_signature_unverified"),
    "RL25": ("signature-noncanonical-base64", "revocation_list_signature_unverified"),
    "RL26": ("another-chain", "revocation_list_other_chain"),
    "RL27": ("list-in-force-replayed", "revocation_list_rollback:2<=2"),
    "RL28": ("rollback", "revocation_list_rollback:1<=2"),
    "RL29": ("seq-gap", "revocation_list_gap:3>2"),
    "RL30": ("fresh-reader-past-seq-1", "revocation_list_gap:2>1"),
    "RL31": ("fork", "revocation_list_previous_mismatch"),
    "RL32": ("issued-before-list-in-force", "revocation_list_time_reversed"),
    "RL33": ("entry-from-future", "revocation_entry_from_future"),
    "RL34": ("list-drops-entry", "revocation_list_drops_entry:agent:agent:alpha"),
    "RL35": ("list-edits-entry", "revocation_list_drops_entry:agent:agent:alpha"),
    "RL36": ("old-root-after-rotation", "revocation_list_signer_not_a_root"),
    "RL37": ("root-revoked-without-successor", "revocation_list_signer_not_a_root"),
    "RL38": ("successor-revoked-sorting-before", "revocation_list_signer_not_a_root"),
    "RL39": ("successor-revoked-sorting-after", "revocation_list_signer_not_a_root"),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def public(label: str) -> bytes:
    return bytes(rail.ed25519_public_key(_seed(label)))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def key_id(label: str) -> str:
    return _sha(public(label))


def _unsafe(value: Any) -> bool:
    """True when a value holds an integer no exact reader keeps, which ListDigest refuses."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) > MAX_EXACT
    if isinstance(value, dict):
        return any(_unsafe(v) for v in value.values())
    if isinstance(value, list):
        return any(_unsafe(v) for v in value)
    return False


def list_digest(body: Any) -> str | None:
    """sha256: + hex SHA-256 of JCS(body), or None when the body cannot be canonicalized."""
    if _unsafe(body):
        return None
    return "sha256:" + _sha(rail.jcs_dumps(body))


def body(
    seq: int = 1,
    previous: str | None = None,
    issued: str = T1,
    entries: Any = None,
    signer: str = "root-a",
    **overrides: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "entries": entries if entries is not None else [],
        "issuedAt": issued,
        "issuerKey": b64(public(signer)),
        "listId": LIST_ID,
        "previous": previous,
        "seq": seq,
        "type": TYPE,
    }
    value.update(overrides)
    return value


def signed(value: Any, signer: str = "root-a") -> dict[str, Any]:
    """The published form, signed over DOMAIN || JCS(value)."""
    return {
        "body": value,
        "sig": b64(rail.ed25519_sign(_seed(signer), DOMAIN + rail.jcs_dumps(value))),
    }


def entry(kind: str, ident: str, revoked: str = T1, **extra: Any) -> dict[str, Any]:
    return {"id": ident, "kind": kind, "revokedAt": revoked, **extra}


# ---------------------------------------------------------------------------
# the state model: the chain rules for lists already known to be accepted
# ---------------------------------------------------------------------------


def initial_state(roots: list[str]) -> dict[str, Any]:
    return {
        "entries": {},
        "head": "",
        "issuedAt": "",
        "listId": "",
        "roots": sorted(set(roots)),
        "seq": 0,
    }


def install(state: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    keys = [e for e in value["entries"] if e["kind"] == "key"]
    joined = [
        _sha(base64.b64decode(e["successor"]))
        for e in keys
        if "successor" in e and e["id"] in state["roots"]
    ]
    gone = {e["id"] for e in keys}
    return {
        "entries": {(e["kind"], e["id"]): e for e in value["entries"]},
        "head": list_digest(value),
        "issuedAt": value["issuedAt"],
        "listId": value["listId"],
        "roots": sorted((set(state["roots"]) | set(joined)) - gone),
        "seq": value["seq"],
    }


def published(state: dict[str, Any]) -> dict[str, Any]:
    revoked = {kind: sorted(i for (k, i) in state["entries"] if k == kind) for kind in KINDS}
    return {
        "head": state["head"],
        "issuedAt": state["issuedAt"],
        "listId": state["listId"],
        "revoked": revoked,
        "roots": state["roots"],
        "seq": state["seq"],
    }


def held_state(roots: list[str], lists: list[Any], accepted: int) -> dict[str, Any]:
    state = initial_state(roots)
    for value in lists[:accepted]:
        state = install(state, value["body"])
    return published(state)


# ---------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------


def shared_cases() -> list[dict[str, Any]]:
    raw = SHARED.read_bytes()
    if _sha(raw) != SHARED_SHA256:
        raise SystemExit(f"{SHARED} is not the pinned copy of the shared vectors")
    out = []
    for vector in json.loads(raw):
        slug, reason = SHARED_CASES[vector["id"]]
        expected = vector["expected"]
        index = expected.get("index")
        accepted = len(vector["lists"]) if index is None else index
        state = held_state(vector["roots"], vector["lists"], accepted)
        if index is None and state != expected["state"]:
            raise SystemExit(
                f"{vector['id']}: the state model gives {state}, the vector {expected['state']}"
            )
        if index is not None and not reason.split(":")[0] == expected["refused"]:
            raise SystemExit(
                f"{vector['id']}: {reason} does not carry the code {expected['refused']}"
            )
        out.append(
            {
                "id": f"{vector['id'].lower()}-{slug}",
                "description": vector["description"],
                "source": f"shared:{vector['id']}",
                "roots": vector["roots"],
                "lists": vector["lists"],
                "reason": reason,
                "index": index,
                "state": state,
            }
        )
    return out


def _first(
    value: Any,
    reason: str,
    description: str,
    ident: str,
    roots: list[str] | None = None,
    signer: str = "root-a",
) -> dict[str, Any]:
    """A one-list case refused at index 0 (reason "in_force" when accepted)."""
    lists = [
        value
        if isinstance(value, (list, int)) or {"sig", "body"} & set(value)
        else signed(value, signer)
    ]
    return {
        "id": ident,
        "description": description,
        "reason": reason,
        "lists": lists,
        "index": None if reason == "in_force" else 0,
        "roots": roots or [key_id("root-a")],
    }


def minted_cases() -> list[dict[str, Any]]:
    shape = "revocation_list_shape:"
    root = key_id("root-a")
    valid = signed(body())
    head1 = list_digest(valid["body"])
    two = [entry("agent", "agent:a"), entry("agent", "agent:b")]
    first_two = signed(body(entries=two))
    with_break = valid["sig"][:20] + "\n" + valid["sig"][20:]
    issuer = b64(public("root-a"))
    cases: list[dict[str, Any]] = [
        _first(
            [],
            shape + "signed_list_members",
            "a signed list that is an array",
            "m-signed-list-array",
        ),
        _first(
            {"bodyx": valid["body"], "sig": valid["sig"]},
            shape + "signed_list_members",
            "a signed list with no body member",
            "m-signed-list-without-body",
        ),
        _first(
            {"body": valid["body"], "sigx": valid["sig"]},
            shape + "signed_list_members",
            "a signed list with no sig member",
            "m-signed-list-without-sig",
        ),
        _first(
            {"body": [], "sig": valid["sig"]},
            shape + "body_members",
            "a body that is an array",
            "m-body-array",
        ),
        _first(
            {k if k != "issuedAt" else "issued_at": v for k, v in body().items()},
            shape + "body_members",
            "a body with seven members, one misnamed",
            "m-body-member-misnamed",
        ),
        _first(body(listId=""), shape + "list_id_form", "an empty list id", "m-list-id-empty"),
        _first(
            body(listId="example revocations"),
            shape + "list_id_form",
            "a list id with a space",
            "m-list-id-with-space",
        ),
        _first(body(seq=0), shape + "seq_not_a_positive_exact_integer", "seq zero", "m-seq-zero"),
        _first(
            body(previous=head1),
            shape + "previous_form",
            "a first list that names a previous list",
            "m-first-list-with-previous",
        ),
        _first(
            body(entries={}),
            shape + "entries_not_a_list",
            "entries that are an object",
            "m-entries-object",
        ),
        _first(
            body(entries=[5]),
            shape + "entry_not_an_object",
            "an entry that is a number",
            "m-entry-number",
        ),
        _first(
            body(entries=[entry("agent", "agent:a", zzz="x")]),
            shape + "entry_members",
            "an entry with a member the format does not define",
            "m-entry-unknown-member",
        ),
        _first(
            body(entries=[{"id": "agent:a", "revokedAt": T1}]),
            shape + "entry_members",
            "an entry with no kind",
            "m-entry-without-kind",
        ),
        _first(
            body(entries=[{"kind": "agent", "revokedAt": T1}]),
            shape + "entry_members",
            "an entry with no id",
            "m-entry-without-id",
        ),
        _first(
            body(entries=[{"id": "agent:a", "kind": "agent"}]),
            shape + "entry_members",
            "an entry with no revokedAt",
            "m-entry-without-revoked-at",
        ),
        _first(
            body(entries=[entry("agent", "agent:a", reason=5)]),
            shape + "entry_reason_not_text",
            "an entry reason that is a number",
            "m-entry-reason-number",
        ),
        _first(
            body(entries=[entry("permit", "AB" * 32)]),
            shape + "entry_id_form:permit",
            "an upper-case permit digest",
            "m-permit-id-upper-case",
        ),
        _first(
            body(entries=[entry("key", "k")]),
            shape + "entry_id_form:key",
            "a key id that is not a digest",
            "m-key-id-not-a-digest",
        ),
        _first(
            body(entries=[entry("key", key_id("other"), successor="!!")]),
            shape + "successor_not_base64",
            "a successor that is not base64",
            "m-successor-not-base64",
        ),
        _first(
            body(issuerKey=5),
            shape + "issuerKey_not_base64",
            "an issuer key that is a number",
            "m-issuer-key-number",
        ),
        _first(
            body(issuerKey=b64(b"A" * 31)),
            shape + "issuerKey_not_an_ed25519_key",
            "an issuer key of 31 bytes",
            "m-issuer-key-31-bytes",
        ),
        _first(
            body(issuerKey=issuer[:5] + "\n" + issuer[5:]),
            shape + "issuerKey_not_canonical_base64",
            "an issuer key with a line break, which a base64 decoder skips",
            "m-issuer-key-line-break",
        ),
        _first(
            {"body": valid["body"], "sig": with_break},
            "revocation_list_signature_unverified",
            "a genuine signature with a line break inside its base64",
            "m-signature-line-break",
        ),
        _first(
            body(entries=[entry("agent", "agent:a"), {"id": "zz", "kind": "zz", "revokedAt": T1}]),
            shape + "entry_kind_unknown",
            "a second entry of an unknown kind",
            "m-second-entry-unknown-kind",
        ),
        _first(
            body(entries=[entry("agent", "agent:a"), entry("agent", "agent:b", T2)]),
            "revocation_entry_from_future",
            "a second entry revoked after the list's issue time",
            "m-second-entry-from-future",
        ),
        _first(
            body(entries=[entry("agent", "agent:a", revoked="x")]),
            shape + "revokedAt_not_a_utc_second",
            "an entry revokedAt that is not a time",
            "m-revoked-at-not-a-time",
        ),
        _first(
            body(entries=[entry("grant", root)]),
            "in_force",
            "a revoked grant whose id equals a root key id leaves the root pinned",
            "m-grant-id-equals-root",
        ),
        _first(
            body(entries=[entry("key", key_id("other"), successor=b64(public("root-b")))]),
            "in_force",
            "a revoked key that is not a root brings in no successor",
            "m-successor-of-non-root",
        ),
        _first(
            valid,
            "in_force",
            "a root pinned twice is held once",
            "m-root-pinned-twice",
            roots=[root, root],
        ),
        _first(
            body(
                entries=[
                    entry(kind, ident)
                    for kind, ident in (
                        ("agent", "agent:a"),
                        ("build", "build:a"),
                        ("grant", "a" * 64),
                        ("key", key_id("other")),
                        ("permit", "b" * 64),
                        ("sponsor", "sponsor:a"),
                        ("stream", "stream:a"),
                    )
                ]
            ),
            "in_force",
            "one entry of every kind",
            "m-every-kind",
        ),
    ]
    for ident, text, reason in (
        ("len-21", "2026-06-01T00:00:00ZZ", "issuedAt_not_a_utc_second"),
        ("year-letter", "2O26-06-01T00:00:00Z", "issuedAt_not_a_utc_second"),
        ("dash-4", "2026_06-01T00:00:00Z", "issuedAt_not_a_utc_second"),
        ("month-letter", "2026-0x-01T00:00:00Z", "issuedAt_not_a_utc_second"),
        ("dash-7", "2026-06_01T00:00:00Z", "issuedAt_not_a_utc_second"),
        ("day-letter", "2026-06-0xT00:00:00Z", "issuedAt_not_a_utc_second"),
        ("t-lower-case", "2026-06-01t00:00:00Z", "issuedAt_not_a_utc_second"),
        ("hour-letter", "2026-06-01T0x:00:00Z", "issuedAt_not_a_utc_second"),
        ("colon-13", "2026-06-01T00_00:00Z", "issuedAt_not_a_utc_second"),
        ("minute-letter", "2026-06-01T00:0x:00Z", "issuedAt_not_a_utc_second"),
        ("colon-16", "2026-06-01T00:00_00Z", "issuedAt_not_a_utc_second"),
        ("second-slash", "2026-06-01T00:00:0/Z", "issuedAt_not_a_utc_second"),
        ("z-lower-case", "2026-06-01T00:00:00z", "issuedAt_not_a_utc_second"),
        ("year-zero", "0000-06-01T00:00:00Z", "issuedAt_not_a_calendar_instant"),
    ):
        cases.append(
            _first(body(issued=text), shape + reason, f"issuedAt {text!r}", f"m-time-{ident}")
        )
    second = signed(body(seq=2, previous=head1, issued=T2))
    cases += [
        {
            "id": "m-second-list-null-previous",
            "description": "a second list whose previous is null",
            "lists": [valid, signed(body(seq=2, issued=T2))],
            "index": 1,
            "roots": [root],
            "reason": shape + "previous_form",
        },
        {
            "id": "m-previous-not-a-digest",
            "description": "a second list whose previous is not a list digest",
            "lists": [valid, signed(body(seq=2, previous="sha256:" + "Z" * 64, issued=T2))],
            "index": 1,
            "roots": [root],
            "reason": shape + "previous_form",
        },
        {
            "id": "m-drops-second-held-entry",
            "description": "a list that drops the second of two held entries",
            "lists": [
                first_two,
                signed(
                    body(seq=2, previous=list_digest(first_two["body"]), issued=T2, entries=two[:1])
                ),
            ],
            "index": 1,
            "roots": [root],
            "reason": "revocation_list_drops_entry:agent:agent:b",
        },
        {
            "id": "m-two-lists-in-force",
            "description": "two lists in force",
            "lists": [valid, second],
            "index": None,
            "roots": [root],
            "reason": "in_force",
        },
    ]
    for case in cases:
        accepted = len(case["lists"]) if case["index"] is None else case["index"]
        case["state"] = held_state(case["roots"], case["lists"], accepted)
        case["source"] = "minted"
    return cases


def file_digest(value: Any) -> str | None:
    if isinstance(value, dict) and "body" in value:
        return list_digest(value["body"])
    return None


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for row in manifest["vectors"]:
        directory = base / row["path"]
        declared = row["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{row['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{row['id']}: file digest mismatch")
        entries.append({**row, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    rows: list[dict[str, Any]] = []
    for case in [*shared_cases(), *minted_cases()]:
        directory = root / "cases" / case["id"]
        directory.mkdir(parents=True, exist_ok=True)
        names = [f"list-{i + 1:02d}.json" for i in range(len(case["lists"]))]
        files = {"roots.json": _json({"roots": case["roots"]})}
        files.update({name: _json(value) for name, value in zip(names, case["lists"], strict=True)})
        for name, data in files.items():
            (directory / name).write_bytes(data)
        rows.append(
            {
                "description": case["description"],
                "expected": {
                    "decision": "accept" if case["reason"] == "in_force" else "reject",
                    "index": case["index"],
                    "listDigests": [file_digest(v) for v in case["lists"]],
                    "reason": case["reason"],
                    "state": case["state"],
                },
                "files": {name: _sha(data) for name, data in sorted(files.items())},
                "id": case["id"],
                "lists": names,
                "path": f"cases/{case['id']}",
                "source": case["source"],
            }
        )
    manifest: dict[str, Any] = {
        "corpusDigest": _sha(_json(rows)),
        "suite": SUITE,
        "verifierContract": "aee-verify <corpus-dir>",
        "vectors": rows,
    }
    words = [row["expected"]["decision"] for row in rows]
    manifest["counts"] = {word: words.count(word) for word in sorted(set(words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
