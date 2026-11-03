"""Build the signature-coverage cases byte-identically.

Every case is one signed structure. Each denied case changes the accepting
control so the check it names is the first that fails and every earlier check
passes; each allowed case is a control that keeps a verifier from denying
everything. Rows sharing ``sharedSignature`` carry byte-identical signed payloads
and signatures, which is the failure in one line: one signature, two readings.
Keys are test keys and every member is synthetic.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
import unicodedata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import signaturecoverage as reader  # noqa: E402

SUITE = reader.SUITE
SEED = hashlib.sha256(b"signature-coverage/v1 test key, published on purpose").digest()
OTHER_SEED = hashlib.sha256(b"signature-coverage/v1 second test key").digest()
READS = [["decision"]]
NFC = unicodedata.normalize("NFC", "résumé")
NFD = unicodedata.normalize("NFD", NFC)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def entries(*pairs: Any) -> dict[str, Any]:
    """A map as readers see it, in order, repeats kept."""
    return {"entries": [list(pair) for pair in pairs]}


def build(name: str, source: dict[str, Any], payload: bytes | None = None,
          excluded: list[str] | None = None, reads: list[list[str]] | None = None,
          signed_with: bytes = SEED, **top: Any) -> dict[str, Any]:
    """One signed structure; the payload defaults to the flattened source."""
    if payload is None:
        plain = reader.flatten(source)
        payload = reader._canonical({key: item for key, item in plain.items()
                                     if key not in (excluded or [])})
    record: dict[str, Any] = {
        "consumerReads": READS if reads is None else reads,
        "contractId": reader.CONTRACT_ID,
        "envelope": {
            "algorithm": "ed25519",
            "excluded": excluded or [],
            "payload": base64.b64encode(payload).decode(),
            "publicKey": base64.b64encode(rail.ed25519_public_key(SEED)).decode(),
            "signature": base64.b64encode(rail.ed25519_sign(signed_with, payload)).decode(),
        },
        "recordId": f"record-{name}",
        "source": source,
    }
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


Case = tuple[str, dict[str, Any], str, str, str]
DENY_ONE = entries(("decision", "deny"))
ROLE_ADMIN = entries(("role", "admin"))
DENY_PAYLOAD = b'{"decision":"deny"}'


def _controls() -> list[Case]:
    ok = reader.ALLOWED_REASON
    cases = [
        ("allow-one-entry-for-the-key", DENY_ONE, {}, "control: the signed payload and the "
         "source hold one entry each"),
        ("allow-empty-source", entries(), {"reads": []}, "control: nothing to read and "
         "nothing signed"),
        ("allow-key-repeated-in-sibling-maps",
         entries(("a", entries(("k", 1))), ("b", entries(("k", 2)))), {"reads": [["a", "k"]]},
         "control: one key name in two sibling maps is not a repeat"),
        ("allow-key-repeated-across-list-elements",
         entries(("items", [entries(("k", 1)), entries(("k", 2))])), {"reads": [["items"]]},
         "control: one key name in two list elements is not a repeat"),
        ("allow-keys-differing-in-case", entries(("Decision", "allow"), ("decision", "deny")),
         {}, "control: keys that differ in case are two keys and both are signed"),
        ("allow-keys-differing-in-normal-form", entries((NFC, 1), (NFD, 2)),
         {"reads": [[NFC]]}, "control: keys that differ in Unicode normal form are two keys "
         "and both are signed"),
        ("allow-declared-exclusion-not-read",
         entries(("decision", "deny"), ("flags", 1)), {"excluded": ["flags"]},
         "control: a key declared outside the signature that no consumer reads"),
        ("allow-largest-exact-integer", entries(("n", reader.MAX_EXACT_INTEGER)),
         {"reads": [["n"]]}, "control: the largest integer every JSON parser reads exactly"),
        ("allow-number-spelled-another-way", entries(("n", 1.0)),
         {"payload": b'{"n":1}', "reads": [["n"]]},
         "control: 1.0 and 1 are one JSON number, so a byte comparison is the wrong check"),
    ]
    return [(name, build(name, source, **options), "allow", ok, edit)
            for name, source, options, edit in cases]


def _denied_envelope() -> list[Case]:
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    cases: list[Case] = [
        ("reject-contract-id-missing",
         build("reject-contract-id-missing", DENY_ONE, contractId=None),
         "deny", "contract_id_missing", "the record names no contract"),
        ("reject-contract-id-unknown",
         build("reject-contract-id-unknown", DENY_ONE, contractId=unknown),
         "deny", "contract_id_unknown", "the record names a contract that does not exist"),
        ("reject-signature-by-another-key",
         build("reject-signature-by-another-key", DENY_ONE, signed_with=OTHER_SEED),
         "deny", "signature_invalid", "the signature comes from a key other than the one "
         "the envelope names"),
    ]
    tampered = build("reject-signature-over-other-bytes", DENY_ONE)
    tampered["envelope"]["payload"] = base64.b64encode(b'{"decision":"allow"}').decode()
    cases.append(("reject-signature-over-other-bytes", tampered, "deny", "signature_invalid",
                  "the payload changed after signing"))
    return cases


def _denied_payload() -> list[Case]:
    repeats = [
        ("reject-payload-repeats-member", b'{"decision":"allow","decision":"deny"}', DENY_ONE,
         "the signed bytes hold both values: one parser reads allow, another deny"),
        ("reject-payload-repeats-nested-member",
         b'{"ctx":{"role":"user","role":"admin"}}', entries(("ctx", ROLE_ADMIN)),
         "the signed bytes repeat a member one level down"),
        ("reject-payload-repeats-member-by-escape",
         b'{"decision":"allow","\\u0064ecision":"deny"}', DENY_ONE,
         "the second name is an escape of the first, so a byte comparison misses it"),
    ]
    cases: list[Case] = [(name, build(name, source, payload), "deny",
                          "payload_repeated_member", edit)
                         for name, payload, source, edit in repeats]
    big = reader.MAX_EXACT_INTEGER + 2
    cases += [
        ("reject-payload-integer-past-exact-range",
         build("reject-payload-integer-past-exact-range", entries(("n", big)),
               reads=[["n"]]),
         "deny", "number_not_interoperable", "a parser holding doubles reads the signed "
         "integer as a neighbouring value"),
        ("reject-source-integer-past-exact-range",
         build("reject-source-integer-past-exact-range", entries(("n", big)), b'{"n":1}',
               reads=[["n"]]),
         "deny", "number_not_interoperable", "the source holds an integer past the exact "
         "range while the payload holds a small one"),
    ]
    return cases


def _denied_repeats() -> list[Case]:
    role_pair = entries(("role", "user"), ("role", "admin"))
    repeats: list[tuple[str, dict[str, Any], str, str]] = [
        ("reject-repeat-kept-last", entries(("decision", "allow"), ("decision", "deny")), "deny",
         "first-entry readers read allow; the signer kept the last entry and signed deny"),
        ("reject-repeat-kept-first", entries(("decision", "deny"), ("decision", "allow")), "deny",
         "last-entry readers read allow; the signer kept the first entry and signed deny"),
        ("reject-repeat-identical-values", entries(("decision", "deny"), ("decision", "deny")),
         "deny", "both entries agree today, and the signature would stay valid if either "
         "changed"),
        ("reject-repeat-with-entry-between",
         entries(("decision", "allow"), ("reason", "ok"), ("decision", "deny")), None,
         "the repeat is not adjacent, so a check of neighbouring entries misses it"),
        ("reject-repeat-three-times",
         entries(("decision", "deny"), ("decision", "allow"), ("decision", "deny")), "deny",
         "first and last agree and the middle entry reads allow"),
        ("reject-repeat-empty-key", entries(("", "allow"), ("", "deny")), None,
         "the empty string is a key and repeats like any other"),
    ]
    cases: list[Case] = []
    for name, source, _, edit in repeats:
        reads = None if name != "reject-repeat-empty-key" else [[""]]
        payload = DENY_PAYLOAD if name != "reject-repeat-empty-key" else None
        cases.append((name, build(name, source, payload, reads=reads), "deny",
                      "source_repeated_key", edit))
    nested = [
        ("reject-repeat-in-nested-map", entries(("ctx", role_pair)), [["ctx", "role"]],
         "the repeat sits one map down, under a key that appears once"),
        ("reject-repeat-in-list-element", entries(("items", [entries(("k", 1)), role_pair])),
         [["items"]], "the repeat sits in a map inside a list"),
    ]
    cases += [(name, build(name, source, reads=reads), "deny", "source_repeated_key", edit)
              for name, source, reads, edit in nested]
    cases.append(("reject-repeat-under-excluded-key",
                  build("reject-repeat-under-excluded-key",
                        entries(("decision", "deny"), ("proof", "a"), ("proof", "b")),
                        DENY_PAYLOAD, excluded=["proof"]),
                  "deny", "source_repeated_key", "a key declared outside the signature "
                  "repeats, so the record is still malformed"))
    return cases


def _denied_flatten() -> list[Case]:
    cases: list[tuple[str, dict[str, Any], bytes, list[list[str]] | None, str]] = [
        ("reject-value-changed-after-signing", entries(("decision", "allow")), DENY_PAYLOAD, None,
         "no repeat at all: the source holds another value than the payload"),
        ("reject-member-added-after-signing",
         entries(("decision", "deny"), ("override", "allow")), DENY_PAYLOAD, None,
         "a member the signature does not cover and nothing declares outside it"),
        ("reject-member-missing-from-source", entries(), DENY_PAYLOAD, [],
         "the payload holds a member the source does not"),
        ("reject-keys-folded-by-case", entries(("Decision", "allow"), ("decision", "deny")),
         DENY_PAYLOAD, None, "the flatten folded case and two keys became one"),
        ("reject-keys-folded-by-normal-form", entries((NFC, 1), (NFD, 2)),
         reader._canonical({NFC: 2}), [[NFC]],
         "the flatten normalised Unicode and two keys became one"),
        ("reject-null-member-dropped", entries(("decision", "deny"), ("limit", None)),
         DENY_PAYLOAD, None, "a member with a null value is still a member a reader can see"),
        ("reject-number-signed-as-string", entries(("n", 1)), b'{"n":"1"}', [["n"]],
         "the flatten turned a number into a string"),
        ("reject-boolean-signed-as-number", entries(("ok", True)), b'{"ok":1}', [["ok"]],
         "a boolean is never the number one"),
    ]
    out: list[Case] = [(name, build(name, source, payload, reads=reads), "deny",
                        "reading_differs_from_signed", edit)
                       for name, source, payload, reads, edit in cases]
    out += [
        ("reject-consumer-reads-excluded-key",
         build("reject-consumer-reads-excluded-key", entries(("decision", "deny"), ("host", "a")),
               DENY_PAYLOAD, excluded=["host"], reads=[["host"]]),
         "deny", "consumer_reads_unsigned", "the consumer relies on a key the signer "
         "declares outside the signature"),
        ("reject-consumer-reads-under-excluded-key",
         build("reject-consumer-reads-under-excluded-key",
               entries(("decision", "deny"), ("resource", entries(("host", "a")))), DENY_PAYLOAD,
               excluded=["resource"], reads=[["decision"], ["resource", "host"]]),
         "deny", "consumer_reads_unsigned", "the consumer reads below a key declared "
         "outside the signature"),
    ]
    return out


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, and what it shows."""
    return [*_controls(), *_denied_envelope(), *_denied_payload(), *_denied_repeats(),
            *_denied_flatten()]


def signer_pairs() -> list[dict[str, Any]]:
    """Pairs of sources a reader tells apart. A signer may not sign both as one input."""
    allow, deny = ("decision", "allow"), ("decision", "deny")
    user, admin = ("role", "user"), ("role", "admin")
    rows: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
        ("repeat-against-the-entry-kept-last", entries(allow, deny), entries(deny)),
        ("repeat-against-the-entry-kept-first", entries(deny, allow), entries(deny)),
        ("repeat-with-shadowed-value-changed", entries(allow, deny), entries(deny, deny)),
        ("repeat-with-kept-value-changed", entries(deny, allow), entries(deny, deny)),
        ("repeat-nested", entries(("ctx", entries(user, admin))),
         entries(("ctx", entries(admin)))),
        ("repeat-nested-first", entries(("ctx", entries(admin, user))),
         entries(("ctx", entries(admin)))),
        ("repeat-in-list-element", entries(("items", [entries(user, admin)])),
         entries(("items", [entries(admin)]))),
        ("keys-differing-in-case", entries(("Decision", "allow"), deny), entries(deny)),
        ("keys-differing-in-normal-form", entries((NFC, 1), (NFD, 2)), entries((NFC, 2))),
        ("null-member-against-absent", entries(deny, ("limit", None)), entries(deny)),
        ("number-against-string", entries(("n", 1)), entries(("n", "1"))),
        ("boolean-against-number", entries(("ok", True)), entries(("ok", 1))),
    ]
    return [{"first": first, "id": name, "second": second} for name, first, second in rows]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    rows = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        rows.append({**entry, "files": files})
    return _sha(_json(rows))


def _shared_signatures(entries_out: list[dict[str, Any]], records: dict[str, Any]) -> None:
    """Mark rows whose signed bytes and signature are identical to another row's."""
    def signed(record: dict[str, Any]) -> tuple[str, str]:
        return record["envelope"]["payload"], record["envelope"]["signature"]

    groups: dict[tuple[str, str], list[str]] = {}
    for name, record in records.items():
        groups.setdefault(signed(record), []).append(name)
    for entry in entries_out:
        group = groups[signed(records[entry["id"]])]
        if len(group) > 1:
            entry["sharedSignature"] = sorted(group)


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the signer pairs and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    rows, records = [], {}
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        records[name] = body
        rows.append({"edit": edit, "expected": expected,
                     "files": {"record.json": _sha(data)}, "id": name,
                     "path": f"cases/{name}", "retained": reader.retained(copy.deepcopy(body))})
    _shared_signatures(rows, records)
    pairs = _json(signer_pairs())
    (root / "signer-pairs.json").write_bytes(pairs)
    words = [row["expected"]["decision"] for row in rows]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(rows)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "signerContract": "signer source.json --json; {\"refused\": true} or "
                          "{\"signatureInput\": \"<base64>\"}",
        "signerPairs": len(signer_pairs()),
        "signerPairsSha256": _sha(pairs),
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": rows,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
