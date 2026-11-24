"""Catalog documents that list agents and tools: entry digests, attestation pins and subject binding.

Two shapes are read: an ARD manifest (draft-bu-dawn-ard-discovery-00), whose entries carry one
``trustManifest`` object, and an AI Catalog document, whose entries carry a ``trustManifests``
array. Both list ``entries[]`` (nested catalogs are read through ``data.entries``), and both pin
evidence with algorithm-prefixed digests (``sha256:<lowercase hex>``).

The rule this set exists for is attestation transplantation. An attestation pinned only by its
own digest (``attestations[].digest``) proves the attestation file was not swapped; it says
nothing about which artifact the attestation covers. Copied into another publisher's entry, the
same pin checks out again. So an entry delivered by ``url`` that carries attestations must carry
its own ``digest`` (``entry_digest_missing_for_url``), and an attestation document must be a
signed in-toto statement (``attestation_unsigned``, ``attestation_payload_type``) one of whose
subjects carries the entry's digest (``attestation_subject_mismatch``). A subject binds by digest
alone: a subject whose ``name`` equals the entry's identifier and whose digest names other bytes
covers those other bytes, and reading the name as the binding is the transplant again, under the
same identifier. An inline entry with no ``digest`` is bound by the SHA-256 of its data's RFC 8785
bytes.

Every member this set reads has the shape the format gives it, or the entry is refused: an entry,
a trust manifest or an attestation that is not an object, or an ``entries``, ``trustManifests`` or
``attestations`` that is not an array, is refused (``entry_malformed``,
``trust_manifest_malformed``, ``attestation_malformed``) rather than skipped, because a skipped
attestation is one no rule here judged and a lenient reader still follows. So is an entry ``url``
or an attestation ``uri`` that is not a non-empty string (read as "not passed", it would turn a
malformed pin into a gap the caller may accept by warning), and an attestation ``size`` that is
not a whole number of bytes (skipped, it bounds nothing).

A binding subject must agree with the artifact under every algorithm it names. A digest set that
carries the entry's SHA-512 and some other bytes' SHA-256 names two artifacts: a verifier that
matches SHA-512 binds the entry, one that prefers SHA-256 binds the other bytes. Where the caller
passed the artifact (or the entry is inline), each algorithm in the subject's digest set is
computed and a disagreement is refused (``attestation_digest_set_split``).

The statement inside the envelope must be an in-toto Statement (``_type`` of
``https://in-toto.io/Statement/v1`` or ``v0.1``), not any JSON object with a ``subject`` array
(``attestation_not_a_statement``). Both base64 alphabets are read, as DSSE requires of a verifier.

The caller passes the bytes it holds in ``files``, keyed by the URL or URI the catalog names; an
inline ``data:`` URI is read directly. Nothing is fetched. A pin whose bytes the caller did not
pass refuses as not evaluated, never passes; list the ``*-not-evaluated`` codes in ``warn`` to
accept a check that could not run. A DSSE envelope counts as signed when it carries a
signature whose ``sig`` is non-empty base64; whether that signature verifies is the verifier's
question, asked after admission, and this set does not answer it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import urllib.parse
from collections.abc import Iterator
from typing import Any

from . import strict_json
from .canonical import canonical_bytes
from .dsse import decode_base64
from .rules import Check, Context, RuleSet, register
from .strict_json import Refusal

#: Algorithm, hashlib name and hex length, for the algorithms SHA-256 or stronger.
ALGORITHMS = {
    "sha256": ("sha256", 64),
    "sha384": ("sha384", 96),
    "sha512": ("sha512", 128),
    "sha3-256": ("sha3_256", 64),
    "sha3-384": ("sha3_384", 96),
    "sha3-512": ("sha3_512", 128),
}
WEAK = frozenset({"md5", "sha1", "sha-1", "sha224", "sha-224"})
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPES = frozenset({"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"})
#: in-toto digest-set keys and their hashlib names, for the algorithms this set computes.
DIGEST_SET_ALGORITHMS = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
                         "sha3_256": "sha3_256", "sha3_384": "sha3_384", "sha3_512": "sha3_512"}


def _entries(document: Any, prefix: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    entries = document.get("entries") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        return
    for index, entry in enumerate(entries):
        path = f"{prefix}/entries/{index}"
        if isinstance(entry, dict):
            yield path, entry
            data = entry.get("data")
            if isinstance(data, dict) and isinstance(data.get("entries"), list):
                yield from _entries(data, f"{path}/data")


def _manifests(path: str, entry: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    single = entry.get("trustManifest")
    if isinstance(single, dict):
        yield f"{path}/trustManifest", single
    many = entry.get("trustManifests")
    for index, manifest in enumerate(many if isinstance(many, list) else []):
        if isinstance(manifest, dict):
            yield f"{path}/trustManifests/{index}", manifest


def _attestations(path: str, entry: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for mpath, manifest in _manifests(path, entry):
        items = manifest.get("attestations")
        for index, item in enumerate(items if isinstance(items, list) else []):
            if isinstance(item, dict):
                yield f"{mpath}/attestations/{index}", item


def parse_digest(value: Any, where: str) -> tuple[str, str]:
    """``(hashlib name, hex)`` of an algorithm-prefixed digest, or a refusal."""
    if not isinstance(value, str) or ":" not in value:
        raise Refusal("digest_malformed", where, "not an algorithm-prefixed digest <alg>:<hex>")
    algorithm, _, hexvalue = value.partition(":")
    if algorithm.lower() in WEAK:
        raise Refusal("digest_algorithm_weak", where, f"{algorithm} is shorter than SHA-256")
    if algorithm not in ALGORITHMS:
        raise Refusal("digest_malformed", where, f"unknown or non-lowercase algorithm {algorithm!r}")
    name, length = ALGORITHMS[algorithm]
    if len(hexvalue) != length or any(c not in "0123456789abcdef" for c in hexvalue):
        raise Refusal("digest_malformed", where, f"{algorithm} wants {length} lowercase hex characters")
    return name, hexvalue


def _digest_paths(path: str, entry: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    if "digest" in entry:
        yield f"{path}/digest", entry["digest"]
    for mpath, manifest in _manifests(path, entry):
        subject = manifest.get("subject")
        if isinstance(subject, dict) and "digest" in subject:
            yield f"{mpath}/subject/digest", subject["digest"]
        provenance = manifest.get("provenance")
        for index, link in enumerate(provenance if isinstance(provenance, list) else []):
            if isinstance(link, dict) and "sourceDigest" in link:
                yield f"{mpath}/provenance/{index}/sourceDigest", link["sourceDigest"]
    for apath, item in _attestations(path, entry):
        if "digest" in item:
            yield f"{apath}/digest", item["digest"]


def _shape_refusals(catalog: Any, prefix: str = "") -> Iterator[Refusal]:
    """Every member on the path to an attestation that is not the type the format gives it."""
    if not isinstance(catalog, dict) or not isinstance(catalog.get("entries"), list):
        yield Refusal("entry_malformed", f"{prefix}/entries", "a catalog carries an entries array")
        return
    for index, entry in enumerate(catalog["entries"]):
        path = f"{prefix}/entries/{index}"
        if not isinstance(entry, dict):
            yield Refusal("entry_malformed", path, "an entry is an object")
            continue
        if "url" in entry and not _nonempty(entry["url"]):
            yield Refusal("entry_malformed", f"{path}/url", "url is a non-empty string")
        if "trustManifest" in entry and not isinstance(entry["trustManifest"], dict):
            yield Refusal("trust_manifest_malformed", f"{path}/trustManifest", "trustManifest is an object")
        if "trustManifests" in entry:
            many = entry["trustManifests"]
            if not isinstance(many, list):
                yield Refusal("trust_manifest_malformed", f"{path}/trustManifests", "trustManifests is an array")
            else:
                for m, manifest in enumerate(many):
                    if not isinstance(manifest, dict):
                        yield Refusal("trust_manifest_malformed", f"{path}/trustManifests/{m}", "a trust manifest is an object")
        for mpath, manifest in _manifests(path, entry):
            if "attestations" not in manifest:
                continue
            items = manifest["attestations"]
            if not isinstance(items, list):
                yield Refusal("attestation_malformed", f"{mpath}/attestations", "attestations is an array")
                continue
            for a, item in enumerate(items):
                apath = f"{mpath}/attestations/{a}"
                if not isinstance(item, dict):
                    yield Refusal("attestation_malformed", apath, "an attestation is an object")
                    continue
                if not _nonempty(item.get("uri")):
                    yield Refusal("attestation_malformed", f"{apath}/uri", "an attestation names its document by a non-empty string uri")
                size = item.get("size")
                if "size" in item and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
                    yield Refusal("attestation_malformed", f"{apath}/size", "size is a whole number of bytes")
        data = entry.get("data")
        if isinstance(data, dict) and "entries" in data:
            yield from _shape_refusals(data, f"{path}/data")


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _check_entry_shape(context: Context) -> None:
    for refusal in _shape_refusals(context.document):
        context.note(refusal)
    for path, entry in _entries(context.document):
        if ("url" in entry) == ("data" in entry):
            context.note(Refusal("entry_url_xor_data", path, "an entry carries exactly one of url and data"))


def _check_digest_format(context: Context) -> None:
    for path, entry in _entries(context.document):
        for where, value in _digest_paths(path, entry):
            try:
                parse_digest(value, where)
            except Refusal as refusal:
                context.note(refusal)


def _has_attestations(path: str, entry: dict[str, Any]) -> bool:
    return any(True for _ in _attestations(path, entry))


def _signed(path: str, entry: dict[str, Any]) -> bool:
    return any("signature" in m for _, m in _manifests(path, entry))


def _check_digest_required(context: Context) -> None:
    for path, entry in _entries(context.document):
        if "digest" in entry:
            continue
        if "url" in entry and (_has_attestations(path, entry) or _signed(path, entry)):
            context.note(
                Refusal(
                    "entry_digest_missing_for_url",
                    path,
                    "an entry delivered by url with attestations or a signed manifest names no digest of its artifact",
                )
            )
        elif _signed(path, entry):
            context.note(Refusal("entry_digest_missing", path, "an entry with a signed manifest names no digest"))


def _check_subject(context: Context) -> None:
    for path, entry in _entries(context.document):
        for mpath, manifest in _manifests(path, entry):
            subject = manifest.get("subject")
            if "signature" in manifest and not isinstance(subject, dict):
                context.note(Refusal("manifest_subject_missing", mpath, "a signed manifest carries no subject"))
                continue
            if not isinstance(subject, dict):
                continue
            for member in ("identifier", "type", "digest"):
                if subject.get(member) != entry.get(member):
                    context.note(
                        Refusal("manifest_subject_mismatch", f"{mpath}/subject/{member}", f"subject.{member} is not the entry's {member}")
                    )
            if ("version" in subject) != ("version" in entry) or subject.get("version") != entry.get("version"):
                context.note(Refusal("manifest_subject_mismatch", f"{mpath}/subject/version", "subject.version and entry.version differ"))


def _held(context: Context, uri: Any) -> bytes | None:
    """The bytes the caller passed for ``uri``, or an inline data: URI's bytes, or None."""
    if not isinstance(uri, str):
        return None
    if uri.startswith("data:"):
        header, _, body = uri[5:].partition(",")
        if header.endswith(";base64"):
            try:
                return base64.b64decode(body, validate=True)
            except (ValueError, binascii.Error):
                return None
        return urllib.parse.unquote_to_bytes(body)
    return context.files.get(uri)


def _matches(digest: Any, data: bytes, where: str) -> bool:
    name, hexvalue = parse_digest(digest, where)
    return hashlib.new(name, data).hexdigest() == hexvalue


def _check_entry_bytes(context: Context) -> None:
    for path, entry in _entries(context.document):
        if "digest" not in entry:
            continue
        if "data" in entry:
            data = canonical_bytes(entry["data"])
        else:
            held = _held(context, entry.get("url"))
            if held is None:
                context.note(Refusal("entry-bytes-not-evaluated", f"{path}/digest", "the artifact at url was not passed"))
                continue
            data = held
        try:
            if not _matches(entry["digest"], data, f"{path}/digest"):
                context.note(Refusal("entry_digest_mismatch", f"{path}/digest", "the artifact bytes do not have the entry's digest"))
        except Refusal:
            continue  # digest-format reports it


def _check_attestation_pins(context: Context) -> None:
    for path, entry in _entries(context.document):
        for apath, item in _attestations(path, entry):
            held = _held(context, item.get("uri"))
            if held is None:
                if "digest" in item:
                    context.note(Refusal("attestation-pin-not-evaluated", f"{apath}/digest", "the attestation document was not passed"))
                continue
            size = item.get("size")
            if isinstance(size, int) and not isinstance(size, bool) and len(held) > size:
                context.note(Refusal("attestation_size_exceeded", f"{apath}/size", f"{len(held)} bytes against a stated {size}"))
            if "digest" in item:
                try:
                    if not _matches(item["digest"], held, f"{apath}/digest"):
                        context.note(Refusal("attestation_digest_mismatch", f"{apath}/digest", "the attestation bytes do not have the pinned digest"))
                except Refusal:
                    continue


def _signature_present(signature: Any) -> bool:
    """A DSSE signature entry whose ``sig`` is non-empty, canonical base64 (standard or URL-safe)."""
    sig = signature.get("sig") if isinstance(signature, dict) else None
    try:
        return bool(decode_base64(sig, "sig"))
    except ValueError:
        return False


def _statement(held: bytes) -> tuple[dict[str, Any] | None, str]:
    """The statement of a signed in-toto DSSE envelope, or None and the code that refuses it."""
    try:
        envelope = strict_json.loads(held)
    except Refusal:
        return None, "attestation_unsigned"
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
        return None, "attestation_unsigned"
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not any(_signature_present(s) for s in signatures):
        return None, "attestation_unsigned"
    if envelope.get("payloadType") != IN_TOTO_PAYLOAD_TYPE:
        return None, "attestation_payload_type"
    try:
        statement = strict_json.loads(decode_base64(envelope["payload"], "payload"))
    except (Refusal, ValueError):
        return None, "attestation_unsigned"
    if not isinstance(statement, dict):
        return None, "attestation_unsigned"
    if statement.get("_type") not in STATEMENT_TYPES:
        return None, "attestation_not_a_statement"
    return statement, ""


def _entry_digest(entry: dict[str, Any]) -> tuple[str, str] | None:
    """The entry's ``(in-toto digest-set key, hex)``: its ``digest``, or for an inline entry with
    none, the SHA-256 of its data's RFC 8785 bytes. None when neither is readable."""
    digest = entry.get("digest")
    if isinstance(digest, str):
        algorithm, _, hexvalue = digest.partition(":")
        return (algorithm.replace("-", "_"), hexvalue) if algorithm in ALGORITHMS and hexvalue else None
    if "data" in entry and "url" not in entry:
        return "sha256", hashlib.sha256(canonical_bytes(entry["data"])).hexdigest()
    return None


def _binding_sets(statement: dict[str, Any], entry: dict[str, Any]) -> list[dict[str, Any]]:
    """The digest sets of the subjects that carry the entry's digest under the same algorithm. The
    name is not a binding: two artifacts can carry one name, and only the digest says which one."""
    subjects = statement.get("subject")
    expected = _entry_digest(entry)
    if expected is None:
        return []
    key, hexvalue = expected
    out = []
    for subject in subjects if isinstance(subjects, list) else []:
        named = subject.get("digest") if isinstance(subject, dict) else None
        if isinstance(named, dict) and named.get(key) == hexvalue:
            out.append(named)
    return out


def _artifact_bytes(context: Context, entry: dict[str, Any]) -> bytes | None:
    """The bytes the entry's digest is over, when this set holds them: an inline entry's RFC 8785
    data, or the bytes the caller passed for its url."""
    if "data" in entry and "url" not in entry:
        return canonical_bytes(entry["data"])
    return _held(context, entry.get("url"))


def _split(digest_set: dict[str, Any], data: bytes) -> str | None:
    """The first algorithm of ``digest_set`` under which ``data`` has another digest, or None."""
    for key, value in sorted(digest_set.items()):
        name = DIGEST_SET_ALGORITHMS.get(key)
        if name is not None and hashlib.new(name, data).hexdigest() != value:
            return key
    return None


def _check_attestation_subject(context: Context) -> None:
    for path, entry in _entries(context.document):
        for apath, item in _attestations(path, entry):
            held = _held(context, item.get("uri"))
            if held is None:
                context.note(Refusal("attestation-subject-not-evaluated", apath, "the attestation document was not passed"))
                continue
            statement, code = _statement(held)
            if statement is None:
                why = {
                    "attestation_unsigned": "the attestation is not a signed statement, so nothing binds it to this entry",
                    "attestation_payload_type": f"the envelope's payloadType is not {IN_TOTO_PAYLOAD_TYPE}, so its payload is not a statement",
                    "attestation_not_a_statement": "the payload's _type is not an in-toto Statement, so its subject is not a binding",
                }[code]
                context.note(Refusal(code, apath, why))
            else:
                bound = _binding_sets(statement, entry)
                if not bound:
                    context.note(Refusal("attestation_subject_mismatch", apath, "no subject of the signed statement carries the entry's digest"))
                    continue
                data = _artifact_bytes(context, entry)
                split = None
                for digest_set in bound if data is not None else []:
                    split = split or _split(digest_set, data)
                if split:
                    context.note(Refusal("attestation_digest_set_split", apath,
                                         f"the binding subject's {split} names other bytes than the artifact: one digest set, two artifacts"))


CATALOG_ATTESTATIONS = register(
    RuleSet(
        name="catalog-attestations",
        summary="ARD and AI Catalog entries: digests, attestation pins, and attestations bound to the entry they sit in",
        checks=(
            Check("entry-shape", "entries, manifests and attestations are the types the format gives them; each entry carries exactly one of url and data", _check_entry_shape),
            Check("digest-format", "every digest is <alg>:<lowercase hex>, SHA-256 or stronger", _check_digest_format),
            Check("digest-required", "an entry by url with attestations or a signed manifest names its digest", _check_digest_required),
            Check("subject", "a signed manifest has a subject equal to the entry", _check_subject),
            Check("entry-bytes", "the artifact bytes passed have the entry's digest", _check_entry_bytes),
            Check("attestation-pins", "each attestation passed has its pinned digest and size", _check_attestation_pins),
            Check("attestation-subject", "each attestation is a signed in-toto statement whose subject carries the entry's digest", _check_attestation_subject),
        ),
        option_help={},
    )
)
