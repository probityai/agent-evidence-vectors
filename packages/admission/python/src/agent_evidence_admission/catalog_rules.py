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
signed statement whose subject names that entry (``attestation_unsigned``,
``attestation_subject_mismatch``).

The caller passes the bytes it holds in ``files``, keyed by the URL or URI the catalog names; an
inline ``data:`` URI is read directly. Nothing is fetched. A pin whose bytes the caller did not
pass refuses as not evaluated, never passes; list the ``*-not-evaluated`` codes in ``warn`` to
accept a check that could not run. A DSSE envelope counts as signed when it
carries a signature; whether that signature verifies is the verifier's question, asked after
admission, and this set does not answer it.
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


def _check_entry_shape(context: Context) -> None:
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


def _statement(held: bytes) -> dict[str, Any] | None:
    """The statement of a DSSE envelope that carries at least one signature, else None."""
    try:
        envelope = strict_json.loads(held)
    except Refusal:
        return None
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
        return None
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not any(isinstance(s, dict) and s.get("sig") for s in signatures):
        return None
    try:
        statement = strict_json.loads(base64.b64decode(envelope["payload"], validate=True))
    except (Refusal, ValueError, binascii.Error):
        return None
    return statement if isinstance(statement, dict) else None


def _binds(statement: dict[str, Any], entry: dict[str, Any]) -> bool:
    """A subject naming the entry's identifier or its digest (under the same algorithm)."""
    subjects = statement.get("subject")
    digest = entry.get("digest")
    algorithm, _, hexvalue = digest.partition(":") if isinstance(digest, str) else ("", "", "")
    for subject in subjects if isinstance(subjects, list) else []:
        if not isinstance(subject, dict):
            continue
        if entry.get("identifier") is not None and subject.get("name") == entry.get("identifier"):
            return True
        named = subject.get("digest")
        if hexvalue and isinstance(named, dict) and named.get(algorithm.replace("-", "_")) == hexvalue:
            return True
    return False


def _check_attestation_subject(context: Context) -> None:
    for path, entry in _entries(context.document):
        for apath, item in _attestations(path, entry):
            held = _held(context, item.get("uri"))
            if held is None:
                context.note(Refusal("attestation-subject-not-evaluated", apath, "the attestation document was not passed"))
                continue
            statement = _statement(held)
            if statement is None:
                context.note(
                    Refusal(
                        "attestation_unsigned",
                        apath,
                        "the attestation is not a signed statement, so nothing binds it to this entry",
                    )
                )
            elif not _binds(statement, entry):
                context.note(Refusal("attestation_subject_mismatch", apath, "the signed statement's subject names neither the entry nor its digest"))


CATALOG_ATTESTATIONS = register(
    RuleSet(
        name="catalog-attestations",
        summary="ARD and AI Catalog entries: digests, attestation pins, and attestations bound to the entry they sit in",
        checks=(
            Check("entry-shape", "each entry carries exactly one of url and data", _check_entry_shape),
            Check("digest-format", "every digest is <alg>:<lowercase hex>, SHA-256 or stronger", _check_digest_format),
            Check("digest-required", "an entry by url with attestations or a signed manifest names its digest", _check_digest_required),
            Check("subject", "a signed manifest has a subject equal to the entry", _check_subject),
            Check("entry-bytes", "the artifact bytes passed have the entry's digest", _check_entry_bytes),
            Check("attestation-pins", "each attestation passed has its pinned digest and size", _check_attestation_pins),
            Check("attestation-subject", "each attestation is a signed statement naming the entry", _check_attestation_subject),
        ),
        option_help={},
    )
)
