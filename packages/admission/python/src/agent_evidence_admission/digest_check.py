"""The three-step digest check.

1. Read the document that describes an artifact: a TEA artifact (``formats[].checksums``), a
   CycloneDX BOM in JSON or XML (``metadata.component.hashes``), or an in-toto statement
   (``subject[].digest``), bare or in a DSSE envelope.
2. Recompute the artifact's digest with every algorithm the document names.
3. Pass only when one named digest equals the recomputed one.

A document that names no digest fails: a check that cannot compare anything has not passed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

FETCH_TIMEOUT_SECONDS = 60

#: Algorithm spellings seen in TEA, CycloneDX and in-toto, mapped to hashlib names.
ALGORITHMS: dict[str, str] = {
    "sha-256": "sha256",
    "sha256": "sha256",
    "sha-384": "sha384",
    "sha384": "sha384",
    "sha-512": "sha512",
    "sha512": "sha512",
    "sha3-256": "sha3_256",
    "sha3-512": "sha3_512",
}


@dataclass(frozen=True)
class Result:
    """The outcome of one check. ``reason`` is empty when ``ok``."""

    ok: bool
    reason: str
    matched: tuple[str, str] | None
    declared: tuple[tuple[str, str], ...]


def _algorithm(name: object) -> str | None:
    return ALGORITHMS.get(str(name).strip().lower()) if isinstance(name, str) else None


def _hash_entries(items: Any, alg_key: str, value_key: str) -> Iterator[tuple[str, str]]:
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            algorithm = _algorithm(item.get(alg_key))
            value = item.get(value_key)
            if algorithm and isinstance(value, str):
                yield algorithm, value.strip().lower()


def _subject_entries(document: Any) -> Iterator[tuple[str, str]]:
    """Digests in the positions that name the document's own subject, and nowhere else.

    A BOM also lists its dependencies' hashes and an attestation its materials' digests. An
    artifact matching one of those is that dependency, not the thing the document covers.
    """
    if not isinstance(document, dict):
        return
    # DSSE envelope: the statement is the base64 payload.
    if isinstance(document.get("payload"), str) and "payloadType" in document:
        try:
            statement = json.loads(base64.b64decode(document["payload"], validate=True))
        except (ValueError, binascii.Error):
            return
        yield from _subject_entries(statement)
        return
    # in-toto statement subjects.
    for subject in document.get("subject", []) if isinstance(document.get("subject"), list) else []:
        digest = subject.get("digest") if isinstance(subject, dict) else None
        for name, value in digest.items() if isinstance(digest, dict) else []:
            algorithm = _algorithm(name)
            if algorithm and isinstance(value, str):
                yield algorithm, value.strip().lower()
    # CycloneDX: the component the BOM describes.
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if isinstance(component, dict):
        yield from _hash_entries(component.get("hashes"), "alg", "content")
    # TEA artifact: each format's checksums, or checksums on the object itself.
    yield from _hash_entries(document.get("checksums"), "algType", "algValue")
    formats = document.get("formats")
    for fmt in formats if isinstance(formats, list) else []:
        if isinstance(fmt, dict):
            yield from _hash_entries(fmt.get("checksums"), "algType", "algValue")


def declared_digests(document: Any) -> list[tuple[str, str]]:
    """Every (algorithm, hex digest) naming the document's subject, in order, without repeats."""
    seen: dict[tuple[str, str], None] = {}
    for entry in _subject_entries(document):
        seen.setdefault(entry, None)
    return list(seen)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _cyclonedx_xml(root: ElementTree.Element) -> dict[str, Any]:
    """The subject component's hashes of a CycloneDX XML BOM, in the JSON shape."""
    hashes: list[dict[str, str]] = []
    for metadata in (child for child in root if _local(child.tag) == "metadata"):
        for component in (child for child in metadata if _local(child.tag) == "component"):
            for block in (child for child in component if _local(child.tag) == "hashes"):
                for item in (child for child in block if _local(child.tag) == "hash"):
                    hashes.append({"alg": item.get("alg", ""), "content": (item.text or "").strip()})
    return {"bomFormat": "CycloneDX", "metadata": {"component": {"hashes": hashes}}}


def parse_document(raw: bytes) -> Any:
    """Parse a JSON document, or a CycloneDX XML BOM. Raises ValueError on anything else."""
    text = raw.decode("utf-8-sig", errors="strict").lstrip()
    if text.startswith("<"):
        if "<!DOCTYPE" in text.upper():
            raise ValueError("refusing an XML document with a DOCTYPE")
        try:
            return _cyclonedx_xml(ElementTree.fromstring(text))
        except ElementTree.ParseError as error:
            raise ValueError(f"not well-formed XML: {error}") from error
    return json.loads(text)


def check(document: Any, artifact: bytes) -> Result:
    """Run steps 2 and 3 of the check on an already-read document and artifact."""
    declared = tuple(declared_digests(document))
    if not declared:
        return Result(False, "no-digest-named", None, declared)
    computed = {algorithm: hashlib.new(algorithm, artifact).hexdigest() for algorithm, _ in declared}
    for algorithm, value in declared:
        if computed[algorithm] == value:
            return Result(True, "", (algorithm, value), declared)
    return Result(False, "digest-mismatch", None, declared)


def read_source(source: str) -> bytes:
    """Read a local path, or fetch an https URL. Plain http is refused: the digest is the point."""
    if source.startswith("https://"):
        request = urllib.request.Request(source, headers={"User-Agent": "agent-evidence-admission"})
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            return bytes(response.read())
    if source.startswith("http://"):
        raise ValueError(f"refusing {source}: fetch the document over https")
    return Path(source).read_bytes()
