"""Re-mint the catalog-trust-manifest corpus from CASES.json alone.

This generator shares no code with gen_vectors.py or the agent_evidence_vectors
package: it reads the case table, canonicalizes with its own RFC 8785 writer and
signs with `cryptography` (RFC 6979 deterministic ES256, RFC 8032 Ed25519). The
corpus test runs it into an empty directory and requires every byte to equal the
committed corpus, so a defect in either implementation's signing input,
canonical form or serialization shows up as a byte difference.

    cd corpora/vectors-catalog-trust-manifest
    uv run --extra generators python gen_vectors_independent.py OUT
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
ORDER_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TYPS = {"ai-catalog-2026-11": "ai-catalog-trust-manifest+jws",
        "ai-catalog-snapshot": "ai-catalog+jws"}
DSSE_KIND = b"application/vnd.in-toto+json"


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unpadded(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jcs(value: Any) -> bytes:
    """RFC 8785 for the values the table produces: integers, strings, booleans, null."""
    if value is None:
        return b"null"
    if value is True or value is False:
        return b"true" if value else b"false"
    if isinstance(value, int):
        return str(value).encode()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(item) for item in value) + b"]"
    names = sorted(value, key=lambda name: [unit for unit in name.encode("utf-16-be")])
    return b"{" + b",".join(jcs(name) + b":" + jcs(value[name]) for name in names) + b"}"


class Keys:
    def __init__(self, table: dict[str, list[Any]]) -> None:
        self.table = table

    def private(self, name: str) -> Any:
        label = self.table[name][3].encode()
        if self.table[name][2] == "EdDSA":
            return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest())
        number = int.from_bytes(hashlib.sha256(label).digest(), "big") % (ORDER_N - 1) + 1
        return ec.derive_private_key(number, ec.SECP256R1())

    def sign(self, name: str, message: bytes) -> bytes:
        key = self.private(name)
        if isinstance(key, Ed25519PrivateKey):
            return key.sign(message)
        r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256(),
                                                               deterministic_signing=True)))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def jwk(self, name: str) -> dict[str, str]:
        public = self.private(name).public_key()
        if self.table[name][2] == "EdDSA":
            return {"crv": "Ed25519", "kty": "OKP",
                    "x": unpadded(public.public_bytes(Encoding.Raw, PublicFormat.Raw))}
        numbers = public.public_numbers()
        return {"crv": "P-256", "kty": "EC", "x": unpadded(numbers.x.to_bytes(32, "big")),
                "y": unpadded(numbers.y.to_bytes(32, "big"))}


def edit(document: Any, operations: list[dict[str, Any]], names: dict[str, str]) -> None:
    def follow(path: list[Any]) -> Any:
        node = document
        for step in path:
            node = node[step]
        return node

    def fill(value: Any) -> Any:
        if isinstance(value, str):
            return names.get(value, value)
        if isinstance(value, list):
            return [fill(item) for item in value]
        if isinstance(value, dict):
            return {key: fill(item) for key, item in value.items()}
        return value

    for operation in operations:
        holder, last = follow(operation["path"][:-1]), operation["path"][-1]
        if operation["op"] == "del":
            del holder[last]
        elif operation["op"] == "copy":
            holder[last] = copy.deepcopy(follow(operation["from"]))
        else:
            holder[last] = fill(copy.deepcopy(operation["value"]))


def signing_payload(catalog: dict[str, Any], spec: dict[str, Any]) -> Any:
    kind = spec["construction"]
    if kind == "ai-catalog-snapshot":
        whole = copy.deepcopy(catalog)
        whole["signature"].pop("jws", None)
        whole.pop("additionalSignatures", None)
        return whole
    entry = catalog["entries"][spec["entry"]]
    if kind == "ard-draft-bu-00":
        manifest = copy.deepcopy(entry["trustManifest"])
        manifest.pop("signature", None)
        return manifest
    if kind == "field-whole-entry":
        whole = copy.deepcopy(entry)
        whole["trustManifest"].pop("signature", None)
        return whole
    manifest = copy.deepcopy(entry["trustManifests"][spec["manifest"]])
    manifest["signature"].pop("jws", None)
    manifest.pop("additionalSignatures", None)
    return manifest


class Minter:
    def __init__(self, table: dict[str, Any]) -> None:
        self.keys = Keys(table["keys"])
        self.key_table = table["keys"]
        self.publisher = self.key_table["publisher"][0]
        self.assessor = self.key_table["assessor"][0]

    def card(self, slug: str) -> dict[str, Any]:
        return {"description": f"The {slug} agent.", "name": f"{slug} agent",
                "url": f"https://publisher.example/agents/{slug}", "version": "1.0.0"}

    def manifest(self, signer: str, subject: dict[str, Any]) -> dict[str, Any]:
        return {"contributor": signer, "signature": {
            "expiresAt": "2027-11-01T00:00:00Z", "issuedAt": "2026-11-01T00:00:00Z",
            "profile": "did-web-v1", "signer": signer}, "subject": dict(subject)}

    def entry(self, slug: str, sha: str, ard: bool) -> dict[str, Any]:
        identifier = f"urn:air:publisher.example:agent:{slug}"
        subject = {"digest": sha, "identifier": identifier,
                   "type": "application/a2a-agent-card+json", "version": "1.0.0"}
        out: dict[str, Any] = {
            "digest": sha, "displayName": slug, "identifier": identifier,
            "type": "application/a2a-agent-card+json",
            "url": f"https://publisher.example/agents/{slug}/agent-card.json", "version": "1.0.0"}
        if ard:
            out["trustManifest"] = {"expiresAt": "2027-11-01T00:00:00Z",
                                    "identity": self.publisher,
                                    "issuedAt": "2026-11-01T00:00:00Z", "subject": subject}
        else:
            out["trustManifests"] = [self.manifest(self.publisher, subject)]
        return out

    def statement_file(self, spec: dict[str, Any], names: dict[str, str]) -> bytes:
        if spec["kind"] == "sarif":
            return dump({"runs": [{"results": [], "tool": {"driver": {"name": "scanner"}}}],
                         "version": "2.1.0"})
        target = names["$ARTIFACT" if spec["subject"] == "artifact" else "$OTHER"]
        body = json.dumps({"_type": "https://in-toto.io/Statement/v1",
                           "predicate": {"result": "pass"}, "predicateType": spec["predicate"],
                           "subject": [{"digest": {"sha256": target[7:]},
                                        "name": "agent-card.json"}]},
                          separators=(",", ":"), sort_keys=True).encode()
        pae = b"DSSEv1 " + str(len(DSSE_KIND)).encode() + b" " + DSSE_KIND + b" " + \
            str(len(body)).encode() + b" " + body
        return dump({"payload": base64.b64encode(body).decode(), "payloadType": DSSE_KIND.decode(),
                     "signatures": [{"keyid": self.assessor + "#es256", "sig": base64.b64encode(
                         self.keys.sign("assessor", pae)).decode()}]})

    def jws(self, catalog: dict[str, Any], spec: dict[str, Any]) -> str:
        did, fragment, alg, _ = self.key_table[spec["key"]]
        header: dict[str, Any] = {"alg": alg, "kid": did + "#" + fragment}
        if spec["construction"] in TYPS:
            header["typ"] = TYPS[spec["construction"]]
        for name, value in spec["header"].items():
            if value is None:
                header.pop(name, None)
            else:
                header[name] = value
        protected = unpadded(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        body = jcs(signing_payload(catalog, spec))
        signed = body if header.get("b64") is False else unpadded(body).encode()
        signature = self.keys.sign(spec["key"], protected.encode() + b"." + signed)
        if spec["form"] == "attached":
            return protected + "." + unpadded(body) + "." + unpadded(signature)
        if spec["form"] == "padded":
            return protected + ".." + base64.urlsafe_b64encode(signature).decode()
        return protected + ".." + unpadded(signature)

    @staticmethod
    def store(catalog: dict[str, Any], spec: dict[str, Any], value: str) -> None:
        kind, entry = spec["construction"], catalog["entries"][spec["entry"]]
        if kind == "ai-catalog-snapshot":
            catalog["signature"]["jws"] = value
        elif kind in ("ard-draft-bu-00", "field-whole-entry"):
            entry["trustManifest"]["signature"] = value
        else:
            entry["trustManifests"][spec["manifest"]]["signature"]["jws"] = value

    def documents(self, operations: list[dict[str, Any]], names: dict[str, str]) -> bytes:
        documents: dict[str, Any] = {}
        for name, (did, fragment, _, _) in self.key_table.items():
            document = documents.setdefault(did, {"@context": ["https://www.w3.org/ns/did/v1"],
                                                  "assertionMethod": [], "id": did,
                                                  "verificationMethod": []})
            document["verificationMethod"].append({"controller": did, "id": did + "#" + fragment,
                                                   "publicKeyJwk": self.keys.jwk(name),
                                                   "type": "JsonWebKey2020"})
            document["assertionMethod"].append(did + "#" + fragment)
        edit(documents, operations, names)
        return dump(documents)

    def case(self, case: dict[str, Any]) -> dict[str, bytes]:
        card = self.card("travel")
        edit(card, case["artifact"], {})
        names = {"$ARTIFACT": "sha256:" + digest(dump(card)),
                 "$OTHER": "sha256:" + digest(dump(self.card("billing")))}
        ard = case["shape"] == "ard"
        catalog: dict[str, Any] = {
            "entries": [self.entry("travel", names["$ARTIFACT"], ard)],
            "host": {"displayName": "Publisher Example", "identifier": self.publisher},
            "specVersion": "1.0"}
        if case["secondEntry"]:
            catalog["entries"].append(self.entry("billing", names["$OTHER"], ard))
        if case["assessor"]:
            first = catalog["entries"][0]["trustManifests"]
            first.append(self.manifest(self.assessor, first[0]["subject"]))
        if case["shape"] == "snapshot":
            catalog["signature"] = {"expiresAt": "2027-11-01T00:00:00Z",
                                    "issuedAt": "2026-11-01T00:00:00Z",
                                    "profile": "did-web-v1", "signer": self.publisher}
        out: dict[str, bytes] = {}
        references = []
        for position, spec in enumerate(case["attestations"]):
            data = self.statement_file(spec, names)
            file_name = case["context"]["attestationFiles"][position]
            out[file_name] = data
            references.append({
                "digest": "sha256:" + digest(data),
                "mediaType": "application/sarif+json" if spec["kind"] == "sarif"
                else "application/vnd.in-toto+json",
                "type": spec["predicate"], "uri": "https://assessor.example/evidence/" + file_name})
        if references:
            first_entry = catalog["entries"][0]
            target = first_entry["trustManifest"] if ard else first_entry["trustManifests"][0]
            target["attestations"] = references
        edit(catalog, case["before"], names)
        for spec in case["sign"]:
            self.store(catalog, spec, self.jws(catalog, spec))
        edit(catalog, case["after"], names)
        text = dump(catalog).decode("ascii")
        for old, new in case["raw"]:
            text = text.replace(old, new, 1)
        for position in case["attestationAfter"]:
            file_name = case["context"]["attestationFiles"][position]
            out[file_name] += b"\n"
        edit(card, case["artifactAfter"], {})
        out["did-documents.json"] = self.documents(case["dids"], names)
        out["artifact.json"] = dump(card)
        out["catalog.json"] = text.encode("ascii")
        out["context.json"] = dump(case["context"])
        return out


def mint(table: dict[str, Any], target: Path) -> None:
    minter = Minter(table)
    rows = []
    for case in table["cases"]:
        files = minter.case(case)
        folder = target / "cases" / case["id"]
        folder.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            (folder / name).write_bytes(files[name])
        rows.append({"edit": case["edit"], "expected": case["expected"],
                     "files": {name: digest(files[name]) for name in sorted(files)},
                     "id": case["id"], "path": "cases/" + case["id"]})
    accepted = sum(row["expected"]["decision"] == "accept" for row in rows)
    (target / "MANIFEST.json").write_bytes(dump({
        "corpusDigest": digest(dump(rows)),
        "counts": {"accept": accepted, "reject": len(rows) - accepted},
        "suite": table["suite"], "vectors": rows}))


if __name__ == "__main__":
    mint(json.loads((HERE / "CASES.json").read_text(encoding="ascii")), Path(sys.argv[1]))
