"""Build the deterministic DNS-AID RRset vectors.

    python3 corpora/vectors-dns-aid-rrset-v01/gen_vectors.py

Each member is the SVCB RRset a zone serves for one agent name, beside the agent
protocols its publisher says it published. The manifest holds the codes a reader
must report under the rule in check_vectors.py: one record per published agent
protocol, and no record that names none or two. Both drafts' own example RRsets
are controls that must pass. The runtime members are snapshots of a publisher
after a sequence of operations (publish mcp then a2a; delete one), so a reader
can be run over a live backend's answer the same way. All fixtures are synthetic.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "dns-aid-rrset/v1"
OWNER = "_chat._agents.example.com"

SPECIFICATION = {
    "status": "proposal of this repository, not a vendored upstream text",
    "scope": (
        "The SVCB RRset served for one DNS-AID agent name. The agent protocol of a record is "
        "its proto SvcParam when that member is present, even when it is empty, and otherwise "
        "the alpn tokens that are not transports (h2, h3, h2c, http/1.1). Each is a "
        "comma-separated string or a list of strings. A conforming RRset has exactly one record "
        "per agent protocol the publisher published, and no record names no protocol or two. "
        "Any other shape, a published list that is not strings, or a member file that is not "
        "strict JSON (a duplicate name, a NaN literal) is rrset-malformed. All fixtures are "
        "synthetic."
    ),
    "sources": [
        "RFC 9460 Service Binding and Parameter Specification via the DNS (SVCB)",
        "IETF draft on DNS-based agent discovery, revision 02, section 3.1.1 example records",
        "IETF draft on DNS-based agent discovery, newer revision 00, section 3.1.1 and Table 1 (proto)",
    ],
    "verifierContract": (
        "verifier <case file>: the last stdout line is one JSON object with `verdict` (valid "
        "or invalid) and `codes` (a set); exit 0 for valid, 1 for invalid."
    ),
}


def rec(alpn: Any, proto: Any = None, target: str = "chat.example.com") -> dict[str, Any]:
    params: dict[str, Any] = {"alpn": alpn, "port": 443}
    if proto is not None:
        params["proto"] = proto
    return {"owner": OWNER, "params": params, "priority": 1, "target": target}


BOTH = ["a2a", "mcp"]
MEMBERS: tuple[tuple[str, Any, list[Any], list[str], str], ...] = (
    ("two-records-bare-alpn", BOTH, [rec("mcp"), rec("a2a")], [],
     "two records, alpn=mcp and alpn=a2a: one record per protocol"),
    ("draft-02-example-rrset", BOTH, [rec("mcp,h2,h3"), rec("a2a,h2,h3")], [],
     "the earlier draft's example: the protocol shares alpn with the transports"),
    ("draft-newer-00-example-rrset", BOTH, [rec("h2,h3", "a2a"), rec("h2,h3", "mcp")], [],
     "the newer draft's example: alpn carries the transports, proto the agent protocol"),
    ("one-record-after-overwrite", BOTH, [rec("a2a")], ["protocol-record-missing"],
     "after publishing mcp then a2a only the a2a record remains: the second publish replaced the first"),
    ("two-protocols-one-alpn", BOTH, [rec("mcp,a2a")], ["record-names-two-protocols"],
     "one record names two agent protocols in alpn"),
    ("two-protocols-one-proto", BOTH, [rec("h2,h3", "a2a,mcp"), rec("h2,h3", "mcp")],
     ["record-names-two-protocols"], "one record's proto value names two agent protocols"),
    ("transport-only-record", BOTH, [rec("h2,h3"), rec("mcp"), rec("a2a")], ["record-names-no-protocol"],
     "a record whose alpn names only transports and that carries no proto"),
    ("duplicate-protocol-record", BOTH, [rec("mcp"), rec("mcp", target="chat2.example.com"), rec("a2a")],
     ["protocol-record-duplicated"], "two records for mcp, so which endpoint serves it is undecided"),
    ("unpublished-protocol-record", ["mcp"], [rec("mcp"), rec("a2a")], ["protocol-record-unexpected"],
     "a record for a protocol the publisher did not publish"),
    ("after-delete-sibling-kept", ["a2a"], [rec("a2a")], [],
     "after deleting the mcp record the a2a record is still served"),
    ("after-delete-sibling-lost", ["a2a"], [], ["protocol-record-missing"],
     "deleting the mcp record also removed the a2a record"),
    ("alpn-as-list", BOTH, [rec(["mcp", "h2"]), rec(["a2a", "h3"])], [],
     "alpn as a list of ids (RFC 9460 7.1.1): reading its text form ['mcp', 'h2'] would find two protocols"),
    ("proto-empty", ["mcp"], [rec("mcp", "")], ["protocol-record-missing", "record-names-no-protocol"],
     "proto is present and empty, so the record names no protocol; it does not fall back to alpn"),
    ("record-not-object", BOTH, ["mcp"], ["rrset-malformed"], "a record that is a string, not an object"),
    ("published-as-string", "mcp", [rec("mcp")], ["rrset-malformed"],
     "published is the string mcp, not a list; read as a set of characters it would be m, c and p"),
    ("alpn-not-a-string", ["mcp"], [rec(5)], ["rrset-malformed"], "alpn is the number 5"),
    ("member-duplicate-alpn", BOTH, [rec("mcp"), rec("a2a")], ["rrset-malformed"],
     "the member file names the first record's alpn twice; a first-wins reader sees h2 and no mcp record"),
)

#: Member files whose text is edited after writing, so one is not strict JSON:
#: (the text to find, the text put in front of it).
TEXT_EDITS = {"member-duplicate-alpn": ('    "alpn": "mcp",\n', '    "alpn": "h2",\n')}


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def corpus_digest(manifest: dict[str, Any], root: str | Path = ROOT) -> str:
    base, body = Path(root), b""
    for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
        data = (base / entry["file"]).read_bytes()
        if _sha(data) != entry["sha256"]:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        body += data
    return _sha(body)


def generate(root: Path = ROOT) -> dict[str, Any]:
    (root / "cases").mkdir(parents=True, exist_ok=True)
    names = {f"{m[0]}.json" for m in MEMBERS}
    for stale in (root / "cases").glob("*.json"):
        if stale.name not in names:
            stale.unlink()
    entries = []
    for name, published, rrset, codes, description in MEMBERS:
        data = _json({"case": name, "published": published, "rrset": rrset})
        if name in TEXT_EDITS:
            find, before = TEXT_EDITS[name]
            assert data.count(find.encode()) == 1, name
            data = data.replace(find.encode(), (before + find).encode())
        (root / "cases" / f"{name}.json").write_bytes(data)
        entries.append({"description": description,
                        "expected": {"codes": sorted(codes), "verdict": "invalid" if codes else "valid"},
                        "file": f"cases/{name}.json", "id": name,
                        "kind": "reject" if codes else "accept", "sha256": _sha(data)})
    digest = corpus_digest({"vectors": entries}, root)
    manifest = {"corpusDigest": digest,
                "counts": {k: n for k in ("accept", "reject") if (n := sum(e["kind"] == k for e in entries))},
                "specification": SPECIFICATION, "suite": SUITE, "vectors": entries}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    lines = ["# DNS-AID RRset vectors", "", "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
             "", f"Suite: `{SUITE}`.", "", f"Corpus digest: `{digest}`", "",
             "| id | kind | codes | case |", "| --- | --- | --- | --- |"]
    for e in entries:
        codes = ", ".join(f"`{c}`" for c in e["expected"]["codes"]) or "none"
        lines.append(f"| `{e['id']}` | {e['kind']} | {codes} | {e['description']} |")
    (root / "INDEX.md").write_bytes(("\n".join(lines) + "\n").encode())
    return manifest


if __name__ == "__main__":
    generate()
