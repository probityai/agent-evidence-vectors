"""Build the propagation-step cases byte-identically.

Every case is one hop's attribution between two agents. Each denied case is
built so the check it names is the first that fails; each allowed case is a
control that keeps a verifier from denying everything. Every member is
synthetic: agents, sources and message bodies are fixed labelled strings.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import propagationstep as reader  # noqa: E402

SUITE = reader.SUITE
T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=UTC)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def ts(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def message(mid: str, sender: str, to: str, at: float) -> dict[str, Any]:
    body = f"synthetic propagation-step message {mid} from {sender} to {to}".encode()
    return {"digest": "sha256:" + _sha(body), "from": sender, "id": mid, "sentAt": ts(at),
            "to": to}


MESSAGES = [message("m1", "agent-a", "agent-c", 60), message("m2", "agent-c", "agent-b", 90),
            message("m3", "agent-b", "agent-a", 150), message("m4", "agent-a", "agent-b", 400)]


def link(mid: str) -> dict[str, str]:
    found = next(m for m in MESSAGES if m["id"] == mid)
    return {"digest": found["digest"], "messageId": mid}


def exposure(agent: str, source: str, at: float) -> dict[str, Any]:
    return {"agent": agent, "at": ts(at), "source": source}


SHARED = [exposure("agent-a", "doc-poisoned", 10), exposure("agent-b", "doc-poisoned", 20)]
OWN = [exposure("agent-a", "doc-poisoned", 10), exposure("agent-b", "doc-clean", 20)]
CHAIN = [link("m1"), link("m2")]


def build(name: str, attributed: str, chain: list[dict[str, str]], *,
          exposures: list[dict[str, Any]] | None = None, effect_at: float = 120,
          hop_from: str = "agent-a", hop_to: str = "agent-b", **top: Any) -> dict[str, Any]:
    """One hop's attribution, with the message log, chain, exposures and effect."""
    record: dict[str, Any] = {
        "chain": copy.deepcopy(chain), "contractId": reader.CONTRACT_ID,
        "effect": {"agent": hop_to, "at": ts(effect_at)},
        "exposures": copy.deepcopy(exposures if exposures is not None else OWN),
        "hop": {"attributedAs": attributed, "from": hop_from, "to": hop_to},
        "messages": copy.deepcopy(MESSAGES), "recordId": f"record-{name}",
    }
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, and what it shows."""
    ok = reader.ALLOWED_REASON
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    bad_digest = [link("m1"), {**link("m2"), "digest": "sha256:" + _sha(b"another message")}]
    late_b = [exposure("agent-a", "doc-poisoned", 10), exposure("agent-b", "doc-poisoned", 200)]
    return [
        ("allow-propagation-by-digest-chain",
         build("allow-propagation-by-digest-chain", "propagation", CHAIN),
         "allow", ok, "control: A's message reaches B through C, each link carrying the logged "
         "message's digest, before B acts"),
        ("allow-common-cause-shared-source",
         build("allow-common-cause-shared-source", "common_cause", [], exposures=SHARED),
         "allow", ok, "control: both agents read the same poisoned document and no message "
         "joins them; the hop is attributed as common cause"),
        ("allow-not-established-both",
         build("allow-not-established-both", "not_established", CHAIN, exposures=SHARED),
         "allow", ok, "control: a chain and a shared source both precede the effect, and the "
         "hop is left not established"),
        ("reject-contract-id-missing",
         build("reject-contract-id-missing", "propagation", CHAIN, contractId=None),
         "deny", "contract_id_missing", "the record names no contract"),
        ("reject-contract-id-unknown",
         build("reject-contract-id-unknown", "propagation", CHAIN, contractId=unknown),
         "deny", "contract_id_unknown", "the record names a contract version that does not "
         "exist"),
        ("reject-hop-to-itself",
         build("reject-hop-to-itself", "propagation", CHAIN, hop_to="agent-a"),
         "deny", "hop_endpoints_missing", "the hop runs from an agent to itself"),
        ("reject-chain-digest-mismatch",
         build("reject-chain-digest-mismatch", "propagation", bad_digest),
         "deny", "chain_digest_mismatch", "the second link carries a digest the logged message "
         "does not have"),
        ("reject-chain-gap", build("reject-chain-gap", "propagation", [link("m2")]),
         "deny", "chain_not_connected", "the chain starts at C's message, not at one A sent"),
        ("reject-edge-after-effect", build("reject-edge-after-effect", "propagation", [link("m4")]),
         "deny", "edge_after_effect", "the only message from A reaches B after B acted"),
        ("reject-common-cause-attributed-as-propagation",
         build("reject-common-cause-attributed-as-propagation", "propagation", [],
               exposures=SHARED),
         "deny", "propagation_without_edge", "both agents read the same poisoned document and "
         "no message joins them, and the hop is attributed as propagation"),
        ("reject-common-cause-without-shared-source",
         build("reject-common-cause-without-shared-source", "common_cause", []),
         "deny", "common_cause_unsupported", "the hop is attributed as common cause and the "
         "agents read different sources"),
        ("reject-common-cause-exposure-after-effect",
         build("reject-common-cause-exposure-after-effect", "common_cause", [], exposures=late_b),
         "deny", "common_cause_unsupported", "B read the shared document only after it acted"),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
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
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({"edit": edit, "expected": expected,
                        "files": {"record.json": _sha(data)}, "id": name,
                        "path": f"cases/{name}", "retained": reader.retained(body)})
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
