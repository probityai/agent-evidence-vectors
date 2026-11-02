"""Judge one attribution of harm propagating from one agent to another.

In a multi-agent incident, agent B misbehaves after agent A was compromised,
and a report says the compromise propagated from A to B. That attribution is a
claim about an edge: a message A sent that B received before it acted. Two
agents exposed to the same poisoned source misbehave too, with no edge between
them, and attributing that common cause as propagation sends containment to
the wrong place.

Every record is one hop's attribution: the hop (from, to, and how it is
attributed: ``propagation``, ``common_cause`` or ``not_established``), the
message log, the digest chain the attribution cites from A's message to B's
input, each agent's exposures to outside sources, and when B's effect
happened. The reader checks in a fixed order and names the first check that
fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the propagation-step contract (``contract_id_unknown``);
3. the hop names two different agents (``hop_endpoints_missing``);
4. every chain link names a logged message and carries that message's digest
   (``chain_digest_mismatch``);
5. the chain starts at a message A sent, ends at a message B received, and
   each link's receiver is the next link's sender (``chain_not_connected``);
6. every chain message was sent in order and before B's effect
   (``edge_after_effect``);
7. a hop attributed as propagation cites a chain (``propagation_without_edge``);
8. a hop attributed as common cause names a source both agents were exposed to
   before B's effect (``common_cause_unsupported``).

A record that passes all eight is ``allow`` with reason
``attribution_supported``. ``not_established`` is always available.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import (
    ALLOW,
    DENY,
    EXIT_FOR,
    check_corpus,
    cli,
    run_corpus,
)

SUITE = "propagation-step/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/propagation-step"
ALLOWED_REASON = "attribution_supported"
ATTRIBUTIONS = ("propagation", "common_cause", "not_established")
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "hop_endpoints_missing",
    "chain_digest_mismatch",
    "chain_not_connected",
    "edge_after_effect",
    "propagation_without_edge",
    "common_cause_unsupported",
)
__all__ = ["ALLOW", "CONTRACT_ID", "DENY", "EXIT_FOR", "SUITE", "check", "main", "verify"]
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-propagation-step" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-propagation-step")

Record = dict[str, Any]


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _messages(record: Record) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in record["messages"]}


def _digest_mismatch(record: Record) -> bool:
    messages = _messages(record)
    return any(link["messageId"] not in messages
               or messages[link["messageId"]]["digest"] != link["digest"]
               for link in record["chain"])


def _not_connected(record: Record) -> bool:
    chain, hop = record["chain"], record["hop"]
    if not chain:
        return False
    sent = [_messages(record)[link["messageId"]] for link in chain]
    if sent[0]["from"] != hop["from"] or sent[-1]["to"] != hop["to"]:
        return True
    return any(a["to"] != b["from"] for a, b in zip(sent, sent[1:], strict=False))


def _after_effect(record: Record) -> bool:
    sent = [_at(_messages(record)[link["messageId"]]["sentAt"]) for link in record["chain"]]
    effect = _at(record["effect"]["at"])
    return sent != sorted(sent) or any(at >= effect for at in sent)


def _common_cause_unsupported(record: Record) -> bool:
    hop = record["hop"]
    if hop["attributedAs"] != "common_cause":
        return False
    effect = _at(record["effect"]["at"])

    def sources(agent: str) -> set[str]:
        return {item["source"] for item in record["exposures"]
                if item["agent"] == agent and _at(item["at"]) < effect}

    return not sources(hop["from"]) & sources(hop["to"])


def retained(record: Record) -> dict[str, Any]:
    """The hop, its attribution and the chain length a verifier keeps."""
    hop = record["hop"]
    return {"attributedAs": hop["attributedAs"], "chainLength": len(record["chain"]),
            "from": hop.get("from", ""), "to": hop.get("to", "")}


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None."""
    hop = record["hop"]
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "hop_endpoints_missing": lambda: (not hop.get("from") or not hop.get("to")
                                          or hop["from"] == hop["to"]),
        "chain_digest_mismatch": lambda: _digest_mismatch(record),
        "chain_not_connected": lambda: _not_connected(record),
        "edge_after_effect": lambda: _after_effect(record),
        "propagation_without_edge": lambda: (hop["attributedAs"] == "propagation"
                                             and not record["chain"]),
        "common_cause_unsupported": lambda: _common_cause_unsupported(record),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    record: Record = json.loads(record_path.read_text(encoding="utf-8"))
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    return cli(argv, __doc__, verify, check, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
