#!/usr/bin/env python3
"""Build the frozen occurrence-binding corpus for one paid request occurrence.

One request occurrence is frozen: the call, its nonce, the payer agent and the
responder. Every case starts from one intact set of three signed artifacts bound
to it (the issuer's budget statement, the payment receipt and the execution
receipt) under one frozen set of trust inputs, then changes one thing and states
the answer it expects on each axis.

The keys are TEST keys derived from a published recipe, so anyone can rebuild
the corpus byte for byte:
``seed = sha256("aev-occurrence-binding-test-key/<role>/v1")``.

    python scripts/occurrence-binding-build.py           # write the corpus
    python scripts/occurrence-binding-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.invocation_axes.reader import (  # noqa: E402
    canonical,
    invocation_binding,
    sha256_tag,
)
from agent_evidence_vectors.occurrence_binding.reader import (  # noqa: E402
    AXES,
    BUDGET_SCHEMA,
    EXECUTION_SCHEMA,
    NOT_RUN,
    NOT_RUN_SCHEMA,
    OCCURRENCE_SCHEMA,
    PAYMENT_SCHEMA,
    TRUST_SCHEMA,
    occurrence_binding,
)
from run_vectors import ed25519_public_key, ed25519_sign  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/occurrence_binding/corpus"
E = "ESTABLISHED"
C = "CONTRADICTED"
N = "NOT_ESTABLISHED"
ROLES = ("issuer", "payment_rail", "responder", "agent", "outsider")
VERIFIER_COMMAND = "agent-evidence-vectors-occurrence-binding --output <new directory>"


def _seed(role: str) -> bytes:
    return hashlib.sha256(f"aev-occurrence-binding-test-key/{role}/v1".encode()).digest()


KEYS = {role: ed25519_public_key(_seed(role)) for role in ROLES}
KEYIDS = {role: "sha256:" + hashlib.sha256(pub).hexdigest() for role, pub in KEYS.items()}

REQUEST: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 41,
    "method": "tools/call",
    "params": {
        "name": "audit_estimate",
        "arguments": {"estimate_id": "EST-2291", "line_items": 14, "region": "JP-13"},
    },
}


# The input the call is pinned to: the first two lines of an estimate fixture,
# as a payer sends it for the audit. The pin is sha256 over its RFC 8785 bytes.
FULL_FIXTURE: dict[str, Any] = {
    "lines": [
        {"item": "外壁塗装 シリコン", "qty": 180, "unit": "㎡", "unit_price": 3200},
        {"item": "足場設置 ㎡単価", "qty": 240, "unit": "㎡", "unit_price": 900},
        {"item": "高圧洗浄", "qty": 180, "unit": "㎡", "unit_price": 250},
    ],
    "type": "horizon-shield.estimate-fixture.v0",
}
INPUT = dict(FULL_FIXTURE, lines=FULL_FIXTURE["lines"][:2])
INPUT_PIN = sha256_tag(canonical(INPUT))
# The full three-line fixture: a run that audits it audited another input.
OTHER_INPUT_PIN = sha256_tag(canonical(FULL_FIXTURE))
# Two published versions of the reference price dataset the audit reads; the
# occurrence freezes the later one. These are digests of the published files.
DATASET_PIN = "sha256:7b16600e50ed73b844ff5b2718f04a6dd4d9ace0367982fb8d139db509d023fd"
OTHER_DATASET_PIN = "sha256:85418e4af9d3d727af2eb1c95566aa56f21d8ae1046601bc259baa302515680d"


def _occurrence(nonce: str = "occ-0001", request: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": OCCURRENCE_SCHEMA,
        "request": copy.deepcopy(REQUEST if request is None else request),
        "occurrence_nonce": nonce,
        "payer_agent": "agent:buyer-1",
        "responder": "service:estimate-audit",
        "price_units": 300,
        "currency": "test-units",
        "input_pins": {"input_sha256": INPUT_PIN, "dataset_sha256": DATASET_PIN},
        "input_file": "input.json",
        "trust_inputs": "trust.json",
        "verifier_command": VERIFIER_COMMAND,
    }


OCCURRENCE = _occurrence()
OCC = occurrence_binding(OCCURRENCE)
CALL = invocation_binding(REQUEST)
OTHER_REQUEST = copy.deepcopy(REQUEST)
OTHER_REQUEST["params"]["arguments"]["estimate_id"] = "EST-2292"
# The same call content, run a second time: only the nonce differs.
SAME_CALL_SECOND_RUN = occurrence_binding(_occurrence("occ-0002"))
OTHER_CALL_RUN = occurrence_binding(_occurrence("occ-0003", OTHER_REQUEST))


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _sign(statement: dict[str, Any], role: str) -> dict[str, Any]:
    return {
        "statement": statement,
        "keyid": KEYIDS[role],
        "signature_hex": ed25519_sign(_seed(role), canonical(statement)).hex(),
    }


def _broken(envelope: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(envelope)
    sig = bytearray(bytes.fromhex(out["signature_hex"]))
    sig[5] ^= 0x01
    out["signature_hex"] = sig.hex()
    return out


def _budget(**override: Any) -> dict[str, Any]:
    statement = {
        "schema": BUDGET_SCHEMA,
        "budget_id": "budget-17",
        "issuer": "issuer:principal-1",
        "agent": "agent:buyer-1",
        "limit_units": 1000,
        "spent_before_units": 600,
        "currency": "test-units",
    }
    statement.update(override)
    return statement


BUDGET = _sign(_budget(), "issuer")


def _payment(budget: dict[str, Any] = BUDGET, **override: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "schema": PAYMENT_SCHEMA,
        "budget_digest": sha256_tag(canonical(budget["statement"])),
        "amount_units": 300,
        "currency": "test-units",
        "rail": "testnet",
        "occurrence_binding": OCC,
    }
    statement.update(override)
    return {k: v for k, v in statement.items() if v is not None}


def _execution(**override: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "schema": EXECUTION_SCHEMA,
        "responder": "service:estimate-audit",
        "call_binding": CALL,
        "occurrence_binding": OCC,
        "input_sha256": INPUT_PIN,
        "dataset_sha256": DATASET_PIN,
        "outcome": "DISPATCHED",
    }
    statement.update(override)
    return {k: v for k, v in statement.items() if v is not None}


def _not_run(**override: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "schema": NOT_RUN_SCHEMA,
        "responder": "service:estimate-audit",
        "call_binding": CALL,
        "occurrence_binding": OCC,
        "outcome": NOT_RUN,
    }
    statement.update(override)
    return {k: v for k, v in statement.items() if v is not None}


def _set(
    budget: dict[str, Any] | None = BUDGET,
    payment: dict[str, Any] | None = None,
    execution: dict[str, Any] | None = None,
    no_execution: bool = False,
    not_run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out = {
        "budget": budget,
        "payment": payment if payment is not None else _sign(_payment(), "payment_rail"),
        "execution": None
        if no_execution
        else (execution if execution is not None else _sign(_execution(), "responder")),
    }
    if not_run is not None:
        out["not_run"] = not_run
    return out


def _expect(*words: str) -> dict[str, str]:
    out: dict[str, str] = {axis: word for axis, word in zip(AXES, words, strict=True)}
    out.update({"settlement_finality": N, "work_acceptance": N, "observed_effect": N})
    return out


def _cases() -> list[dict[str, Any]]:
    agent_budget = _sign(_budget(), "agent")
    rows: list[tuple[str, str, str, dict[str, Any], dict[str, str]]] = [
        (
            "intact_occurrence",
            "all",
            "Budget, payment and execution, each signed by its trusted key and bound to the"
            " frozen occurrence.",
            _set(),
            _expect(E, E, E, E, E, E, N),
        ),
        (
            "mismatched_occurrence",
            "occurrence_link",
            "Control: every artifact is natively valid, but the execution receipt is for"
            " another occurrence of a different call.",
            _set(
                execution=_sign(
                    _execution(
                        call_binding=invocation_binding(OTHER_REQUEST),
                        occurrence_binding=OTHER_CALL_RUN,
                    ),
                    "responder",
                )
            ),
            _expect(E, E, E, E, C, N, N),
        ),
        (
            "same_content_different_execution",
            "occurrence_link",
            "Control: the execution receipt carries the same call content but is for a second"
            " run of that call. Matching call content is not the same execution.",
            _set(execution=_sign(_execution(occurrence_binding=SAME_CALL_SECOND_RUN), "responder")),
            _expect(E, E, E, E, C, N, N),
        ),
        (
            "execution_names_call_content_only",
            "occurrence_link",
            "The execution receipt commits to the call content and to no occurrence, so the"
            " link cannot be decided.",
            _set(execution=_sign(_execution(occurrence_binding=None), "responder")),
            _expect(E, E, E, E, N, N, N),
        ),
        (
            "payment_names_no_occurrence",
            "occurrence_link",
            "The payment receipt commits to no occurrence, so it could be moved to any call.",
            _set(payment=_sign(_payment(occurrence_binding=None), "payment_rail")),
            _expect(E, E, E, E, N, E, N),
        ),
        (
            "payment_moved_to_other_occurrence",
            "occurrence_link",
            "The payment receipt names a second run of the same call.",
            _set(payment=_sign(_payment(occurrence_binding=SAME_CALL_SECOND_RUN), "payment_rail")),
            _expect(E, E, E, E, C, E, N),
        ),
        (
            "budget_signed_by_agent",
            "budget_statement",
            "The spending limit is the agent's own statement, not the issuer's.",
            _set(
                budget=agent_budget,
                payment=_sign(_payment(budget=agent_budget), "payment_rail"),
            ),
            _expect(N, E, E, N, E, E, N),
        ),
        (
            "budget_signature_broken",
            "budget_statement",
            "One bit of the issuer's signature changed.",
            _set(budget=_broken(BUDGET)),
            _expect(C, E, E, N, E, E, N),
        ),
        (
            "budget_signed_by_untrusted_key",
            "budget_statement",
            "A valid signature by a key the trust inputs do not list.",
            _set(
                budget=_sign(_budget(), "outsider"),
                payment=_sign(_payment(budget=_sign(_budget(), "outsider")), "payment_rail"),
            ),
            _expect(N, E, E, N, E, E, N),
        ),
        (
            "payment_exceeds_issuer_limit",
            "spend_within_budget",
            "The payment is larger than what is left of the issuer's limit.",
            _set(payment=_sign(_payment(amount_units=401), "payment_rail")),
            _expect(E, E, E, C, E, E, N),
        ),
        (
            "payment_names_other_budget",
            "spend_within_budget",
            "The payment names a budget statement other than the one presented.",
            _set(
                payment=_sign(
                    _payment(budget=_sign(_budget(budget_id="budget-18"), "issuer")),
                    "payment_rail",
                )
            ),
            _expect(E, E, E, C, E, E, N),
        ),
        (
            "payment_signed_by_untrusted_key",
            "payment_receipt",
            "A valid signature by a key the trust inputs do not list for the rail.",
            _set(payment=_sign(_payment(), "outsider")),
            _expect(E, N, E, N, E, E, N),
        ),
        (
            "payment_signature_broken_link_intact",
            "payment_receipt",
            "The payment signature fails while its committed occurrence is right: the native"
            " verdict and the link are separate claims.",
            _set(payment=_broken(_sign(_payment(), "payment_rail"))),
            _expect(E, C, E, N, E, E, N),
        ),
        (
            "execution_signature_broken_link_intact",
            "execution_receipt",
            "The execution signature fails while its committed occurrence is right.",
            _set(execution=_broken(_sign(_execution(), "responder"))),
            _expect(E, E, C, E, E, N, N),
        ),
        (
            "execution_signed_by_issuer_key",
            "execution_receipt",
            "A trusted key, but trusted for the issuer role, not the responder role.",
            _set(execution=_sign(_execution(), "issuer")),
            _expect(E, E, N, E, E, N, N),
        ),
        (
            "no_execution_receipt",
            "execution_receipt",
            "Paid, with no execution receipt.",
            _set(no_execution=True),
            _expect(E, E, N, E, N, N, N),
        ),
        (
            "input_other_fixture",
            "input_pinned",
            "The receipt states it audited the full three-line fixture, not the pinned"
            " two-line input. A different input digest is refused.",
            _set(execution=_sign(_execution(input_sha256=OTHER_INPUT_PIN), "responder")),
            _expect(E, E, E, E, E, C, N),
        ),
        (
            "input_other_dataset_version",
            "input_pinned",
            "The receipt states the earlier version of the reference dataset, not the one"
            " the occurrence froze. A different dataset digest is refused.",
            _set(execution=_sign(_execution(dataset_sha256=OTHER_DATASET_PIN), "responder")),
            _expect(E, E, E, E, E, C, N),
        ),
        (
            "input_not_stated",
            "input_pinned",
            "The receipt states no input digest, so whether the pinned input was audited"
            " cannot be decided.",
            _set(execution=_sign(_execution(input_sha256=None), "responder")),
            _expect(E, E, E, E, E, N, N),
        ),
        (
            "lost_call_no_statement",
            "not_run_settlement",
            "Control: paid, no reply and no statement. A bare missing reply leaves the call"
            " unresolved and the held amount held.",
            _set(no_execution=True),
            _expect(E, E, N, E, N, N, N),
        ),
        (
            "lost_call_settled_not_run",
            "not_run_settlement",
            "Paid, no reply, and the responder signs a statement naming this occurrence and"
            " saying the call did not run. The call is settled as not run.",
            _set(no_execution=True, not_run=_sign(_not_run(), "responder")),
            _expect(E, E, N, E, N, N, E),
        ),
        (
            "lost_call_statement_names_other_occurrence",
            "not_run_settlement",
            "Control: the responder's not-run statement names a second run of the same call."
            " It says nothing about this occurrence, which stays unresolved.",
            _set(
                no_execution=True,
                not_run=_sign(_not_run(occurrence_binding=SAME_CALL_SECOND_RUN), "responder"),
            ),
            _expect(E, E, N, E, N, N, N),
        ),
        (
            "lost_call_statement_names_call_content_only",
            "not_run_settlement",
            "The not-run statement names the call content and no occurrence, so it could be"
            " moved to any run of the call.",
            _set(
                no_execution=True,
                not_run=_sign(_not_run(occurrence_binding=None), "responder"),
            ),
            _expect(E, E, N, E, N, N, N),
        ),
        (
            "lost_call_statement_signed_by_payer",
            "not_run_settlement",
            "The payer agent, not the responder, signs that the call did not run.",
            _set(no_execution=True, not_run=_sign(_not_run(), "agent")),
            _expect(E, E, N, E, N, N, N),
        ),
        (
            "lost_call_statement_signature_broken",
            "not_run_settlement",
            "One bit of the responder's not-run signature changed.",
            _set(no_execution=True, not_run=_broken(_sign(_not_run(), "responder"))),
            _expect(E, E, N, E, N, N, C),
        ),
        (
            "not_run_beside_execution_receipt",
            "not_run_settlement",
            "The responder signs both an execution receipt and a not-run statement for this"
            " occurrence.",
            _set(not_run=_sign(_not_run(), "responder")),
            _expect(E, E, E, E, E, E, C),
        ),
    ]
    return [
        {"id": cid, "axis": axis, "description": desc, "artifacts": arts, "expected": exp}
        for cid, axis, desc, arts, exp in rows
    ]


def _trust() -> dict[str, Any]:
    listed = ("issuer", "payment_rail", "responder", "agent")
    return {
        "schema": TRUST_SCHEMA,
        "key_recipe": "seed = sha256('aev-occurrence-binding-test-key/<role>/v1'); TEST keys only",
        "keys": {KEYIDS[r]: {"role_label": r, "public_hex": KEYS[r].hex()} for r in listed},
        "roles": {
            "issuer": [KEYIDS["issuer"]],
            "payment_rail": [KEYIDS["payment_rail"]],
            "responder": [KEYIDS["responder"]],
        },
    }


def build() -> dict[str, str]:
    """Return every corpus file's text, manifest last."""
    files = {
        "occurrence.json": _dump(OCCURRENCE),
        "input.json": _dump(INPUT),
        "trust.json": _dump(_trust()),
        "cases.json": _dump(
            {
                "schema": "aev-occurrence-binding-cases/v1",
                "occurrence_binding": OCC,
                "call_binding": CALL,
                "cases": _cases(),
            }
        ),
    }
    files["manifest.json"] = _dump(
        {
            "schema": "aev-occurrence-binding-corpus/v1",
            "members": {
                name: sha256_tag(text.encode("utf-8")) for name, text in sorted(files.items())
            },
        }
    )
    return files


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check exit 1 if the committed files differ."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    files = build()
    if args.check:
        stale = [
            name
            for name, text in files.items()
            if not (CORPUS / name).exists() or (CORPUS / name).read_text() != text
        ]
        if stale:
            print(f"stale corpus members: {stale}", file=sys.stderr)
            return 1
        return 0
    CORPUS.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (CORPUS / name).write_text(text)
    print(f"wrote {len(files)} files, {len(_cases())} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
