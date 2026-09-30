"""Generate the capability-id corpus (draft). Deterministic: re-running rewrites the same bytes."""

from __future__ import annotations

import json
from pathlib import Path

from check_vectors import capability_id

HERE = Path(__file__).resolve().parent
MEMBERS = HERE / "members"

PAYMENT = '{"action":"invoke","resource":{"type":"tool","id":"payment-authorization"}}'
PAYMENT_REORDERED = (
    '{ "resource" : { "id" : "payment-authorization", "type" : "tool" }, "action" : "invoke" }'
)
REFUND = '{"action":"invoke","resource":{"type":"tool","id":"refund-lookup"}}'
CAPPED = PAYMENT[:-1] + ',"constraints":{"max_amount_cents":9007199254740991}}'


def member(
    decision_text: str,
    invocation_text: str,
    *,
    decision_id: str | None = None,
    invocation_id: str | None = None,
) -> dict[str, object]:
    derived = decision_id if decision_id is not None else capability_id(decision_text)
    return {
        "decision": {"capability_id": derived, "descriptor_text": decision_text},
        "invocation": {
            "capability_id": invocation_id if invocation_id is not None else derived,
            "descriptor_text": invocation_text,
        },
    }


def cases() -> list[tuple[str, str, str, dict[str, object]]]:
    payment_id = capability_id(PAYMENT)
    return [
        (
            "CAP-A1",
            "valid",
            "the decision mints the id from its descriptor and the gateway copies it",
            member(PAYMENT, PAYMENT),
        ),
        (
            "CAP-A2",
            "valid",
            "member order and whitespace differ; the canonical bytes, and so the id, do not",
            member(PAYMENT, PAYMENT_REORDERED),
        ),
        (
            "CAP-A3",
            "valid",
            "a constraint at the largest I-JSON safe integer is admitted",
            member(CAPPED, CAPPED),
        ),
        (
            "CAP-R1",
            "duplicate-member",
            "the action member appears twice, so two parsers can derive two ids",
            member(PAYMENT, PAYMENT, decision_id=payment_id)
            | {
                "decision": {
                    "capability_id": payment_id,
                    "descriptor_text": PAYMENT.replace('{"action"', '{"action":"read","action"', 1),
                }
            },
        ),
        (
            "CAP-R2",
            "integer-not-ijson-safe",
            "a constraint at 2^53 + 1 aliases 2^53 in a double-based reader",
            {
                "decision": {
                    "capability_id": payment_id,
                    "descriptor_text": CAPPED.replace("9007199254740991", "9007199254740993"),
                },
                "invocation": {"capability_id": payment_id, "descriptor_text": CAPPED},
            },
        ),
        (
            "CAP-R3",
            "number-not-integer",
            "the same bound written as a float is refused, not rounded",
            {
                "decision": {
                    "capability_id": payment_id,
                    "descriptor_text": CAPPED.replace("9007199254740991", "1.0e3"),
                },
                "invocation": {"capability_id": payment_id, "descriptor_text": CAPPED},
            },
        ),
        (
            "CAP-R4",
            "invoker-chosen-id",
            "the gateway reports an id of its own instead of the decision's",
            member(PAYMENT, PAYMENT, invocation_id="payment-authorization"),
        ),
        (
            "CAP-R5",
            "id-not-derived",
            "the decision carries a readable name where the digest belongs",
            member(
                PAYMENT,
                PAYMENT,
                decision_id="invoke:payment-authorization",
                invocation_id="invoke:payment-authorization",
            ),
        ),
        (
            "CAP-R6",
            "descriptor-mismatch",
            "the gateway copies a granted id onto a call to a different tool",
            member(PAYMENT, REFUND),
        ),
        (
            "CAP-R7",
            "ill-formed-string",
            "a lone surrogate in a member name has no UTF-8 encoding to hash",
            {
                "decision": {
                    "capability_id": payment_id,
                    "descriptor_text": PAYMENT.replace('"id"', '"id\\ud800"', 1),
                },
                "invocation": {"capability_id": payment_id, "descriptor_text": PAYMENT},
            },
        ),
    ]


def main() -> None:
    MEMBERS.mkdir(exist_ok=True)
    entries = []
    for case_id, expect, why, body in cases():
        (MEMBERS / f"{case_id}.json").write_text(
            json.dumps(body, indent=2) + "\n", encoding="utf-8"
        )
        entries.append({"id": case_id, "expect": expect, "why": why})
    manifest = {
        "corpus": "capability-id",
        "status": "draft",
        "derivation": "sha256 over RFC 8785 bytes of the admitted descriptor",
        "members": entries,
    }
    (HERE / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
