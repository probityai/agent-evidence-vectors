"""Judge one paid request occurrence: three native verdicts and two cross-artifact links.

A paid agent call leaves three signed artifacts behind: the issuer's budget
statement (the spending limit), the payment receipt and the execution receipt.
Each artifact has its own native verdict, decided from its own bytes and the
frozen trust inputs alone:

* ``budget_statement``: signed by a key the trust inputs name for the issuer.
* ``payment_receipt``: signed by a key the trust inputs name for the payment rail.
* ``execution_receipt``: signed by a key the trust inputs name for the responder.

Two further claims join artifacts, and they are reported apart from the native
verdicts so neither can stand in for the other:

* ``spend_within_budget``: the payment names this budget statement, and the
  issuer's remaining limit covers it. It rests on the budget and payment
  verdicts, so it is not established unless both are.
* ``occurrence_link``: the payment and the execution receipt both commit to the
  one frozen request occurrence. It is judged from the committed values only,
  never from the signatures, so a broken signature and an intact link can both be
  true. Matching call content alone does not establish that two records describe
  the same execution: a receipt that commits only to the call content leaves the
  link not established, and one that names another occurrence of the same call
  contradicts it.

Three properties are ``NOT_ESTABLISHED`` in every case: settlement finality, work
acceptance and the observed effect of the call (the invocation three-axis corpus
judges the last one). The reader never reads a case's expected answer.
"""

from __future__ import annotations

from typing import Any

from ..invocation_axes.reader import (
    MalformedInput,
    canonical,
    invocation_binding,
    parse_strict,
    sha256_tag,
)
from ..w3cintake import ed25519_verify

__all__ = [
    "AXES",
    "NON_CLAIMS",
    "MalformedInput",
    "canonical",
    "evaluate",
    "occurrence_binding",
    "parse_strict",
    "sha256_tag",
    "summary",
]

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

NATIVE_AXES = ("budget_statement", "payment_receipt", "execution_receipt")
LINK_AXES = ("spend_within_budget", "occurrence_link")
AXES = (*NATIVE_AXES, *LINK_AXES)
NON_CLAIMS = ("settlement_finality", "work_acceptance", "observed_effect")

OCCURRENCE_SCHEMA = "aev-request-occurrence/v1"
TRUST_SCHEMA = "aev-occurrence-trust/v1"
BUDGET_SCHEMA = "aev-issuer-budget/v1"
PAYMENT_SCHEMA = "aev-payment-receipt/v1"
EXECUTION_SCHEMA = "aev-execution-receipt/v1"

#: Native axis -> (artifact name in a case, schema it must carry, trust role).
ARTIFACTS = {
    "budget_statement": ("budget", BUDGET_SCHEMA, "issuer"),
    "payment_receipt": ("payment", PAYMENT_SCHEMA, "payment_rail"),
    "execution_receipt": ("execution", EXECUTION_SCHEMA, "responder"),
}


def _result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"result": status, "reason": reason}
    out.update(extra)
    return out


def occurrence_binding(occurrence: Any) -> str:
    """Bind one request occurrence: the call content plus who and which occurrence.

    The call is bound as the invocation three-axis corpus binds it (method and
    params, never the JSON-RPC id). The nonce is what separates two occurrences of
    the same call; the payer and responder are part of the occurrence, not of the
    call.
    """
    if not isinstance(occurrence, dict) or occurrence.get("schema") != OCCURRENCE_SCHEMA:
        raise MalformedInput(f"occurrence is not {OCCURRENCE_SCHEMA}")
    nonce = occurrence.get("occurrence_nonce")
    if not isinstance(nonce, str) or not nonce:
        raise MalformedInput("occurrence needs a non-empty occurrence_nonce")
    return sha256_tag(
        canonical(
            {
                "call_binding": invocation_binding(occurrence.get("request")),
                "occurrence_nonce": nonce,
                "payer_agent": occurrence.get("payer_agent"),
                "responder": occurrence.get("responder"),
            }
        )
    )


def statement_digest(envelope: dict[str, Any]) -> str:
    """The digest a later artifact uses to name a signed statement."""
    return sha256_tag(canonical(envelope["statement"]))


def _check_trust(trust: Any) -> None:
    if not isinstance(trust, dict) or trust.get("schema") != TRUST_SCHEMA:
        raise MalformedInput(f"trust inputs are not {TRUST_SCHEMA}")
    if not isinstance(trust.get("keys"), dict) or not isinstance(trust.get("roles"), dict):
        raise MalformedInput("trust inputs need a keys map and a roles map")


def judge_signed(envelope: Any, schema: str, role: str, trust: dict[str, Any]) -> dict[str, Any]:
    """A native verdict: the statement's own signature under the trust inputs."""
    if envelope is None:
        return _result(NOT_ESTABLISHED, "artifact_absent")
    if not isinstance(envelope, dict) or not isinstance(envelope.get("statement"), dict):
        raise MalformedInput("a signed artifact needs a statement object")
    if envelope["statement"].get("schema") != schema:
        raise MalformedInput(f"statement schema is not {schema}")
    keyid = envelope.get("keyid")
    key = trust["keys"].get(keyid)
    if key is None:
        return _result(NOT_ESTABLISHED, "key_not_in_trust_inputs", keyid=keyid)
    if keyid not in trust["roles"].get(role, []):
        return _result(NOT_ESTABLISHED, "key_not_trusted_for_role", keyid=keyid, role=role)
    try:
        public = bytes.fromhex(key["public_hex"])
        signature = bytes.fromhex(str(envelope.get("signature_hex")))
    except ValueError as exc:
        raise MalformedInput("key or signature is not hex") from exc
    if not ed25519_verify(public, canonical(envelope["statement"]), signature):
        return _result(CONTRADICTED, "signature_does_not_verify", keyid=keyid)
    return _result(ESTABLISHED, "signed_by_trusted_key", keyid=keyid, role=role)


def judge_spend(artifacts: dict[str, Any], native: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """The payment names this budget, and the issuer's remaining limit covers it."""
    if native["budget_statement"]["result"] != ESTABLISHED:
        return _result(NOT_ESTABLISHED, "budget_not_established")
    if native["payment_receipt"]["result"] != ESTABLISHED:
        return _result(NOT_ESTABLISHED, "payment_not_established")
    budget = artifacts["budget"]["statement"]
    payment = artifacts["payment"]["statement"]
    if payment.get("budget_digest") != statement_digest(artifacts["budget"]):
        return _result(CONTRADICTED, "payment_names_other_budget")
    if payment.get("currency") != budget.get("currency"):
        return _result(CONTRADICTED, "currency_differs_from_budget")
    amounts = (
        budget.get("limit_units"),
        budget.get("spent_before_units"),
        payment.get("amount_units"),
    )
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in amounts):
        raise MalformedInput("limit, prior spend and amount must be non-negative integers")
    limit, spent, amount = amounts
    if spent + amount > limit:
        return _result(
            CONTRADICTED, "exceeds_issuer_limit", remaining_units=limit - spent, amount_units=amount
        )
    return _result(ESTABLISHED, "within_issuer_limit", remaining_units=limit - spent - amount)


def judge_link(
    artifacts: dict[str, Any], expected_occurrence: str, expected_call: str
) -> dict[str, Any]:
    """Both receipts commit to the frozen occurrence. Signatures are not read here."""
    payment = artifacts.get("payment")
    execution = artifacts.get("execution")
    if payment is None or execution is None:
        return _result(NOT_ESTABLISHED, "receipt_absent")
    paid = payment["statement"].get("occurrence_binding")
    ran = execution["statement"].get("occurrence_binding")
    call = execution["statement"].get("call_binding")
    if paid is None:
        return _result(NOT_ESTABLISHED, "payment_names_no_occurrence")
    if paid != expected_occurrence:
        return _result(CONTRADICTED, "payment_for_other_occurrence")
    if ran is None:
        if call == expected_call:
            return _result(NOT_ESTABLISHED, "execution_names_call_content_only")
        return _result(CONTRADICTED, "execution_for_other_call")
    if ran != expected_occurrence:
        if call == expected_call:
            return _result(CONTRADICTED, "same_call_content_other_occurrence")
        return _result(CONTRADICTED, "execution_for_other_occurrence")
    if call != expected_call:
        return _result(CONTRADICTED, "occurrence_names_other_call")
    return _result(ESTABLISHED, "both_receipts_commit_to_the_occurrence")


def evaluate(occurrence: Any, trust: Any, case: dict[str, Any]) -> dict[str, Any]:
    """Judge one case. ``case['expected']`` is never read here."""
    _check_trust(trust)
    expected_occurrence = occurrence_binding(occurrence)
    expected_call = invocation_binding(occurrence["request"])
    artifacts = case.get("artifacts")
    if not isinstance(artifacts, dict):
        raise MalformedInput("a case needs an artifacts map")
    out: dict[str, Any] = {
        "occurrence_binding": expected_occurrence,
        "call_binding": expected_call,
    }
    for axis, (name, schema, role) in ARTIFACTS.items():
        out[axis] = judge_signed(artifacts.get(name), schema, role, trust)
    out["spend_within_budget"] = judge_spend(artifacts, out)
    out["occurrence_link"] = judge_link(artifacts, expected_occurrence, expected_call)
    for prop in NON_CLAIMS:
        out[prop] = _result(NOT_ESTABLISHED, "outside_this_corpus")
    return out


def summary(actual: dict[str, Any]) -> dict[str, str]:
    """The per-axis and non-claim result words, in a fixed order."""
    return {key: actual[key]["result"] for key in (*AXES, *NON_CLAIMS)}
