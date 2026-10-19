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

Two further claims settle what happened to the call:

* ``input_pinned``: the execution receipt states the digest of the input it
  processed and of the reference dataset it read, and both equal the pins the
  frozen occurrence fixed before the call. A receipt naming another digest is
  refused. It rests on the execution verdict, so it is not established unless
  the receipt is, and only a receipt for this occurrence is read.
* ``not_run_settlement``: a lost call (paid or held, no answer) stays
  unresolved. It is settled as not run only by a statement, signed by a key the
  trust inputs name for the responder, that names this occurrence and says the
  call did not run. A bare missing reply, a statement naming another occurrence
  or only the call content, or one signed by any other key leaves it
  unresolved; a statement beside an execution receipt for the same occurrence
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
    "input_pins",
    "invocation_binding",
    "occurrence_binding",
    "parse_strict",
    "sha256_tag",
    "summary",
]

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

NATIVE_AXES = ("budget_statement", "payment_receipt", "execution_receipt")
LINK_AXES = ("spend_within_budget", "occurrence_link", "input_pinned", "not_run_settlement")
AXES = (*NATIVE_AXES, *LINK_AXES)
NON_CLAIMS = ("settlement_finality", "work_acceptance", "observed_effect")

OCCURRENCE_SCHEMA = "aev-request-occurrence/v1"
TRUST_SCHEMA = "aev-occurrence-trust/v1"
BUDGET_SCHEMA = "aev-issuer-budget/v1"
PAYMENT_SCHEMA = "aev-payment-receipt/v1"
EXECUTION_SCHEMA = "aev-execution-receipt/v1"
NOT_RUN_SCHEMA = "aev-not-run-statement/v1"
NOT_RUN = "NOT_RUN"

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


def input_pins(occurrence: Any) -> dict[str, str]:
    """The input and dataset digests the occurrence fixed before the call."""
    pins = occurrence.get("input_pins") if isinstance(occurrence, dict) else None
    if not isinstance(pins, dict) or set(pins) != {"input_sha256", "dataset_sha256"}:
        raise MalformedInput("occurrence needs input_pins with input_sha256 and dataset_sha256")
    for value in pins.values():
        if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
            raise MalformedInput("an input pin must be a sha256:<64 hex> tag")
    return pins


def judge_input(
    artifacts: dict[str, Any],
    native: dict[str, dict[str, Any]],
    pins: dict[str, str],
    expected_occurrence: str,
) -> dict[str, Any]:
    """The receipt for this occurrence processed exactly the pinned input and dataset."""
    if native["execution_receipt"]["result"] != ESTABLISHED:
        return _result(NOT_ESTABLISHED, "execution_not_established")
    receipt = artifacts["execution"]["statement"]
    if receipt.get("occurrence_binding") != expected_occurrence:
        return _result(NOT_ESTABLISHED, "receipt_not_for_this_occurrence")
    stated = {name: receipt.get(name) for name in ("input_sha256", "dataset_sha256")}
    if stated["input_sha256"] is None:
        return _result(NOT_ESTABLISHED, "receipt_states_no_input_digest")
    if stated["dataset_sha256"] is None:
        return _result(NOT_ESTABLISHED, "receipt_states_no_dataset_digest")
    if stated["input_sha256"] != pins["input_sha256"]:
        return _result(
            CONTRADICTED,
            "input_differs_from_pin",
            pinned=pins["input_sha256"],
            stated=stated["input_sha256"],
        )
    if stated["dataset_sha256"] != pins["dataset_sha256"]:
        return _result(
            CONTRADICTED,
            "dataset_differs_from_pin",
            pinned=pins["dataset_sha256"],
            stated=stated["dataset_sha256"],
        )
    return _result(ESTABLISHED, "input_and_dataset_match_pins")


def judge_not_run(
    artifacts: dict[str, Any],
    native: dict[str, dict[str, Any]],
    trust: dict[str, Any],
    expected_occurrence: str,
    expected_call: str,
) -> dict[str, Any]:
    """A lost call is settled as not run only by the responder's signed word for it."""
    statement = artifacts.get("not_run")
    if statement is None:
        return _result(NOT_ESTABLISHED, "no_signed_not_run_statement")
    shape = statement.get("statement") if isinstance(statement, dict) else None
    if isinstance(shape, dict) and shape.get("outcome") != NOT_RUN:
        raise MalformedInput(f"a not-run statement must say outcome {NOT_RUN}")
    signed = judge_signed(statement, NOT_RUN_SCHEMA, "responder", trust)
    if signed["result"] != ESTABLISHED:
        return _result(signed["result"], "not_run_" + signed["reason"])
    body: dict[str, Any] = statement["statement"]
    named = body.get("occurrence_binding")
    if named is None:
        if body.get("call_binding") == expected_call:
            return _result(NOT_ESTABLISHED, "not_run_names_call_content_only")
        return _result(NOT_ESTABLISHED, "not_run_names_other_call")
    if named != expected_occurrence:
        return _result(NOT_ESTABLISHED, "not_run_names_other_occurrence")
    execution = artifacts.get("execution")
    if (
        native["execution_receipt"]["result"] == ESTABLISHED
        and execution is not None
        and execution["statement"].get("occurrence_binding") == expected_occurrence
    ):
        return _result(CONTRADICTED, "execution_receipt_says_it_ran")
    return _result(ESTABLISHED, "responder_signed_not_run_for_this_occurrence")


def evaluate(occurrence: Any, trust: Any, case: dict[str, Any]) -> dict[str, Any]:
    """Judge one case. ``case['expected']`` is never read here."""
    _check_trust(trust)
    expected_occurrence = occurrence_binding(occurrence)
    expected_call = invocation_binding(occurrence["request"])
    pins = input_pins(occurrence)
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
    out["input_pinned"] = judge_input(artifacts, out, pins, expected_occurrence)
    out["not_run_settlement"] = judge_not_run(
        artifacts, out, trust, expected_occurrence, expected_call
    )
    for prop in NON_CLAIMS:
        out[prop] = _result(NOT_ESTABLISHED, "outside_this_corpus")
    return out


def summary(actual: dict[str, Any]) -> dict[str, str]:
    """The per-axis and non-claim result words, in a fixed order."""
    return {key: actual[key]["result"] for key in (*AXES, *NON_CLAIMS)}
