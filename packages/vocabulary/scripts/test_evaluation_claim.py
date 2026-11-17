#!/usr/bin/env python3
"""Hold the registry, the validator and the guide to the evaluation_claim section.

Every term starts proposed with no issuer and carries a criticality, a review date, a
definition, a check and a promotion trigger; a term declaring closed values defines each of
them; the guide at docs/evaluation-claim.md names every term and every value; every registered value is
accepted and an unregistered one refused through registry.check_value; the real validator
accepts a crosswalk that maps the section and refuses one that files a term under the wrong
section; and the reference derivations (the payment-scope/v1 evaluator, asserted-verdict
re-derivation, the three-valued decision, check order, vacuity, evidence attribution, signer distinctness,
lifecycle binding with three rule-deletion mutants, and the time bounds) give the expected
value for each case. Nothing is restated here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_VOCAB = _ROOT / "vocabulary.yaml"
_REGISTRY = _ROOT / "registry.py"
_INDEX = _ROOT / "registry.json"
_PAGE = _ROOT / "docs" / "evaluation-claim.md"
SECTION = "evaluation_claim"
PROBE_TERM = "asserted_verdict"
_EXPECTED_TERMS = {'evaluator', 'asserted_verdict', 'verification_decision', 'check_outcome', 'vacuity_witness', 'evidence_attribution', 'signer_distinctness', 'lifecycle_binding', 'on_behalf_of', 'anchor_within', 'anchor_early_allowance', 'block_time_allowance', 'clock_skew_tolerance', 'conformance_extension'}
_REQUIRED_KEYS = ("criticality", "review_by", "definition", "promotion_trigger", "source_path")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_registry():
    spec = importlib.util.spec_from_file_location("vocabulary_registry", _REGISTRY)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _check_one_closed_term(registry, index: dict, name: str, values: list) -> list[str]:
    """Each registered value of one closed term is accepted; an unregistered one is refused."""
    failures = []
    try:
        for value in values:
            judged = registry.check_value(index, name, value, None)
            if judged.outcome != registry.OK:
                failures.append(f"{name}: registered value {value!r} was judged {judged.outcome}")
        refused = registry.check_value(index, name, "not-a-registered-value", None)
    except KeyError:
        return [f"{name}: the registry index declares no values for a term that lists them"]
    if refused.outcome != registry.MALFORMED:
        failures.append(f"{name}: an unregistered value was judged {refused.outcome}, "
                        "not malformed")
    return failures


def _check_closed_values(registry, index: dict, section: dict) -> list[str]:
    """Run the closed-value check for every term that lists values."""
    failures = []
    for name, term in section.items():
        values = term.get("values")
        if values is not None:
            failures.extend(_check_one_closed_term(registry, index, name, values))
    return failures


def _crosswalk(section: str) -> dict:
    return {
        "system": SECTION + "-test",
        "system_url": "https://example.invalid/" + SECTION + "-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.10.0",
        section: {PROBE_TERM: {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / (SECTION + "-test.yaml")
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(
            path, known, match_types, evidence_states, errors, warnings)
    return errors


def _check_fields(name: str, term: dict) -> list[str]:
    """The status, issuer list, check and required keys of one term."""
    failures = []
    if term.get("status") != "proposed":
        failures.append(f"{name}: status must start proposed")
    if term.get("issuers_in_production") != []:
        failures.append(f"{name}: issuers_in_production must be empty")
    for key in ("check", *_REQUIRED_KEYS):
        if not str(term.get(key, "")).strip():
            failures.append(f"{name}: no {key}")
    return failures


def _check_definitions(name: str, term: dict) -> list[str]:
    """A term that lists values defines each of them and nothing else."""
    values = term.get("values")
    if values is None:
        return []
    defined = term.get("value_definitions") or {}
    missing = [v for v in values if not str(defined.get(v, "")).strip()]
    extra = sorted(set(defined) - set(values))
    if missing or extra:
        return [f"{name}: undefined values {missing}, stray definitions {extra}"]
    return []


def _check_guide(name: str, term: dict, page: str) -> list[str]:
    """The guide names the term and every value it lists."""
    failures = [] if f"`{name}`" in page else [f"{name}: the guide never names it"]
    for value in term.get("values") or []:
        if f"`{value}`" not in page:
            failures.append(f"{name}: the guide never names the value `{value}`")
    return failures


def _check_terms(section: dict, page: str) -> list[str]:
    failures = []
    if set(section) != _EXPECTED_TERMS:
        differ = sorted(set(section) ^ _EXPECTED_TERMS)
        failures.append(f"terms {differ} differ from the ones the section carries")
    for name, term in section.items():
        failures.extend(_check_fields(name, term))
        failures.extend(_check_definitions(name, term))
        failures.extend(_check_guide(name, term, page))
    return failures



_EVAL = "https://probityai.github.io/agent-evidence-vectors/evaluator/payment-scope/v1"
_SCOPE = {"currency": "USD", "amount_ceiling_minor": 10, "merchants": ["m-1"], "expires_at": 2000,
          "actions": ["pay"], "single_use": True}
_PAY = {"currency": "USD", "amount_minor": 10, "merchant": "m-1", "at": 1000, "action": "pay", "prior_uses": 0}

#: (payment changes, expected (verdict, first failing dimension))
_PAYMENTS = (
    ({}, ("within", None)),
    ({"amount_minor": 11}, ("outside", "amount")),
    ({"amount_minor": 500}, ("outside", "amount")),
    ({"currency": "EUR", "amount_minor": 500}, ("outside", "currency")),
    ({"merchant": "m-2"}, ("outside", "merchant")),
    ({"at": 2000}, ("within", None)),
    ({"at": 2001}, ("outside", "expiry")),
    ({"action": "refund"}, ("outside", "action")),
    ({"prior_uses": 1}, ("outside", "single_use")),
)

#: (scope changes, payment changes): each makes the record malformed, so the evaluator raises
#: MalformedInputs and returns no verdict. Every one of these returned "within" before.
_MALFORMED = (
    ({}, {"amount_minor": -500}),
    ({}, {"amount_minor": 9.99}),
    ({}, {"amount_minor": True}),
    ({}, {"prior_uses": -1}),
    ({"merchants": "m-10"}, {}),
    ({"actions": "pay-later"}, {}),
    ({"single_use": 0}, {"prior_uses": 3}),
    ({"currency": "usd"}, {"currency": "usd"}),
    ({"expires_at": 2 ** 53}, {}),
    ({}, {"merchant": None}),
)

#: (record, expected asserted_verdict value or refusal reason)
_ASSERTED = (
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": _PAY}, "asserted": "within"}, "rederived_agrees"),
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": {**_PAY, "amount_minor": 11}},
      "asserted": "within"}, "asserted_verdict_contradicted"),
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": _PAY}, "asserted": "outside"},
     "asserted_verdict_contradicted"),
    ({"inputs": {"scope": _SCOPE, "payment": _PAY}, "asserted": "within"}, "evaluator_unknown"),
    ({"evaluator": "https://example.invalid/evaluator/other/v1", "inputs": {}, "asserted": "within"},
     "evaluator_unknown"),
    ({"evaluator": "http://example.invalid/e", "inputs": {}, "asserted": "within"}, "evaluator-not-an-https-uri"),
    ({"evaluator": "https://", "inputs": {}, "asserted": "within"}, "evaluator-not-an-https-uri"),
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": {**_PAY, "amount_minor": -500}},
      "asserted": "within"}, "evaluator-inputs-malformed"),
    ({"evaluator": _EVAL, "asserted": "within"}, "evaluator-inputs-malformed"),
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE}, "asserted": "within"}, "evaluator-inputs-malformed"),
    # A record with no assertion makes no claim to contradict; one outside the evaluator's outputs is no verdict.
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": _PAY}}, "no-asserted-verdict"),
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": _PAY}, "asserted": ["within"]},
     "asserted-verdict-not-an-evaluator-output"),
    ({"evaluator": _EVAL, "inputs": {"scope": _SCOPE, "payment": _PAY}, "asserted": "Within"},
     "asserted-verdict-not-an-evaluator-output"),
)

#: (per-check results, expected decision, expected exit status)
_DECISIONS = (
    (["pass", "pass"], "accepted", 0),
    (["pass", "fail"], "rejected", 1),
    (["undecided", "fail"], "rejected", 1),
    (["pass", "undecided"], "indeterminate", 2),
)

_PROFILE = ["parse", "signature", "key", "scope"]
#: (report, expected value or refusal reason)
_REPORTS = (
    ([("parse", "pass"), ("signature", "pass"), ("key", "pass"), ("scope", "pass")], "pass"),
    ([("parse", "pass"), ("signature", "fail"), ("key", "not_evaluated"), ("scope", "not_evaluated")], "fail"),
    ([("parse", "pass"), ("signature", "fail"), ("key", "pass"), ("scope", "not_evaluated")],
     "check-after-a-failure-reported-as-run"),
    ([("parse", "not_evaluated"), ("signature", "not_evaluated"), ("key", "not_evaluated"),
      ("scope", "not_evaluated")], "not_evaluated"),
    ([("parse", "pass"), ("signature", "pass"), ("key", "not_evaluated"), ("scope", "pass")], "not_evaluated"),
    ([("parse", "pass"), ("signature", "pass")], "report-does-not-list-the-profile-in-order"),
)

#: (passed, witness, expected value)
_VACUITY = ((True, True, "witnessed"), (True, False, "vacuous_pass"), (True, None, "no_witness"),
            (False, True, "witnessed"), (False, False, "witness-contradicts-a-failing-property"),
            ("no", False, "vacuity-result-not-a-boolean"), (True, 0, "vacuity-result-not-a-boolean"))

_A = {"id": "a", "key": "ka", "authority": "org-a"}
_B = {"id": "b", "key": "kb", "authority": "org-b"}
#: (named signers, signatures, required, issuer key, expected value)
_SIGNERS = (
    ([_A, _B], {"a": True, "b": True}, 2, None, "distinct"),
    ([_A, _B], {"a": True}, 2, None, "key_named_not_signing"),
    ([_A, {**_A, "id": "a2"}], {"a": True, "a2": True}, 2, None, "one_key_two_ids"),
    ([_A, _B], {"a": True, "b": True}, 2, "kb", "own_key_as_cosigner"),
    ([_A, {**_B, "authority": "org-a"}], {"a": True, "b": True}, 2, None, "one_authority_threshold"),
    ([_A, {**_B, "id": "a"}], {"a": True}, 2, None, "key_named_not_signing"),
    ([_A], {"a": True}, 2, None, "below_threshold"),
    # The issuer never counts toward the required number: issuer plus one cosigner is a count of 1.
    ([_B], {"b": True}, 1, "ka", "distinct"),
    ([_A, _B], {"a": True, "b": True}, 1, "ka", "own_key_as_cosigner"),
    ([_A, _B], {"a": True, "b": "yes"}, 2, None, "key_named_not_signing"),
    # A threshold below 1, or a boolean, is met by nobody signing.
    ([], {}, 0, None, "required-count-not-a-positive-integer"),
    ([_A], {"a": True}, -3, None, "required-count-not-a-positive-integer"),
    ([_A], {"a": True}, True, None, "required-count-not-a-positive-integer"),
    ([{"key": "ka", "authority": "org-a"}], {}, 1, None, "signer-entry-malformed"),
)


def _art(id_, kind, instruction, digest, *, auth=True, binding="b-ok", decision="d1"):
    return {"id": id_, "kind": kind, "decision": decision, "instruction": instruction, "digest": digest,
            "authenticated": auth, "binding": binding}


_DEC = _art("dec", "decision", "i1", "-")
_ACTIVE = frozenset({"b-ok"})
#: (name, artifacts, expected state for group (d1, instruction))
_LIFECYCLE = (
    ("C0 honest", [_DEC, _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X")], "i1", "satisfied"),
    ("V1 cross-instruction", [_DEC, _art("c1", "control", "i1", "X"), _art("e1", "execution", "i2", "X")],
     "i2", "not_evaluated"),
    ("V2 receiver disagrees", [_DEC, _art("c1", "control", "i1", "X"), _art("c2", "control", "i1", "Y"),
                               _art("e1", "execution", "i1", "X")], "i1", "failure"),
    ("V3 duplicate identity", [_DEC, _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X"),
                               _art("e1", "execution", "i1", "Y")], "i1", "indeterminate"),
    ("V3b order swapped", [_DEC, _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "Y"),
                           _art("e1", "execution", "i1", "X")], "i1", "indeterminate"),
    ("V4 revoked binding", [_DEC, _art("c1", "control", "i1", "X"),
                            _art("e1", "execution", "i1", "X", binding="b-revoked")], "i1", "not_evaluated"),
    ("V5 unbound key", [_DEC, _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X", auth=False)],
     "i1", "failure"),
    ("V8 decision unauthenticated", [_art("dec", "decision", "i1", "-", auth=False),
                                     _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X")],
     "i1", "failure"),
    ("missing control", [_DEC, _art("e1", "execution", "i1", "X")], "i1", "not_evaluated"),
    ("missing execution", [_DEC, _art("c1", "control", "i1", "X")], "i1", "missing"),
    ("V9 no decision record", [_art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X")],
     "i1", "missing"),
    ("V10 decision unauthenticated, member inactive",
     [_art("dec", "decision", "i1", "-", auth=False), _art("c1", "control", "i1", "X", binding="b-revoked"),
      _art("e1", "execution", "i1", "X")], "i1", "failure"),
    ("V11 two decision records with one identity",
     [_DEC, _art("dec", "decision", "i1", "Z"), _art("c1", "control", "i1", "X"),
      _art("e1", "execution", "i1", "X")], "i1", "indeterminate"),
    ("V13 one identity in two groups", [_DEC, _art("dec2", "decision", "i2", "-"), _art("c1", "control", "i1", "X"),
     _art("e1", "execution", "i1", "X"), _art("c1", "control", "i2", "Y"), _art("e2", "execution", "i2", "Y")],
     "i1", "indeterminate"),
    ("V12 decision under a revoked binding", [_art("dec", "decision", "i1", "-", binding="b-revoked"),
     _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X")], "i1", "not_evaluated"),
)

_TIME = {"max_age": 3600, "uncertainty": 0, "clock_skew_tolerance": 300, "anchor_within": 600,
         "block_time_allowance": 7200, "anchor_early_allowance": 900}
#: (issued_at, check_time, anchor_time, expected value or refusal reason)
_TIMES = (
    (10000, 10000, None, "in-bounds"),
    (10300, 10000, None, "in-bounds"),
    (10301, 10000, None, "issued-in-the-future"),
    (13601, 10000, None, "issued-in-the-future"),
    (10000, 13600, None, "in-bounds"),
    (10000, 13601, None, "too-old"),
    (10000, 10000, 17800, "in-bounds"),
    (10000, 10000, 17801, "anchor-late"),
    (10000, 10000, 9100, "in-bounds"),
    (10000, 10000, 9099, "anchor-before-issuance"),
    (10000, 10000, 0, "anchor-before-issuance"),
    (10000, 2 ** 53, None, "time-member-outside-the-safe-range"),
    (-1, 10000, None, "time-member-outside-the-safe-range"),
)


#: (signer verifies, co-signature: None absent, else whether it verifies, expected value or refusal code).
_ATTRIBUTION = (
    (True, True, "co_signed"),
    (True, None, "single_signed"),
    (True, False, "unattributed_evidence"),
    (False, None, "unattributed_evidence"),
    (False, True, "unattributed_evidence"),
    ("yes", None, "attribution-result-not-a-boolean"),
    (True, 1, "attribution-result-not-a-boolean"),
)


def _label(derived) -> str:
    return derived.reason if derived.refused and derived.value is None else derived.value


def _lifecycle_mutants(registry) -> list[str]:
    """Deleting the duplicate, revocation or grouping rule turns V3, V4 or V1 red."""
    failures = []
    original = registry._group_state

    def no_duplicate_rule(group, active, shared=frozenset()):
        return original([a for i, a in enumerate(group) if a["id"] not in {g["id"] for g in group[:i]}], active)

    def no_revocation_rule(group, active, shared=frozenset()):
        return original(group, frozenset({a["binding"] for a in group}), shared)

    def no_cross_group_identity_rule(group, active, shared=frozenset()):
        return original(group, active)

    mutants = (("duplicate", no_duplicate_rule, "V3 duplicate identity"),
               ("revocation", no_revocation_rule, "V4 revoked binding"),
               ("cross-group identity", no_cross_group_identity_rule, "V13 one identity in two groups"))
    for rule, mutant, case in mutants:
        registry._group_state = mutant
        try:
            _, artifacts, instruction, expected = next(c for c in _LIFECYCLE if c[0] == case)
            if registry.lifecycle_binding(artifacts, _ACTIVE)[("d1", instruction)] == expected:
                failures.append(f"deleting the {rule} rule left {case} green")
        finally:
            registry._group_state = original
    _, artifacts, _, expected = next(c for c in _LIFECYCLE if c[0] == "V1 cross-instruction")
    regrouped = [{**a, "instruction": "all"} for a in artifacts]
    if registry.lifecycle_binding(regrouped, _ACTIVE)[("d1", "all")] == expected:
        failures.append("deleting the grouping by instruction left V1 cross-instruction green")
    return failures


def _preimage_cases(registry) -> list[str]:
    """Six registered tags; each pre-image differs from every other over the same bytes; others refuse."""
    failures = []
    body = b'{"a":1}'
    images = {(k, p): registry.lifecycle_preimage(k, p, body)
              for k in ("decision", "control", "execution") for p in ("hash", "signature")}
    if len(set(images.values())) != 6 or len(registry.LIFECYCLE_TAGS) != 6:
        failures.append("lifecycle pre-images are not six distinct byte strings")
    if images[("control", "signature")] != b"agent-evidence/lifecycle-binding/v1/control/signature\n" + body:
        failures.append(f"control signature pre-image is {images[('control', 'signature')]!r}")
    for kind, purpose in (("receipt", "hash"), ("control", "sig"), ("Control", "signature")):
        try:
            registry.lifecycle_preimage(kind, purpose, body)
            failures.append(f"lifecycle_preimage accepted the unregistered tag {kind}/{purpose}")
        except registry.MalformedInputs:
            pass
    return failures


def _check_derivations(registry) -> tuple[list[str], int]:
    """Each reference derivation gives the expected value or refusal for every case."""
    failures = []
    for change, expected in _PAYMENTS:
        got = registry.payment_scope_v1(_SCOPE, {**_PAY, **change})
        if got != expected:
            failures.append(f"payment_scope_v1 with {change} gave {got}, expected {expected}")
    for record, expected in _ASSERTED:
        got = _label(registry.asserted_verdict(record))
        if got != expected:
            failures.append(f"asserted_verdict({record.get('asserted')!r}) gave {got!r}, expected {expected!r}")
    for checks, expected, status in _DECISIONS:
        got = registry.verification_decision(checks).value
        if got != expected or registry.exit_status(got) != status:
            failures.append(f"verification_decision({checks}) gave {got!r}, expected {expected!r} exit {status}")
    for report, expected in _REPORTS:
        got = _label(registry.check_outcomes(report, _PROFILE))
        if got != expected:
            failures.append(f"check_outcomes({report}) gave {got!r}, expected {expected!r}")
    for report, profile, expected in (([], [], "profile-names-no-check"),
                                      ([("parse", "pass"), ("parse", "pass")], ["parse", "parse"],
                                       "profile-names-a-check-twice")):
        got = _label(registry.check_outcomes(report, profile))
        if got != expected:
            failures.append(f"check_outcomes over the profile {profile} gave {got!r}, expected {expected!r}")
    for passed, witness, expected in _VACUITY:
        got = _label(registry.vacuity_witness(passed, witness))
        if got != expected:
            failures.append(f"vacuity_witness({passed}, {witness}) gave {got!r}, expected {expected!r}")
    for signature, cosignature, expected in _ATTRIBUTION:
        got = _label(registry.evidence_attribution(signature, cosignature))
        if got != expected:
            failures.append(f"evidence_attribution({signature}, {cosignature}) gave {got!r}, expected {expected!r}")
    for named, sigs, required, issuer, expected in _SIGNERS:
        got = _label(registry.signer_distinctness(named, sigs, required, issuer))
        if got != expected:
            failures.append(f"signer_distinctness case {expected} gave {got!r}")
    for name, artifacts, instruction, expected in _LIFECYCLE:
        got = registry.lifecycle_binding(artifacts, _ACTIVE).get(("d1", instruction))
        if got != expected:
            failures.append(f"lifecycle_binding {name} gave {got!r}, expected {expected!r}")
    for issued, now, anchor, expected in _TIMES:
        got = _label(registry.time_bounds(issued, now, anchor, _TIME))
        if got != expected:
            failures.append(f"time_bounds({issued}, {now}, {anchor}) gave {got!r}, expected {expected!r}")
    for scope_change, pay_change in _MALFORMED:
        try:
            got = registry.payment_scope_v1({**_SCOPE, **scope_change}, {**_PAY, **pay_change})
        except registry.MalformedInputs:
            continue
        failures.append(f"payment_scope_v1 with {scope_change} {pay_change} gave {got}, expected malformed")
    honest = [_DEC, _art("c1", "control", "i1", "X"), _art("e1", "execution", "i1", "X")]
    no_auth = {k: v for k, v in honest[2].items() if k != "authenticated"}
    for name, bad in (("an unregistered artifact kind", _art("e2", "execution_report", "i1", "Y")),
                      ("an artifact with no authenticated member", no_auth),
                      ("an authenticated member that is a string", {**honest[2], "authenticated": "true"}),
                      ("an artifact that is not an object", "e1")):
        try:
            got = registry.lifecycle_binding([*honest[:2], bad], _ACTIVE)
            failures.append(f"lifecycle_binding accepted {name} and gave {got}")
        except registry.MalformedInputs:
            pass
    failures.extend(_preimage_cases(registry))
    partial = {k: v for k, v in _TIME.items() if k != "anchor_within"}
    got = _label(registry.time_bounds(10000, 10000, 10500, partial))
    if got != "time-profile-member-missing":
        failures.append(f"time_bounds with no anchor_within gave {got!r}, expected a refusal")
    misspelled = {**_TIME, "clock_skew_tollerance": 300}
    got = _label(registry.time_bounds(10000, 10000, None, misspelled))
    if got != "time-profile-member-unknown":
        failures.append(f"time_bounds with a misspelled member gave {got!r}, expected a refusal by name")
    no_early = {k: v for k, v in _TIME.items() if k != "anchor_early_allowance"}
    got = _label(registry.time_bounds(10000, 10000, 10500, no_early))
    if got != "time-profile-member-missing":
        failures.append(f"time_bounds with no anchor_early_allowance gave {got!r}, expected a refusal")
    got = _label(registry.time_bounds(10000, 10000, None, no_early))
    if got != "in-bounds":
        failures.append(f"time_bounds with no anchor time asked for anchor_early_allowance and gave {got!r}")
    failures.extend(_lifecycle_mutants(registry))
    count = (len(_PAYMENTS) + len(_MALFORMED) + 2 + len(_ASSERTED) + len(_DECISIONS) + len(_REPORTS) + len(_VACUITY) + len(_ATTRIBUTION)
             + len(_SIGNERS) + len(_LIFECYCLE) + len(_TIMES) + 11)
    return failures, count


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(_VOCAB.read_text())
        page = _PAGE.read_text(encoding="utf-8")
        validator = _load_validator()
        registry = _load_registry()
        index = json.loads(_INDEX.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        print(f"test_evaluation_claim: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None or registry is None:
        print("test_evaluation_claim: could not load the validator or the registry", file=sys.stderr)
        return 2

    section = vocab.get(SECTION)
    if not isinstance(section, dict) or not section:
        print(f"FAIL: vocabulary.yaml has no {SECTION} section")
        return 1
    failures = _check_terms(section, page)
    failures.extend(_check_closed_values(registry, index, section))
    derived, count = _check_derivations(registry)
    failures.extend(derived)
    ok = _run(validator, _crosswalk(SECTION))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("record_binding"))
    if not any(SECTION in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_evaluation_claim: {len(section)} terms and the guide agree; closed values accept and refuse "
          f"as registered, both validator cases behave, {count} derivation cases agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
