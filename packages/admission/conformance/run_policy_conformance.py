"""Drive the conformance corpus through the Kyverno and CUE admission rails.

The rego rail beside this directory carries a unit suite and a corpus oracle. Its
three Kyverno siblings and its CUE sibling shipped as deployment artefacts with no
execution of any kind, in continuous integration or out, so every defect ever found
in them was found by reading the expressions rather than by running them. This gate
closes that gap. It drives the vectors of the published conformance corpus through
three engines at once, the rego module with `opa`, the three Kyverno policies with
Kyverno's own JMESPath engine, and the CUE policy with `cue`, and it fails when a
rail admits a statement the rego oracle rejects, or rejects one the oracle admits,
outside a declared and justified set.

WHAT IS EXECUTED, AND WHAT IS NOT. This is a policy-body conformance gate, not a
cluster test. On the Kyverno rail each `conditions` entry is evaluated with
`kyverno jp query`, the command line front end to `pkg/engine/jmespath`, which is
the same engine and the same custom function set (`regex_match`, `parse_json`,
`base64_decode`, `not_null`, `ends_with`, `type`, `time_*`) the admission webhook
uses. The evaluation context reproduces what the webhook builds: Kyverno marshals
`statement["predicate"]` into a context entry named after the attestation and also
merges that same predicate at the context root, so both the `evidence.` prefix and
the bare member name resolve, and the input handed to the engine here is built the
same way. Two layers above the JMESPath are modeled rather than executed, and both
are guarded so the modelling cannot quietly widen: the attestation `type` selector,
because Kyverno looks up statements by predicate type and errors when none matches,
and the three comparison operators these policies use, because a policy that grows a
fourth operator makes this driver refuse to run rather than measure less than the
policy enforces. Not executed at all: registry resolution, the envelope signature
against the pinned public key, attestor counting, and digest mutation. Those need a
registry and a signed image and stay with the gated cluster recipe in the guide.
What IS checked about them, because nothing else in this bundle checks it, is the
literals they would run on: the key each document carries against the published one,
the attestor count, `required`, `failurePolicy`, and the enforcement pair. Those
fields sit outside `conditions`, so neither the corpus run nor the condition-parity
check reaches them, and a document that lost one would pass this gate in silence.

On the CUE rail the policy body is extracted from the manifest and run through
`cue vet`. That is a stricter evaluator than the one policy-controller uses: cosign
compiles the policy with `CompileString` and reports `Unify(doc).Validate()` without
`cue.Concrete(true)`, under which an absent member leaves an incomplete value rather
than an error, while `cue vet` reports it. The guide records that difference and it
is unchanged here. What this rail measures is therefore an upper bound on the
deployed rail's strictness. It is pinned as such: it detects any change to the policy
body, and it licenses no claim about cosign's evaluator, which remains unexecuted.

WHY EACH RAIL'S SET DIFFERS FROM THE ORACLE, AND WHY THE DIFFERENCE IS DECLARED.
Kyverno and CUE have their own evaluability boundary and it is not rego's. Both are
pass-only rails that additionally require every row to be substrate-observed and
intercepted, which is stronger than the spec's clean-row gate and stronger than rego,
so they deny some statements rego admits. Both also read less of the predicate than
rego does, so they admit some statements rego denies. Skipping what a rail cannot
decide is how this bundle reached a state with four unexecuted policy artefacts, so
neither direction is skipped: every divergence is declared below with a reason, and
the declaration is asserted for exact equality in both directions. A rail that gains
power over a declared admit fails this gate loudly rather than leaving a stale
exemption behind, which is the same discipline the rego denylist runs under.

Run: python3 conformance/run_policy_conformance.py
     python3 conformance/run_policy_conformance.py --measure
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_ADMISSION = _HERE.parent
_REGO_MODULE = _ADMISSION / "rego" / "execution_evidence.rego"
_CORPUS = _ADMISSION / "rego" / "corpus_vectors.json"
_KYVERNO_DIR = _ADMISSION / "kyverno"
_IVP_POLICY = _KYVERNO_DIR / "imagevalidatingpolicy-adversarial-execution-evidence.yaml"
_CUE_POLICY = (
    _ADMISSION
    / "policy-controller"
    / "clusterimagepolicy-adversarial-execution-evidence-cue.yaml"
)

# The comparison operators these policies use. Kyverno ships many more; only these
# are modeled, so a policy that grows a fourth has to be looked at rather than
# silently evaluated by a model that does not cover it.
_MODELLED_OPERATORS = frozenset({"Equals", "In", "GreaterThan"})

# A condition whose literal is still the shipped placeholder is a consumer anchor. It
# denies every vector by construction, which is the shipped default and the reason
# the guide tells an operator to pin before rolling out. Driving the corpus through
# an unpinned anchor would measure the placeholder rather than the policy, so anchor
# conditions are lifted out of the corpus run the way the rego suite runs its corpus
# tests under the explicit unpinned opt-out. They are not skipped: the crafted cases
# drive the matched, mismatched and unedited forms through the same evaluator.
_ANCHOR_PLACEHOLDER = "PIN-ME-"

# The evidence-age condition compares the wall clock against an instant the corpus
# fixes in the past, so every vector would read as stale and the condition would measure
# the calendar rather than the policy. It is lifted out of the corpus run and
# covered by seven crafted cases.
_FRESHNESS_MARKER = "time_now("

# The crafted anchor, freshness and case fixtures are all built by perturbing ONE
# healthy accept: a clean pass carrying an arming and a sealed record. It used to be
# named by the slug it was authored under, and suiteRevision 28 deleted every slug in
# the corpus, so `statements[_BASE_VECTOR]` raised KeyError after the whole corpus run
# had already been paid for -- twenty-five minutes of policy evaluation thrown away on
# a lookup that could have been resolved at load.
#
# It is named here by what it IS: the accept forcing exactly these spec conditions and
# expecting exactly this answer, which selects one vector in the published corpus and
# would go on selecting it through another re-layout. No slug and no digest, for the
# reason given at the head of ../rego/corpus_scope.py.
_BASE_CONDITIONS = (
    "aee-c-7",
    "aee-c-14",
    "aee-c-26",
    "aee-c-48",
    "aee-c-63",
    "aee-c-64",
    "aee-c-65",
)
_BASE_EXPECTED = {"verdict": "valid", "result": "pass"}

# Every fixture this driver writes lives under one directory created fresh for the
# running process. It used to be a constant, and a constant is shared by every run
# against the same machine: two of them unlink each other's fixtures, and the second
# reports every vector as a file that does not exist. That reads as a broken corpus
# or a broken generator, which is a conclusion someone might act on, and this gate is
# the one that decides whether four deployment artefacts agree with their oracle.
_WORKDIR_PREFIX = "execution-evidence-conf-"

Verdict = tuple[bool, str]


class PolicyError(RuntimeError):
    """A policy could not be evaluated, which on every rail means deny."""


# ---------------------------------------------------------------------------
# Narrowing helpers. Both engines and both manifests hand back parsed JSON or
# YAML, which is untyped by construction; every value is narrowed where it enters
# rather than carried onward as an unchecked value.
# ---------------------------------------------------------------------------


def _as_dict(value: object, what: str) -> dict[str, Any]:
    """Narrow to an object, returning the SAME object rather than a copy.

    Callers mutate what they are handed when they build a crafted statement, so a
    helper that quietly returned a copy would make every mutation land on a
    throwaway and every crafted case silently pass.
    """
    if not isinstance(value, dict):
        raise PolicyError(f"{what} is not an object")
    return value


def _as_list(value: object, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{what} is not an array")
    return value


def _as_str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{what} is not a string")
    return value


def _load_json(path: Path) -> dict[str, Any]:
    return _as_dict(json.loads(path.read_text(encoding="utf-8")), str(path))


def _load_manifest(path: Path) -> dict[str, Any]:
    """Read a deployment manifest through Kyverno's own YAML to JSON converter.

    Using the converter that ships with the tool consuming these documents, rather
    than a second YAML library, means the gate reads a manifest exactly as the tool
    does. It also keeps the driver's dependency set to the three engines it already
    needs to execute anything at all.
    """
    return _as_dict(_jp_run(_kyverno_binary(), path, "@"), str(path))


@cache
def _kyverno_binary() -> str:
    return _tool("KYVERNO_BIN", "kyverno")


def _tool(env_name: str, binary: str) -> str:
    found = os.environ.get(env_name) or shutil.which(binary)
    if not found:
        raise SystemExit(
            f"{binary} was not found. Install it or set {env_name}. This gate exists "
            f"because these rails were never executed; it will not report a rail as "
            f"verified on the strength of the policy file alone."
        )
    return found


# ---------------------------------------------------------------------------
# Kyverno rail
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Slot:
    """One condition, reduced to the expressions and the comparison it needs."""

    index: int
    operator: str
    key_expr: str
    value_expr: str | None
    literal: object


@dataclass(frozen=True)
class KyvernoPolicy:
    name: str
    attestation_type: str
    slots: tuple[_Slot, ...]
    deferred: dict[str, int] = field(default_factory=dict)
    # Every condition the document carries except the freshness window, rendered so
    # two policies can be compared for structural equality. The corpus cannot catch
    # a condition that goes missing from one sibling when no vector exercises it,
    # and that is exactly how the freshness variant lost its posture-digest binding
    # while its header went on claiming to extend the policy that carries it.
    parity: tuple[str, ...] = ()


_VAR = re.compile(r"^\{\{(?P<expr>.*)\}\}$", re.DOTALL)


def _expr_of(node: object) -> str | None:
    """The JMESPath inside a whole-string variable, or None for a plain literal."""
    if not isinstance(node, str):
        return None
    match = _VAR.match(node.strip())
    return match.group("expr").strip() if match else None


def _attestation_of(doc: dict[str, Any]) -> dict[str, Any]:
    for rule in _as_list(doc["spec"]["rules"], "spec.rules"):
        for verify in _as_list(_as_dict(rule, "rule").get("verifyImages") or [], "v"):
            entries = _as_dict(verify, "verifyImages").get("attestations") or []
            for att in _as_list(entries, "attestations"):
                return _as_dict(att, "attestation")
    raise PolicyError("policy carries no attestation")


def _condition_list(att: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for group in _as_list(att.get("conditions") or [], "conditions"):
        grp = _as_dict(group, "condition group")
        if set(grp) != {"all"}:
            raise PolicyError(f"only an `all` group is modeled, found {sorted(grp)}")
        out.extend(_as_dict(c, "condition") for c in _as_list(grp["all"], "all"))
    return out


def _is_anchor(cond: dict[str, Any]) -> bool:
    value = cond.get("value")
    return isinstance(value, str) and value.startswith(_ANCHOR_PLACEHOLDER)


def _is_freshness(cond: dict[str, Any]) -> bool:
    return _FRESHNESS_MARKER in str(cond.get("key", ""))


def _slots_of(
    conds: list[dict[str, Any]], *, keep: set[int] | None = None
) -> tuple[_Slot, ...]:
    """One slot per condition, numbered as the POLICY FILE numbers them.

    ``keep`` is the set of positions still being measured; the rest are dropped AFTER
    numbering, never before. That ordering is the whole point. This function used to be
    handed the already-filtered list, so lifting the two anchor conditions out for the
    corpus run renumbered everything after them and conditions (13) through (16) were
    reported as (11) through (14) in every failure message the corpus run emitted. A
    diagnostic that names a condition has one job, and a renumbered one sends its reader
    to a rule that is not the rule that failed. The guide now cites each condition by its
    ordinal AND its permanent slug for the same reason.
    """
    slots: list[_Slot] = []
    for index, cond in enumerate(conds, 1):
        if keep is not None and index not in keep:
            continue
        key_expr = _expr_of(cond["key"])
        if key_expr is None:
            raise PolicyError(
                f"condition {index} has a literal key, which is not modeled"
            )
        slots.append(
            _Slot(
                index=index,
                operator=_as_str(cond["operator"], "operator"),
                key_expr=key_expr,
                value_expr=_expr_of(cond.get("value")),
                literal=cond.get("value"),
            )
        )
    return tuple(slots)


def _read_policy(path: Path, *, corpus_mode: bool) -> KyvernoPolicy:
    """Load one ClusterPolicy.

    In corpus mode the anchor and freshness conditions are lifted out, and how many
    of each is recorded so the caller can assert the deferral is the expected one
    rather than a condition that quietly stopped being measured.
    """
    att = _attestation_of(_load_manifest(path))
    conds = _condition_list(att)
    unknown = {_as_str(c["operator"], "operator") for c in conds} - _MODELLED_OPERATORS
    if unknown:
        raise SystemExit(
            f"{path.name} uses operators this driver does not model: {sorted(unknown)}. "
            f"Model them, or the gate measures less than the policy enforces."
        )
    deferred = {
        "anchor": sum(1 for c in conds if _is_anchor(c)),
        "freshness": sum(1 for c in conds if _is_freshness(c)),
    }
    parity = tuple(
        f"{c['operator']}|{c['key']}|{c.get('value')!r}"
        for c in conds
        if not _is_freshness(c)
    )
    keep = None
    if corpus_mode:
        keep = {
            index
            for index, cond in enumerate(conds, 1)
            if not _is_anchor(cond) and not _is_freshness(cond)
        }
    return KyvernoPolicy(
        name=path.name,
        attestation_type=_as_str(att["type"], "attestation type"),
        slots=_slots_of(conds, keep=keep),
        deferred=deferred,
        parity=parity,
    )


def _jp_run(binary: str, input_path: Path, query: str) -> object:
    """Evaluate one query with Kyverno's own JMESPath engine.

    The input goes in as a file rather than on standard input because the command
    line tool prints an interactive prompt to standard output when it reads from a
    stream, which would land in the middle of the result.
    """
    proc = subprocess.run(
        [binary, "jp", "query", "-c", "-i", str(input_path), query],
        capture_output=True,
        text=True,
        check=False,
    )
    body = "\n".join(
        line for line in proc.stdout.splitlines() if not line.startswith("# ")
    ).strip()
    if proc.returncode != 0 or not body:
        raise PolicyError((proc.stderr or proc.stdout or "no output").strip())
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"engine returned unparseable output: {exc}") from exc


def _jp_batch(binary: str, input_path: Path, exprs: list[str]) -> list[object]:
    """Evaluate every expression against one input in a single process.

    A multiselect list keeps this to one process per policy per vector. An engine
    error aborts the batch, which is what Kyverno does too: condition substitution
    runs over the whole list and a failure anywhere in it fails the attestation
    check, so the verdict is deny either way. The caller falls back to one process
    per expression only to name the culprit.
    """
    parsed = _jp_run(binary, input_path, "[" + ", ".join(exprs) + "]")
    if not isinstance(parsed, list) or len(parsed) != len(exprs):
        raise PolicyError(f"multiselect returned {parsed!r}")
    return list(parsed)


_INNER_VAR = re.compile(r"\{\{(?P<expr>[^{}]*)\}\}")


def _substitute_nested(binary: str, path: Path, expr: str) -> str:
    """Resolve variables nested inside a JMESPath expression, innermost first.

    Kyverno substitutes variables before it evaluates, so a condition may embed a
    `{{ ... }}` inside a string literal, as the freshness window does with
    `time_add('{{ evidence.issuedAt }}', '168h')`. The resolved value is inserted
    as a bare string because the surrounding quotes are already in the expression.
    A variable that resolves to nothing becomes the empty string, which is what
    makes an absent timestamp fail the condition rather than skip it.
    """
    current = expr
    for _ in range(4):
        match = _INNER_VAR.search(current)
        if match is None:
            return current
        value = _jp_run(binary, path, match.group("expr").strip())
        rendered = "" if value is None else str(value)
        current = current[: match.start()] + rendered + current[match.end() :]
    raise PolicyError("variable nesting is deeper than this driver resolves")


def _resolve_expr(binary: str, path: Path, expr: str) -> object:
    if "{{" in expr:
        return _jp_run(binary, path, _substitute_nested(binary, path, expr))
    return _jp_run(binary, path, expr)


def _resolve_one(binary: str, path: Path, slot: _Slot) -> tuple[object, object] | str:
    try:
        key = _resolve_expr(binary, path, slot.key_expr)
        value = (
            _resolve_expr(binary, path, slot.value_expr)
            if slot.value_expr is not None
            else slot.literal
        )
    except PolicyError as exc:
        return str(exc)
    return (key, value)


def _resolve_slots(
    binary: str, path: Path, slots: tuple[_Slot, ...]
) -> list[tuple[object, object] | str]:
    exprs: list[str] = []
    nested = False
    for slot in slots:
        exprs.append(slot.key_expr)
        nested = nested or "{{" in slot.key_expr
        if slot.value_expr is not None:
            exprs.append(slot.value_expr)
            nested = nested or "{{" in slot.value_expr
    if nested:
        return [_resolve_one(binary, path, slot) for slot in slots]
    try:
        flat = _jp_batch(binary, path, exprs)
    except PolicyError:
        return [_resolve_one(binary, path, slot) for slot in slots]
    out: list[tuple[object, object] | str] = []
    cursor = 0
    for slot in slots:
        key = flat[cursor]
        cursor += 1
        value: object = slot.literal
        if slot.value_expr is not None:
            value = flat[cursor]
            cursor += 1
        out.append((key, value))
    return out


def _same_json(left: object, right: object) -> bool:
    """JSON equality that does not let a boolean compare equal to a number."""
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return bool(left == right)


def _numeric(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"expected a number, got {value!r}")
    return float(value)


def _apply_operator(operator: str, key: object, value: object) -> bool:
    if operator == "Equals":
        return _same_json(key, value)
    if operator == "In":
        if not isinstance(value, list):
            raise PolicyError(f"In expects a list, got {value!r}")
        return any(_same_json(key, item) for item in value)
    if operator == "GreaterThan":
        return _numeric(key) > _numeric(value)
    raise PolicyError(f"operator {operator} is not modeled")


def kyverno_input(predicate: dict[str, Any]) -> dict[str, Any]:
    """Reproduce the context the webhook builds around an attestation's predicate."""
    doc: dict[str, Any] = dict(predicate)
    doc["evidence"] = predicate
    return doc


def kyverno_verdict(
    binary: str, policy: KyvernoPolicy, statement: dict[str, Any], path: Path
) -> Verdict:
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False, "statement carries no predicate object"
    if statement.get("predicateType") != policy.attestation_type:
        return False, "no attestation carries the predicate type this policy selects"
    for slot, item in zip(
        policy.slots, _resolve_slots(binary, path, policy.slots), strict=True
    ):
        if isinstance(item, str):
            return False, f"condition {slot.index} could not be evaluated: {item}"
        key, value = item
        try:
            satisfied = _apply_operator(slot.operator, key, value)
        except PolicyError as exc:
            return False, f"condition {slot.index} could not be compared: {exc}"
        if not satisfied:
            return False, f"condition {slot.index} ({slot.operator}) not satisfied"
    return True, ""


def kyverno_decodable(binary: str, path: Path) -> str | None:
    """The engine's complaint if it cannot read the input at all, else None.

    This is a property of the harness rather than of the deployed rail, and it is
    reported separately for that reason. In a cluster the statement reaches Kyverno
    already decoded by cosign, so a fault that only the command line tool's own JSON
    reader can see is not evidence about the policy.
    """
    try:
        _jp_run(binary, path, "@")
    except PolicyError as exc:
        return str(exc)
    return None


# ---------------------------------------------------------------------------
# CUE rail
# ---------------------------------------------------------------------------


def cue_source(*, drop_anchors: bool) -> str:
    doc = _load_manifest(_CUE_POLICY)
    authorities = _as_list(doc["spec"]["authorities"], "authorities")
    attestations = _as_list(
        _as_dict(authorities[0], "authority")["attestations"], "attestations"
    )
    policy = _as_dict(_as_dict(attestations[0], "attestation")["policy"], "policy")
    src = _as_str(policy["data"], "policy.data")
    if not drop_anchors:
        return src
    lines = src.splitlines()
    kept = [line for line in lines if _ANCHOR_PLACEHOLDER not in line]
    if len(kept) == len(lines):
        raise PolicyError(
            "the CUE policy carries no anchor placeholder, so the documented decline "
            "path has moved and this driver is stale"
        )
    return "\n".join(kept) + "\n"


def cue_verdict(
    binary: str, policy_path: Path, statement: dict[str, Any], workdir: Path, tag: str
) -> Verdict:
    data = workdir / f"stmt-{tag}.json"
    data.write_text(json.dumps(statement), encoding="utf-8")
    proc = subprocess.run(
        [binary, "vet", str(policy_path), str(data)],
        capture_output=True,
        text=True,
        check=False,
    )
    data.unlink(missing_ok=True)
    if proc.returncode == 0:
        return True, ""
    lines = (proc.stderr or proc.stdout).strip().splitlines()
    return False, lines[0] if lines else "cue vet failed with no message"


# ---------------------------------------------------------------------------
# CEL rail (ImageValidatingPolicy)
# ---------------------------------------------------------------------------
#
# WHAT IS EXECUTED HERE, AND WHAT IS MODELED. The `ImageValidatingPolicy` beside the
# ClusterPolicy bundle expresses its checks as CEL, and this rail drives them through
# Kyverno's OWN CEL compiler -- the same `pkg/cel` compiler and the same extension
# libraries (`base64`, `json`, `hash`, `lists`, `sets`, `time`) the admission webhook
# builds -- by lifting `spec.variables` and `spec.validations` verbatim into a
# `ValidatingPolicy` over an unstructured resource carrying the statement. That is the
# same shape of lift the JMESPath rail above performs with `kyverno jp query`: the
# expressions are executed, and exactly one layer around them is modeled.
#
# The modeled layer is `extractPayload`. Its documented precondition is a prior
# `verifyAttestationSignatures`, which needs a registry and a signed image, so the
# corpus statement is bound to the `statement` variable directly instead. That is
# sound because `extractPayload` returns the FULL in-toto Statement -- Kyverno's
# `imageverify` library is a passthrough of the kyverno/sdk loader, which unmarshals
# what cosign's `AttestationToPayloadJSON` produced, and every arm of that function
# marshals a Statement. A custom predicate type takes its `default:` arm. So the
# object this harness binds is the object the deployed rail evaluates, and the only
# unexecuted parts are the registry fetch and the envelope signature -- the same two
# the JMESPath rail leaves to the gated cluster recipe.
#
# THE DEFERRALS ARE THE SAME THREE, FOR THE SAME REASONS. Registry-dependent
# validations, consumer anchors still carrying their `PIN-ME-` placeholder, and the
# wall-clock freshness bound are lifted out of the corpus run and counted, so a
# document that quietly loses one fails `_check_deferrals` rather than measuring less
# than it enforces.
_CEL_REGISTRY_MARKERS = (
    "verifyImageSignatures",
    "verifyAttestationSignatures",
    "variables.verified",
)
_CEL_FRESHNESS_MARKER = "time.now("

# The resource kind the lifted policy matches. It is an unstructured document rather
# than a Pod because what is under test is the statement body, not the workload.
_CEL_GROUP = "evidence.example"
_CEL_RESOURCE = "payloads"


@dataclass
class CelPolicy:
    """The ImageValidatingPolicy, reduced to what the corpus run can execute."""

    name: str
    variables: list[dict[str, str]]
    validations: list[dict[str, str]]
    deferred: dict[str, int]


def _read_ivp(path: Path) -> CelPolicy:
    doc = _load_manifest(path)
    spec = _as_dict(doc["spec"], "spec")
    variables: list[dict[str, str]] = []
    for entry in _as_list(spec.get("variables", []), "variables"):
        item = _as_dict(entry, "variable")
        name = _as_str(item["name"], "variable name")
        if name == "verified":
            # Its whole body is the registry-dependent signature count.
            continue
        if name == "statement":
            variables.append(
                {"name": "statement", "expression": "object.spec.statement"}
            )
            continue
        variables.append(
            {"name": name, "expression": _as_str(item["expression"], "expression")}
        )
    if not any(v["name"] == "statement" for v in variables):
        raise SystemExit(
            f"{path.name} declares no `statement` variable. This driver binds the "
            f"corpus statement to that name, so a policy that renamed it would be "
            f"measured against an unbound context rather than against the corpus."
        )
    kept: list[dict[str, str]] = []
    deferred: Counter[str] = Counter()
    for entry in _as_list(spec.get("validations", []), "validations"):
        item = _as_dict(entry, "validation")
        expr = _as_str(item["expression"], "expression")
        if any(marker in expr for marker in _CEL_REGISTRY_MARKERS):
            deferred["registry"] += 1
            continue
        if _ANCHOR_PLACEHOLDER in expr:
            deferred["anchor"] += 1
            continue
        if _CEL_FRESHNESS_MARKER in expr:
            deferred["freshness"] += 1
            continue
        kept.append(
            {"expression": expr, "message": _as_str(item["message"], "message")}
        )
    return CelPolicy(
        name=path.name, variables=variables, validations=kept, deferred=dict(deferred)
    )


def cel_document(policy: CelPolicy) -> dict[str, Any]:
    """The lifted policy, as the document `kyverno apply` is handed."""
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "ValidatingPolicy",
        "metadata": {"name": "execution-evidence-cel-rail"},
        "spec": {
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": [_CEL_GROUP],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE"],
                        "resources": [_CEL_RESOURCE],
                    }
                ]
            },
            "variables": policy.variables,
            "validations": policy.validations,
        },
    }


def cel_verdict(
    binary: str, policy_path: Path, statement: dict[str, Any], workdir: Path, tag: str
) -> Verdict:
    # The resource file must carry a `.yaml` suffix. `kyverno apply` selects its
    # loader by extension and SILENTLY IGNORES a `.json` one, which presents as
    # "Applying 0 policy rule(s)" with a zero exit status -- a policy that never ran,
    # wearing the shape of a policy that found nothing to say. JSON is valid YAML, so
    # the content stays JSON and only the suffix changes.
    resource = workdir / f"cel-{tag}.yaml"
    resource.write_text(
        json.dumps(
            {
                "apiVersion": f"{_CEL_GROUP}/v1",
                "kind": "Payload",
                "metadata": {"name": "vector"},
                "spec": {"statement": statement},
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [binary, "apply", str(policy_path), "--resource", str(resource)],
        capture_output=True,
        text=True,
        check=False,
    )
    resource.unlink(missing_ok=True)
    out = proc.stdout + proc.stderr
    # A policy that did not load, and a policy that did not compile, are HARNESS
    # faults and are raised rather than returned. Returning them would record a deny,
    # and a deny is a finding: it would read as the rail refusing the vector when in
    # fact nothing was ever evaluated. This is the failure this bundle keeps finding
    # in its own gates, so it is refused explicitly here.
    if "Applying 0 policy rule(s)" in out:
        raise SystemExit(
            f"the lifted CEL policy did not load while evaluating {tag}, so nothing "
            f"was evaluated. This is a harness fault and is never reported as a "
            f"denial: {out.strip()[:300]}"
        )
    if "failed to compile policy" in out:
        raise SystemExit(
            f"the lifted CEL policy did not compile while evaluating {tag}: "
            f"{out.strip()[:600]}"
        )
    if "pass: 1," in out:
        return True, ""
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("1 -"):
            return False, stripped[3:].strip()[:160]
    # A CEL runtime error. Kyverno reports it as `error: 1` with no named message; it
    # is a deny on the deployed rail too, because `failurePolicy: Fail`.
    return False, "the CEL engine raised a runtime error"


# ---------------------------------------------------------------------------
# rego oracle
# ---------------------------------------------------------------------------


def rego_verdict(
    binary: str, pins: Path, statement: dict[str, Any], workdir: Path, tag: str
) -> Verdict:
    data = workdir / f"rego-{tag}.json"
    data.write_text(json.dumps(statement), encoding="utf-8")
    proc = subprocess.run(
        [
            binary,
            "eval",
            "-f",
            "raw",
            "-d",
            str(_REGO_MODULE),
            "-d",
            str(pins),
            "-i",
            str(data),
            "data.sigstore.isCompliant",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    data.unlink(missing_ok=True)
    answer = proc.stdout.strip()
    if proc.returncode != 0 or answer not in {"true", "false"}:
        return False, f"opa eval did not answer: {(proc.stderr or answer)[:160]}"
    return answer == "true", ""


# ---------------------------------------------------------------------------
# Declared divergence from the rego oracle
# ---------------------------------------------------------------------------

# The reason families. Each names the layer a defect lives in, which is what makes a
# declared admit a boundary rather than an excuse.
_RESULT_RECOMPUTE = (
    "the result recompute over the carried vocabulary, which no JMESPath condition "
    "performs, so a statement whose result is a lie beside its own rows satisfies "
    "condition (1)"
)
_REFS_JOIN = (
    "per-row reference resolution, which is a join JMESPath has no operator for: "
    "conditions (8) and (9) assert the covering records exist on the statement, not "
    "that the row cites them"
)
_RUN_IDENTITY = "the run-identity recompute, which needs canonical JSON and SHA-256"
_UNREAD_MEMBER = "a predicate member no constraint on this rail reads"
_OUTSIDE_CONTEXT = (
    "a STATEMENT member outside this rail's evaluation context. Kyverno hands the "
    "conditions the predicate object and nothing else, both merged at the context "
    "root and marshalled under the attestation's name (pkg/engine/internal, "
    'EvaluateConditions and getRawResp, both of which read statement["predicate"]), '
    "so `subject` cannot be named from any condition however the condition is "
    "written. Not a check this rail declined; a member it cannot see"
)
_ANCHOR_DEFERRED_DIGEST = (
    "the substrate digest's SHAPE, which both of these rails constrain only through "
    "the consumer anchor, and anchor conditions are lifted out of the corpus run "
    "because an unedited placeholder denies every vector by construction. A PINNED "
    "deployment compares that member against a lowercase 64-hex literal and denies "
    "the truncated form with it, so the divergence belongs to the corpus harness "
    "rather than to either deployed rail. The runEntropy sibling of the same fault "
    "needs no anchor on the Kyverno rail, where condition (14) patterns it directly, "
    "which is why bad-608-digest-uppercase is declared for the CUE rail alone"
)
_NO_ROOT_REFERENCE = (
    "a record payload member that has to be compared against a value living "
    "elsewhere in the document, and a filter can name only literals and fields of "
    "the element under test"
)
_COVERAGE_ALGEBRA = (
    "the coverage set algebra over the corpus manifest, which needs set union and "
    "disjointness across three lists"
)
_CUE_NO_PAYLOAD = (
    "a record payload member, and this rail never decodes a payload at all: the "
    "base64 decode plus JSON parse is the construct the policy body records as "
    "unmeasured under cosign's evaluator"
)
_HARNESS_DECODER = (
    "the Kyverno command line tool's own JSON reader refuses the escape, so this "
    "denial belongs to the harness rather than to the deployed rail, which receives "
    "a statement cosign has already decoded. Recorded as a divergence rather than "
    "claimed as a rail strength"
)
_CUE_DECODER = (
    "CUE's JSON reader rejects the unpaired surrogate, and cosign compiles the "
    "attestation bytes with CUE too, so unlike the Kyverno rail this denial does "
    "carry to the deployed rail"
)
_UNREF_ARMING_NULL_ARMEDAT = (
    "an unreferenced carried arming record with no aeeArmedAt; the Kyverno armedAt "
    "condition errors on the null and denies, where the rego oracle admits because "
    "it evaluates only referenced records and never sees this carried one"
)
_UNREF_SEALED_POSTURE = (
    "an unreferenced carried sealed record with a non-pinned aeePostureDigest; the "
    "CEL posture condition denies, where the rego oracle admits because it evaluates "
    "only referenced records and never sees this carried one"
)

# ---------------------------------------------------------------------------
# Declarations are keyed on WHAT a vector forces, never on the authoring slug it
# was minted under. suiteRevision 28 deleted every slug in the published corpus (see
# the note above `_BASE_CONDITIONS`), so a `dict[slug, reason]` table -- what this
# file carried until the corpus moved under it -- matches nothing and reports every
# vector as undeclared. `../rego/corpus_scope.py` solved the identical problem for
# the rego oracle's own denylist by resolving a vector through its manifest's
# `reason` and `expected` fields, which `corpus_vectors.json` already projects and
# survive a re-layout that renames every file. The tables below do the same: each
# `_Divergence` names a reason and an expected answer, plus a `shape` predicate over
# the parsed statement wherever those two do not separate it from a sibling that
# carries the identical reason and answer for a genuinely different cause.
#
# Resolution here does not assert a count the way corpus_scope.resolve() does,
# because `_check_declared` already re-derives the same guarantee from a live rail
# result: a vector this file wrongly includes shows up as "gained power over a
# declared admit," and one it wrongly omits shows up as "not declared," both against
# an actual `kyverno jp query` / `cue vet` / `kyverno apply` run rather than a count
# nobody has re-verified. Refusing on a stale count here would duplicate that check
# with a weaker one.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Divergence:
    reason: str
    expected: dict[str, Any]
    why: str
    shape: Callable[[dict[str, Any]], bool] | None = None


def _decoded_record_payloads(statement: dict[str, Any]) -> list[dict[str, Any]]:
    """Every observation-record payload that decodes into a JSON object.

    A shape predicate separates one corpus vector from a sibling sharing its reason
    and expected answer; a record this cannot decode is never that sibling, so it is
    skipped rather than raised.
    """
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return []
    records = predicate.get("observationRecords")
    if not isinstance(records, list):
        return []
    out: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        raw = record.get("payload")
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(base64.b64decode(raw))
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            out.append(payload)
    return out


def _network_posture_digest(statement: dict[str, Any]) -> str | None:
    predicate = statement.get("predicate")
    env = (
        predicate.get("observationEnvironment") if isinstance(predicate, dict) else None
    )
    posture = env.get("networkPosture") if isinstance(env, dict) else None
    digest = posture.get("digest") if isinstance(posture, dict) else None
    sha = digest.get("sha256") if isinstance(digest, dict) else None
    return sha if isinstance(sha, str) else None


def _sealed_posture_mismatched(
    payload: dict[str, Any], posture_digest: str | None
) -> bool:
    digest = payload.get("aeePostureDigest")
    return isinstance(digest, str) and digest != posture_digest


def _c65_sealed_needs_root_reference(statement: dict[str, Any]) -> bool:
    """Separates bad-710's posture-digest root-reference class from its refs-join
    siblings (a non-boolean or false aeeStillArmed, a missing or out-of-bound
    aeeDropCount, a reconstructed method): those compare fine once the right record
    is joined, where this compares the sealed record's aeePostureDigest against the
    environment root, a reference no filter over the element under test can make.
    """
    posture = _network_posture_digest(statement)
    return any(
        payload.get("aeeKind") == "sealed"
        and _sealed_posture_mismatched(payload, posture)
        for payload in _decoded_record_payloads(statement)
    )


def _c63_arming_needs_root_reference(statement: dict[str, Any]) -> bool:
    """Separates the armedAt/posture root-reference class from CUE's payload-only
    class (a reconstructed method, an absent armedAt, a lowercase RFC 3339 separator
    or zone designator): those are read straight off the decoded payload, which
    Kyverno already does through parse_json and CUE never does at all. What is left
    compares armedAt against issuedAt, or a missing posture digest against the
    environment root, out of both rails' reach.
    """
    for payload in _decoded_record_payloads(statement):
        if payload.get("aeeKind") != "arming":
            continue
        if payload.get("aeeMethod") == "reconstructed":
            return False
        armed_at = payload.get("armedAt")
        if not isinstance(armed_at, str) or armed_at != armed_at.upper():
            return False
    return True


_CHAIN_SCOPE_TOKENS = frozenset({"subject", "corpus", "networkPosture"})


def _c89_arming_needs_root_reference(statement: dict[str, Any]) -> bool:
    """Separates the chain root-reference class from bad-722/bad-988's closed-
    vocabulary class. aeeChainScope's vocabulary is a closed literal list, so asking
    whether every element is a member of it needs no reference outside the element
    under test, and Kyverno's conditions (19)/(20) already do; CUE never decodes the
    payload to ask it at all. What is left -- a non-array or missing scope, an
    unsorted scope, a zero run sequence, a non-hex previous binding -- either
    compares against issuedAt/posture at the document root or is a format check
    neither rail's declared conditions perform.
    """
    for payload in _decoded_record_payloads(statement):
        if payload.get("aeeKind") != "arming":
            continue
        scope = payload.get("aeeChainScope")
        if isinstance(scope, list) and any(
            not isinstance(token, str) or token not in _CHAIN_SCOPE_TOKENS
            for token in scope
        ):
            return False
    return True


def _c99_declares_undeclared_attack(statement: dict[str, Any]) -> bool:
    """The arming record's aeeAssessedAttacks names an attack the corpus manifest
    never declares -- a comparison against the manifest at the document root, not
    against the element under test.
    """
    predicate = statement.get("predicate")
    env = (
        predicate.get("observationEnvironment") if isinstance(predicate, dict) else None
    )
    corpus = env.get("corpus") if isinstance(env, dict) else None
    manifest = corpus.get("manifest") if isinstance(corpus, dict) else None
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    declared: set[str] = set()
    if isinstance(classes, dict):
        for ids in classes.values():
            if isinstance(ids, list):
                declared.update(i for i in ids if isinstance(i, str))
    for payload in _decoded_record_payloads(statement):
        if payload.get("aeeKind") != "arming":
            continue
        attacks = payload.get("aeeAssessedAttacks")
        if isinstance(attacks, list) and any(
            isinstance(a, str) and a not in declared for a in attacks
        ):
            return True
    return False


def _c99_assessed_attacks_unsorted(statement: dict[str, Any]) -> bool:
    for payload in _decoded_record_payloads(statement):
        if payload.get("aeeKind") != "arming":
            continue
        attacks = payload.get("aeeAssessedAttacks")
        if isinstance(attacks, list) and sorted(attacks) != attacks:
            return True
    return False


def _c99_multiple_arming_records(statement: dict[str, Any]) -> bool:
    """A second arming record declaring nothing needs comparing it against the
    FIRST arming record's aeeAssessedAttacks -- a member of one element of the same
    list compared against a member of a different element, no more expressible than
    a document-root reference. A single arming record naming an attack the manifest
    never declares is a simpler, already-reachable comparison and carries no
    declaration here.
    """
    return (
        sum(
            1
            for p in _decoded_record_payloads(statement)
            if p.get("aeeKind") == "arming"
        )
        > 1
    )


def _has_lone_or_reversed_surrogate(statement: dict[str, Any]) -> bool:
    """The harness/CUE JSON decoder rejects a lone or reversed UTF-16 surrogate
    literally present in the statement's text. Two siblings under the identical
    reason and answer carry a different statement-malformed cause that a JSON reader
    parses cleanly, so they are excluded here.
    """
    text = json.dumps(statement, ensure_ascii=False)
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _c59_substrate_digest_noncanonical(statement: dict[str, Any]) -> bool:
    """Separates bad-609's substrate-digest shape (deferred to the consumer anchor
    on both rails) from bad-608's runEntropy-digest shape: Kyverno's condition (14)
    patterns the runEntropy digest directly and needs no anchor, so an uppercase
    runEntropy digest alone is already denied and carries no declaration here.
    """
    predicate = statement.get("predicate")
    env = (
        predicate.get("observationEnvironment") if isinstance(predicate, dict) else None
    )
    substrate = env.get("substrate") if isinstance(env, dict) else None
    digest = substrate.get("digest") if isinstance(substrate, dict) else None
    sha = digest.get("sha256") if isinstance(digest, dict) else None
    return isinstance(sha, str) and (len(sha) != 64 or sha != sha.lower())


def _c98_no_interception_records(statement: dict[str, Any]) -> bool:
    """Separates the simple two-record arming/sealed chain (bad-955/bad-997's shape,
    which needs the manifest at the document root) from a crafted multi-row vector
    that also carries "interception" records: that shape's manifest already declares
    every attack its own sealed records observe, so its own coverage/refs-join
    conditions -- not a comparison against the manifest -- are what deny it, and it
    carries no declaration here.
    """
    return not any(
        p.get("aeeKind") == "interception" for p in _decoded_record_payloads(statement)
    )


def _c82_coverage_needs_root_reference(statement: dict[str, Any]) -> bool:
    """A manifest-declared attack with NO row at all needs comparing the row set
    against the manifest at the document root. A manifest-declared attack that DOES
    have a row, whose own observationRefs is empty or insufficient, is a per-row
    check the rail already reaches without any root reference, regardless of the
    statement's own recomputed result -- which is why a "degraded" result alone
    (every declared attack has a row; only the row's own reference count is short)
    carries no declaration here, while a "pass" or "fail" result with a wholly
    absent row does.
    """
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False
    env = predicate.get("observationEnvironment")
    corpus_env = env.get("corpus") if isinstance(env, dict) else None
    manifest = corpus_env.get("manifest") if isinstance(corpus_env, dict) else None
    classes = manifest.get("classes") if isinstance(manifest, dict) else None
    declared: set[str] = set()
    if isinstance(classes, dict):
        for ids in classes.values():
            if isinstance(ids, list):
                declared.update(i for i in ids if isinstance(i, str))
    rows = predicate.get("attackResults")
    row_ids = (
        {r.get("attackId") for r in rows if isinstance(r, dict)}
        if isinstance(rows, list)
        else set()
    )
    missing = declared - row_ids
    return bool(missing) and predicate.get("result") != "degraded"


def _c2_result_recompute_needs_root_reference(statement: dict[str, Any]) -> bool:
    """A row whose actualLayer is a real layer (not "none") needs the full result
    recompute over the carried vocabulary to verify -- the root-reference boundary
    this family's name states. A row left at "none" is a simpler, already-reachable
    self-consistency check and carries no declaration here.
    """
    predicate = statement.get("predicate")
    rows = predicate.get("attackResults") if isinstance(predicate, dict) else None
    if not isinstance(rows, list):
        return False
    return any(isinstance(r, dict) and r.get("actualLayer") != "none" for r in rows)


def _c48_not_indirect_result(statement: dict[str, Any]) -> bool:
    """A "pass_indirect" result marks a carried, evidence-free row (basis
    "artifact", method "reconstructed", no observation records at all) that a
    simpler, self-contained check already denies. The clean-row-layer-conditional-
    on-label check this family names applies only to a row backed by real evidence.
    """
    predicate = statement.get("predicate")
    return isinstance(predicate, dict) and predicate.get("result") != "pass_indirect"


def _unreferenced_indices(statement: dict[str, Any]) -> set[int]:
    predicate = statement.get("predicate")
    records = (
        predicate.get("observationRecords") if isinstance(predicate, dict) else None
    )
    if not isinstance(records, list):
        return set()
    referenced: set[int] = set()
    rows = predicate.get("attackResults") if isinstance(predicate, dict) else None
    for row in rows or []:
        if isinstance(row, dict):
            referenced.update(
                r for r in (row.get("observationRefs") or []) if isinstance(r, int)
            )
    return set(range(len(records))) - referenced


def _unreferenced_sealed_posture_mismatch(statement: dict[str, Any]) -> bool:
    """The one unreferenced-carried-sealed-record defect the CEL posture condition
    can see: a carried record's aeePostureDigest present and not the pinned digest.
    The other thirteen siblings under this same reason and answer carry a different
    member fault each -- a missing or non-boolean aeeStillArmed, a missing or
    negative aeeDropCount, drops with no bound or past one, a reconstructed method, a
    missing aeeObservedSet or aeeObservedAttacks, an unknown observed attack, or
    covering nothing at all -- none of which this rail's posture condition reads.
    """
    predicate = statement.get("predicate")
    records = (
        predicate.get("observationRecords") if isinstance(predicate, dict) else None
    )
    if not isinstance(records, list):
        return False
    posture = _network_posture_digest(statement)
    for index in _unreferenced_indices(statement):
        record = records[index]
        if not isinstance(record, dict):
            continue
        raw = record.get("payload")
        if not isinstance(raw, str):
            continue
        try:
            payload = json.loads(base64.b64decode(raw))
        except (ValueError, TypeError):
            continue
        if (
            isinstance(payload, dict)
            and payload.get("aeeKind") == "sealed"
            and _sealed_posture_mismatched(payload, posture)
        ):
            return True
    return False


# Corpus vectors the Kyverno rails ADMIT and the rego oracle DENIES. Every family is
# a rule the rail cannot express, not a rule it forgot. All three Kyverno documents
# share this set and are asserted to agree.
_KYVERNO_ADMITS: tuple[_Divergence, ...] = (
    _Divergence(
        "aee-c-2; aee-c-6 | codes: result-recompute-mismatch",
        {"codes": ["result-recompute-mismatch"], "verdict": "invalid"},
        _RESULT_RECOMPUTE,
    ),
    _Divergence(
        "aee-c-14 | codes: clean-row-uncovered",
        {"codes": ["clean-row-uncovered"], "verdict": "invalid"},
        _REFS_JOIN,
    ),
    _Divergence(
        "aee-c-68 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _REFS_JOIN,
    ),
    _Divergence(
        "aee-c-22; aee-c-62 | codes: run-binding-mismatch",
        {
            "alsoCarries": ["sealed-record-absent"],
            "codes": ["run-binding-mismatch"],
            "verdict": "invalid",
        },
        _RUN_IDENTITY,
    ),
    _Divergence(
        "aee-c-75; aee-c-22 | codes: run-binding-mismatch",
        {
            "alsoCarries": ["sealed-record-absent"],
            "codes": ["run-binding-mismatch"],
            "verdict": "invalid",
        },
        _RUN_IDENTITY,
    ),
    # This family carries the splice-by-substitution vectors the corpus gained at
    # suiteRevision 26 alongside the direct posture/vocabulary splices: all carry
    # exactly what a spliced run binding carries -- verdict invalid under aee-c-22 --
    # so they are the same obstruction reached by a different edit.
    _Divergence(
        "aee-c-22; aee-c-60 | codes: run-binding-mismatch",
        {
            "alsoCarries": ["sealed-record-absent"],
            "codes": ["run-binding-mismatch"],
            "verdict": "invalid",
        },
        _RUN_IDENTITY,
    ),
    _Divergence(
        "aee-c-75 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _RUN_IDENTITY,
    ),
    # bad-609's substrate-digest shape from bad-608's runEntropy-digest shape, which
    # Kyverno's condition (14) already catches directly and which CUE alone declares.
    _Divergence(
        "aee-c-59 | codes: digest-not-canonical",
        {"codes": ["digest-not-canonical"], "verdict": "invalid"},
        _ANCHOR_DEFERRED_DIGEST,
        shape=_c59_substrate_digest_noncanonical,
    ),
    _Divergence(
        "aee-c-59; aee-c-60 | codes: subject-sha256-missing",
        {
            "alsoEmits": ["sealed-record-absent"],
            "codes": ["subject-sha256-missing"],
            "verdict": "invalid",
        },
        _OUTSIDE_CONTEXT,
    ),
    # armedAt-after-issuedAt, a missing posture digest, and a non-UTC armedAt offset:
    # all three compare the arming record against the document root, unlike their
    # payload-decodable siblings under the same reason, which CUE alone declares.
    _Divergence(
        "aee-c-63 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
        shape=_c63_arming_needs_root_reference,
    ),
    _Divergence(
        "aee-c-63; aee-c-65 | codes: arming-covers-nothing,sealed-covers-nothing,clean-row-uncovered",
        {
            "alsoEmits": ["sealed-record-absent"],
            "codes": [
                "arming-covers-nothing",
                "sealed-covers-nothing",
                "clean-row-uncovered",
            ],
            "verdict": "invalid",
        },
        _NO_ROOT_REFERENCE,
    ),
    # bad-710's shape (a referenced sealed record's posture digest mismatched
    # against the environment root) from its refs-join siblings under the identical
    # reason and answer: a non-boolean or false aeeStillArmed, a missing or
    # out-of-bound aeeDropCount, and a reconstructed method all resolve once the
    # right record is joined, which posture-digest equality does not.
    _Divergence(
        "aee-c-65 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
        shape=_c65_sealed_needs_root_reference,
    ),
    _Divergence(
        "aee-c-65 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _REFS_JOIN,
        shape=lambda s: not _c65_sealed_needs_root_reference(s),
    ),
    _Divergence(
        "aee-c-65 | codes: sealed-covers-nothing",
        {
            "alsoCarries": ["arming-covers-nothing"],
            "alsoEmits": ["sealed-record-absent"],
            "codes": ["sealed-covers-nothing"],
            "verdict": "invalid",
        },
        _NO_ROOT_REFERENCE,
    ),
    _Divergence(
        "aee-c-64; aee-c-65 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
    ),
    # bad-718 through bad-723 -- a zero run sequence, a missing, non-array or
    # unsorted chain scope, a non-hex previous binding -- from the closed-vocabulary
    # siblings bad-722 and bad-988, which CUE alone declares.
    _Divergence(
        "aee-c-89 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
        shape=_c89_arming_needs_root_reference,
    ),
    _Divergence(
        "aee-c-98 | codes: observed-attack-uncaught",
        {"codes": ["observed-attack-uncaught"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
        shape=_c98_no_interception_records,
    ),
    # bad-987's shape (an assessed attack the manifest never declares) from its
    # unsorted sibling bad-978, which CUE alone declares, and from a carried arming
    # record that omits aeeAssessedAttacks entirely, which is outside the rego
    # oracle's own scope too and needs no declaration on either rail.
    _Divergence(
        "aee-c-99 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
        shape=_c99_declares_undeclared_attack,
    ),
    # bad-998's shape (a second arming record comparing its own aeeAssessedAttacks
    # against the first's) from a single arming record whose one assessed attack
    # exceeds a still-simpler, already-reachable manifest comparison.
    _Divergence(
        "aee-c-99 | codes: assessed-set-exceeds-declaration",
        {"codes": ["assessed-set-exceeds-declaration"], "verdict": "invalid"},
        _NO_ROOT_REFERENCE,
        shape=_c99_multiple_arming_records,
    ),
    _Divergence(
        "aee-c-83 | codes: coverage-missing",
        {"codes": ["coverage-missing"], "verdict": "invalid"},
        _COVERAGE_ALGEBRA,
    ),
    _Divergence(
        "aee-c-82 | codes: coverage-incomplete",
        {"codes": ["coverage-incomplete"], "verdict": "invalid"},
        _COVERAGE_ALGEBRA,
        shape=_c82_coverage_needs_root_reference,
    ),
    # The sealed-record class faults, in the same refs-join family as bad-710's
    # siblings above: a missing aeeDropCount, a non-boolean aeeStillArmed, a missing
    # aeeStillArmed. Each carries a well-formed third sealed record no row
    # references, so the existential filter is satisfied by the spare record while
    # the one the row cites is still broken.
    _Divergence(
        "aee-c-64 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _REFS_JOIN,
    ),
)

# Corpus vectors the Kyverno rails DENY and the rego oracle ADMITS.
_KYVERNO_DENIES: tuple[_Divergence, ...] = (
    _Divergence(
        "aee-c-18 | codes: statement-malformed",
        {"codes": ["statement-malformed"], "verdict": "invalid"},
        _HARNESS_DECODER,
        shape=_has_lone_or_reversed_surrogate,
    ),
    # An unreferenced carried arming record omitting aeeArmedAt. The Kyverno armedAt
    # condition evaluates a JMESPath over the null field and errors ("Invalid type
    # for <nil>, expected string"), which Kyverno treats as a denial. The rego oracle
    # admits because it evaluates only referenced records and never sees this carried
    # one -- the same scope boundary that puts this vector on the rego rail's own
    # denylist. The sibling carried-record vectors carry their defect in sealed
    # records whose conditions tolerate a missing member, so only this one trips
    # this rail; they admit on both rails and need no declaration here.
    _Divergence(
        "aee-c-108 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _UNREF_ARMING_NULL_ARMEDAT,
    ),
)

# The CUE rail admits everything Kyverno admits, for the same reasons (the families
# above, unfiltered by any Kyverno-only shape), plus the plain predicate members the
# Kyverno rail reads and this rail does not, plus the record-payload family Kyverno
# reaches through parse_json and this rail does not. Those plain members are
# expressible in CUE and are not written into the policy body: see "What the
# Kyverno rail is for" in ../README.md for why that decision was scoped to the
# Kyverno rail. `subject` is a separate case, an unread member here and an
# unreachable one there, so its reason differs by rail. The corpus manifest is the
# same shape of case: this policy body never names `observationEnvironment.corpus`,
# so the declaration floor over its classes is a member it does not read rather than
# an expression it cannot write.
_CUE_ADMITS: tuple[_Divergence, ...] = (
    *_KYVERNO_ADMITS,
    _Divergence(
        "aee-c-24 | codes: batch-root-missing",
        {"codes": ["batch-root-missing"], "verdict": "invalid"},
        _UNREAD_MEMBER,
    ),
    _Divergence(
        "aee-c-48 | codes: clean-row-layer-not-none",
        {"codes": ["clean-row-layer-not-none"], "verdict": "invalid"},
        _UNREAD_MEMBER,
        shape=_c48_not_indirect_result,
    ),
    _Divergence(
        "aee-c-57 | codes: run-entropy-missing",
        {
            "alsoEmits": ["sealed-record-absent"],
            "codes": ["run-entropy-missing"],
            "verdict": "invalid",
        },
        _UNREAD_MEMBER,
    ),
    _Divergence(
        "aee-c-59 | codes: digest-not-canonical",
        {"codes": ["digest-not-canonical"], "verdict": "invalid"},
        _UNREAD_MEMBER,
    ),
    _Divergence(
        "aee-c-59; aee-c-60 | codes: subject-sha256-missing",
        {
            "alsoEmits": ["sealed-record-absent"],
            "codes": ["subject-sha256-missing"],
            "verdict": "invalid",
        },
        _UNREAD_MEMBER,
    ),
    _Divergence(
        "aee-c-92 | codes: corpus-manifest-no-attacks",
        {"codes": ["corpus-manifest-no-attacks"], "verdict": "invalid"},
        _UNREAD_MEMBER,
    ),
    _Divergence(
        "aee-c-2 | codes: result-recompute-mismatch",
        {"codes": ["result-recompute-mismatch"], "verdict": "invalid"},
        _RESULT_RECOMPUTE,
        shape=_c2_result_recompute_needs_root_reference,
    ),
    # The arming record class conditions denied by the Kyverno rail, which decodes
    # the payload with parse_json: a reconstructed method, an absent armedAt, and a
    # lowercase RFC 3339 separator or zone designator.
    _Divergence(
        "aee-c-63 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _CUE_NO_PAYLOAD,
        shape=lambda s: not _c63_arming_needs_root_reference(s),
    ),
    # The sealed-record class conditions, in the same family as the arming ones
    # above and denied by the Kyverno rail: a reconstructed method, a negative
    # aeeDropCount, a missing aeeDropCount, a non-boolean aeeStillArmed, drops with
    # no bound or past one.
    _Divergence(
        "aee-c-65 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _CUE_NO_PAYLOAD,
    ),
    _Divergence(
        "aee-c-64 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _CUE_NO_PAYLOAD,
    ),
    _Divergence(
        "aee-c-71 | codes: record-kind-unknown-covers-nothing",
        {"codes": ["record-kind-unknown-covers-nothing"], "verdict": "invalid"},
        _CUE_NO_PAYLOAD,
    ),
    # The unsorted sibling of the arming-assessed-attacks family Kyverno declares
    # for a different (root-reference) reason above.
    _Divergence(
        "aee-c-99 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _CUE_NO_PAYLOAD,
        shape=_c99_assessed_attacks_unsorted,
    ),
    # The two the Kyverno rail reaches through conditions (19) and (20). Both read
    # members INSIDE a base64 record payload, and this policy body never decodes
    # one. It could be made to under `cue vet`, which accepts an import -- and that
    # is exactly why it is not: the deployed rail is cosign's CompileString over a
    # policy STRING, and a check that passes this harness while being absent in the
    # cluster is a worse outcome than a declared gap.
    _Divergence(
        "aee-c-89 | codes: arming-covers-nothing",
        {"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        _CUE_NO_PAYLOAD,
        shape=lambda s: not _c89_arming_needs_root_reference(s),
    ),
    # The attribution axis, which the Kyverno rail now reads through its condition
    # (18) and this policy body still does not name anywhere. Recorded as an unread
    # member rather than dressed as an obstruction: `attribution` is a plain string
    # on a plain row, so this rail could ask the same existential question the
    # Kyverno rail asks, and the reason it does not is the same scoping decision
    # that left the other unread members above with this rail. The clean-row-layer
    # family above already covers the later row sharing its reason and answer.
    _Divergence(
        "aee-c-100 | codes: attribution-pinned-recordless",
        {"codes": ["attribution-pinned-recordless"], "verdict": "invalid"},
        _UNREAD_MEMBER,
    ),
)

_CUE_DENIES: tuple[_Divergence, ...] = (
    _Divergence(
        "aee-c-18 | codes: statement-malformed",
        {"codes": ["statement-malformed"], "verdict": "invalid"},
        _CUE_DECODER,
        shape=_has_lone_or_reversed_surrogate,
    ),
)


def _resolve_divergence(
    meta: dict[str, tuple[str, dict[str, Any], dict[str, Any]]],
    families: tuple[_Divergence, ...],
) -> dict[str, str]:
    """Vector name -> declared reason, for every vector a family's shape claims.

    A vector is claimed by the first family whose reason, expected answer and (if
    given) shape all match; over- and under-inclusion are not asserted here because
    `_check_declared` already compares the resolved set against what each rail
    actually decided on a live run and reports either drift on its own.
    """
    out: dict[str, str] = {}
    for name, (reason, expected, statement) in meta.items():
        for family in families:
            if family.reason != reason or family.expected != expected:
                continue
            if family.shape is not None and not family.shape(statement):
                continue
            out[name] = family.why
            break
    return out


def _vector_meta(
    corpus: dict[str, Any],
) -> dict[str, tuple[str, dict[str, Any], dict[str, Any]]]:
    """Every vector's own reason, expected answer and statement, keyed by name."""
    out: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {}
    for bucket in ("accept", "reject", "reject_denylisted"):
        for entry in _as_list(corpus[bucket], bucket):
            item = _as_dict(entry, "vector")
            name = _as_str(item["name"], "name")
            reason = item.get("reason")
            out[name] = (
                reason if isinstance(reason, str) else "",
                _as_dict(item["expected"], "expected"),
                _as_dict(item["statement"], "statement"),
            )
    return out


# ---------------------------------------------------------------------------
# Crafted cases
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One crafted statement with the verdict each rail family must return."""

    name: str
    statement: dict[str, Any]
    rego: bool
    kyverno: bool
    cue: bool
    why: str


def _mutate(statement: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(statement)


def _set_signatures(statement: dict[str, Any], value: object) -> dict[str, Any]:
    out = _mutate(statement)
    records = _as_list(out["predicate"]["observationRecords"], "observationRecords")
    _as_dict(records[0], "record")["signatures"] = value
    return out


def _edit_payload(
    statement: dict[str, Any], kind: str, edit: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    out = _mutate(statement)
    for raw in _as_list(out["predicate"]["observationRecords"], "observationRecords"):
        record = _as_dict(raw, "record")
        payload = _as_dict(
            json.loads(base64.b64decode(_as_str(record["payload"], "payload"))),
            "payload",
        )
        if payload.get("aeeKind") != kind:
            continue
        edit(payload)
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        record["payload"] = base64.b64encode(encoded.encode("utf-8")).decode("ascii")
    return out


def _negative_drop(payload: dict[str, Any]) -> None:
    payload["aeeDropCount"] = -1
    payload["aeeDropBound"] = 5


def _empty_refs(statement: dict[str, Any]) -> dict[str, Any]:
    """A passing statement whose only row cites nothing.

    The corpus carries a vector for this, but it also carries a failing result, so
    on a pass-only rail the result condition denies it first and the refs rule is
    never reached. Isolating it here is what makes the refs conjunct a measured
    constraint on both rails rather than an unexercised one.
    """
    out = _mutate(statement)
    for raw in _as_list(out["predicate"]["attackResults"], "attackResults"):
        _as_dict(raw, "row")["observationRefs"] = []
    return out


def _bad_posture_digest(statement: dict[str, Any]) -> dict[str, Any]:
    out = _mutate(statement)
    env = _as_dict(out["predicate"]["observationEnvironment"], "env")
    _as_dict(_as_dict(env["networkPosture"], "posture")["digest"], "digest")[
        "sha256"
    ] = "NOT-A-DIGEST"
    return out


def _with_issued_at(statement: dict[str, Any], moment: str | None) -> dict[str, Any]:
    out = _mutate(statement)
    if moment is None:
        out["predicate"].pop("issuedAt", None)
    else:
        out["predicate"]["issuedAt"] = moment
    return out


def _with_armed_at(statement: dict[str, Any], moment: str) -> dict[str, Any]:
    """Move the substrate-signed instant every freshness bound is measured against.

    Editing the payload is what an attacker cannot do, which is the point of these
    cases: the harness re-encodes the record because it is building a fixture, while
    the party the policy models holds only the envelope key and would have to leave
    this value exactly where the substrate put it.
    """
    return _edit_payload(
        statement, "arming", lambda p: p.__setitem__("armedAt", moment)
    )


def _without_arming_records(statement: dict[str, Any]) -> dict[str, Any]:
    """Drop every arming record, leaving no substrate-signed instant to measure."""
    out = _mutate(statement)
    records = _as_list(out["predicate"]["observationRecords"], "observationRecords")
    out["predicate"]["observationRecords"] = [
        record
        for record in records
        if _as_dict(
            json.loads(
                base64.b64decode(_as_str(_as_dict(record, "r")["payload"], "p"))
            ),
            "payload",
        ).get("aeeKind")
        != "arming"
    ]
    return out


def _rfc3339(delta: timedelta) -> str:
    return (datetime.now(tz=UTC) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_cases(base: dict[str, Any]) -> list[Case]:
    """The crafted statements, each pinning one behavior the corpus cannot reach."""
    return [
        Case(
            "baseline-unmutated",
            _mutate(base),
            rego=True,
            kyverno=True,
            cue=True,
            why="the control: every rail admits the unmutated base, so a rail that "
            "denies everything cannot pass this gate by denying the mutants too",
        ),
        Case(
            "signatures-is-a-string",
            _set_signatures(base, "x"),
            rego=False,
            kyverno=False,
            cue=False,
            why="JMESPath length() counts a string, so without a type guard on the "
            "signature filter one string reads as one signature present",
        ),
        Case(
            "signatures-is-an-object",
            _set_signatures(base, {"a": 1}),
            rego=False,
            kyverno=False,
            cue=False,
            why="the same hole in its object spelling",
        ),
        Case(
            "sealed-record-drop-count-negative",
            _edit_payload(base, "sealed", _negative_drop),
            rego=False,
            kyverno=False,
            cue=True,
            why="a negative drop count satisfies an upper bound on its own, so the "
            "bounded arm needs a lower bound as well; CUE reads no record payload "
            "and admits it, which is the declared shape of that rail",
        ),
        Case(
            "row-observation-refs-empty",
            _empty_refs(base),
            rego=False,
            kyverno=False,
            cue=False,
            why="the non-empty observationRefs requirement, which is the one piece "
            "of the spec's coverage validity rule the CUE rail can express and is "
            "otherwise reached by no passing vector",
        ),
        Case(
            "network-posture-digest-malformed",
            _bad_posture_digest(base),
            rego=False,
            kyverno=False,
            cue=False,
            why="the posture-digest binding, which the freshness variant had dropped "
            "while claiming to extend the policy that carries it",
        ),
        Case(
            "issuance-lag-far-beyond-the-bound",
            _with_issued_at(base, "2099-01-01T00:00:00Z"),
            rego=True,
            kyverno=False,
            cue=True,
            why="the byte-pure issuance-lag bound, condition (16). Every published "
            "vector carries a lag of at most a few hours, so the corpus cannot "
            "distinguish a rail that enforces the bound from one that does not, and "
            "without this case the condition would ride along unexercised. The rego "
            "rail admits because its equivalent bound is a consumer pin this run "
            "leaves unset, and CUE admits because it decodes no record payload and "
            "so cannot reach armedAt at all",
        ),
    ]


def freshness_cases(base: dict[str, Any]) -> list[tuple[str, dict[str, Any], bool]]:
    """Timestamps for the evidence-age condition the corpus cannot exercise.

    The corpus fixes its timestamps in the past, so every vector would read as stale
    and the comparison would measure the calendar rather than the policy. That is why
    the condition is lifted out of the corpus run and driven here instead, and why
    these statements carry timestamps computed relative to now.

    Every case moves `armedAt`, because that is the operand the condition reads. The
    cases that move `issuedAt` are still here and their expectations are now the
    opposite of what they used to be: they pin that the producer-asserted field no
    longer decides anything, which is the defect this condition was rewritten to close.
    """
    stale = "2025-12-31T23:59:00Z"
    return [
        (
            "freshness-armed-recent",
            _with_armed_at(base, _rfc3339(timedelta(hours=-1))),
            True,
        ),
        (
            "freshness-armed-stale",
            _with_armed_at(base, _rfc3339(timedelta(hours=-200))),
            False,
        ),
        # No arming record means no substrate-signed instant, so there is nothing this
        # bound can honestly be measured against. It denies rather than falling back to
        # `issuedAt`, and it denies rather than passing vacuously on an empty filter.
        ("freshness-no-arming-record", _without_arming_records(base), False),
        # The attack, promoted from a fuzzer mutation to a declared expectation. The
        # run was armed years ago and the statement claims to have been issued minutes
        # ago, which is what a party holding the envelope key produces for free. The
        # window this file used to carry admitted it; measured against the signed
        # instant it is denied, and this case is the regression test for that.
        (
            "freshness-restated-old-run",
            _with_issued_at(
                _with_armed_at(base, stale), _rfc3339(timedelta(minutes=-5))
            ),
            False,
        ),
        # The same edit on a genuinely recent run is still admitted, so the denial above
        # is attributable to the age of the run and not to the restatement itself.
        (
            "freshness-restated-recent-run",
            _with_issued_at(
                _with_armed_at(base, _rfc3339(timedelta(hours=-1))),
                _rfc3339(timedelta(minutes=-5)),
            ),
            True,
        ),
        # `issuedAt` in the far future no longer buys freshness. Under the shipped
        # window this single edit admitted any statement forever.
        (
            "freshness-issuedat-future-run-stale",
            _with_issued_at(_with_armed_at(base, stale), "2099-01-01T00:00:00Z"),
            False,
        ),
        # ...and an absent `issuedAt` no longer denies, because this condition does not
        # read the field at all any more. The fail-closed direction moved to the arming
        # record, where the thing being measured actually lives.
        (
            "freshness-issuedat-absent-run-recent",
            _with_issued_at(_with_armed_at(base, _rfc3339(timedelta(hours=-1))), None),
            True,
        ),
    ]


def anchor_cases(base: dict[str, Any]) -> list[tuple[str, str, str, bool]]:
    """Corpus and substrate pins: matched, mismatched, and left unedited."""
    env = _as_dict(base["predicate"]["observationEnvironment"], "env")
    corpus = _as_str(
        _as_dict(_as_dict(env["corpus"], "corpus")["digest"], "digest")["sha256"],
        "corpus digest",
    )
    substrate = _as_str(
        _as_dict(_as_dict(env["substrate"], "substrate")["digest"], "digest")["sha256"],
        "substrate digest",
    )
    wrong = "0" * 64
    return [
        ("anchors-pinned-and-matching", corpus, substrate, True),
        ("anchors-pinned-corpus-mismatch", wrong, substrate, False),
        ("anchors-pinned-substrate-mismatch", corpus, wrong, False),
        (
            "anchors-left-unedited",
            _ANCHOR_PLACEHOLDER + "CORPUS",
            _ANCHOR_PLACEHOLDER + "SUBSTRATE",
            False,
        ),
    ]


def _corpus_vectors(corpus: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    out: list[tuple[str, str, dict[str, Any]]] = []
    for bucket in ("accept", "reject", "reject_denylisted"):
        for entry in _as_list(corpus[bucket], bucket):
            item = _as_dict(entry, "vector")
            out.append(
                (
                    bucket,
                    _as_str(item["name"], "name"),
                    _as_dict(item["statement"], "s"),
                )
            )
    return out


@dataclass
class Rig:
    kyverno: str
    cue: str
    opa: str
    workdir: Path
    pins: Path
    cue_policy: Path
    policies: list[KyvernoPolicy]
    cel: CelPolicy
    cel_policy: Path


def _build_rig(workdir: Path) -> Rig:
    pins = workdir / "unpinned.json"
    # The oracle runs as an explicitly unpinned consumer on both consumer-pin
    # families. The corpus vectors carry their own corpus and substrate digests and
    # their own manifests, so there is no single context or class name to demand
    # across them, and a value read out of the vector under test would assert
    # nothing. Both declines are made out loud here for the same reason a deployment
    # has to make them out loud: the shipped default on either is deny.
    #
    # The admission THRESHOLD is deliberately left unstated, because its absent value
    # is the spec's own default and the strict end of its range: `result == "pass"`
    # alone. That is the posture the Kyverno and CUE rails carry as a literal, so the
    # oracle and the rails being measured against it are compared at the same
    # threshold. Relaxing it is a separate declaration and appears only where the
    # row-provenance divergence is measured, below.
    pins.write_text(
        json.dumps(
            {"consumer": {"allow_unpinned_anchors": True, "allow_unpinned_scope": True}}
        ),
        encoding="utf-8",
    )
    cue_policy = workdir / "policy-corpus.cue"
    cue_policy.write_text(cue_source(drop_anchors=True), encoding="utf-8")
    policies = [
        _read_policy(p, corpus_mode=True)
        for p in sorted(_KYVERNO_DIR.glob("clusterpolicy-*.yaml"))
    ]
    cel = _read_ivp(_IVP_POLICY)
    # The suffix is load-bearing, not cosmetic: see the note in `cel_verdict`.
    cel_policy = workdir / "policy-cel.yaml"
    cel_policy.write_text(json.dumps(cel_document(cel)), encoding="utf-8")
    return Rig(
        kyverno=_kyverno_binary(),
        cue=_tool("CUE_BIN", "cue"),
        opa=_tool("OPA_BIN", "opa"),
        workdir=workdir,
        pins=pins,
        cue_policy=cue_policy,
        policies=policies,
        cel=cel,
        cel_policy=cel_policy,
    )


def _reject_repeated_names(items: list[tuple[str, dict[str, Any]]]) -> None:
    """Refuse a batch whose items do not carry distinct names.

    Each worker names the fixtures it writes after the item it was handed, so two
    items sharing a name put two threads on the same paths, and one unlinks what the
    other is about to read. That is the collision two whole invocations used to have
    through a shared directory, one level down, and it presents the same misleading
    way: vectors reporting that a file does not exist, which invites the reader to
    doubt the corpus. Distinct names are a property of the corpus rather than of this
    driver, so they are asserted here rather than assumed.
    """
    repeated = sorted(
        name for name, count in Counter(name for name, _ in items).items() if count > 1
    )
    if repeated:
        raise SystemExit(
            f"this batch carries repeated names {repeated}. Every worker names its "
            f"fixtures after the item it is given, so these would race on the same "
            f"paths and report each other's files as missing."
        )


def _run_all(
    rig: Rig, items: list[tuple[str, dict[str, Any]]], jobs: int
) -> dict[str, dict[str, Verdict]]:
    _reject_repeated_names(items)
    rails = [p.name for p in rig.policies] + ["cue", "cel", "rego"]
    results: dict[str, dict[str, Verdict]] = {r: {} for r in rails}
    undecodable: dict[str, str] = {}

    def work(item: tuple[str, dict[str, Any]]) -> None:
        name, statement = item
        predicate = statement.get("predicate")
        path = rig.workdir / f"kyv-{name}.json"
        payload = kyverno_input(predicate) if isinstance(predicate, dict) else {}
        path.write_text(json.dumps(payload), encoding="utf-8")
        complaint = kyverno_decodable(rig.kyverno, path)
        if complaint is not None:
            undecodable[name] = complaint
        for policy in rig.policies:
            results[policy.name][name] = kyverno_verdict(
                rig.kyverno, policy, statement, path
            )
        path.unlink(missing_ok=True)
        results["cue"][name] = cue_verdict(
            rig.cue, rig.cue_policy, statement, rig.workdir, name
        )
        results["cel"][name] = cel_verdict(
            rig.kyverno, rig.cel_policy, statement, rig.workdir, name
        )
        results["rego"][name] = rego_verdict(
            rig.opa, rig.pins, statement, rig.workdir, name
        )

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(work, items))
    results["_undecodable"] = {k: (False, v) for k, v in undecodable.items()}
    return results


def _print_measurement(
    results: dict[str, dict[str, Verdict]], buckets: dict[str, str]
) -> None:
    for rail, verdicts in results.items():
        if rail.startswith("_") or rail == "rego":
            continue
        print("\n" + "=" * 74 + f"\n{rail}")
        for direction, want in (
            ("RAIL ADMITS, ORACLE DENIES", True),
            ("ORACLE ADMITS, RAIL DENIES", False),
        ):
            names = [
                n
                for n, (ok, _) in verdicts.items()
                if ok is want and results["rego"][n][0] is not want
            ]
            print(f" {direction} ({len(names)}):")
            for name in sorted(names):
                print(f'    "{name}": "",  # {buckets[name]}')
    undecodable = results.get("_undecodable", {})
    if undecodable:
        print("\nKyverno command line tool could not decode the input for:")
        for name in sorted(undecodable):
            print(f"    {name}")


def _check_declared(
    rail: str,
    verdicts: dict[str, Verdict],
    oracle: dict[str, Verdict],
    admits: dict[str, str],
    denies: dict[str, str],
) -> list[str]:
    problems: list[str] = []
    seen_admits: set[str] = set()
    seen_denies: set[str] = set()
    for name, (ok, why) in verdicts.items():
        expected = oracle[name][0]
        if ok == expected:
            continue
        if ok and name in admits:
            seen_admits.add(name)
        elif not ok and name in denies:
            seen_denies.add(name)
        elif ok:
            problems.append(
                f"{rail}: ADMITS {name}, which the rego oracle denies, and it is not "
                f"declared. Either the policy lost a check or the vector belongs in "
                f"the declared set with a reason."
            )
        else:
            problems.append(
                f"{rail}: DENIES {name}, which the rego oracle admits, and it is not "
                f"declared. Reason given: {why}"
            )
    for name in sorted(set(admits) - seen_admits):
        problems.append(
            f"{rail}: {name} is declared as admitted past the oracle but the rail now "
            f"denies it. The rail gained power; drop the declaration."
        )
    for name in sorted(set(denies) - seen_denies):
        problems.append(
            f"{rail}: {name} is declared as denied against the oracle but the rail now "
            f"admits it. Drop the declaration."
        )
    return problems


def _check_lockstep(
    results: dict[str, dict[str, Verdict]], policies: list[KyvernoPolicy]
) -> list[str]:
    problems: list[str] = []
    if len(policies) < 2:
        return problems
    reference = policies[0].name
    for policy in policies[1:]:
        for name, (ok, why) in results[policy.name].items():
            if ok != results[reference][name][0]:
                problems.append(
                    f"{policy.name} and {reference} disagree on {name}: "
                    f"{'admit' if ok else 'deny'} against "
                    f"{'admit' if results[reference][name][0] else 'deny'}. "
                    f"The three Kyverno documents are meant to carry the same "
                    f"conditions. Reason given: {why}"
                )
    return problems


def _check_condition_parity(policies: list[KyvernoPolicy]) -> list[str]:
    """The three Kyverno documents must carry the same conditions.

    The corpus catches a condition that changes what a rail decides about a
    published vector. It cannot catch one that goes missing from a single sibling
    when no vector exercises it, and that is the shape of the defect the freshness
    variant carried: it dropped the posture-digest binding, and because every corpus
    vector carries a well-formed posture digest, all three documents went on agreeing
    on every one of them. Comparing the condition sets directly is what closes it,
    and it costs nothing to run.
    """
    problems: list[str] = []
    reference = policies[0]
    for policy in policies[1:]:
        if policy.parity == reference.parity:
            continue
        missing = [c for c in reference.parity if c not in policy.parity]
        extra = [c for c in policy.parity if c not in reference.parity]
        detail = "; ".join(
            [f"absent from {policy.name}: {c}" for c in missing]
            + [f"only in {policy.name}: {c}" for c in extra]
        )
        problems.append(
            f"{policy.name} does not carry the same conditions as {reference.name}. "
            f"Beyond its freshness window these documents are meant to be the same "
            f"policy. {detail}"
        )
    return problems


# The fields OUTSIDE `conditions` that decide what the rail is and whom it trusts.
#
# The parity check above compares condition sets and nothing else, and the corpus run
# reaches only what a JMESPath engine evaluates, so none of these fields is measured
# by either. That is the same shape as the defect the parity check was written for,
# one level up, and it is not hypothetical: the audit variant already differs from
# its siblings in `mutateDigest`, which nothing here noticed and whose header claimed
# the two documents were identical. A public key quietly replaced, `required` flipped
# to false so an image carrying no attestation at all is admitted, an attestor count
# of zero, or `failurePolicy: Ignore` so a webhook outage admits the fleet would each
# pass every other check in this file unchanged, and the first of those is the whole
# trust decision on this rail.
_EXPECTED_ATTESTATION_TYPE = (
    "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
)
_PUBLISHED_KEY = (
    _ADMISSION / "keys" / "observation-key.pub"
)
# Per document: the enforcement action, and whether the rule pins the image to its
# digest form. The audit variant does not, because rewriting the image reference of a
# Pod it is not blocking would mutate a resource it only reports on.
_EXPECTED_ENFORCEMENT: dict[str, tuple[str, bool]] = {
    "clusterpolicy-adversarial-execution-evidence.yaml": ("Enforce", True),
    "clusterpolicy-adversarial-execution-evidence-audit.yaml": ("Audit", False),
    "clusterpolicy-adversarial-execution-evidence-freshness.yaml": ("Enforce", True),
}


def _pem_lines(value: object) -> tuple[str, ...] | None:
    """A PEM block reduced to its non-empty lines, so indentation cannot mask a swap."""
    if not isinstance(value, str):
        return None
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def _policy_facts(path: Path) -> dict[str, object]:
    doc = _load_manifest(path)
    spec = _as_dict(doc["spec"], "spec")
    rule = _as_dict(_as_list(spec["rules"], "rules")[0], "rule")
    verify = _as_dict(_as_list(rule["verifyImages"], "verifyImages")[0], "verifyImages")
    att = _as_dict(_as_list(verify["attestations"], "attestations")[0], "attestation")
    attestor = _as_dict(_as_list(att["attestors"], "attestors")[0], "attestor")
    entry = _as_dict(_as_list(attestor["entries"], "entries")[0], "entry")
    return {
        "spec.failurePolicy": spec.get("failurePolicy"),
        "verifyImages.required": verify.get("required"),
        "verifyImages.imageReferences": verify.get("imageReferences"),
        "verifyImages.failureAction": verify.get("failureAction"),
        "verifyImages.mutateDigest": verify.get("mutateDigest"),
        "attestation.type": att.get("type"),
        "attestor.count": attestor.get("count"),
        "attestor.publicKeys": _pem_lines(
            _as_dict(entry["keys"], "keys").get("publicKeys")
        ),
    }


def _expected_facts(name: str) -> dict[str, object]:
    action, mutate = _EXPECTED_ENFORCEMENT[name]
    return {
        "spec.failurePolicy": "Fail",
        "verifyImages.required": True,
        "verifyImages.imageReferences": ["*"],
        "verifyImages.failureAction": action,
        "verifyImages.mutateDigest": mutate,
        "attestation.type": _EXPECTED_ATTESTATION_TYPE,
        "attestor.count": 1,
        "attestor.publicKeys": _pem_lines(_PUBLISHED_KEY.read_text(encoding="utf-8")),
    }


def _check_policy_invariants(paths: list[Path]) -> list[str]:
    problems: list[str] = []
    for path in paths:
        if path.name not in _EXPECTED_ENFORCEMENT:
            problems.append(
                f"{path.name} is a Kyverno document this gate has no expectation for. "
                f"Add it to the enforcement table, or the fields outside its "
                f"conditions are enforced by nothing."
            )
            continue
        facts = _policy_facts(path)
        for name, want in _expected_facts(path.name).items():
            if not _same_json(facts[name], want):
                problems.append(
                    f"{path.name}: {name} is {facts[name]!r}, expected {want!r}. "
                    f"No condition and no corpus vector reads this field, so nothing "
                    f"else in this gate would have said so."
                )
    return problems


# The three rails' admit totals over the whole projected corpus.
#
# WHY A DECLARATION AND NOT ONLY A PRINTED LINE. Three of the figures the deployment
# guide publishes come from executing three engines over every vector, which takes
# minutes and needs the `kyverno`, `cue` and `opa` binaries. A cheap prose gate cannot
# pay that on every push, and a figure nobody compares against is the hand-typed cache
# that put nineteen wrong numbers in the guide in the first place. So the totals are
# written down HERE, next to the run that measures them, and asserted below: this file
# is the committed measurement, and `scripts/lint_admission_counts.py` reads these
# three integers rather than re-deriving them. The measurement half runs wherever this
# driver runs, which is every push through `.github/workflows/admission-policy-
# conformance.yml`; the prose half runs on the cheap gate. Neither is guessed.
#
# Only the ORACLE's total is independent. The other two are forced by it and by the
# declared divergence tables above -- a Kyverno total is the oracle's total plus the
# vectors this rail admits past it, minus the ones it denies past it -- and the arithmetic
# is asserted below beside the measurement, so a table edited without a rerun cannot
# leave a total standing.
# Corpus vectors the CEL rail ADMITS and the rego oracle DENIES.
#
# THE SET IS EMPTY, AND THAT IS THE MEASUREMENT THIS RAIL EXISTS TO REPORT. The
# JMESPath bundle declares thirty-five, every one of them a rule that path cannot
# express. Ported to CEL, all thirty-five close: the refs join is native list
# indexing, the result recompute and the coverage partition are ordinary set algebra,
# the posture-digest equalities needed only a document-root reference that policy
# variables supply, the record payloads open with `base64.decode` + `json.unmarshal`,
# and the run-identity recompute -- which no other rail here can attempt at all --
# reproduces byte for byte with `hash.sha256` over `json.marshal`, whose object output
# is key-sorted and therefore RFC 8785 for this corpus's ASCII profile.
#
# An empty declaration is asserted for equality exactly as a populated one is, so a
# CEL rail that LOSES power over any vector fails this gate loudly.
_CEL_ADMITS: tuple[_Divergence, ...] = ()

# Corpus vectors the CEL rail DENIES and the rego oracle ADMITS. The same family the
# JMESPath rail declares, in the same layer and for the same reason, but the reason is
# spelled separately rather than shared. Two rails citing one constant would put the
# same sentence on two rows of the divergence table, and the count gate beside this
# driver mutates a declaration line to prove the case it asserts can fail -- a
# duplicated line makes that mutation ambiguous and the case would assert nothing.
_CEL_TOOL_DECODER = (
    "the Kyverno command line tool's JSON reader refuses the escape before any CEL "
    "runs, so this denial belongs to the harness rather than to the deployed rail, "
    "which is handed a statement cosign has already decoded. Recorded as a divergence "
    "rather than claimed as a rail strength"
)
_CEL_DENIES: tuple[_Divergence, ...] = (
    _Divergence(
        "aee-c-18 | codes: statement-malformed",
        {"codes": ["statement-malformed"], "verdict": "invalid"},
        _CEL_TOOL_DECODER,
        shape=_has_lone_or_reversed_surrogate,
    ),
    # An unreferenced carried sealed record whose aeePostureDigest is not the pinned
    # network posture digest. The CEL posture condition reads that digest and denies;
    # the rego oracle admits because it evaluates only referenced records and never
    # sees this carried one -- the same scope boundary that puts this vector on the
    # rego rail's own denylist. Thirteen siblings under the identical reason and
    # answer carry a different member fault each and are outside this declaration.
    _Divergence(
        "aee-c-108 | codes: sealed-covers-nothing",
        {"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        _UNREF_SEALED_POSTURE,
        shape=_unreferenced_sealed_posture_mismatch,
    ),
)

# Corrected 2026-08-04 from a real run, never by hand: the corpus gained sixteen
# unreferenced-carried-record rejects (bad-1001..1016), which every rail admits except
# where a single condition trips -- Kyverno denies bad-1015 on a null aeeArmedAt and CEL
# denies bad-1006 on a non-pinned aeePostureDigest, both declared above. So rego, cue
# gain all sixteen and kyverno, cel gain fifteen. Measured locally with
# `python3 run_policy_conformance.py` and independently by CI.
#
# Corrected 2026-08-26 from a real run, never by hand: the corpus moved to
# suiteRevision 26 and gained eight vectors, six of which every rail admits. The two
# that divide the rails are the splices declared above, which the oracle denies and
# the JMESPath and CUE rails cannot reach.
_MEASURED_ADMITS: dict[str, int] = {
    "rego": 62,
    "kyverno": 98,
    "cue": 116,
    "cel": 58,
}


def _check_measured_admits(
    measured: dict[str, int],
    resolved: dict[str, tuple[dict[str, str], dict[str, str]]],
) -> list[str]:
    """The declared admit totals are this run's, and the two derived ones add up.

    ``resolved`` carries each rail's admits/denies dicts as `_resolve_divergence`
    produced them for THIS run, so the arithmetic below is checked against vectors
    the corpus actually offers this run rather than a family count that says nothing
    about how many vectors matched it.
    """
    problems: list[str] = []
    for rail, want in _MEASURED_ADMITS.items():
        got = measured[rail]
        if got != want:
            problems.append(
                f"_MEASURED_ADMITS declares {rail} admits {want} and this run measured "
                f"{got}. The declaration is what the deployment guide's rail table is "
                f"checked against, so it is corrected from the measurement and never "
                f"the other way round."
            )
    oracle = _MEASURED_ADMITS["rego"]
    for rail, (admits, denies) in resolved.items():
        implied = oracle + len(admits) - len(denies)
        if implied != _MEASURED_ADMITS[rail]:
            problems.append(
                f"_MEASURED_ADMITS says {rail} admits {_MEASURED_ADMITS[rail]}, and the "
                f"oracle's {oracle} plus its {len(admits)} resolved admits minus its "
                f"{len(denies)} resolved denies is {implied}. A rail's total is not an "
                f"independent quantity; if these disagree one of the two was typed."
            )
    return problems


def _check_cel_deferrals(policy: CelPolicy) -> list[str]:
    """The CEL rail lifts exactly three families out of the corpus run.

    Same discipline as `_check_deferrals` next door. A validation silently leaving one
    of these families -- an anchor that stopped being a placeholder, a freshness bound
    that lost its clock call -- would be driven through the corpus and measure the
    literal rather than the policy, or would vanish from the count entirely. Neither
    is allowed to happen quietly.
    """
    problems: list[str] = []
    expected = {"registry": 2, "anchor": 2, "freshness": 1}
    for family, want in expected.items():
        got = policy.deferred.get(family, 0)
        if got != want:
            problems.append(
                f"{policy.name} defers {got} {family} validation(s), expected {want}. "
                f"A deferral that appeared is a check no longer measured; one that "
                f"vanished is a placeholder now being driven through the corpus."
            )
    if not policy.validations:
        problems.append(
            f"{policy.name} contributed no corpus-driven validations at all, so this "
            f"rail would admit every vector and report agreement it never tested."
        )
    return problems


def _check_deferrals(policies: list[KyvernoPolicy]) -> list[str]:
    problems: list[str] = []
    for policy in policies:
        anchors = policy.deferred.get("anchor", 0)
        if anchors != 2:
            problems.append(
                f"{policy.name} carries {anchors} anchor conditions, expected the "
                f"corpus and substrate pins. A pin that stopped being a placeholder "
                f"is now silently driven through the corpus."
            )
        fresh = policy.deferred.get("freshness", 0)
        expected_fresh = 1 if "freshness" in policy.name else 0
        if fresh != expected_fresh:
            problems.append(
                f"{policy.name} carries {fresh} freshness conditions, expected "
                f"{expected_fresh}."
            )
    return problems


def _run_cases(rig: Rig, cases: list[Case]) -> list[str]:
    items = [(c.name, c.statement) for c in cases]
    results = _run_all(rig, items, jobs=4)
    problems: list[str] = []
    for case in cases:
        for policy in rig.policies:
            got = results[policy.name][case.name]
            if got[0] != case.kyverno:
                problems.append(
                    f"{policy.name}: crafted case {case.name} expected "
                    f"{'admit' if case.kyverno else 'deny'}, got "
                    f"{'admit' if got[0] else 'deny'} ({got[1]}). {case.why}"
                )
        for rail, want in (("cue", case.cue), ("rego", case.rego)):
            got = results[rail][case.name]
            if got[0] != want:
                problems.append(
                    f"{rail}: crafted case {case.name} expected "
                    f"{'admit' if want else 'deny'}, got "
                    f"{'admit' if got[0] else 'deny'} ({got[1]}). {case.why}"
                )
    return problems


def _run_freshness(rig: Rig, base: dict[str, Any]) -> list[str]:
    policy = _read_policy(
        _KYVERNO_DIR / "clusterpolicy-adversarial-execution-evidence-freshness.yaml",
        corpus_mode=False,
    )
    only_fresh = KyvernoPolicy(
        name=policy.name,
        attestation_type=policy.attestation_type,
        slots=tuple(s for s in policy.slots if _FRESHNESS_MARKER in s.key_expr),
    )
    if len(only_fresh.slots) != 1:
        return [
            "the freshness policy no longer carries exactly one freshness condition"
        ]
    problems: list[str] = []
    for name, statement, want in freshness_cases(base):
        predicate = _as_dict(statement["predicate"], "predicate")
        path = rig.workdir / f"fresh-{name}.json"
        path.write_text(json.dumps(kyverno_input(predicate)), encoding="utf-8")
        got = kyverno_verdict(rig.kyverno, only_fresh, statement, path)
        path.unlink(missing_ok=True)
        if got[0] != want:
            problems.append(
                f"freshness condition: {name} expected "
                f"{'admit' if want else 'deny'}, got "
                f"{'admit' if got[0] else 'deny'} ({got[1]})"
            )
    return problems


# The published accepts whose clean row is not a live interception. Under the default
# consumer policy the rego rail denies each, exactly as these rails do. Under the
# consumer opt-in the rego rail admits them and these rails still deny them, because
# neither has a consumer data document to opt in with.
#
# THE PIN IS FORCED AGAINST THE MEASURED SET, and once it was not. The rego suite
# derives the same set from the corpus and pins its size
# (test_unintercepted_clean_set_is_the_pinned_size), which is what caught the two
# indirect accepts the corpus gained; this list stood at three names with nothing
# forcing it, so those two were never carried through the opt-in on this side and a
# future one would be missed the same way. A pin nobody compares
# against is a pin that only shrinks. _measured_unintercepted_clean below derives it,
# _run_provenance_divergence iterates the DERIVED set rather than this one so a new
# vector is measured on the run that introduces it, and the disagreement is reported as
# a problem so the list is brought back rather than left behind.
#
# It was a list of five authoring slugs until suiteRevision 28 renamed every vector,
# at which point it matched nothing and the comparison below reported a drift that was
# entirely the pin's own. What the pin is FOR survives the rename: it is the ratchet
# that makes a corpus gaining or losing one of these shapes reddens rather than quietly
# changing what the default posture is proven against. That is a statement about how
# MANY there are, so it is pinned as a count -- the derived set still supplies the
# names, and a derivation that stopped selecting anything is exactly what the count
# catches.
_UNINTERCEPTED_CLEAN_COUNT = 5


def _measured_unintercepted_clean(corpus: dict[str, Any]) -> tuple[str, ...]:
    """The accepts the recompute floors at pass_indirect and rego fully vouches for.

    Same derivation as the rego suite's `_sound_indirect_accepts`: an accept the rego
    rail can evaluate end to end (`regoSound`) whose published result is
    `pass_indirect` is, by the recompute's own definition, a statement carrying a clean
    row that is not a live interception.
    """
    return tuple(
        sorted(
            _as_str(_as_dict(entry, "vector")["name"], "name")
            for entry in _as_list(corpus["accept"], "accept")
            if _as_dict(entry, "vector").get("regoSound") is True
            and _as_dict(_as_dict(entry, "vector")["expected"], "expected").get(
                "result"
            )
            == "pass_indirect"
        )
    )


def _base_statement(
    corpus: dict[str, Any], statements: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """The one accept the crafted fixtures perturb, resolved through the projection.

    Refuses unless exactly one accept forces the declared conditions and expects the
    declared answer. Both halves are the manifest's own answer-neutral fields, carried
    into the projection by the generator, so this survives a corpus re-layout that
    moves every file and renames every vector.
    """
    want = "; ".join(_BASE_CONDITIONS)
    hits = [
        _as_str(_as_dict(entry, "vector")["name"], "name")
        for entry in _as_list(corpus["accept"], "accept")
        if _as_dict(entry, "vector").get("reason") == want
        and _as_dict(entry, "vector").get("expected") == _BASE_EXPECTED
    ]
    if len(hits) != 1:
        raise PolicyError(
            f"the crafted fixtures rest on the accept forcing {want} and expecting "
            f"{json.dumps(_BASE_EXPECTED, sort_keys=True)}, and the corpus offers "
            f"{len(hits)} of them ({', '.join(sorted(hits)) or 'NONE'}). Every anchor, "
            f"freshness and case fixture is built by perturbing it, so a run that "
            f"guessed at a substitute would measure a different statement than the one "
            f"these cases were written against."
        )
    return statements[hits[0]]


def _run_provenance_divergence(
    rig: Rig,
    corpus: dict[str, Any],
    statements: dict[str, dict[str, Any]],
    results: dict[str, dict[str, Verdict]],
) -> list[str]:
    """Measure where the row-provenance gates actually part company.

    The gate the Kyverno and CUE rails apply is scoped to every row, while the spec
    and the rego rail scope it to clean rows. That reads like a divergence and it is
    one, but it is NOT reachable under the default consumer policy: on a passing
    statement the rego rail has already run the result recompute, so every row it
    admits is clean, and its clean-row gate then demands the same substrate and
    intercepted pair. The difference appears only once a consumer sets the opt-in
    the rego rail offers and these two rails have no equivalent of. That is what is
    measured here, so the divergence recorded in the four policy files is a
    measurement rather than a reading of the expressions.

    The rego opt-in is TWO declarations rather than one. `accepted_results` is the
    admission threshold and `admit_unintercepted_clean_rows` is the clean-row
    provenance obligation, and the module denies a consumer document that states only
    one of them: the spec requires a policy relaxed to admit `pass_indirect` to keep
    keying on each clean row's basis and method, which a single flag doing both jobs
    could not express. Both are written here for that reason, and the Kyverno and CUE
    rails have neither, which is exactly the divergence being measured.
    """
    opt_in = rig.workdir / "opt-in.json"
    opt_in.write_text(
        json.dumps(
            {
                "consumer": {
                    "allow_unpinned_anchors": True,
                    "allow_unpinned_scope": True,
                    "accepted_results": ["pass", "pass_indirect"],
                    "admit_unintercepted_clean_rows": True,
                }
            }
        ),
        encoding="utf-8",
    )
    problems: list[str] = []
    measured = _measured_unintercepted_clean(corpus)
    if len(measured) != _UNINTERCEPTED_CLEAN_COUNT:
        problems.append(
            f"_UNINTERCEPTED_CLEAN_COUNT is {_UNINTERCEPTED_CLEAN_COUNT} and the "
            f"corpus measures {len(measured)} ({', '.join(measured) or 'NONE'}). The "
            f"count is the ratchet, exactly as the rego suite's "
            f"test_unintercepted_clean_set_is_the_pinned_size forces on its side; the "
            f"vectors below were measured from the corpus, so nothing went unchecked, "
            f"but the corpus has gained or lost one of these shapes and the pin must "
            f"be moved deliberately rather than left to follow."
        )
    for name in measured:
        admitted, why = rego_verdict(
            rig.opa, opt_in, statements[name], rig.workdir, f"optin-{name}"
        )
        if not admitted:
            problems.append(
                f"rego under the consumer opt-in denies {name} ({why}). The opt-in is "
                f"what makes the row-provenance divergence reachable, so without it "
                f"the divergence recorded in the policy files is unmeasured."
            )
        for rail in [p.name for p in rig.policies] + ["cue"]:
            if results[rail][name][0]:
                problems.append(
                    f"{rail} admits {name}, an unintercepted clean row. These rails "
                    f"have no consumer opt-in, so they are expected to deny it "
                    f"whatever the rego rail is configured to do."
                )
    return problems


def _pin_kyverno(policy: KyvernoPolicy, corpus: str, substrate: str) -> KyvernoPolicy:
    slots: list[_Slot] = []
    for slot in policy.slots:
        literal = slot.literal
        if isinstance(literal, str) and literal.startswith(_ANCHOR_PLACEHOLDER):
            literal = corpus if "CORPUS" in literal else substrate
        slots.append(
            _Slot(slot.index, slot.operator, slot.key_expr, slot.value_expr, literal)
        )
    return KyvernoPolicy(policy.name, policy.attestation_type, tuple(slots))


def _run_anchors(rig: Rig, base: dict[str, Any]) -> list[str]:
    shipped = _read_policy(
        _KYVERNO_DIR / "clusterpolicy-adversarial-execution-evidence.yaml",
        corpus_mode=False,
    )
    problems: list[str] = []
    predicate = _as_dict(base["predicate"], "predicate")
    path = rig.workdir / "anchor-input.json"
    path.write_text(json.dumps(kyverno_input(predicate)), encoding="utf-8")
    for name, corpus, substrate, want in anchor_cases(base):
        policy = _pin_kyverno(shipped, corpus, substrate)
        got = kyverno_verdict(rig.kyverno, policy, base, path)
        if got[0] != want:
            problems.append(
                f"Kyverno anchors: {name} expected "
                f"{'admit' if want else 'deny'}, got "
                f"{'admit' if got[0] else 'deny'} ({got[1]})"
            )
        problems.extend(_run_cue_anchor(rig, base, name, corpus, substrate, want))
    path.unlink(missing_ok=True)
    return problems


def _run_cue_anchor(
    rig: Rig, base: dict[str, Any], name: str, corpus: str, substrate: str, want: bool
) -> list[str]:
    src = cue_source(drop_anchors=False)
    src = re.sub(r'"PIN-ME-[A-Z-]*CORPUS-DIGEST"', json.dumps(corpus), src)
    src = re.sub(r'"PIN-ME-[A-Z-]*SUBSTRATE-DIGEST"', json.dumps(substrate), src)
    policy_path = rig.workdir / f"anchor-{name}.cue"
    policy_path.write_text(src, encoding="utf-8")
    got = cue_verdict(rig.cue, policy_path, base, rig.workdir, f"anchor-{name}")
    policy_path.unlink(missing_ok=True)
    if got[0] == want:
        return []
    return [
        (
            f"CUE anchors: {name} expected {'admit' if want else 'deny'}, got "
            f"{'admit' if got[0] else 'deny'} ({got[1]})"
        )
    ]


def _new_workdir() -> Path:
    """Create this run's fixture directory, named for the running process.

    The base stays where it was, so a continuous integration runner still gets its
    own scratch area, but the leaf is minted rather than spelled out: the directory
    is created exclusively, which is what makes two runs against one checkout
    incapable of being handed the same name.
    """
    base = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=_WORKDIR_PREFIX, dir=base))


def _gate(args: argparse.Namespace, workdir: Path) -> int:
    """Run every rail over the corpus in the directory the caller minted."""
    corpus = _as_dict(_load_json(_CORPUS)["corpus_vectors"], "corpus_vectors")
    vectors = _corpus_vectors(corpus)
    buckets = {name: bucket for bucket, name, _ in vectors}
    rig = _build_rig(workdir)

    for policy in rig.policies:
        print(
            f"policy {policy.name:<62} corpus-driven={len(policy.slots)} "
            f"deferred={policy.deferred}"
        )

    results = _run_all(rig, [(n, s) for _, n, s in vectors], args.jobs)
    if args.measure:
        _print_measurement(results, buckets)
        return 0

    meta = _vector_meta(corpus)
    kyverno_admits = _resolve_divergence(meta, _KYVERNO_ADMITS)
    kyverno_denies = _resolve_divergence(meta, _KYVERNO_DENIES)
    cue_admits = _resolve_divergence(meta, _CUE_ADMITS)
    cue_denies = _resolve_divergence(meta, _CUE_DENIES)
    cel_admits = _resolve_divergence(meta, _CEL_ADMITS)
    cel_denies = _resolve_divergence(meta, _CEL_DENIES)

    problems: list[str] = []
    problems.extend(
        _check_policy_invariants(sorted(_KYVERNO_DIR.glob("clusterpolicy-*.yaml")))
    )
    problems.extend(_check_deferrals(rig.policies))
    problems.extend(_check_condition_parity(rig.policies))
    problems.extend(_check_lockstep(results, rig.policies))
    for policy in rig.policies:
        problems.extend(
            _check_declared(
                policy.name,
                results[policy.name],
                results["rego"],
                kyverno_admits,
                kyverno_denies,
            )
        )
    problems.extend(
        _check_declared("cue", results["cue"], results["rego"], cue_admits, cue_denies)
    )
    problems.extend(
        _check_declared("cel", results["cel"], results["rego"], cel_admits, cel_denies)
    )
    problems.extend(_check_cel_deferrals(rig.cel))

    statements = {name: statement for _, name, statement in vectors}
    base = _base_statement(corpus, statements)
    problems.extend(_run_cases(rig, build_cases(base)))
    problems.extend(_run_freshness(rig, base))
    problems.extend(_run_anchors(rig, base))
    problems.extend(_run_provenance_divergence(rig, corpus, statements, results))

    measured = {
        "kyverno": sum(1 for ok, _ in results[rig.policies[0].name].values() if ok),
        "cue": sum(1 for ok, _ in results["cue"].values() if ok),
        "cel": sum(1 for ok, _ in results["cel"].values() if ok),
        "rego": sum(1 for ok, _ in results["rego"].values() if ok),
    }
    problems.extend(
        _check_measured_admits(
            measured,
            {
                "kyverno": (kyverno_admits, kyverno_denies),
                "cue": (cue_admits, cue_denies),
                "cel": (cel_admits, cel_denies),
            },
        )
    )
    print(
        f"\n{len(vectors)} corpus vectors through {len(rig.policies)} Kyverno "
        f"ClusterPolicy documents, the ImageValidatingPolicy, the CUE policy and the "
        f"rego oracle. JMESPath ClusterPolicy admits {measured['kyverno']}, CUE "
        f"admits {measured['cue']}, the CEL ImageValidatingPolicy admits "
        f"{measured['cel']}, rego admits {measured['rego']}."
    )
    if problems:
        print(f"\n{len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        "The JMESPath, CEL and CUE rails agree with the rego oracle within the "
        "declared scope."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Kyverno and CUE conformance gate")
    parser.add_argument(
        "--measure",
        action="store_true",
        help="print the measured divergence instead of asserting the declared one",
    )
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()

    workdir = _new_workdir()
    # A directory minted per run has to be removed by the run that minted it, and a
    # removal on the failure path is how a debuggable failure becomes an undebuggable
    # one. What survives a red gate is what a reader cannot reconstruct by hand: the
    # two consumer documents this run pinned, and the CUE policy body as it was
    # extracted from the manifest and stripped of its anchors, which is the thing a
    # CUE divergence has to be read against. The per-vector statements are not among
    # them and do not need to be, because each is the named vector in the published
    # corpus. Failure and exception alike keep the directory and name it on standard
    # error rather than leaving it to be guessed at; a green gate keeps nothing.
    keep = True
    try:
        code = _gate(args, workdir)
        keep = code != 0
        return code
    finally:
        if keep:
            print(f"the fixtures for this run are kept at {workdir}", file=sys.stderr)
        else:
            shutil.rmtree(workdir)


if __name__ == "__main__":
    raise SystemExit(main())
