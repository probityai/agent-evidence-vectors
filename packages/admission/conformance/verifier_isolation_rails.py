"""The two engine rails of the verifier isolation family: Kyverno's CEL and CUE.

`run_verifier_isolation_conformance.py` imports this module. It runs a statement through the
shipped CEL policy and the shipped CUE policy and returns what each rail answered; it decides
nothing about dispositions.

KYVERNO CEL. The ImageValidatingPolicy is lifted into ValidatingPolicy documents over a plain
resource that carries the statement, with the registry-dependent signature validation removed
and the contract pin set, the way `run_change_admission_conformance.py` lifts its policy.
Two lifts are run. The whole policy gives the verdict the engine gives. The same variables with
ONE validation each, applied together in a single `kyverno apply`, give the reason every
validation returns, because the engine reports only the first failing validation of a policy.

CUE. The policy body is read out of the ClusterImagePolicy and run twice. `cue vet` is the strict
run: it reports a required member that is absent and a value that is not concrete. `cue eval`
is the lenient run: it unifies the policy with the statement and reports a conflict only. That is
how cosign's evaluator reads a policy (`pkg/policy/eval.go`, `evaluateCue`): it unifies and calls
`Validate()` with neither `Final` nor `Concrete`, so an absent member is not an error. The
command line cannot execute cosign itself, so the lenient run is the nearest reading and is
named as one.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
IVP = ROOT / "kyverno" / "imagevalidatingpolicy-verifier-isolation.yaml"
CIP = ROOT / "policy-controller" / "clusterimagepolicy-verifier-isolation-cue.yaml"

CEL_GROUP = "evidence.example"
REGISTRY_MARKER = "variables.verified"
PIN_MESSAGE = "contract_digest_mismatch"
PIN_PLACEHOLDER = "PIN-ME-REPLACE-WITH-THE-CONTRACT-DIGEST"
CUE_MARK = re.compile(r"//\s*rule:\s*(\S+)\s*$")
UNSAFE = "vi-9:unsafe_loader"


class CouldNotRun(Exception):
    """A check could not run. Never reported as a pass."""


def tool(env: str, name: str) -> str:
    found = os.environ.get(env) or shutil.which(name)
    if not found:
        raise CouldNotRun(f"{name} was not found; install it or set {env}")
    return found


def load_yaml(kyverno: str, path: Path) -> dict[str, Any]:
    """Read a manifest through Kyverno's own YAML reader, as the sibling harnesses do."""
    proc = subprocess.run([kyverno, "jp", "query", "-c", "-i", str(path), "@"], capture_output=True, text=True, check=False)
    body = "\n".join(line for line in proc.stdout.splitlines() if not line.startswith("# ")).strip()
    if proc.returncode != 0 or not body:
        raise CouldNotRun(f"kyverno could not read {path.name}: {proc.stderr.strip()[:300]}")
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise CouldNotRun(f"{path.name} is not a mapping")
    return doc


def contract_pin(case: dict[str, Any]) -> str | None:
    pin = case["consumer"].get("expected_contract_sha256")
    return pin if isinstance(pin, str) else None


def engine_consumer(case: dict[str, Any]) -> dict[str, Any]:
    """The pins an engine gives the rego reference: the signature checked, and the vector's contract pin."""
    pins: dict[str, Any] = {"signature_verified_upstream": True}
    pin = contract_pin(case)
    if pin is not None:
        pins["expected_contract_sha256"] = pin
    return pins


def normalise(reasons: list[str]) -> list[str]:
    """Fold the per-loader reasons into one entry per unsafe loader name, sorted."""
    out: set[str] = set()
    for r in reasons:
        if r.startswith(UNSAFE + ":"):
            out.update(f"{UNSAFE}:{n}" for n in r[len(UNSAFE) + 1:].split(","))
        else:
            out.add(r)
    return sorted(out)


# ---------------------------------------------------------------------------
# Kyverno CEL
# ---------------------------------------------------------------------------


def _key(validation: dict[str, Any]) -> str:
    """The reason a validation returns: its message, or the literal a messageExpression starts with."""
    if "message" in validation:
        return str(validation["message"])
    lit = re.match(r"'([^']*)'", str(validation.get("messageExpression", "")))
    if not lit:
        raise CouldNotRun("a validation carries neither a message nor a messageExpression that starts with a literal")
    return lit.group(1).rstrip(":")


class CelRail:
    def __init__(self, kyverno: str, work: Path) -> None:
        self.kyverno = kyverno
        self.work = work
        spec = load_yaml(kyverno, IVP)["spec"]
        self.variables = spec["variables"]
        self.validations: list[dict[str, Any]] = [v for v in spec["validations"] if REGISTRY_MARKER not in v["expression"]]
        if len(spec["validations"]) - len(self.validations) != 1:
            raise CouldNotRun("expected exactly one registry-dependent validation to lift out")
        self.keys = [_key(v) for v in self.validations]
        if len(set(self.keys)) != len(self.keys):
            raise CouldNotRun(f"{IVP.name} returns one reason from two validations")
        names = {v["name"] for v in self.variables}
        if not {"statement", "pinnedContract"} <= names:
            raise CouldNotRun(f"{IVP.name} no longer declares the variables this driver binds")
        self._policies: dict[tuple[str | None, str | None], Path] = {}

    def reasons_in_policy(self) -> list[str]:
        return list(self.keys)

    def _lifted_variables(self, pin: str | None) -> list[dict[str, Any]]:
        out = []
        for v in self.variables:
            if v["name"] == "verified":
                continue
            if v["name"] == "statement":
                out.append({"name": "statement", "expression": "object.spec.statement"})
            elif v["name"] == "pinnedContract":
                out.append({"name": "pinnedContract", "expression": json.dumps(pin or "")})
            else:
                out.append(v)
        return out

    def _policy(self, name: str, pin: str | None, validations: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "apiVersion": "policies.kyverno.io/v1alpha1",
            "kind": "ValidatingPolicy",
            "metadata": {"name": name},
            "spec": {
                "matchConstraints": {
                    "resourceRules": [
                        {"apiGroups": [CEL_GROUP], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["payloads"]}
                    ]
                },
                "variables": self._lifted_variables(pin),
                "validations": validations,
            },
        }

    def _kept(self, pin: str | None, without: str | None) -> list[dict[str, Any]]:
        """The validations that apply: with no pin the contract comparison is declined, as the policy's header says."""
        drop = {without} if without else set()
        if pin is None:
            drop.add(PIN_MESSAGE)
        return [v for v, k in zip(self.validations, self.keys, strict=True) if k not in drop]

    def whole_dir(self, pin: str | None, without: str | None = None) -> Path:
        key = (pin, without)
        if key not in self._policies:
            d = self.work / f"whole-{len(self._policies)}"
            d.mkdir()
            doc = self._policy("verifier-isolation-cel-rail", pin, self._kept(pin, without))
            (d / "policy.yaml").write_text(json.dumps(doc), encoding="utf-8")
            self._policies[key] = d
        return self._policies[key]

    def split_dir(self, pin: str | None) -> Path:
        key = (pin, "<split>")
        if key not in self._policies:
            d = self.work / f"split-{len(self._policies)}"
            d.mkdir()
            for i, v in enumerate(self._kept(pin, None)):
                doc = self._policy(f"rule-{i:02d}", pin, [v])
                (d / f"rule-{i:02d}.yaml").write_text(json.dumps(doc), encoding="utf-8")
            self._policies[key] = d
        return self._policies[key]

    def _apply(self, policies: Path, statement: dict[str, Any]) -> str:
        # `kyverno apply` selects its loader by extension and ignores `.json`, so the
        # resource is JSON content under a `.yaml` name.
        resource = self.work / "resource.yaml"
        body = {"apiVersion": f"{CEL_GROUP}/v1", "kind": "Payload", "metadata": {"name": "vector"}, "spec": {"statement": statement}}
        resource.write_text(json.dumps(body), encoding="utf-8")
        command = [self.kyverno, "apply", str(policies), "--resource", str(resource)]
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        out = proc.stdout + proc.stderr
        if "Applying 0 policy rule(s)" in out or "failed to compile" in out:
            raise CouldNotRun(f"the lifted CEL policy did not run: {out.strip()[:400]}")
        return out

    @staticmethod
    def _summary(out: str) -> tuple[int, int, int]:
        m = re.search(r"pass: (\d+), fail: (\d+), warn: (\d+), error: (\d+)", out)
        if not m:
            raise CouldNotRun(f"kyverno apply printed no summary: {out.strip()[:300]}")
        return int(m[1]), int(m[2]) + int(m[3]), int(m[4])

    def admits(self, statement: dict[str, Any], pin: str | None, without: str | None = None) -> bool:
        """The verdict the engine gives the whole policy, with one validation removed when asked."""
        passed, failed, errors = self._summary(self._apply(self.whole_dir(pin, without), statement))
        if errors:
            raise CouldNotRun("the CEL engine raised a runtime error on a vector; a validation is not total")
        return passed == 1 and failed == 0

    def reasons(self, statement: dict[str, Any], pin: str | None) -> list[str]:
        """Every reason the engine returns for the statement, one validation at a time."""
        d = self.split_dir(pin)
        out = self._apply(d, statement)
        _passed, failed, errors = self._summary(out)
        if errors:
            raise CouldNotRun("the CEL engine raised a runtime error on a vector; a validation is not total")
        found = re.findall(r"^policy rule-\d+ -> resource \S+ failed:\n1 -  (.*)$", out, re.MULTILINE)
        if len(found) != failed:
            raise CouldNotRun(f"kyverno reported {failed} failing rules and {len(found)} reasons could be read: {out.strip()[:300]}")
        return normalise(found)


# ---------------------------------------------------------------------------
# CUE
# ---------------------------------------------------------------------------


class CueRail:
    def __init__(self, cue: str, kyverno: str, work: Path) -> None:
        self.cue = cue
        self.work = work
        doc = load_yaml(kyverno, CIP)
        try:
            attestation = doc["spec"]["authorities"][0]["attestations"][0]
            policy = attestation["policy"]
            self.source: str = policy["data"]
        except (KeyError, IndexError, TypeError) as exc:
            raise CouldNotRun(f"{CIP.name} no longer has the shape this driver reads: {exc}") from exc
        if policy.get("type") != "cue":
            raise CouldNotRun(f"{CIP.name} does not carry a cue policy")
        if self.source.count(PIN_PLACEHOLDER) != 1:
            raise CouldNotRun(f"{CIP.name} does not carry the contract placeholder exactly once")
        self.lines = self.source.splitlines()
        self.marks = [m.group(1) if (m := CUE_MARK.search(line)) else None for line in self.lines]
        self._n = 0

    def reasons_in_policy(self) -> list[str]:
        return sorted({m for m in self.marks if m})

    def render(self, pin: str | None, *, without: str | None = None) -> str:
        """The policy text for one run: the contract pin applied or declined, and one rule's lines removed."""
        out = []
        for line, mark in zip(self.lines, self.marks, strict=True):
            if mark == PIN_MESSAGE:
                if pin is None:
                    continue
                line = line.replace(PIN_PLACEHOLDER, pin)
            if without is not None and mark == without:
                continue
            out.append(line)
        return "\n".join(out) + "\n"

    def admits(self, statement: dict[str, Any], pin: str | None, *, without: str | None = None, lenient: bool = False) -> bool:
        self._n += 1
        policy = self.work / f"policy-{self._n}.cue"
        data = self.work / f"stmt-{self._n}.json"
        policy.write_text(self.render(pin, without=without), encoding="utf-8")
        data.write_text(json.dumps(statement), encoding="utf-8")
        command = "eval" if lenient else "vet"
        proc = subprocess.run([self.cue, command, str(policy), str(data)], capture_output=True, text=True, check=False)
        policy.unlink(missing_ok=True)
        data.unlink(missing_ok=True)
        if proc.returncode == 0:
            return True
        message = (proc.stderr or proc.stdout).strip()
        # A policy that does not compile says nothing about the vector. Only an error that names a
        # path under the statement is a refusal.
        if not re.search(r"^\"?(predicate|predicateType|_type|subject)\"?[.:]", message, re.MULTILINE):
            raise CouldNotRun(f"cue failed without naming a field of the statement: {message[:300]}")
        return False
