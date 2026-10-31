"""Run the agent change admission vectors through every rail that carries the rule.

    python3 conformance/run_change_admission_conformance.py
    python3 conformance/run_change_admission_conformance.py --skip-mutations

Four checks, each refusing on the first disagreement it can name:

1. The rego module answers every vector with exactly the refusal set the vector
   declares (`rego/agent_change_admission_vectors.json`).
2. The engine corpus. Kyverno and policy-controller see an in-toto Statement
   attached to an image, after their own key authority verified it, so each
   vector whose envelope opens is turned into that statement: its subject is the
   image, and the deployment pins the harness digest. The rego module, run under
   that deployment's pins, is the reference for this corpus. A vector whose
   envelope does not open (an unknown payload type, a payload that is not a JSON
   object) never reaches a policy in a cluster: the engine refuses it first. Those
   are counted and named, never silently dropped.
3. Kyverno's CEL rail. The ImageValidatingPolicy is lifted into a
   ValidatingPolicy over a plain document carrying the statement, with the
   registry-dependent signature check removed and the harness pin set, and
   `kyverno apply` must admit exactly the statements the reference admits.
4. The policy-controller manifest. The module embedded in it, with its
   placeholder digest replaced by the pin, must return exactly the reference
   refusal set on every statement, with no data document at all, as
   policy-controller runs it.

Then, unless skipped, the mutation sweep: each refusal rule in the module is
deleted in turn and `opa test` must fail, so a rule nothing exercises is found.

Needs `opa` and `kyverno` on the path (or OPA_BIN, KYVERNO_BIN). Exit 0 when every
check agrees, 1 on any disagreement, 2 when a check could not run.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "rego" / "agent_change_admission.rego"
TESTS = ROOT / "rego" / "agent_change_admission_test.rego"
VECTORS = ROOT / "rego" / "agent_change_admission_vectors.json"
IVP = ROOT / "kyverno" / "imagevalidatingpolicy-agent-change-admission.yaml"
CIP = ROOT / "policy-controller" / "clusterimagepolicy-agent-change-admission.yaml"

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
BARE_TYPE = "application/vnd.ratchet.decision+json"
INTOTO_TYPE = "application/vnd.in-toto+json"
PLACEHOLDER = "PIN-ME-REPLACE-WITH-THE-ADMITTED-HARNESS-DIGEST"
REGISTRY_MARKER = "variables.verified"
CEL_GROUP = "evidence.example"


class CouldNotRun(Exception):
    """A check could not run. Never reported as a pass."""


def tool(env: str, name: str) -> str:
    found = os.environ.get(env) or shutil.which(name)
    if not found:
        raise CouldNotRun(f"{name} was not found; install it or set {env}")
    return found


def opa_value(opa: str, module_text: str, query: str, value: Any, data: dict[str, Any] | None, work: Path) -> Any:
    (work / "m.rego").write_text(module_text, encoding="utf-8")
    (work / "in.json").write_text(json.dumps(value), encoding="utf-8")
    cmd = [opa, "eval", "-f", "json", "-d", str(work / "m.rego"), "-i", str(work / "in.json")]
    if data is not None:
        (work / "data.json").write_text(json.dumps(data), encoding="utf-8")
        cmd += ["-d", str(work / "data.json")]
    proc = subprocess.run([*cmd, query], capture_output=True, text=True, check=False)
    try:
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise CouldNotRun(f"opa returned no value for {query}: {proc.stderr.strip()[:300]}") from exc


def load_yaml(kyverno: str, path: Path) -> dict[str, Any]:
    """Read a manifest through Kyverno's own YAML reader, as the sibling harness does."""
    proc = subprocess.run([kyverno, "jp", "query", "-c", "-i", str(path), "@"], capture_output=True, text=True, check=False)
    body = "\n".join(line for line in proc.stdout.splitlines() if not line.startswith("# ")).strip()
    if proc.returncode != 0 or not body:
        raise CouldNotRun(f"kyverno could not read {path.name}: {proc.stderr.strip()[:300]}")
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise CouldNotRun(f"{path.name} is not a mapping")
    return doc


def engine_statement(vector_input: dict[str, Any], image_digest: str) -> dict[str, Any] | None:
    """The statement an engine hands the policy for this vector, or None when its envelope does not open."""
    if "payloadType" not in vector_input and "envelope" not in vector_input:
        statement = dict(vector_input)
    else:
        env = vector_input.get("envelope", vector_input)
        try:
            body = json.loads(base64.b64decode(env["payload"], validate=True))
        except (KeyError, TypeError, ValueError):
            return None
        if not isinstance(body, dict):
            return None
        if env.get("payloadType") == INTOTO_TYPE:
            statement = body
        elif env.get("payloadType") == BARE_TYPE:
            statement = {
                "_type": STATEMENT_TYPE,
                "predicateType": body.get("predicateType"),
                "predicate": {k: v for k, v in body.items() if k != "predicateType"},
            }
        else:
            return None
    return {**statement, "subject": [{"name": "image", "digest": {"sha256": image_digest}}]}


def lifted_cel(kyverno: str, pin: str) -> dict[str, Any]:
    doc = load_yaml(kyverno, IVP)
    spec = doc["spec"]
    variables = []
    for v in spec["variables"]:
        if v["name"] == "verified":
            continue
        if v["name"] == "statement":
            variables.append({"name": "statement", "expression": "object.spec.statement"})
        elif v["name"] == "pinnedHarness":
            variables.append({"name": "pinnedHarness", "expression": json.dumps(pin)})
        else:
            variables.append(v)
    names = {v["name"] for v in variables}
    if not {"statement", "pinnedHarness", "decision"} <= names:
        raise CouldNotRun(f"{IVP.name} no longer declares the variables this driver binds")
    validations = [v for v in spec["validations"] if REGISTRY_MARKER not in v["expression"]]
    if len(spec["validations"]) - len(validations) != 1:
        raise CouldNotRun("expected exactly one registry-dependent validation to lift out")
    return {
        "apiVersion": "policies.kyverno.io/v1alpha1",
        "kind": "ValidatingPolicy",
        "metadata": {"name": "agent-change-admission-cel-rail"},
        "spec": {
            "matchConstraints": {
                "resourceRules": [
                    {"apiGroups": [CEL_GROUP], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["payloads"]}
                ]
            },
            "variables": variables,
            "validations": validations,
        },
    }


def cel_admits(kyverno: str, policy: Path, statement: dict[str, Any], work: Path) -> tuple[bool, str]:
    # `kyverno apply` selects its loader by extension and ignores `.json`, so the
    # resource is JSON content under a `.yaml` name.
    resource = work / "resource.yaml"
    resource.write_text(
        json.dumps({"apiVersion": f"{CEL_GROUP}/v1", "kind": "Payload", "metadata": {"name": "vector"}, "spec": {"statement": statement}}),
        encoding="utf-8",
    )
    proc = subprocess.run([kyverno, "apply", str(policy), "--resource", str(resource)], capture_output=True, text=True, check=False)
    out = proc.stdout + proc.stderr
    if "Applying 0 policy rule(s)" in out or "failed to compile" in out:
        raise CouldNotRun(f"the lifted CEL policy did not run: {out.strip()[:400]}")
    if "pass: 1," in out:
        return True, ""
    for line in out.splitlines():
        if line.strip().startswith("1 -"):
            return False, line.strip()[3:].strip()[:160]
    return False, "the CEL engine raised a runtime error"


def mutation_sweep(opa: str) -> list[str]:
    """Delete each refusal rule in turn; `opa test` must fail every time."""
    source = MODULE.read_text(encoding="utf-8")
    spans = [
        (m.start(), m.end())
        for m in re.finditer(r"^errors contains [^\n]*\{\n.*?\n\}\n|^errors contains [^\n{]*\n", source, re.MULTILINE | re.DOTALL)
    ]
    if not spans:
        raise CouldNotRun("no refusal rule found to mutate")
    survivors = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        shutil.copy(TESTS, work / TESTS.name)
        shutil.copy(VECTORS, work / VECTORS.name)
        for start, end in spans:
            (work / MODULE.name).write_text(source[:start] + source[end:], encoding="utf-8")
            proc = subprocess.run([opa, "test", "--timeout", "300s", str(work)], capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                survivors.append(source[start:end].splitlines()[0])
    print(f"mutation sweep: {len(spans)} refusal rules deleted one at a time, {len(survivors)} survived")
    return [f"refusal rule not exercised by any test: {s}" for s in survivors]


def run(skip_mutations: bool) -> int:
    opa = tool("OPA_BIN", "opa")
    kyverno = tool("KYVERNO_BIN", "kyverno")
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))["agent_change_admission_vectors"]
    cases: dict[str, Any] = doc["cases"]
    pin, image = doc["candidate_digest"], doc["image_digest"]
    module = MODULE.read_text(encoding="utf-8")
    cip = load_yaml(kyverno, CIP)
    embedded = cip["spec"]["authorities"][0]["attestations"][0]["policy"]["data"]
    if embedded.count(PLACEHOLDER) != 1:
        raise CouldNotRun(f"{CIP.name} does not carry the harness placeholder exactly once")
    embedded = embedded.replace(PLACEHOLDER, pin)
    engine_pins = {"signature_verified_upstream": True, "subject_binding": "image", "expected_candidate_digest": pin}
    failures: list[str] = []
    counts = {"rego": 0, "engine": 0, "cel": 0, "policy-controller": 0, "envelope-layer": 0, "admitted": 0}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        policy = work / "lifted.yaml"
        policy.write_text(json.dumps(lifted_cel(kyverno, pin)), encoding="utf-8")
        for name in sorted(cases):
            case = cases[name]
            got = opa_value(opa, module, "data.agent_change_admission.reasons", case["input"],
                            {"change_admission_consumer": case["consumer"]}, work)
            counts["rego"] += 1
            if got != sorted(case["reasons"]):
                failures.append(f"rego {name}: expected {sorted(case['reasons'])}, got {got}")
            statement = engine_statement(case["input"], image)
            if statement is None:
                counts["envelope-layer"] += 1
                print(f"engine corpus: {name} does not open past the envelope; the engine refuses it first")
                continue
            reference = opa_value(opa, module, "data.agent_change_admission.reasons", statement,
                                  {"change_admission_consumer": engine_pins}, work)
            counts["engine"] += 1
            admits, why = cel_admits(kyverno, policy, statement, work)
            counts["cel"] += 1
            counts["admitted"] += int(admits)
            if admits != (reference == []):
                failures.append(f"cel {name}: reference {reference or 'admit'}, CEL {'admit' if admits else why}")
            pc = opa_value(opa, embedded, "data.sigstore.reasons", statement, None, work)
            counts["policy-controller"] += 1
            if pc != reference:
                failures.append(f"policy-controller {name}: reference {reference}, embedded module {pc}")
        # Positive control: under a pin naming another harness, both engine rails
        # must refuse the statement they admit above. A rail that admits it anyway
        # was never comparing the digest at all.
        control = engine_statement(cases["statement-admitted"]["input"], image)
        other = "0" * 64
        stray = work / "control.yaml"
        stray.write_text(json.dumps(lifted_cel(kyverno, other)), encoding="utf-8")
        if control is None or cel_admits(kyverno, stray, control, work)[0]:
            failures.append("control: the CEL rail admitted a statement for a harness other than the pin")
        if opa_value(opa, embedded.replace(pin, other), "data.sigstore.isCompliant", control, None, work):
            failures.append("control: the embedded module admitted a statement for a harness other than the pin")
    if counts["admitted"] == 0 or counts["admitted"] == counts["cel"]:
        failures.append(f"the engine corpus admits {counts['admitted']} of {counts['cel']}; it measures nothing")
    print("vectors answered: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    if not skip_mutations:
        failures += mutation_sweep(opa)
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{len(failures)} disagreement(s)")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--skip-mutations", action="store_true", help="skip the rule deletion sweep")
    args = parser.parse_args(argv[1:])
    try:
        return run(args.skip_mutations)
    except CouldNotRun as exc:
        print(f"could not run: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
