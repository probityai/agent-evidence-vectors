"""Run the Microsoft Agent Control Specification runtime on fixed pre_tool_call contexts.

This is the observed run the decision-record corpus is built from. It activates one
manifest and one Rego bundle held in memory, evaluates each context at
``pre_tool_call``, and writes everything a record must bind: the context the runtime
judged, the manifest bytes, the policy bundle, and the verdict exactly as the runtime
returned it on the agent-hooks wire (``Verdict.to_wire``).

Run it from this directory:

    uv run python run_acs.py ../observed/run-acs-0.4.0a4.json

The agent-hooks builder stamps each context with the time it was built, so a second
run writes different context bytes and the same verdicts. The committed file is the
record of one run; ``gen_vectors.py`` reads it and never imports the runtime.
"""

from __future__ import annotations

import json
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Any

from agent_control_spec import ActivatedPolicy
from agent_hooks import AgentContextBuilder

MANIFEST = """agent_control_specification_version: "0.4.0-alpha.1"
metadata:
  name: decision-record-run
policies:
  tool_gate:
    type: rego
    bundle: ./policy
    query: data.tool_gate.verdict
tools:
  read_file: {}
  delete_branch: {}
  send_payment: {}
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: tool_gate
"""

POLICY_SOURCE = """package tool_gate

default verdict := {"decision": "allow", "reason": "tool_permitted"}

verdict := {"decision": "deny", "reason": "destructive_tool"} if {
  input.snapshot.tool_call.name == "delete_branch"
}

verdict := {"decision": "escalate", "reason": "payment_needs_approval"} if {
  input.snapshot.tool_call.name == "send_payment"
  input.policy_target.value.amount > 100
}
"""

BUNDLE: dict[str, Any] = {"modules": {"tool_gate.rego": POLICY_SOURCE}}

#: (case name, tool, arguments). Each reaches a different verdict.
CASES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("read-allowed", "read_file", {"path": "README.md"}),
    ("delete-denied", "delete_branch", {"branch": "main"}),
    ("payment-escalated", "send_payment", {"amount": 250, "currency": "USD"}),
    ("payment-allowed", "send_payment", {"amount": 40, "currency": "USD"}),
)


def context_for(call_id: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    builder = AgentContextBuilder(agent_id="agent-1", framework="run_acs", session_id="session-1")
    return dict(builder.pre_tool_call(call_id=call_id, name=tool, args=args))


def main(out: Path) -> int:
    policy = ActivatedPolicy.from_memory(MANIFEST, {"tool_gate": BUNDLE})
    cases = []
    for index, (name, tool, args) in enumerate(CASES, start=1):
        context = context_for(f"call-{index}", tool, args)
        verdict = policy.evaluate("pre_tool_call", context)
        wire = verdict.to_wire()
        if str(wire.get("reason", "")).startswith("runtime_error:"):
            print(f"{name}: the runtime failed instead of deciding: {wire}", file=sys.stderr)
            return 1
        cases.append({"name": name, "context": context, "verdict": wire})
    run = {
        "runtime": {
            "distribution": "agent-control-spec",
            "version": version("agent-control-spec"),
            "agentHooksSdk": version("agent-hooks-sdk"),
            "repository": "https://github.com/responsibleai/agent-control-spec",
        },
        "interventionPoint": "pre_tool_call",
        "manifest": MANIFEST,
        "policyBundle": BUNDLE,
        "cases": cases,
    }
    out.write_text(
        json.dumps(run, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    for case in cases:
        print(f"{case['name']}: {case['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
