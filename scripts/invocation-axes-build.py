#!/usr/bin/env python3
"""Build the frozen three-axis corpus for one pinned MCP invocation.

Every case starts from one intact pair: a decision capture package and an
execution bundle, both bound to the same ``tools/call`` bytes. Each case then
changes one thing and states the answer it expects on each axis.

    python scripts/invocation-axes-build.py           # write the corpus
    python scripts/invocation-axes-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.invocation_axes.reader import (  # noqa: E402
    CAPTURE_SCHEMA,
    EXECUTION_SCHEMA,
    INDEPENDENT_SOURCE,
    canonical,
    invocation_binding,
    sha256_tag,
)

CORPUS = PACKAGING / "agent_evidence_vectors/invocation_axes/corpus"
E = "ESTABLISHED"
C = "CONTRADICTED"
N = "NOT_ESTABLISHED"

INVOCATION: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {
        "name": "update_ticket",
        "arguments": {
            "ticket_id": "OPS-4127",
            "status": "closed",
            "labels": ["resolved", "p2"],
            "reopen_count": 0,
        },
    },
}
BINDING = invocation_binding(INVOCATION)


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _request(**params_override: Any) -> dict[str, Any]:
    request = copy.deepcopy(INVOCATION)
    request["id"] = "proxy-31"
    request["params"].update(params_override)
    return request


def _capture(
    objects: dict[str, str], pinned: bool = True, listed: list[str] | None = None
) -> dict[str, Any]:
    names = sorted(objects) if listed is None else listed
    manifest = {
        "schema": CAPTURE_SCHEMA,
        "objects": [
            {"name": name, "sha256": sha256_tag(objects[name].encode("utf-8"))}
            for name in names
            if name in objects
        ],
    }
    return {
        "pinned_package_digest": sha256_tag(canonical(manifest)) if pinned else None,
        "manifest": manifest,
        "objects": objects,
    }


def _decision(verdict: str = "allow", binding: str = BINDING) -> str:
    return _dump(
        {
            "request_binding": binding,
            "decision": verdict,
            "policy": "tickets-close-allowed@3",
        }
    )


def _objects(request: dict[str, Any] | None = None, verdict: str = "allow") -> dict[str, str]:
    return {
        "request.json": _dump(_request() if request is None else request),
        "decision.json": _decision(verdict),
    }


def _execution(**override: Any) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "schema": EXECUTION_SCHEMA,
        "call_binding": BINDING,
        "dispatch": {"outcome": "DISPATCHED"},
        "execution_report": {"status": "success", "message": "ticket closed"},
        "postcondition": {
            "tool_id": "update_ticket",
            "expected_fields": {"status": "closed", "reopen_count": 0},
        },
        "observation": {
            "source": INDEPENDENT_SOURCE,
            "fields": {"status": "closed", "reopen_count": 0, "assignee": "ops"},
        },
    }
    bundle.update(override)
    return bundle


def _expect(
    integrity: str, correspondence: str, effect: str, under_authority: str
) -> dict[str, str]:
    return {
        "package_integrity": integrity,
        "request_decision_correspondence": correspondence,
        "observed_effect": effect,
        "effect_under_authority": under_authority,
        "capture_authenticity": N,
        "capture_coverage": N,
        "kernel_to_tool_attribution": N,
    }


def _one_byte_changed() -> dict[str, Any]:
    capture = _capture(_objects())
    text = capture["objects"]["request.json"]
    capture["objects"]["request.json"] = text.replace("OPS-4127", "OPS-4128", 1)
    return capture


def _manifest_rewritten() -> dict[str, Any]:
    changed = _capture(_objects(_request(name="delete_ticket")))
    changed["pinned_package_digest"] = _capture(_objects())["pinned_package_digest"]
    return changed


def _reordered_request() -> dict[str, Any]:
    request = _request()
    args = request["params"]["arguments"]
    request["params"]["arguments"] = {k: args[k] for k in reversed(list(args))}
    return request


def _labels_reversed() -> dict[str, Any]:
    request = _request()
    request["params"]["arguments"] = dict(request["params"]["arguments"], labels=["p2", "resolved"])
    return request


def _changed_argument() -> dict[str, Any]:
    request = _request()
    request["params"]["arguments"] = dict(request["params"]["arguments"], status="deleted")
    return request


def _hop_meta() -> dict[str, Any]:
    request = _request()
    request["params"]["_meta"] = {
        "progressToken": "hop-2",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "aiInvocation": {"reason": "close the resolved ticket", "turnId": "t-19"},
    }
    return request


def _argument_moved_into_meta() -> dict[str, Any]:
    request = _request()
    args = dict(request["params"]["arguments"])
    status = args.pop("status")
    request["params"]["arguments"] = args
    request["params"]["_meta"] = {"status": status}
    return request


def _cases() -> list[dict[str, Any]]:
    other = sha256_tag(b"a different tools/call")
    not_dispatched = {"outcome": "REFUSED"}
    rows: list[tuple[str, str, str, dict[str, Any], dict[str, Any] | None, dict[str, str]]] = [
        (
            "intact_pair",
            "all",
            "The pinned package and a bundle for the same call; every axis holds.",
            _capture(_objects()),
            _execution(),
            _expect(E, E, E, E),
        ),
        (
            "one_byte_changed_in_member",
            "package_integrity",
            "One byte of request.json changed; the manifest still names the old digest."
            " The effect bundle is judged on its own.",
            _one_byte_changed(),
            _execution(),
            _expect(C, N, E, N),
        ),
        (
            "manifest_rewritten_to_cover_change",
            "package_integrity",
            "A consistent package for a different tool, presented under the original pin.",
            _manifest_rewritten(),
            _execution(),
            _expect(C, N, E, N),
        ),
        (
            "member_missing",
            "package_integrity",
            "decision.json is listed but absent.",
            _missing_member(),
            _execution(),
            _expect(C, N, E, N),
        ),
        (
            "unlisted_member_added",
            "package_integrity",
            "An extra member the manifest does not list.",
            _unlisted_member(),
            _execution(),
            _expect(C, N, E, N),
        ),
        (
            "unpinned_self_consistent",
            "package_integrity",
            "Every member matches its manifest, but no digest was pinned beforehand.",
            _capture(_objects(), pinned=False),
            _execution(),
            _expect(N, N, E, N),
        ),
        (
            "package_claims_complete_coverage",
            "package_integrity",
            "An intact package with a member asserting complete capture and kernel"
            " attribution; those stay unestablished.",
            _capture(
                dict(
                    _objects(),
                    **{
                        "coverage.json": _dump(
                            {"coverage": "complete", "kernel_to_tool": "attributed"}
                        )
                    },
                )
            ),
            _execution(),
            _expect(E, E, E, E),
        ),
        (
            "argument_members_reordered",
            "request_decision_correspondence",
            "Object member order and JSON-RPC id differ; the call is the same.",
            _capture(_objects(_reordered_request())),
            _execution(),
            _expect(E, E, E, E),
        ),
        (
            "argument_value_changed",
            "request_decision_correspondence",
            "The captured request closes a different state than the pinned call.",
            _capture(_objects(_changed_argument())),
            _execution(),
            _expect(E, C, E, N),
        ),
        (
            "hop_metadata_added",
            "request_decision_correspondence",
            "A later hop added params._meta (progress token, trace context, client audit"
            " context) and a new JSON-RPC id; the call is the same.",
            _capture(_objects(_hop_meta())),
            _execution(),
            _expect(E, E, E, E),
        ),
        (
            "argument_moved_into_meta",
            "request_decision_correspondence",
            "An argument was taken out of arguments and put in params._meta; excluding"
            " _meta does not hide the change.",
            _capture(_objects(_argument_moved_into_meta())),
            _execution(),
            _expect(E, C, E, N),
        ),
        (
            "array_order_changed",
            "request_decision_correspondence",
            "Label order is part of the call.",
            _capture(_objects(_labels_reversed())),
            _execution(),
            _expect(E, C, E, N),
        ),
        (
            "tool_name_changed",
            "request_decision_correspondence",
            "The captured request names another tool.",
            _capture(_objects(_request(name="delete_ticket"))),
            _execution(),
            _expect(E, C, E, N),
        ),
        (
            "decision_bound_to_other_request",
            "request_decision_correspondence",
            "The decision names a different request binding.",
            _capture(
                {"request.json": _dump(_request()), "decision.json": _decision(binding=other)}
            ),
            _execution(),
            _expect(E, C, E, N),
        ),
        (
            "decision_absent",
            "request_decision_correspondence",
            "An intact package that retains the request and no decision.",
            _capture({"request.json": _dump(_request())}),
            _execution(),
            _expect(E, N, E, N),
        ),
        (
            "deny_and_not_dispatched",
            "request_decision_correspondence",
            "A bound deny, and a bundle that shows no dispatch.",
            _capture(_objects(verdict="deny")),
            _execution(dispatch=not_dispatched, execution_report=None, observation=None),
            _expect(E, E, N, C),
        ),
        (
            "bundle_for_other_call",
            "observed_effect",
            "The execution bundle is bound to another call.",
            _capture(_objects()),
            _execution(call_binding=other),
            _expect(E, E, C, C),
        ),
        (
            "dispatched_after_deny",
            "observed_effect",
            "The capture binds a deny and the bundle shows a dispatch.",
            _capture(_objects(verdict="deny")),
            _execution(),
            _expect(E, E, C, C),
        ),
        (
            "observation_contradicts_delta",
            "observed_effect",
            "The independent read shows the ticket still open.",
            _capture(_objects()),
            _execution(
                observation={
                    "source": INDEPENDENT_SOURCE,
                    "fields": {"status": "open", "reopen_count": 0},
                }
            ),
            _expect(E, E, C, C),
        ),
        (
            "bool_is_not_integer",
            "observed_effect",
            "Observed reopen_count is false, not 0.",
            _capture(_objects()),
            _execution(
                observation={
                    "source": INDEPENDENT_SOURCE,
                    "fields": {"status": "closed", "reopen_count": False},
                }
            ),
            _expect(E, E, C, C),
        ),
        (
            "success_reported_without_dispatch",
            "observed_effect",
            "A success report with no dispatch.",
            _capture(_objects()),
            _execution(dispatch=not_dispatched),
            _expect(E, E, C, C),
        ),
        (
            "observation_absent",
            "observed_effect",
            "Dispatched and reported, never read back.",
            _capture(_objects()),
            _execution(observation=None),
            _expect(E, E, N, N),
        ),
        (
            "observation_from_the_tool",
            "observed_effect",
            "The only read is the tool's own account.",
            _capture(_objects()),
            _execution(
                observation={"source": "tool", "fields": {"status": "closed", "reopen_count": 0}}
            ),
            _expect(E, E, N, N),
        ),
        (
            "vacuous_postcondition",
            "observed_effect",
            "No declared fields, so nothing can be observed.",
            _capture(_objects()),
            _execution(postcondition={"tool_id": "update_ticket", "expected_fields": {}}),
            _expect(E, E, N, N),
        ),
        (
            "no_execution_bundle",
            "observed_effect",
            "A capture with no execution evidence at all.",
            _capture(_objects()),
            None,
            _expect(E, E, N, N),
        ),
    ]
    return [
        {"id": cid, "axis": axis, "note": note, "capture": cap, "execution": ex, "expected": exp}
        for cid, axis, note, cap, ex, exp in rows
    ]


def _missing_member() -> dict[str, Any]:
    capture = _capture(_objects())
    del capture["objects"]["decision.json"]
    return capture


def _unlisted_member() -> dict[str, Any]:
    capture = _capture(_objects())
    capture["objects"]["note.txt"] = "added after pinning\n"
    return capture


def render() -> dict[str, str]:
    """Every corpus file, by name, as the exact text it must hold."""
    invocation = _dump(INVOCATION)
    cases = _dump(
        {
            "schema": "aev-invocation-axes-cases/v1",
            "invocation": "invocation.json",
            "invocation_binding": BINDING,
            "binding_rule": (
                "sha256 over RFC 8785 bytes of {method, params without _meta};"
                " the JSON-RPC id, version tag and params._meta are excluded"
            ),
            "result_vocabulary": ["ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"],
            "derived": {
                "effect_under_authority": (
                    "observed effect of this invocation under an allow bound to it;"
                    " a bound deny or a contradicted effect contradicts it, and a"
                    " capture that binds no decision leaves it not established"
                )
            },
            "non_claims": [
                "capture_authenticity",
                "capture_coverage",
                "kernel_to_tool_attribution",
            ],
            "cases": _cases(),
        }
    )
    manifest = _dump(
        {
            "schema": "aev-invocation-axes-corpus/v1",
            "members": {
                "invocation.json": sha256_tag(invocation.encode("utf-8")),
                "cases.json": sha256_tag(cases.encode("utf-8")),
            },
        }
    )
    return {"invocation.json": invocation, "cases.json": cases, "manifest.json": manifest}


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check report whether it is current."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    stale = []
    for name, text in render().items():
        path = CORPUS / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
    if stale:
        print("stale corpus files: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
