"""Compare one served MCP tool with a previously trusted definition digest."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from run_vectors import jcs_dumps

PROFILE = "agentavow.mcp-tool-definition.v1"
FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_INTEGER = 2**53 - 1


class InvalidInput(ValueError):
    pass


def _json_domain(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise InvalidInput("definition contains an invalid Unicode scalar") from exc
        return
    if type(value) is int and -SAFE_INTEGER <= value <= SAFE_INTEGER:
        return
    if isinstance(value, list):
        for item in value:
            _json_domain(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _json_domain(key)
            _json_domain(item)
        return
    raise InvalidInput("definition is outside the bounded JSON domain")


def definition_digest(tool: dict[str, Any]) -> str:
    """Digest the six visible fields under the published v1 profile label."""
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
        raise InvalidInput("tool name is missing")
    selected = {key: tool[key] for key in FIELDS if tool.get(key) is not None}
    _json_domain(selected)
    preimage = jcs_dumps({"profile": PROFILE, "tool": selected})
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def compare(pin: dict[str, Any], capture: dict[str, Any]) -> dict[str, str]:
    """Return a named-tool match, change, or an unresolved capture."""
    if not isinstance(pin, dict) or set(pin) != {"endpoint", "toolName", "toolDigest"}:
        raise InvalidInput("pin fields differ")
    if not isinstance(capture, dict) or set(capture) != {"endpoint", "tools"}:
        raise InvalidInput("capture fields differ")
    endpoint, name, wanted = pin["endpoint"], pin["toolName"], pin["toolDigest"]
    if (
        not isinstance(endpoint, str)
        or not endpoint.startswith("https://")
        or not isinstance(name, str)
        or not name
        or not isinstance(wanted, str)
        or not SHA256.fullmatch(wanted)
    ):
        raise InvalidInput("pin values differ")
    if capture["endpoint"] != endpoint:
        return {"verdict": "not_established", "reason": "endpoint_differs"}
    tools = capture["tools"]
    if not isinstance(tools, list) or any(not isinstance(t, dict) for t in tools):
        raise InvalidInput("tools/list is not a list of objects")
    named = [tool for tool in tools if tool.get("name") == name]
    if not named:
        return {"verdict": "not_established", "reason": "tool_missing"}
    if len(named) != 1:
        return {"verdict": "not_established", "reason": "name_ambiguous"}
    try:
        seen = definition_digest(named[0])
    except InvalidInput:
        return {"verdict": "not_established", "reason": "definition_unreadable"}
    return {
        "verdict": "match" if seen == wanted else "changed",
        "reason": "digest_matches" if seen == wanted else "digest_differs",
        "observedDigest": seen,
    }
