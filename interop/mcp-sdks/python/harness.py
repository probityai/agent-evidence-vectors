# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp==2.3.0"]
# ///
"""Decode and re-encode each JSON-RPC line the way the Python SDK's stdio
transports do: types.jsonrpc_message_adapter.validate_json(line, by_name=False),
then model_dump_json(by_alias=True, exclude_unset=True). Only a pydantic
ValidationError counts as a refusal; any other exception stops the run."""

import base64
import sys

from mcp import types
from pydantic import ValidationError

for line in sys.stdin:
    line = line.rstrip("\n")
    try:
        msg = types.jsonrpc_message_adapter.validate_json(line, by_name=False)
        wire = msg.model_dump_json(by_alias=True, exclude_unset=True)
        sys.stdout.write("OK " + base64.b64encode(wire.encode("utf-8")).decode() + "\n")
    except ValidationError as exc:
        sys.stdout.write("ERR " + str(exc).replace("\n", " ")[:200] + "\n")
