"""Answer a NENRIN TSUNAGI batch with the Atlas action-presence reader.

The referee writes ``[{"name": case, "bundle": fixture}, ...]`` to ``{in}`` and
reads ``{case: {"verdict", "refusals", "findings"}}`` from ``{out}``. Each value
is the reader's own ``assess(bundle)["signature"]``: no verdict or code is
renamed, and an unsupported bundle stays ``unsupported`` so the referee scores
it as not reproduced.
"""

import json
import sys
from pathlib import Path

from reader import assess, decode_json

MAX_BATCH_BYTES = 16 * 1024 * 1024


class BatchError(ValueError):
    """The batch file is outside the referee's input contract."""


def answer(raw: bytes) -> dict:
    """Return one reader signature per named case, refusing a malformed batch."""
    if len(raw) > MAX_BATCH_BYTES:
        raise BatchError("batch exceeds 16 MiB")
    cases = decode_json(raw)
    if not isinstance(cases, list) or not cases:
        raise BatchError("batch must be a nonempty array")
    output = {}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"name", "bundle"}:
            raise BatchError("batch case must contain only name and bundle")
        name = case["name"]
        if not isinstance(name, str) or not name or name in output:
            raise BatchError("batch case name must be nonempty and unique")
        output[name] = assess(case["bundle"])["signature"]
    return output


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: batch.py <in.json> <out.json>", file=sys.stderr)
        return 2
    try:
        output = answer(Path(args[0]).read_bytes())
    except (OSError, ValueError, RecursionError) as error:
        print("batch refused: " + str(error), file=sys.stderr)
        return 2
    Path(args[1]).write_text(
        json.dumps(output, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
