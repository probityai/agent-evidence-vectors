"""The Python reference reader over a list of report files, one JSON line each.

Run inside an interpreter that has agent-evidence-vectors installed at the
release under test:

    python -I py_reader.py <list-file> <out.jsonl>

It calls what that release exposes, in the order a reader applies them:
``shape_errors`` and then ``rejections``. A file that does not parse, or on
which the reader raises, is recorded as cannot-read with the reason.
"""

import json
import sys

from agent_evidence_vectors import w3creport


def read(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read()
        load = getattr(w3creport, "load_json", None)
        report = load(data) if load else json.loads(data)
    except Exception as exc:  # noqa: BLE001 - a reader that cannot parse is reported as such
        return {"outcome": "cannot-read", "cited": [], "note": f"{type(exc).__name__}: {exc}"[:300]}
    try:
        shape = w3creport.shape_errors(report)
        if shape:
            return {"outcome": "rejected", "cited": ["shape"], "note": "; ".join(shape)[:300]}
        rejected = sorted(w3creport.rejections(report))
    except Exception as exc:  # noqa: BLE001 - a reader that raises did not read the file
        return {"outcome": "cannot-read", "cited": [],
                "note": f"reader raised {type(exc).__name__}: {exc}"[:300]}
    return {"outcome": "rejected" if rejected else "conforms", "cited": rejected, "note": ""}


def main(listing, out):
    with open(listing, encoding="utf-8") as handle:
        paths = [p for p in handle.read().split("\n") if p]
    with open(out, "w", encoding="utf-8") as handle:
        for path in paths:
            handle.write(json.dumps({"file": path, **read(path)}, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
