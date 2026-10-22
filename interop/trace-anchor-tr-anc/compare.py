"""Grade TRACE's TR-ANC-002 at each pinned commit and hold it to its record.

For every pin in ``pins.json`` this fetches the five stdlib-only files the
check imports from the public commit, refuses any whose SHA-256 differs from
the pin, lays them out as the ``trace_tests`` package, and replays every
vectors-trace-anchor case through ``tr_anc_reader.py``, compared on decision.

The set of members on which a pin disagrees with the corpus must equal the set
recorded for it, exactly. A new disagreement fails, and so does a recorded one
that went away, because either one means the record no longer describes the
code it names.

    python3 interop/trace-anchor-tr-anc/compare.py <capture-dir>
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import traceanchor  # noqa: E402


def fetch(pin: dict[str, object], files: dict[str, str], repository: str, into: Path) -> None:
    raw = repository.replace("https://github.com/", "https://raw.githubusercontent.com/")
    digests = pin["sha256"]
    assert isinstance(digests, dict)
    for local, remote in files.items():
        url = f"{raw}/{pin['commit']}/{remote}"
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 (pinned https)
            data = response.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != digests[local]:
            raise SystemExit(f"{pin['label']}: {local} is {actual}, pinned {digests[local]}")
        target = into / local
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def main() -> int:
    capture = Path(sys.argv[1])
    capture.mkdir(parents=True, exist_ok=True)
    config = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
    reader = f"{sys.executable} {HERE / 'tr_anc_reader.py'}"
    failed = False
    summary = []
    for number, pin in enumerate(config["pins"]):
        source = capture / f"pin-{number}"
        fetch(pin, config["files"], config["repository"], source)
        os.environ["TRACE_CONFORMANCE_SRC"] = str(source)
        answered, errors = traceanchor.check(reader, decision_only=True)
        total = len(json.loads((traceanchor.ROOT / "MANIFEST.json").read_text("utf-8"))["vectors"])
        observed = {error.split(":", 1)[0] for error in errors}
        recorded = set(pin["disagreements"])
        line = (f"{pin['label']} ({pin['commit'][:12]}): answered {answered} of {total}, "
                f"agrees on {total - len(observed)}, disagrees on {len(observed)}")
        print(line)
        summary.append({"label": pin["label"], "commit": pin["commit"], "answered": answered,
                        "total": total, "disagreements": sorted(observed), "errors": errors})
        if answered != total:
            print("  not every case was answered")
            failed = True
        for name in sorted(observed - recorded):
            print(f"  new disagreement: {name}")
            failed = True
        for name in sorted(recorded - observed):
            print(f"  recorded disagreement no longer observed: {name}")
            failed = True
    (capture / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
