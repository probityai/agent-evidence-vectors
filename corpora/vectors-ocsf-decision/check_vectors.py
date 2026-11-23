"""Judge every OCSF decision-record member with agent-evidence-verify and check the corpus digest.

1. The corpus digest recomputes.
2. Every member reads, under the profile it names, to the verdict and code MANIFEST.json declares,
   and every dimension status the entry declares is the one the report gives.

The judge is ``agent_evidence_verify.ocsf_decision``. Without it the check exits 2 and says it did
not run: absence is never a pass.

    uv run --with agent-evidence-verify python corpora/vectors-ocsf-decision/check_vectors.py
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

from digest import corpus_digest

HERE = Path(__file__).resolve().parent


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in items:
        if key in out:
            raise ValueError(f"repeated member {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> object:
    raise ValueError(f"non-finite constant {name}")


def _strict(text: str | bytes) -> Any:
    """Parse one JSON text, refusing a repeated member and NaN, Infinity or -Infinity."""
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)


def declared_differences(report: dict, declared: dict) -> list[str]:
    out = []
    for name, want in declared.items():
        if name == "strict":
            out += [
                f"strict.{k}: declared {v}, read {report['strict'][k]['status']}"
                for k, v in want.items()
                if report["strict"][k]["status"] != v
            ]
        elif report[name]["status"] != want:
            out.append(f"{name}: declared {want}, read {report[name]['status']}")
    return out


def main() -> int:
    try:
        # Loaded by name: the package is installed only where this check runs
        # (CI pins it), so the type gate must not resolve it from the repo env.
        ocsf_decision = importlib.import_module("agent_evidence_verify.ocsf_decision")
    except ImportError:
        print(
            "ocsf-decision: NOT RUN: agent-evidence-verify with the ocsf_decision reader is not "
            "installed"
        )
        return 2
    manifest = _strict((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    failures = []
    for entry in manifest["vectors"]:
        member = _strict((HERE / entry["path"]).read_bytes())
        report, verdict, code = ocsf_decision.read_member(member)
        want = entry["expected"]
        if (verdict, code) != (want["verdict"], want["code"]):
            failures.append(
                f"{entry['id']}: read {verdict} {code}, declared {want['verdict']} {want['code']}"
            )
        failures += [
            f"{entry['id']}: {d}" for d in declared_differences(report, want["dimensions"])
        ]
    if corpus_digest(manifest, str(HERE)) != manifest["corpusDigest"]:
        failures.append("corpusDigest does not recompute")
    for line in failures:
        print(f"FAIL {line}")
    print(f"ocsf-decision: {len(manifest['vectors'])} members, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
