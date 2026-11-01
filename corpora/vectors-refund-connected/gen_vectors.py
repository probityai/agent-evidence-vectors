"""Build the refund-connected manifest from the retained run trees, byte for byte.

The corpus is two retained runs of the connected refund pilot (J01), copied from
``examples/checkout-runner/connected/runs`` at commit
``dcc07c3cdde0ca4beab6f7b5afe6a7e15801eb58`` of the pilot's repository. Run r2 is
the run in which every layer held; run r1 is the run before the dispatch-window
fix, which stopped at an execution step. The manifest records, for every case of
every run, the verdict the reference reader derives at each of the six steps from
the retained bytes alone, and the digest of every file.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import refundconnected as reader  # noqa: E402

SUITE = reader.SUITE
SOURCE_COMMIT = "dcc07c3cdde0ca4beab6f7b5afe6a7e15801eb58"
SOURCE_PATH = "examples/checkout-runner/connected/runs"
RUNS = {
    "r1": "source/j01-connected-20261028-r1",
    "r2": "source/j01-connected-20261028-r2",
}
NOTE = {
    "r1": "run before the dispatch-window fix: the executor stopped before it dispatched",
    "r2": "run after the fix: every layer held and each effect is bound to its operation",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def run_files(root: Path, rel: str) -> dict[str, str]:
    """Every file of one run tree with its SHA-256, keyed by path inside the tree."""
    base = root / rel
    return {
        p.relative_to(base).as_posix(): _sha(p.read_bytes())
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }


def corpus_digest(manifest: dict[str, Any], root: str | Path = ROOT) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    runs = {}
    for key, entry in manifest["runs"].items():
        files = run_files(base, entry["path"])
        if files != entry["files"]:
            raise ValueError(f"{key}: the run tree differs from the manifest")
        runs[key] = {**entry, "files": files}
    return _sha(_json({"runs": runs, "vectors": manifest["vectors"]}))


def _outcome(steps: dict[str, str]) -> str:
    """One word per vector, from the statuses its steps carry.

    The corpus has no accept/reject split because its expectation is a table of step
    statuses. A vector counts as `refused` when any step is refused, `established`
    when every step is established, and `not_established` otherwise.
    """
    statuses = list(steps.values())
    if any(status.startswith("REFUSED") for status in statuses):
        return "refused"
    if all(status == "ESTABLISHED" for status in statuses):
        return "established"
    return "not_established"


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write the manifest from the run trees and return it."""
    runs = {
        key: {"files": run_files(root, rel), "note": NOTE[key], "path": rel}
        for key, rel in RUNS.items()
    }
    vectors = []
    for key, rel in RUNS.items():
        result = reader.judge_run(root / rel)
        for case, steps in result["cases"].items():
            vectors.append(
                {
                    "case": case,
                    "expected": {"run_checks": result["run_checks"], "steps": steps},
                    "id": f"{key}-{case}",
                    "path": rel,
                    "run": key,
                }
            )
    manifest = {
        "contractId": "https://probityai.github.io/agent-evidence-vectors/contract/refund-connected/v1",
        "runs": runs,
        "source": {"commit": SOURCE_COMMIT, "path": SOURCE_PATH},
        "suite": SUITE,
        "vectors": vectors,
    }
    outcomes = [_outcome(entry["expected"]["steps"]) for entry in vectors]
    manifest["counts"] = {word: outcomes.count(word) for word in sorted(set(outcomes))}
    manifest["corpusDigest"] = corpus_digest(manifest, root)
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    out = generate()
    print(f"wrote {len(out['vectors'])} vectors, corpusDigest {out['corpusDigest']}")
