#!/usr/bin/env python3
"""Measure the PEER observer prototype's bounded vantage and snapshot gap.

Run with a checkout of the unpublished prototype supplied explicitly:

    /path/to/observer/.venv/bin/python experiments/observer-vantage/run.py \
        --observer-root /path/to/agent-evidence-observer

The report is deterministic apart from changes to the supplied source tree. It
contains no signing keys or timestamped packets. This harness does not create a
security boundary: direct writes are intentionally made by the same process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def source_digest(root: Path) -> str:
    """Bind the result to the package metadata and every package source file."""
    sources = sorted((root / "src" / "probity_observer").rglob("*.py"))
    files = [root / "pyproject.toml", *sources]
    if not sources:
        raise ValueError("observer root lacks package sources")
    if not all(path.is_file() for path in files):
        raise ValueError("observer root lacks pyproject.toml or package sources")
    digest = hashlib.sha256()
    for path in files:
        rel = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(rel).to_bytes(8, "big") + rel)
        digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def make_interval(directory: Path):
    from probity_observer import Broker, SigningKey, Witness

    workspace = directory / "workspace"
    workspace.mkdir()
    observer = SigningKey.generate()
    witness = SigningKey.generate()
    history = directory / "history.jsonl"
    broker = Broker(
        workspace,
        history,
        {"intervalId": "pilot-1", "scope": "/work", "operation": "write-file"},
        observer,
        Witness(directory / "witness-state.json", witness),
    )
    broker.begin()
    return broker, workspace, history, observer.public_hex, witness.public_hex


def run() -> dict[str, object]:
    from probity_observer import VerificationError, verify_packet
    from probity_observer.history import read_history

    with TemporaryDirectory() as directory:
        broker, workspace, history, observer, witness = make_interval(Path(directory))
        # The self-report is an explicit scripted contradiction, not an agent study.
        self_report = "no write"
        broker.write("one", "/work/result", b"effect")
        retry = broker.write("one", "/work/result", b"effect")
        packet = broker.seal()
        claim = verify_packet(packet, history, observer, witness, workspace)
        kinds = [entry["event"]["kind"] for entry in read_history(history)]
        brokered = {
            "scriptedSelfReport": self_report,
            "acceptedWrites": kinds.count("write"),
            "replayedRequests": kinds.count("retry"),
            "retryReturnedPriorEffect": retry.replayed,
            "offlineVerification": True,
            "witnessScope": claim["witnessScope"],
            "noDetectedGap": claim["coverage"]["noDetectedGap"],
        }

    with TemporaryDirectory() as directory:
        broker, workspace, history, observer, witness = make_interval(Path(directory))
        (workspace / "bypass").write_bytes(b"direct")
        packet = broker.seal()
        claim = verify_packet(packet, history, observer, witness)
        try:
            verify_packet(packet, history, observer, witness, workspace)
        except VerificationError:
            workspace_verified = False
        else:
            workspace_verified = True
        durable = {
            "directWriteSucceeded": (workspace / "bypass").read_bytes() == b"direct",
            "knownGap": claim["coverage"]["knownGaps"],
            "offlineVerificationWithWorkspace": workspace_verified,
        }

    with TemporaryDirectory() as directory:
        broker, workspace, history, observer, witness = make_interval(Path(directory))
        bypass = workspace / "bypass"
        bypass.write_bytes(b"transient")
        direct_succeeded = bypass.read_bytes() == b"transient"
        bypass.unlink()
        packet = broker.seal()
        claim = verify_packet(packet, history, observer, witness, workspace)
        transient = {
            "directWriteSucceeded": direct_succeeded,
            "restoredBeforeSnapshot": not bypass.exists(),
            "knownGap": claim["coverage"]["knownGaps"],
            "offlineVerificationWithWorkspace": True,
            "noDetectedGap": claim["coverage"]["noDetectedGap"],
        }

    return {"brokered": brokered, "durableBypass": durable, "transientBypass": transient}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.observer_root.resolve(strict=True)
    digest = source_digest(root)
    sys.path.insert(0, str(root / "src"))
    print(json.dumps({"profile": "local-peer-pilot-v0", "observerSourceSha256": digest, **run()}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
