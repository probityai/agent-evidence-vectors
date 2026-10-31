#!/usr/bin/env python3
"""Replay the pinned observer admission demo and require bounded refusals.

Requires Linux, Python 3.12.14, and cryptography 46.0.7. All observer package
sources and the unchanged demonstration are checked against immutable Git blob
IDs before private copies are imported. Public keys in a retained bundle are
author-produced fixture pins; they do not establish independent custody.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import logging
import platform
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
PINS = json.loads((ROOT / "source-pins.json").read_text(encoding="utf-8"))
EXPECTED_AUTHORITY = {
    "intervalId": "admission-demo-1", "scope": "/work", "operation": "write-file"
}
EXPECTED_EFFECT = b"one durable effect\n"
REPLAY_REFUSAL = "interval was already admitted by this consumer"
LOGGER = logging.getLogger("atlas.observer_admission")


def capture_sources(observer_root: Path, destination: Path) -> dict[str, str]:
    """Verify and privately copy every imported observer source.

    Parameters
    ----------
    observer_root : Path
        Checkout of the revision recorded in ``source-pins.json``.
    destination : Path
        Empty private directory receiving exact source bytes.

    Returns
    -------
    dict of str to str
        SHA-256 for every checked source, keyed by repository path.

    Raises
    ------
    RuntimeError
        If a pinned file is missing, altered, or the package has extra Python
        sources. Imports occur only after every file passes this check.
    """
    expected = set(PINS["files"])
    package = observer_root / "src" / "probity_observer"
    found = {path.relative_to(observer_root).as_posix() for path in package.rglob("*.py")}
    if found != {path for path in expected if path.startswith("src/")}:
        raise RuntimeError("observer package source set differs from the pins")
    hashes: dict[str, str] = {}
    for name, blob in sorted(PINS["files"].items()):
        content = (observer_root / name).read_bytes()
        header = b"blob " + str(len(content)).encode("ascii") + b"\0"
        if hashlib.sha1(header + content).hexdigest() != blob:
            raise RuntimeError(f"pinned observer source mismatch: {name}")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    return hashes


def load_observer(source_root: Path) -> tuple[ModuleType, ModuleType, ModuleType]:
    """Import the private checked package and its unchanged demonstration.

    Parameters
    ----------
    source_root : Path
        Private source tree written by :func:`capture_sources`.

    Returns
    -------
    tuple of ModuleType
        Observer API, byte primitives, and original demonstration module.

    Raises
    ------
    RuntimeError
        If a different observer is already imported, the module cannot load,
        or the pinned experiment runtime is unavailable.
    """
    if "probity_observer" in sys.modules:
        raise RuntimeError("observer was imported before source verification")
    if platform.python_version() != "3.12.14" or importlib.metadata.version("cryptography") != "46.0.7":
        raise RuntimeError("experiment requires Python 3.12.14 and cryptography 46.0.7")
    sys.path.insert(0, str(source_root / "src"))
    observer = importlib.import_module("probity_observer")
    crypto = importlib.import_module("probity_observer.crypto")
    spec = importlib.util.spec_from_file_location("pinned_admission_demo", source_root / "examples" / "admission_demo.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the pinned observer demonstration")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    return observer, crypto, demo


def require_refusal(operation: Callable[[], Any], error_type: type[Exception], expected: str) -> str:
    """Require an actual refusal with its exact bounded reason.

    Parameters
    ----------
    operation : Callable
        Admission operation to exercise with real verification and storage.
    error_type : type of Exception
        The pinned observer's verification exception.
    expected : str
        Exact expected reason; unrelated failures must propagate.

    Returns
    -------
    str
        Verified refusal reason.

    Raises
    ------
    RuntimeError
        If admission succeeds or refuses for a different reason. The latter
        is logged without packet contents, key bytes, or source credentials.
    """
    try:
        operation()
    except error_type as exc:
        if str(exc) != expected:
            LOGGER.error("unexpected refusal reason: %s", exc)
            raise RuntimeError("observer refusal differs from the expected reason") from exc
        return str(exc)
    raise RuntimeError("observer unexpectedly admitted a negative control")


def check_manifest(bundle: Path, manifest: Path) -> None:
    """Require the exact file set and SHA-256 values of retained CI bytes.

    Parameters
    ----------
    bundle : Path
        Published artifact directory containing the eight retained evidence files.
    manifest : Path
        Public provenance JSON containing a ``fileSha256`` mapping. This is
        an integrity record by the author, not an independent witness.

    Raises
    ------
    RuntimeError
        If a file is added, removed, or changed relative to that record.
    """
    expected = json.loads(manifest.read_text(encoding="utf-8"))["fileSha256"]
    actual = {path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(bundle.rglob("*")) if path.is_file()}
    if actual != expected:
        raise RuntimeError("retained bundle differs from its file manifest")


def evaluate_bundle(bundle: Path, observer: ModuleType, crypto: ModuleType) -> dict[str, Any]:
    """Re-admit retained bytes, check durable state, and exercise three refusals.

    Parameters
    ----------
    bundle : Path
        Original demo output, including policy, decision, state, signed packet,
        broker history, receipt log, and durable file bytes.
    observer, crypto : ModuleType
        Checked modules returned by :func:`load_observer`.

    Returns
    -------
    dict of str to Any
        Deterministic outcomes excluding generated public keys and timestamps.

    Raises
    ------
    RuntimeError
        If a retained artifact, decision, effect, or refusal differs from the
        declared fixture. Verification failures are never counted as success.

    Notes
    -----
    Scratch consumer stores preserve the published bundle unchanged. This is
    a protocol replay by the author, with same-operator fixture key pins.
    """
    producer, consumer = bundle / "producer", bundle / "consumer"
    packet = crypto.strict_loads((producer / "packet.json").read_bytes())
    policy = observer.AdmissionPolicy(**crypto.strict_loads((consumer / "policy.json").read_bytes()))
    history, ledger = producer / "history.jsonl", producer / "ledger.jsonl"
    if policy.interval_id != EXPECTED_AUTHORITY["intervalId"] or policy.authority_digest != crypto.digest("probity-authority-v0", EXPECTED_AUTHORITY):
        raise RuntimeError("retained policy differs from the declared fixture authority")
    effect = (producer / "workspace" / "result.txt").read_bytes()
    if effect != EXPECTED_EFFECT:
        raise RuntimeError("retained durable effect differs from the fixture")
    observer.verify_packet(packet, history, policy.observer_key, policy.witness_key, producer / "workspace")
    retained_decision = crypto.strict_loads((consumer / "decision.json").read_bytes())
    retained_state = crypto.strict_loads((consumer / "state.json").read_bytes())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        store = observer.AdmissionStore(root / "replay.json")
        store.initialize(policy.observer_key, policy.witness_key)
        decision = store.admit(packet, history, ledger, policy)
        state_before = store.state_path.read_bytes()
        if decision != retained_decision or state_before != (consumer / "state.json").read_bytes():
            raise RuntimeError("replayed decision or durable state differs from the retained bundle")
        replay = require_refusal(lambda: store.admit(packet, history, ledger, policy), observer.VerificationError, REPLAY_REFUSAL)
        if store.state_path.read_bytes() != state_before:
            raise RuntimeError("replay refusal changed consumer state")
        wrong_authority = replace(policy, authority_digest=crypto.digest("probity-authority-v0", {**EXPECTED_AUTHORITY, "scope": "/other"}))
        authority_refusal = _fresh_refusal(root / "authority.json", packet, history, ledger, wrong_authority, observer, "packet authority differs from consumer policy")
        changed_packet = copy.deepcopy(packet)
        changed_packet["claim"]["afterRoot"] = "0" * 64
        tamper_refusal = _fresh_refusal(root / "tamper.json", changed_packet, history, ledger, policy, observer, "signature does not verify under the pinned key")
    expected_demo = {
        "status": "demo-passed", "intervalId": policy.interval_id,
        "admissionStatus": "admitted", "replayRefusal": replay,
        "witnessScope": "PEER", "evidence_vantage": "artifact",
        "operator": "same-operator-fixture",
    }
    if crypto.strict_loads((bundle / "demo-report.json").read_bytes()) != expected_demo:
        raise RuntimeError("retained demo report differs from verified outcomes")
    return {
        **expected_demo, "authorityRefusal": authority_refusal,
        "tamperRefusal": tamper_refusal, "refusalsPreserveState": True,
        "admissionCount": len(retained_state["admissions"]),
        "ledgerReceiptCount": decision["ledger"]["count"],
        "effectSha256": hashlib.sha256(effect).hexdigest(),
        "afterRoot": decision["afterRoot"],
        "coverage": packet["claim"]["coverage"],
    }


def _fresh_refusal(state: Path, packet: dict[str, Any], history: Path, ledger: Path,
                   policy: Any, observer: ModuleType, reason: str) -> str:
    """Exercise a negative control before replay protection can mask its cause."""
    store = observer.AdmissionStore(state)
    store.initialize(policy.observer_key, policy.witness_key)
    before = state.read_bytes()
    refusal = require_refusal(lambda: store.admit(packet, history, ledger, policy), observer.VerificationError, reason)
    if state.read_bytes() != before:
        raise RuntimeError("negative-control refusal changed consumer state")
    return refusal


def main() -> None:
    """Run an actual demo or verify a retained bundle against the recorded result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer-root", required=True, type=Path)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--output", type=Path, help="Run the original demo into an empty directory")
    choice.add_argument("--bundle", type=Path, help="Verify an existing demo bundle without modifying it")
    parser.add_argument("--expect", type=Path, help="Require the complete deterministic report to match")
    parser.add_argument("--manifest", type=Path, help="Require exact retained CI bundle bytes")
    args = parser.parse_args()
    if args.manifest is not None:
        if args.bundle is None:
            parser.error("--manifest requires --bundle")
        check_manifest(args.bundle, args.manifest)
    with tempfile.TemporaryDirectory() as directory:
        sources = Path(directory) / "sources"
        hashes = capture_sources(args.observer_root.resolve(), sources)
        observer, crypto, demo = load_observer(sources)
        bundle = args.bundle
        if args.output is not None:
            demo.run_demo(args.output)
            bundle = args.output
        report = {"observerRevision": PINS["revision"], "sourceSha256": hashes,
                  "scope": "author-produced same-operator fixture; no independent custody or live agent",
                  "outcomes": evaluate_bundle(bundle, observer, crypto)}
        if args.expect is not None and report != json.loads(args.expect.read_text(encoding="utf-8")):
            raise RuntimeError("experiment report differs from the recorded result")
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))


if __name__ == "__main__":
    main()
