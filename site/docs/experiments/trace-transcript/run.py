#!/usr/bin/env python3
"""Compare pinned AGT transcript mappers with RFC 8785 on six audit entries.

Requires Python 3.12 and Pydantic 2.13.5. Sources are fetched from immutable
GitHub revisions and checked against their tree blob IDs before import. Pass
``--source-dir`` to use previously retrieved copies with the same blob IDs.
The experiment runs real AuditEntry and mapper code; it does not sign a record
or execute an agent. The JSON result includes source and runtime provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import platform
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

AGT_REVISION = "60931ce0c65db144032cdc8e8f342c66cbb1201c"
RFC8785_REVISION = "655cbe02b8761208e3f4cc49e879ab1e328a7dca"
AGT_BASE = (
    f"https://raw.githubusercontent.com/microsoft/agent-governance-toolkit/{AGT_REVISION}/"
    "agent-governance-python/agent-mesh/src/agentmesh/governance/"
)
SOURCE_PINS = {
    "audit.py": (AGT_BASE + "audit.py", "c9375c709da5ebca67e62d59113c0c42dfd26056"),
    "trace_model.py": (AGT_BASE + "trace_model.py", "44d61be6bd4a5d3fb26544bc869d5cc359671650"),
    "trace_sink.py": (AGT_BASE + "trace_sink.py", "8aa9f5c3658290d7fb9d73fc7044e65961919451"),
    "rfc8785_impl.py": (
        f"https://raw.githubusercontent.com/trailofbits/rfc8785.py/{RFC8785_REVISION}/"
        "src/rfc8785/_impl.py",
        "2c1062d4dfdc97f0c50a3ebffab378de95783547",
    ),
}
SUBJECT = "did:web:example.org:agent"


def read_source(name: str, source_dir: Path | None) -> bytes:
    """Read one source and require its exact pinned Git blob ID.

    Parameters
    ----------
    name : str
        A filename in :data:`SOURCE_PINS`.
    source_dir : Path or None
        Directory containing retrieved source copies, or None to fetch the
        immutable URL. Cached files are verified by the same rule.

    Returns
    -------
    bytes
        Unmodified source bytes.

    Raises
    ------
    RuntimeError
        If the source differs from the pinned tree blob.
    """
    url, expected = SOURCE_PINS[name]
    if source_dir is None:
        request = urllib.request.Request(url, headers={"User-Agent": "probity-atlas-experiment"})
        with urllib.request.urlopen(request, timeout=15) as response:
            content = response.read()
    else:
        content = (source_dir / name).read_bytes()
    header = b"blob " + str(len(content)).encode() + b"\0"
    actual = hashlib.sha1(header + content).hexdigest()
    if actual != expected:
        raise RuntimeError(f"Pinned source mismatch for {name}: {actual} != {expected}")
    return content


def load_modules(source_root: Path) -> tuple[ModuleType, ModuleType, ModuleType, ModuleType]:
    """Load only the pinned audit, mapper, sink, and canonicalizer modules.

    Parameters
    ----------
    source_root : Path
        Temporary directory containing the source bytes from :func:`read_source`.

    Returns
    -------
    tuple of ModuleType
        The unchanged implementations. A synthetic package routes relative
        imports without loading unrelated AGT modules.
    """
    package = ModuleType("agt_byte_experiment")
    package.__path__ = [str(source_root)]
    sys.modules[package.__name__] = package
    audit = importlib.import_module(f"{package.__name__}.audit")
    model = importlib.import_module(f"{package.__name__}.trace_model")
    sink = importlib.import_module(f"{package.__name__}.trace_sink")
    spec = importlib.util.spec_from_file_location("rfc8785_impl", source_root / "rfc8785_impl.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the pinned RFC 8785 implementation")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    return audit, model, sink, oracle


def evaluate_case(
    name: str,
    data: dict[str, Any],
    modules: tuple[ModuleType, ModuleType, ModuleType, ModuleType],
) -> dict[str, Any]:
    """Hash one real audit entry through both mapper paths and the oracle.

    Parameters
    ----------
    name : str
        Stable case identifier.
    data : dict of str to Any
        Audit data varying one byte-format property per case.
    modules : tuple of ModuleType
        Modules returned by :func:`load_modules`.

    Returns
    -------
    dict of str to Any
        The varied input, exact digests, and agreement flags. The transcript
        includes the real chain hashes assigned by MerkleAuditChain.
    """
    audit, model, sink, oracle = modules
    entry = audit.AuditEntry(
        entry_id="audit_fixed",
        timestamp=datetime(2026, 9, 30, tzinfo=UTC),
        event_type="tool_invocation",
        agent_did=SUBJECT,
        action="write",
        data=data,
        session_id="session_fixed",
        sandbox_id="fixed",
        environment="fixed",
        compute_driver="fixed",
    )
    log = audit.AuditLog()
    log._chain.add_entry(entry)
    config = model.TraceModelConfig(
        model={}, runtime={}, enforcement_mode="enforce", build_provenance={}, verifier="test"
    )
    session = model.TraceSession(SUBJECT, [entry], "internal")
    model_record = model.session_to_trust_record(session, config)
    sink_record = sink.session_to_trust_record(
        SUBJECT, log, "sha256:" + "0" * 64, sink.TraceConfig("unused.json")
    )
    canonical = oracle.dumps([entry.model_dump(mode="json")])
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    model_hash = model_record["tool_transcript"]["hash"]
    sink_hash = sink_record["tool_transcript"]["hash"]
    return {
        "case": name,
        "data": data,
        "model_hash": model_hash,
        "sink_hash": sink_hash,
        "rfc8785_hash": expected,
        "model_equals_sink": model_hash == sink_hash,
        "model_equals_rfc8785": model_hash == expected,
        "sink_equals_rfc8785": sink_hash == expected,
    }


def main() -> None:
    """Print the deterministic report with source and runtime provenance."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, help="Use cached exact source blobs")
    args = parser.parse_args()
    sources = {name: read_source(name, args.source_dir) for name in SOURCE_PINS}
    cases = [
        ("ascii-control", {"value": "plain"}),
        ("non-ascii-value", {"value": "\u00e9"}),
        ("utf16-key-order", {"\ue000": "bmp", "\U00010000": "supplementary"}),
        ("integer-valued-float", {"latency": 1.0}),
        ("negative-zero", {"latency": -0.0}),
        ("small-float", {"latency": 0.000001}),
    ]
    with tempfile.TemporaryDirectory() as temporary:
        source_root = Path(temporary)
        for name, content in sources.items():
            (source_root / name).write_bytes(content)
        modules = load_modules(source_root)
        report = {
            "agt_revision": AGT_REVISION,
            "rfc8785_revision": RFC8785_REVISION,
            "python": platform.python_version(),
            "pydantic": importlib.metadata.version("pydantic"),
            "source_sha256": {
                name: hashlib.sha256(content).hexdigest()
                for name, content in sorted(sources.items())
            },
            "scope": "Real AuditEntry and session mapping functions; no signing or live agent run",
            "cases": [evaluate_case(name, data, modules) for name, data in cases],
        }
    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
