"""Check the original native packet and meaningful host refusal boundaries."""
from __future__ import annotations

import argparse
import importlib.util
import json
import marshal
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location("consumer", Path(__file__).with_name("consumer.py"))
consumer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(consumer)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(checkout: Path, archive: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    original = output / "installation"
    replacement = output / "replacement"
    first = consumer.install(checkout, original)
    second = consumer.install(checkout, replacement)
    require(first["build"]["sources"] == second["build"]["sources"], "replacement source selection changed")
    require(first["build"]["wheel"] == second["build"]["wheel"], "same-toolchain wheel replacement changed")
    actual = consumer.evaluate(original, archive, output / "original")
    replaced = consumer.evaluate(replacement, archive, output / "replacement-replay")
    require(actual["publicationDecision"] == "publish-scoped-report", "original evidence failed publication")
    require(actual["modelQualityDecision"] == "hold-quality", "weak original model quality was admitted")
    require(actual["effectDecision"] == "hold-no-effect-authorization", "packet granted effect authority")
    reader = actual["reader"]
    report = reader["report"]
    require(report["population"] == {"planned": 128, "started": 128, "scored": 128,
            "error": 0, "unsupported": 0, "incomplete": 0, "unknown-start": 0}, "native population changed")
    require(len(reader["qualityFailures"]) == len(report["quality"]) == 8, "quality policy did not hold all eight rows")
    require(all(row["formatValid"] == row["schemaValid"] == row["planned"] == row["scored"] == 16
                for row in report["quality"]), "row denominators changed")
    require(actual["reader"] == replaced["reader"], "replacement changed the valid contract result")
    require(actual["repeatStructuredDecisionExact"] and replaced["repeatStructuredDecisionExact"], "repeat failed")
    source_pin = consumer.selection()["sourceContract"]["files"][consumer.PACKAGE + "/schema_contract.py"]
    selected_source = checkout / source_pin["path"]
    reviewed_source = selected_source.read_bytes()
    try:
        selected_source.write_bytes(reviewed_source + b"\n# altered checkout source\n")
        try:
            consumer.install(checkout, output / "changed-source-install")
        except subprocess.CalledProcessError:
            source_refused = True
        else:
            source_refused = False
        require(source_refused, "changed selected source was built into the host reader")
    finally:
        selected_source.write_bytes(reviewed_source)
    changed_archive = output / "changed-archive.zip"
    raw = bytearray(archive.read_bytes())
    raw[len(raw) // 2] ^= 1
    changed_archive.write_bytes(raw)
    archive_refusal = consumer.evaluate(original, changed_archive, output / "archive-refusal")
    require(archive_refusal["publicationDecision"] == "hold-evidence", "changed ZIP was published")
    require("archive bytes differ" in archive_refusal["error"]["message"], "changed ZIP was not refused at authentication")
    changed_archive.unlink()
    with tempfile.TemporaryDirectory(prefix="host-refusal-packet-") as temporary:
        packet = Path(temporary)
        consumer.unpack(archive, packet)
        require(report == json.loads((packet / "report.json").read_bytes()), "reader did not reconstruct the original report")
        (packet / "terminal.json").write_text('{"elapsed_ns":1}\n')
        directory = output / "terminal-refusal"
        directory.mkdir()
        terminal_refusal = consumer.replay(original, packet, directory)
        require(terminal_refusal["publicationDecision"] == "hold-evidence", "changed terminal was published")
    with tempfile.TemporaryDirectory(prefix="host-refusal-helper-") as temporary:
        packet = Path(temporary)
        consumer.unpack(archive, packet)
        helper = packet / "sources/schema_contract.py"
        helper.write_bytes(helper.read_bytes() + b"\nraise RuntimeError('candidate code must not execute')\n")
        # A candidate can rewrite its manifest and convenience pins. Neither
        # changes the receiving project's selected pins or installed code.
        manifest = json.loads((packet / "manifest.json").read_bytes())
        manifest["sources/schema_contract.py"] = consumer.sha(helper.read_bytes())
        consumer.save(packet / "manifest.json", manifest)
        consumer.save(packet / "selected-pins.json", {"manifest": consumer.sha((packet / "manifest.json").read_bytes())})
        directory = output / "helper-refusal"
        directory.mkdir()
        helper_refusal = consumer.replay(original, packet, directory)
        require(helper_refusal["publicationDecision"] == "hold-evidence", "candidate helper override was accepted")
        require(not any("RuntimeError" in str(call) for call in helper_refusal.values()), "candidate code executed")
    site = consumer.verify_installation(original)
    package = site / consumer.PACKAGE / "cli.py"
    marker = output / "candidate-bytecode-executed"
    cache = package.parent / "__pycache__"
    cache.mkdir()
    cache_file = Path(importlib.util.cache_from_source(str(package)))
    metadata = package.stat()
    malicious = compile("from pathlib import Path\nPath(" + repr(str(marker.resolve())) +
                        ").write_text('executed')\nraise SystemExit(79)\n", str(package), "exec")
    cache_file.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack("<III", 0,
                           int(metadata.st_mtime) & 0xffffffff, metadata.st_size & 0xffffffff)
                           + marshal.dumps(malicious))
    # Positive control proves this is usable timestamp/size-matched bytecode.
    # Only this test invokes the deliberately unsafe import, before the gate.
    probe = subprocess.run([str(original / "env/bin/python"), "-I", "-S", "-c",
                            "import sys;sys.path.insert(0,sys.argv[1]);import " + consumer.PACKAGE + ".cli",
                            str(site)], capture_output=True, env=consumer.environment(), timeout=30, check=False)
    require(probe.returncode == 79 and marker.read_text() == "executed", "poisoned bytecode control was inert")
    marker.unlink()
    bytecode_refusal = consumer.evaluate(original, archive, output / "bytecode-refusal")
    require(bytecode_refusal["publicationDecision"] == "hold-evidence" and not marker.exists(),
            "cached bytecode executed before source authentication")
    cache_file.unlink()
    for path in cache.iterdir():
        path.unlink()
    cache.rmdir()
    extra = package.parent / "extra-directory"
    extra.mkdir()
    directory_refusal = consumer.evaluate(original, archive, output / "directory-refusal")
    require(directory_refusal["publicationDecision"] == "hold-evidence", "unselected namespace directory passed")
    extra.rmdir()
    link = package.parent / "redirect.py"
    link.symlink_to(package)
    symlink_refusal = consumer.evaluate(original, archive, output / "symlink-refusal")
    require(symlink_refusal["publicationDecision"] == "hold-evidence", "symlinked namespace entry passed")
    link.unlink()
    package.write_bytes(package.read_bytes() + b"\n# changed installed consumer\n")
    installation_refusal = consumer.evaluate(original, archive, output / "installation-refusal")
    require(installation_refusal["publicationDecision"] == "hold-evidence", "changed installed reader executed")
    require("reviewed source" in installation_refusal["error"]["message"], "installed mutation escaped source check")
    # A fresh selected replacement fixes the invalid environment. The valid
    # packet is replayed again; the altered environment is never reused.
    recovery = consumer.evaluate(replacement, archive, output / "fresh-recovery")
    require(recovery["reader"] == reader, "fresh replacement did not restore the selected contract")
    script = Path(consumer.__file__).resolve()
    exits = {}
    for purpose, expected in (("publication", 0), ("model-quality", 1)):
        call = subprocess.run([sys.executable, "-I", "-B", str(script), "evaluate", str(replacement), str(archive),
                               str(output / ("cli-" + purpose)), "--purpose", purpose],
                              capture_output=True, timeout=60, check=False)
        (output / ("cli-" + purpose + ".stdout.json")).write_bytes(call.stdout)
        (output / ("cli-" + purpose + ".stderr")).write_bytes(call.stderr)
        require(call.returncode == expected, "host CLI failure propagation changed: " + purpose)
        exits[purpose] = call.returncode
    record = {"schema": "policy-vocabulary-native-placement-check-v1",
              "selectionSha256": consumer.sha(consumer.SELECTION.read_bytes()),
              "archive": consumer.selection()["archive"], "sourceContract": consumer.selection()["sourceContract"]["sha256"],
              "population": report["population"], "quality": report["quality"],
              "publicationDecision": actual["publicationDecision"], "modelQualityDecision": actual["modelQualityDecision"],
              "effectDecision": actual["effectDecision"], "qualityRowsHeld": len(reader["qualityFailures"]),
              "structuredRepeatExact": True, "replacementContractExact": True,
              "sameToolchainWheelBytesExact": (original / "wheel" / first["build"]["wheel"]["name"]).read_bytes()
                   == (replacement / "wheel" / second["build"]["wheel"]["name"]).read_bytes(),
              "refusals": {"changedOriginalZIP": "hold-evidence", "changedTerminal": "hold-evidence",
                           "changedReviewedCheckoutSource": "installation-refused",
                           "candidateResignedHelper": "hold-evidence", "changedInstalledReader": "hold-evidence",
                           "matchingMetadataBytecode": "hold-evidence", "unselectedNamespaceDirectory": "hold-evidence",
                           "symlinkedNamespaceEntry": "hold-evidence"},
              "bytecodePositiveControlExit": probe.returncode, "bytecodeMarkerAbsentAfterGate": not marker.exists(),
              "cliExitCodes": exits, "installation": second, "consumerModelCalls": 0, "consumerEffects": 0,
              "originalRunResources": {key: report[key] for key in
                                       ("elapsed_ns", "process_cpu_ns", "nativeTokens", "preparation")},
              "hostReplayResources": {key: actual[key] for key in
                                      ("readerWallNanoseconds", "readerChildrenCPUSeconds", "readerChildrenLifetimePeakRSSKiB", "resourceScope")},
              "scope": consumer.selection()["scope"]}
    require(record["sameToolchainWheelBytesExact"], "complete selected wheel bytes changed")
    consumer.save(output / "verification.json", record)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer-checkout", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.observer_checkout.resolve(), args.archive.resolve(), args.output.resolve()), indent=2))


if __name__ == "__main__":
    main()
