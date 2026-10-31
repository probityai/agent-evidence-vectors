#!/usr/bin/env python3
"""Retain a pinned support-action corpus run and portable replay controls."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SUITE = "customer-support-action/v1"
CONTRACT_SHA256 = "1d16dd1d0e215779cc91fbb4a69a3e2a117bc005b9450e8d4b964012c417b3cd"
CORPUS_DIGEST_DOMAIN = b"probity-customer-support-action-corpus/v1\n"
VERIFY_ENTRYPOINT = "examples/customer-support-action/consumer.py"
CORPUS = "vectors-customer-support-action"
REFUSAL_MARKER = b"customer-support-action: "
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_CASE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_FILE = re.compile(r"[a-z_]+\.(?:json|txt)\Z")


class RunError(ValueError):
    """An experiment precondition or an observed comparison failed."""


def require(condition: bool, message: str) -> None:
    """Refuse a run that cannot establish the stated condition."""
    if not condition:
        raise RunError(message)


def digest(data: bytes) -> str:
    """Return the SHA-256 identity of exact retained bytes."""
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate manifest keys before deriving its commitment."""
    result = {}
    for key, value in pairs:
        require(key not in result, f"corpus manifest repeats key: {key}")
        result[key] = value
    return result


def nonfinite(value: str) -> None:
    """Refuse non-JSON numeric constants in corpus metadata."""
    raise RunError(f"corpus manifest contains non-finite value: {value}")


def canonical(value: Any) -> bytes:
    """Encode the kernel's control-byte format for counterfactual bundles."""
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    """Retain a new human-readable JSON artifact without replacing a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def stop_process(process: subprocess.Popen) -> tuple[bytes, bytes]:
    """Stop only this command's process group and retain its final output."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    return process.communicate()


def command(
    argv: list[str], cwd: Path, env: dict[str, str], output: Path, label: str,
    *, timeout: int = 180,
) -> dict[str, Any]:
    """Save process output before interpreting its result.

    Args:
        argv: Exact executable and arguments. No shell is used.
        cwd: Directory in which the process runs.
        env: Process environment selected by the runner.
        output: New retained-run directory.
        label: Relative directory for this command's raw evidence.
        timeout: Maximum process duration in seconds.

    Returns:
        The actual exit code, bytes, and raw-artifact reference.

    Raises:
        RunError: If the process cannot start or exceeds its bound. Partial
            output and the diagnostic remain retained for that refusal.
    """
    target = output / "raw" / label
    target.mkdir(parents=True, exist_ok=False)
    diagnostic = None
    cancelled = False
    try:
        with subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=os.name == "posix") as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                stdout, stderr = stop_process(process)
                diagnostic = "process timed out"
            except KeyboardInterrupt:
                stdout, stderr = stop_process(process)
                diagnostic, cancelled = "process cancelled", True
            exit_code = process.returncode
    except OSError as exc:
        exit_code, stdout, stderr = None, b"", b""
        diagnostic = f"process could not start: {exc}"
    (target / "stdout").write_bytes(stdout)
    (target / "stderr").write_bytes(stderr)
    metadata = {
        "argv": argv, "cwd": str(cwd), "exit_code": exit_code,
        "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
        "environment": {name: env[name] for name in (
            "PYTHONPATH", "PYTHONNOUSERSITE", "GOMAXPROCS", "GOTOOLCHAIN", "GOWORK",
            "GOFLAGS", "GOPROXY", "GOSUMDB"
        ) if name in env},
    }
    if diagnostic:
        metadata["diagnostic"] = diagnostic
    write_json(target / "command.json", metadata)
    if cancelled:
        raise KeyboardInterrupt
    require(diagnostic is None, f"{label}: {diagnostic}")
    return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr,
            "raw": target.relative_to(output).as_posix()}


def git(root: Path, *args: str) -> bytes:
    """Read source metadata from a caller-selected checkout."""
    result = subprocess.run(["git", "-C", str(root), *args],
                            capture_output=True, check=False)
    require(result.returncode == 0, f"git {args[0]} failed for {root.name}")
    return result.stdout


def export_source(root: Path, revision: str, repository: str, target: Path) -> dict:
    """Export exact public Git bytes, rather than use mutable checkout files."""
    require(bool(_REVISION.fullmatch(revision)), "source revision must be full lowercase Git SHA")
    require(git(root, "rev-parse", "HEAD").decode().strip() == revision,
            f"{repository}: checkout HEAD differs from selected revision")
    require(not git(root, "status", "--porcelain", "--untracked-files=no"),
            f"{repository}: tracked checkout files are not clean")
    origin = git(root, "config", "--get", "remote.origin.url").decode().strip()
    require(origin in {f"https://github.com/{repository}.git",
                       f"https://github.com/{repository}",
                       f"git@github.com:{repository}.git"},
            f"{repository}: origin is not the selected public repository")
    require(git(root, "cat-file", "-t", revision).strip() == b"commit",
            f"{repository}: selected object is not a commit")
    archive = git(root, "archive", "--format=tar", revision)
    files: dict[str, dict[str, Any]] = {}
    target.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        for member in source.getmembers():
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            require(not path.is_absolute() and str(path) == name and
                    all(part not in {".", ".."} for part in name.split("/")),
                    f"{repository}: unsafe archive member")
            destination = target / path
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            require(member.isfile(), f"{repository}: source contains a non-regular file")
            stream = source.extractfile(member)
            require(stream is not None, f"{repository}: archive member is unreadable")
            data = stream.read()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            files[name] = {"sha256": digest(data), "length": len(data)}
    return {"repository": repository, "revision": revision,
            "tree": git(root, "rev-parse", f"{revision}^{{tree}}").decode().strip(),
            "url": f"https://github.com/{repository}/tree/{revision}",
            "archive_sha256": digest(archive), "files": files}


def corpus_entries(root: Path) -> tuple[dict, list[dict]]:
    """Check the selected corpus bytes before a reader sees its members."""
    manifest = json.loads((root / "MANIFEST.json").read_bytes(),
                          object_pairs_hook=unique_object, parse_constant=nonfinite)
    require(isinstance(manifest, dict), "corpus manifest is not an object")
    require(set(manifest) == {"suite", "claimType", "specification", "provenance", "counts",
                              "verifierContract", "vectors", "corpusDigest"},
            "corpus manifest fields differ from the selected contract")
    require(manifest.get("suite") == SUITE, "corpus suite is not selected")
    require(manifest["claimType"] == "customer_support_action/v1", "corpus claim type is not selected")
    require(manifest["specification"] == {"path": "CONTRACT.md", "sha256": CONTRACT_SHA256},
            "corpus specification differs from the immutable consumer contract")
    require(manifest["provenance"] == {"kind": "locally-authored-proposal", "authors": ["Sankalp Gilda"],
                                       "organization": "Probity AI"}, "corpus provenance differs")
    require(manifest["verifierContract"] == "verifier case.json --policy policy.json --json",
            "corpus verifier command differs")
    contract = (root / "CONTRACT.md").read_bytes()
    require(digest(contract) == CONTRACT_SHA256, "raw contract bytes differ from the selected v1 semantics")
    entries = manifest.get("vectors")
    require(isinstance(entries, list) and bool(entries), "corpus contains no vectors")
    require(all(isinstance(entry, dict) for entry in entries), "corpus vector is not an object")
    body = {key: value for key, value in manifest.items() if key != "corpusDigest"}
    encoded = (json.dumps(body, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    preimage = CORPUS_DIGEST_DOMAIN + str(len(contract)).encode("ascii") + b"\n" + contract + b"\n" + encoded
    require(digest(preimage) == manifest["corpusDigest"], "corpus commitment differs from contract and metadata")
    ids = [entry.get("id") for entry in entries]
    require(all(isinstance(name, str) and _CASE_ID.fullmatch(name) for name in ids)
            and len(ids) == len(set(ids)), "corpus case identifiers are invalid")
    population = {"total": len(entries), "supported": 0, "contradicted": 0, "not_established": 0, "refused": 0}
    for entry in entries:
        require(entry.get("path") == f"cases/{entry['id']}", "corpus case path is invalid")
        directory = root / entry["path"]
        files = entry.get("files")
        require(isinstance(files, dict) and all(isinstance(name, str) and _FILE.fullmatch(name)
                                               for name in files),
                "corpus fixture name is invalid")
        require({"case.json", "policy.json"}.issubset(files),
                f"{entry['id']}: case or policy input is absent")
        require({path.name for path in directory.iterdir()} == set(files),
                f"{entry['id']}: fixture file set changed")
        require(all(digest((directory / name).read_bytes()) == sha
                    for name, sha in files.items()), f"{entry['id']}: fixture bytes changed")
        expected = entry.get("expected")
        refused = isinstance(expected, dict) and set(expected) == {"refused"} and expected["refused"] is True
        require(refused or
                (isinstance(expected, dict) and set(expected) == {"decision", "reason", "action"}),
                f"{entry['id']}: expected projection is invalid")
        kind = "refused" if refused else expected["decision"]
        require(refused or kind in {"supported", "contradicted", "not_established"},
                f"{entry['id']}: expected decision is invalid")
        population[kind] += 1
    counts = manifest["counts"]
    require(isinstance(counts, dict) and set(counts) == set(population) and
            all(type(counts[key]) is int and counts[key] == value for key, value in population.items()),
            "corpus populations differ from declared counts")
    require({path.name for path in (root / "cases").iterdir()} == set(ids),
            "corpus directories do not match the manifest")
    return manifest, entries


def projection(result: dict[str, Any], label: str) -> dict:
    """Read an actual projection only after checking the process exit."""
    require(result["exit_code"] == 0, f"{label}: reader did not return a decision")
    try:
        answer = json.loads(result["stdout"])
    except (ValueError, UnicodeError) as exc:
        raise RunError(f"{label}: reader returned no JSON decision") from exc
    require(isinstance(answer, dict) and set(answer) == {"decision", "reason", "action"},
            f"{label}: reader projection is incomplete")
    return answer


def require_refusal(result: dict[str, Any], label: str) -> None:
    """Require an explicit refusal, rather than count reader silence as a pass."""
    require(result["exit_code"] == 2 and not result["stdout"] and
            result["stderr"].startswith(REFUSAL_MARKER),
            f"{label}: expected exit 2, zero stdout and an explicit refusal marker")


def bundled_case(
    entry: dict, corpus: Path, consumer: list[str], env: dict[str, str],
    output: Path, label: str,
) -> tuple[Path, dict, dict]:
    """Retain a carried decision and replay it from an empty working directory."""
    target = output / "packets" / label
    target.mkdir(parents=True)
    bundle = target / "decision.zip"
    directory = corpus / entry["path"]
    created = command([*consumer, str(directory / "case.json"), "--policy",
                       str(directory / "policy.json"), "--bundle", str(bundle), "--json"],
                      output, env, output, f"bundles/{label}/create")
    answer = projection(created, label)
    require(answer == entry["expected"], f"{label}: bundle changed the selected verdict")
    with zipfile.ZipFile(bundle) as archive:
        decision_bytes = archive.read("decision.json")
        (target / "decision.json").write_bytes(decision_bytes)
    with tempfile.TemporaryDirectory(prefix="atlas-support-replay-") as scratch:
        relocated = Path(scratch) / "carried.zip"
        shutil.copyfile(bundle, relocated)
        require(set(Path(scratch).iterdir()) == {relocated}, "replay directory contains source files")
        replayed = command([*consumer, "--replay", str(relocated), "--json"],
                           Path(scratch), env, output, f"bundles/{label}/replay")
    require(projection(replayed, label) == answer and replayed["stdout"] == created["stdout"],
            f"{label}: relocated replay changed the output")
    return bundle, json.loads(decision_bytes), {
        "case_id": entry["id"], "decision": answer,
        "bundle": bundle.relative_to(output).as_posix(), "bundle_sha256": digest(bundle.read_bytes()),
        "packet": (target / "decision.json").relative_to(output).as_posix(),
        "relocated_replay": "matched", "create": created["raw"], "replay": replayed["raw"],
    }


def stale_decision(bundle: Path, original_packet: dict, target: Path) -> None:
    """Retain a changed bundle that still carries the earlier decision."""
    with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(target, "x") as changed:
        for info in source.infolist():
            data = canonical(original_packet) if info.filename == "decision.json" else source.read(info)
            changed.writestr(info, data)


def binding_controls(
    routine: dict, corpus: Path, baseline: dict, consumer: list[str],
    env: dict[str, str], output: Path,
) -> list[dict]:
    """Keep equal outcomes separate from exact policy and source bindings."""
    controls = []
    for name in ("policy-clock-changed", "selected-source-changed", "producer-only-rebound"):
        directory = output / "counterfactuals" / name
        shutil.copytree(corpus / routine["path"], directory)
        case_path, policy_path = directory / "case.json", directory / "policy.json"
        case, policy = json.loads(case_path.read_bytes()), json.loads(policy_path.read_bytes())
        assessment = policy["assessments"][case["case_id"]]
        if name == "policy-clock-changed":
            clock = datetime.fromisoformat(assessment["clock"].replace("Z", "+00:00"))
            assessment["clock"] = (clock + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        else:
            metadata = case["artifacts"]["company_policy"]
            source_path = directory / metadata["path"]
            company = json.loads(source_path.read_bytes())
            company["policy_id"] += "-retained-control"
            source_bytes = canonical(company)
            source_path.write_bytes(source_bytes)
            metadata.update(sha256=digest(source_bytes), length=len(source_bytes))
            if name == "selected-source-changed":
                assessment["bindings"]["company_policy"] = digest(source_bytes)
        case_path.write_bytes(canonical(case))
        policy_path.write_bytes(canonical(policy))
        expected = routine["expected"] if name != "producer-only-rebound" else {
            "decision": "not_established", "reason": "consumer_binding_mismatch",
            "action": "HOLD_FOR_REVIEW",
        }
        entry = {"id": routine["id"], "path": f"counterfactuals/{name}", "expected": expected}
        bundle, packet, retained = bundled_case(entry, output, consumer, env, output, name)
        if name != "producer-only-rebound":
            require(packet["policy_sha256"] != baseline["policy_sha256"],
                    f"{name}: changed selected policy kept its old binding")
            if name == "selected-source-changed":
                require(packet["scope"]["artifacts"]["company_policy"]["sha256"] !=
                        baseline["scope"]["artifacts"]["company_policy"]["sha256"],
                        f"{name}: changed source kept its old binding")
            edited = bundle.with_name("stale-decision.zip")
            stale_decision(bundle, baseline, edited)
            refused = command([*consumer, "--replay", str(edited), "--json"], output,
                              env, output, f"controls/{name}/stale-replay")
            require_refusal(refused, name)
            require(b"bundled decision differs from replay" in refused["stderr"],
                    f"{name}: refusal did not establish a decision-binding mismatch")
            retained.update(stale_decision="refused", stale_replay=refused["raw"],
                            stale_bundle=edited.relative_to(output).as_posix())
        controls.append({"control": name, "result": "pass", **retained})
    return controls


def independent_reader(
    vectors: Path, corpus: Path, entries: list[dict], env: dict[str, str], output: Path,
) -> dict:
    """Retain the Go route built from the exact exported Vectors source."""
    binary = vectors.parent / "aee-verify"
    built = command(["go", "build", "-p", "1", "-o", str(binary), "./cmd/aee-verify"],
                    vectors, env, output, "go/build", timeout=300)
    require(built["exit_code"] == 0, "independent Go reader did not build")
    result = command([str(binary), "-json", str(corpus)], vectors, env, output, "go/read")
    require(result["exit_code"] == 0, "independent Go reader did not conform")
    report = json.loads(result["stdout"])
    require(isinstance(report, dict), "independent Go result is not an object")
    members = report.get("members")
    require(report.get("suite") == SUITE and not report.get("findings") and
            isinstance(members, list) and len(members) == len(entries),
            "independent Go result is incomplete")
    require(all(isinstance(member, dict) for member in members),
            "independent Go member is not an object")
    expected = {entry["id"]: "refused" if entry["expected"] == {"refused": True}
                else entry["expected"]["decision"] for entry in entries}
    observed = {member.get("id"): member.get("kind") for member in members}
    require(observed == expected and all(not member.get("findings") for member in members),
            "independent Go member verdicts or findings disagree")
    return {"raw": result["raw"], "binary_sha256": digest(binary.read_bytes()),
            "members": len(members), "result": "pass",
            "scope": "Second implementation; same Probity operator; expected outputs available."}


def run(args: argparse.Namespace, output: Path) -> dict:
    """Execute the declared finite experiment from immutable source exports."""
    env = dict(os.environ)
    env.update(GOMAXPROCS="1", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="",
               GOPROXY="off", GOSUMDB="off", PYTHONNOUSERSITE="1")
    with tempfile.TemporaryDirectory(prefix="atlas-support-sources-") as scratch:
        workspace = Path(scratch)
        verify, vectors = workspace / "verify", workspace / "vectors"
        sources = {
            "verify": export_source(args.verify_root, args.verify_revision,
                                    "probityai/probity-verify", verify),
            "vectors": export_source(args.vectors_root, args.vectors_revision,
                                     "probityai/agent-evidence-vectors", vectors),
        }
        write_json(output / "source-pins.json", sources)
        consumer = [str(args.verify_python), str(verify / VERIFY_ENTRYPOINT)]
        env["PYTHONPATH"] = str(verify / "src")
        runtime = command([str(args.verify_python), "-c", (
            "import json,platform,cryptography,probity_verify; "
            "print(json.dumps({'python':platform.python_version(),"
            "'cryptography':cryptography.__version__,'verify_module':probity_verify.__file__}))"
        )], output, env, output, "runtime/python")
        require(runtime["exit_code"] == 0, "selected Verify Python runtime is unavailable")
        module = Path(json.loads(runtime["stdout"])["verify_module"]).resolve()
        require(module.is_relative_to(verify / "src"), "runtime imported a different Verify source")
        go_version = command(["go", "version"], output, env, output, "runtime/go")
        require(go_version["exit_code"] == 0, "Go runtime is unavailable")
        corpus = output / "corpus"
        shutil.copytree(vectors / CORPUS, corpus)
        manifest, entries = corpus_entries(corpus)
        answers = []
        for entry in entries:
            directory = corpus / entry["path"]
            result = command([*consumer, str(directory / "case.json"), "--policy",
                              str(directory / "policy.json"), "--json"], output,
                             env, output, f"verify/{entry['id']}")
            if entry["expected"] == {"refused": True}:
                require_refusal(result, entry["id"])
                observed = {"refused": True}
            else:
                observed = projection(result, entry["id"])
                require(observed == entry["expected"], f"{entry['id']}: Verify verdict mismatch")
            answers.append({"case_id": entry["id"], "actual": observed,
                            "result": "pass", "raw": result["raw"]})
        go = independent_reader(vectors, corpus, entries, env, output)
        selected = {}
        for reason in ("routine_action_supported", "manager_action_supported"):
            twins = [entry for entry in entries if entry["expected"].get("reason") == reason]
            require(bool(twins), f"corpus has no {reason} accepting control")
            selected[reason] = twins[0]
        packets = []
        _, baseline, retained = bundled_case(selected["routine_action_supported"], corpus,
                                            consumer, env, output, "routine")
        packets.append(retained)
        _, _, retained = bundled_case(selected["manager_action_supported"], corpus,
                                      consumer, env, output, "manager")
        packets.append(retained)
        controls = binding_controls(selected["routine_action_supported"], corpus, baseline,
                                    consumer, env, output)
    return {
        "schema_version": "atlas-customer-support-action-run/v1", "suite": SUITE,
        "result": "pass", "corpus_digest": manifest["corpusDigest"],
        "contract_sha256": digest((output / "corpus" / "CONTRACT.md").read_bytes()),
        "summary": {"verify_members": len(answers), "go_members": go["members"],
                    "relocated_baseline_bundles": len(packets), "binding_controls": len(controls)},
        "verify": answers, "independent_reader": go, "portable_replay": packets,
        "binding_controls": controls,
        "limits": ["Author-created public fixtures and synthetic advisory reports.",
                   "Two implementations operated by Probity; expected outputs were available.",
                   "Selected authority and consumed-grant snapshots are supplied trust roots.",
                   "No source authentication, atomic grant consumption or live email effect."],
    }


def main(argv: list[str] | None = None) -> int:
    """Create one new retained run; never replace an earlier result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-root", type=Path, required=True)
    parser.add_argument("--verify-revision", required=True)
    parser.add_argument("--verify-python", type=Path, required=True)
    parser.add_argument("--vectors-root", type=Path, required=True)
    parser.add_argument("--vectors-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.verify_root = args.verify_root.resolve()
    args.vectors_root = args.vectors_root.resolve()
    # Keep the venv symlink: resolving it would select the base interpreter.
    args.verify_python = args.verify_python.absolute()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        print("customer-support-experiment: output already exists", file=sys.stderr)
        return 2
    output.mkdir(parents=True)
    provenance = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "source_selection": {"verify_revision": args.verify_revision,
                             "vectors_revision": args.vectors_revision},
        "command": [sys.executable, str(Path(__file__).resolve()), *(argv or sys.argv[1:])],
        "classification": "Author-operated finite raw-artifact and authority-snapshot characterization",
        "answer_exposure": "Published expected results were available before implementation and execution.",
    }
    exit_code = 0
    try:
        report = run(args, output)
    except KeyboardInterrupt:
        report = {"schema_version": "atlas-customer-support-action-run/v1", "suite": SUITE,
                  "result": "cancelled"}
        exit_code = 130
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        report = {"schema_version": "atlas-customer-support-action-run/v1", "suite": SUITE,
                  "result": "not-completed", "diagnostic": str(exc)}
        print(f"customer-support-experiment: {exc}", file=sys.stderr)
        exit_code = 1
    write_json(output / "report.json", report)
    provenance.update(finished_at_utc=datetime.now(timezone.utc).isoformat(), actual_exit_code=exit_code)
    write_json(output / "provenance.json", provenance)
    print(f"{report['result']}: {output / 'report.json'}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
