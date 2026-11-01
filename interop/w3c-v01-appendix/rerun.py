#!/usr/bin/env python3
"""Rerun one row of the v0.1 paper's results-to-inputs table from its pins.

    python rerun.py R1 [R2 ...] [--work DIR] [--results DIR]
    python rerun.py --all

Each row in rows.json names the archive messages that carry its data, the
command, the pinned commits, package versions and attachments, and the digest
the producer or a rerun posted. This script fetches exactly those pins (a git
commit by its full SHA, a list attachment by its posted sha256), runs the
posted command, and compares what comes out with what was posted.

It writes one JSON result per row and exits 0 only when every row it ran
reproduced. A row that does not reproduce is reported with the observed
digests beside the posted ones; nothing is adjusted to make it match.

Needs git, uv and, for R3 and R4, Node. Standard library only. R3-v01 reads the
records R3 wrote, and R14 the reports of R1, R2, R3-v01, R4 and R5.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
ROWS = json.loads((HERE / "rows.json").read_text(encoding="utf-8"))
ARCHIVE = ROWS["archive"]
DEFAULT_MONTH = "2026Oct/"
REPRODUCED, DIFFERS, ERROR, RECORDED = "reproduced", "differs", "error", "recorded"


class Refused(Exception):
    """A pin did not hold: wrong commit, wrong attachment bytes, missing tool."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes())


def run(cmd: list[str], cwd: Path, log: Path, env: dict[str, str] | None = None,
        stdout: Path | None = None, merge: bool = False) -> int:
    """Run a command, appending its output to the row log; return its exit code.

    With ``stdout`` the standard output goes to that file, and with ``merge``
    the standard error goes there too; otherwise both go to the log.
    """
    merged = {**os.environ, **(env or {})}
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"\n$ (cd {cwd}) {' '.join(cmd)}\n")
        handle.flush()
        if stdout is None:
            proc = subprocess.run(cmd, cwd=cwd, env=merged, stdout=handle,
                                  stderr=subprocess.STDOUT, check=False)
        else:
            with stdout.open("wb") as out:
                proc = subprocess.run(cmd, cwd=cwd, env=merged, stdout=out,
                                      stderr=subprocess.STDOUT if merge else handle,
                                      check=False)
        handle.write(f"[exit {proc.returncode}]\n")
    return proc.returncode


def must(code: int, what: str) -> None:
    if code != 0:
        raise Refused(f"{what} exited {code}")


def fetch_commit(repository: str, commit: str, dest: Path, log: Path,
                 paths: list[str] | None = None) -> Path:
    """Check out one commit by full SHA, optionally sparse, and prove HEAD is it."""
    if len(commit) != 40:
        raise Refused(f"{repository}: pin {commit!r} is not a full commit SHA")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    url = f"https://github.com/{repository}.git"
    must(run(["git", "init", "-q"], dest, log), "git init")
    must(run(["git", "remote", "add", "origin", url], dest, log), "git remote add")
    if paths:
        must(run(["git", "sparse-checkout", "set", "--no-cone", *paths], dest, log),
             "git sparse-checkout")
    must(run(["git", "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit],
             dest, log), f"git fetch {repository}@{commit}")
    must(run(["git", "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"],
             dest, log), "git checkout")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=dest, capture_output=True,
                          text=True, check=True).stdout.strip()
    if head != commit:
        raise Refused(f"{repository}: HEAD is {head}, pin is {commit}")
    return dest


def aev_tree(tag: str, dest: Path, log: Path, paths: list[str]) -> Path:
    return fetch_commit(ROWS["aev_repository"], ROWS["aev_tags"][tag], dest, log, paths)


def attachment_url(name: str) -> str:
    """Names like "att-0039/x" are in October; others carry their month, "2026Nov/att-0000/x"."""
    return ARCHIVE + (name if re.match(r"^\d{4}[A-Z][a-z]{2}/", name) else DEFAULT_MONTH + name)


def attachment(name: str, cache: Path) -> bytes:
    """A list attachment, checked against the digest its message posted.

    The archive adds one trailing newline to a text attachment, so for those
    the posted bytes are the served bytes less that newline.
    """
    pin = ROWS["attachments"][name]
    path = cache / name
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fetch_url(attachment_url(name)))
    data = path.read_bytes()
    if pin["text"] and data.endswith(b"\n\n"):
        data = data[:-1]
    if sha256(data) != pin["sha256"]:
        raise Refused(f"{name}: sha256 {sha256(data)}, posted {pin['sha256']}")
    return data


def venv(work: Path, name: str, python: str, packages: list[str], log: Path) -> Path:
    """An isolated interpreter at the row's Python with exactly its pinned packages."""
    target = work / f"venv-{name}"
    if target.exists():
        shutil.rmtree(target)
    must(run(["uv", "venv", "-q", "--python", python, str(target)], work, log), "uv venv")
    py = target / "bin" / "python"
    if packages:
        must(run(["uv", "pip", "install", "-q", "--python", str(py), *packages], work, log),
             "uv pip install")
    return py


def fetch_url(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "w3c-v01-appendix-rerun"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def unittest_summary(text: str) -> dict[str, Any]:
    """Tests run and skipped, from unittest's own closing lines."""
    ran = re.findall(r"^Ran (\d+) tests? in ", text, re.M)
    skipped = re.findall(r"skipped=(\d+)", text)
    return {"ran": int(ran[-1]) if ran else None, "skipped": int(skipped[-1]) if skipped else 0,
            "ok": bool(re.search(r"^OK\b", text, re.M))}


def cargo_test_summary(text: str) -> dict[str, Any]:
    """The tests cargo ran and its closing result lines, read from cargo's own output."""
    ran = sorted((name, outcome) for name, outcome in re.findall(r"^test (\S+) \.\.\. (\w+)$", text, re.M))
    totals = {"passed": 0, "failed": 0, "ignored": 0, "filtered_out": 0}
    results = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                         r"\d+ measured; (\d+) filtered out", text, re.M)
    for _, passed, failed, ignored, filtered in results:
        totals["passed"] += int(passed)
        totals["failed"] += int(failed)
        totals["ignored"] += int(ignored)
        totals["filtered_out"] += int(filtered)
    return {"tests": [name for name, _ in ran], "outcomes": sorted({o for _, o in ran}),
            "result_lines": len(results), **totals}


def platform_record() -> dict[str, str]:
    """The machine a row ran on, written into every result so a digest is read with its platform."""
    runner = {k: os.environ[k] for k in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")
              if k in os.environ}
    return {"system": platform.system(), "machine": platform.machine(),
            "python": platform.python_version(), **runner}


def sha256_check(directory: Path, listing: Path) -> dict[str, Any]:
    """What ``sha256sum -c`` decides, in Python so it runs where GNU coreutils is absent.

    Each line is 64 hex digits, a space, a space or ``*``, then the path. A
    path that is missing or whose bytes hash to another value fails, and so
    does a line of any other form.
    """
    results: list[dict[str, Any]] = []
    for line in listing.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        found = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if not found:
            results.append({"line": line, "ok": False, "why": "not a checksum line"})
            continue
        digest, name = found.groups()
        path = directory / name
        got = sha256_file(path) if path.is_file() else None
        results.append({"file": name, "posted": digest, "observed": got, "ok": got == digest})
    return {"files": len(results), "ok_files": sum(1 for r in results if r["ok"]),
            "results": results, "ok": bool(results) and all(r["ok"] for r in results)}


def rust_toolchain(channel: str, work: Path, log: Path) -> str:
    """Install one Rust toolchain by name with rustup; return the ``+channel`` argument for cargo."""
    if shutil.which("rustup") is None:
        raise Refused("rustup is not on PATH")
    must(run(["rustup", "toolchain", "install", channel, "--profile", "minimal", "--no-self-update"],
             work, log), f"rustup toolchain install {channel}")
    return f"+{channel}"


def tree_digests(root: Path) -> dict[str, str]:
    return {str(p.relative_to(root)): sha256_file(p)
            for p in sorted(root.rglob("*")) if p.is_file()}


def zip_digests(data: bytes, prefix: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith(prefix):
                continue
            out[info.filename[len(prefix):]] = sha256(archive.read(info))
    return out


def compare_trees(posted: dict[str, str], observed: dict[str, str],
                  may_differ: dict[str, str], outside: dict[str, str] | None = None) -> dict[str, Any]:
    """Every posted file must come out byte-identical unless the row says why not.

    A file the run writes that the posted set does not hold fails the row,
    except under a prefix the row names as outside the record set, with why.
    """
    same, differ, allowed, missing = [], [], [], []
    for name, digest in sorted(posted.items()):
        got = observed.get(name)
        if got is None:
            missing.append(name)
        elif got == digest:
            same.append(name)
        elif name in may_differ:
            allowed.append({"file": name, "posted": digest, "observed": got,
                            "why": may_differ[name]})
        else:
            differ.append({"file": name, "posted": digest, "observed": got})
    unposted = sorted(set(observed) - set(posted))
    prefixes = tuple(outside or {})
    beside = [name for name in unposted if prefixes and name.startswith(prefixes)]
    extra = [name for name in unposted if name not in beside]
    return {"identical": len(same), "of": len(posted), "differ": differ,
            "allowed_to_differ": allowed, "missing": missing, "extra": extra,
            "outside_record_set": {"files": len(beside), "why": outside or {}},
            "ok": not differ and not missing and not extra}


def expect_files(out: Path, expect: dict[str, str]) -> dict[str, Any]:
    rows = []
    for name, digest in expect.items():
        path = out / name
        got = sha256_file(path) if path.is_file() else None
        rows.append({"file": name, "posted": digest, "observed": got, "ok": got == digest})
    return {"files": rows, "ok": all(r["ok"] for r in rows)}


# --------------------------------------------------------------------------
# One handler per row. Each returns (ok, detail).
# --------------------------------------------------------------------------

def row_r1(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    out = w / "out"
    out.mkdir()
    must(run(["uvx", row["pins"]["package"], "--emit-w3c-report", "report.json"], out, log),
         "emitter")
    detail = expect_files(out, row["expect"])
    return detail["ok"], detail


def row_r2(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log)
    posted = zip_digests(attachment(p["reference"], w.parent / "_attachments"),
                         p["reference_root"])
    py = venv(w, "r2", p["python"], p["packages"], log)
    out = w / "out"
    must(run([str(py), "-P", "tools/emitir-55.py", "--runner", "Nicolás Rocchia", str(out)],
             src, log), "emitir-55.py")
    detail = compare_trees(posted, tree_digests(out), row["may_differ"])
    detail["SHA256SUMS"] = expect_files(out, row["expect"])
    return detail["ok"], detail


def row_r3(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log)
    data = attachment(p["reference"], w.parent / "_attachments")
    posted = zip_digests(data, p["reference_root"])
    emitter = w / "emit_w3c_v01.py"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        emitter.write_bytes(archive.read(p["emitter"]))
    py = venv(w, "r3", p["python"], [], log)
    out = w / "out"
    must(run([str(py), str(emitter), "--artifact",
              "papers/dependable-multiroot-agent-evidence/artifact", "--out", str(out),
              "--runner", "Anton Sokolov (Tyche Institute)"], src, log), "emit_w3c_v01.py")
    records = out / "records" if (out / "records").is_dir() else out
    detail = compare_trees(posted, tree_digests(records), row["may_differ"],
                           row.get("outside_record_set"))
    detail["SHA256SUMS"] = expect_files(records, row["expect"])
    return detail["ok"], detail


def row_r3_v01(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Run the posted converter over the records the R3 rerun wrote, and compare."""
    p = row["pins"]
    out3 = w.parent / "R3" / "out"
    # The same rule row_r3 applies: the emitter writes records/ or the records themselves.
    records = out3 / "records" if (out3 / "records").is_dir() else out3
    if not (records / "SHA256SUMS").is_file():
        raise Refused("R3-v01 reads the R3 rerun's records: run R3 first")
    data = attachment(p["converter"], w.parent / "_attachments")
    script = w / p["script"]
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        script.write_bytes(archive.read(p["script"]))
        posted_bytes = archive.read(p["posted_report"])
    name = next(iter(row["expect"]))
    out = w / "out"
    out.mkdir()
    py = venv(w, "r3v01", p["python"], [], log)
    must(run([str(py), "-I", str(script), str(records), "--out", str(out / name)], w, log),
         "reencode_v01.py")
    detail = expect_files(out, row["expect"])
    detail["posted file in the zip"] = sha256(posted_bytes)
    ok = detail["ok"] and sha256(posted_bytes) == row["expect"][name]
    return ok, detail


def row_r4(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log)
    here = src / p["directory"]
    committed = here / "records"
    posted = tree_digests(committed)
    sums = sha256_file(committed / "SHA256SUMS")
    py = venv(w, "r4", p["python"], p["packages"], log)
    out = w / "out"
    must(run([str(py), "emit.py", "--runner", "w3c-v01-appendix harness",
              "--runner-wrote", "none", "--out", str(out), "--python", str(py),
              "--work", str(w / "pinned")], here, log), "emit.py")
    detail = compare_trees(posted, tree_digests(out), row["may_differ"])
    detail["committed SHA256SUMS"] = {"posted": list(row["expect"].values())[0],
                                      "observed": sums}
    ok = detail["ok"] and sums == list(row["expect"].values())[0]
    return ok, detail


def row_r4_driver(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log,
                       ["/interop/agentavow-signed-map-v1/", "/interop/agentavow-live-mcp/",
                        "/interop/a2a-s3-retain-2026-10-01/", "/packaging/"])
    here = src / p["directory"]
    py = venv(w, "r4d", p["python"], ["-r", str(src / "interop/a2a-s3-retain-2026-10-01/requirements.txt")], log)
    fixture = w / "vectors.json"
    must(run([str(py), "fetch_fixture.py", "--output", str(fixture)], here, log), "fetch_fixture.py")
    report = w / "fresh-report.json"
    must(run([str(py), "run_agentavow.py", "--fixture", str(fixture)], here, log,
             stdout=report), "run_agentavow.py")
    recorded = json.loads((here / "recorded-run.json").read_text(encoding="utf-8"))
    fresh = json.loads(report.read_text(encoding="utf-8"))
    detail = {"fixture_sha256": {"posted": p["fixture_sha256"], "observed": sha256_file(fixture)},
              "fresh_report_sha256": sha256_file(report),
              "recorded_run_sha256": sha256_file(here / "recorded-run.json"),
              "report_equals_recorded_run": fresh == recorded,
              "cases_matching": sum(1 for r in fresh.get("results", []) if r.get("matches")),
              "cases": len(fresh.get("results", []))}
    ok = (detail["fixture_sha256"]["posted"] == detail["fixture_sha256"]["observed"]
          and fresh == recorded)
    return ok, detail


def row_r5(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log)
    py = venv(w, "r5", p["python"], [], log)
    out = w / "out"
    out.mkdir()
    name = next(iter(row["expect"]))
    must(run([str(py), "-m", "paybench.w3c_report.emit", "--out", str(out / name), "--verify"],
             src, log), "paybench emit --verify")
    detail = expect_files(out, row["expect"])
    detail["bytes"] = (out / name).stat().st_size
    return detail["ok"], detail


def row_r6_rust(w: Path, log: Path, src: Path, commit: str, rust: dict[str, Any]) -> dict[str, Any]:
    """The Rust approval tests of one assay commit, built with the toolchain the commit pins."""
    channel = tomllib.loads((src / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    cargo = rust_toolchain(channel, w, log)
    version = subprocess.run(["rustc", cargo, "--version"], capture_output=True, text=True,
                             check=False).stdout.strip()
    out = w / f"cargo-{commit[:8]}.txt"
    code = run(["cargo", cargo, "test", "--locked", "-p", "assay-core", "--lib", rust["filter"],
                "--", "--test-threads=1"], src, log,
               env={"CARGO_TARGET_DIR": str(w / f"target-{commit[:8]}"), "CARGO_TERM_COLOR": "never"},
               stdout=out, merge=True)
    summary = cargo_test_summary(out.read_text(encoding="utf-8", errors="replace"))
    ok = (code == 0 and summary["tests"] == rust["tests"] and summary["outcomes"] == ["ok"]
          and summary["passed"] == len(rust["tests"]) and not summary["failed"]
          and not summary["ignored"] and summary["result_lines"] == 1)
    return {"toolchain": channel, "rustc": version, "exit": code, "summary": summary, "ok": ok}


def row_r6(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    py = venv(w, "r6", p["python"], [], log)
    detail: dict[str, Any] = {}
    ok = True
    for commit in p["commits"]:
        src = fetch_commit(p["repository"], commit, w / f"src-{commit[:8]}", log)
        here = src / p["directory"]
        stdout = w / f"check-{commit[:8]}.txt"
        code = run([str(py), "check.py", "--controls"], here, log, stdout=stdout)
        test_out = w / f"tests-{commit[:8]}.txt"
        tests = run([str(py), "-m", "unittest", "test_claim_boundary"], here, log,
                    stdout=test_out, merge=True)
        summary = unittest_summary(test_out.read_text(encoding="utf-8", errors="replace"))
        text = stdout.read_text(encoding="utf-8", errors="replace")
        passed = (code == 0 and tests == 0 and row["expect"]["stdout"] in text and summary["ok"]
                  and summary["ran"] == row["expect"]["tests"] and not summary["skipped"])
        rust = row_r6_rust(w, log, src, commit, row["rust"])
        detail[commit] = {"check_exit": code, "unittest_exit": tests, "tests": summary,
                          "check_stdout_sha256": sha256_file(stdout),
                          "check_stdout_last_line": text.strip().splitlines()[-1] if text.strip() else "",
                          "rust": rust, "ok": passed and rust["ok"]}
        ok = ok and detail[commit]["ok"]
    return ok, detail


def row_r7(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log, [f"/{p['directory']}/"])
    py = venv(w, "r7", p["python"], p["packages"], log)
    packet = src / p["directory"] / "controls" / "w3c-control2-20261012"
    manifest = next(packet.rglob("MANIFEST.json"))
    helper = next(packet.rglob("run_control2.py"))
    env = {"PYTHONHASHSEED": "0"}
    test_out = w / "tests.txt"
    tests = run([str(py), "-B", "packages/evidence-fabric/tests/test_w3c_control2_packet.py", "-v"],
                src, log, env=env, stdout=test_out, merge=True)
    summary = unittest_summary(test_out.read_text(encoding="utf-8", errors="replace"))
    replay = w / "replay"
    shutil.copytree(helper.parent, replay)
    helper_out = w / "helper.json"
    helper_exit = run([str(py), "-B", "run_control2.py"], replay, log, env=env, stdout=helper_out)
    try:
        outcome = json.loads(helper_out.read_text(encoding="utf-8"))
    except ValueError:
        outcome = {}
    recount = {k: v for k, v in (outcome.get("state_recount") or {}).items() if v}
    detail = {"MANIFEST.json": {"posted": row["expect"]["packet MANIFEST.json"],
                                "observed": sha256_file(manifest)},
              "run_control2.py": {"posted": row["expect"]["portable helper"],
                                  "observed": sha256_file(helper)},
              "tests": {"posted": row["expect"]["tests"], "observed": summary["ran"],
                        "skipped": summary["skipped"], "exit": tests},
              "outcomes": {"posted": row["expect"]["outcomes"], "observed": recount,
                           "criteria_passed": outcome.get("criteria_passed"), "exit": helper_exit}}
    ok = (tests == 0 and helper_exit == 0 and summary["ok"] and not summary["skipped"]
          and detail["tests"]["observed"] == row["expect"]["tests"]
          and recount == row["expect"]["outcomes"] and outcome.get("criteria_passed") is True
          and detail["MANIFEST.json"]["posted"] == detail["MANIFEST.json"]["observed"]
          and detail["run_control2.py"]["posted"] == detail["run_control2.py"]["observed"])
    return ok, detail


def row_r8(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    data = attachment(p["reader"], w.parent / "_attachments")
    unpacked = w / "reader"
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(unpacked, filter="data")
    base = unpacked / "v01-reader-run1"
    corpus = aev_tree(p["corpus_tag"], w / "aev", log, ["/vectors-w3c-report/vectors/"])
    vectors = corpus / "vectors-w3c-report" / "vectors"
    py = venv(w, "r8", p["python"], [], log)
    must(run([str(py), "-B", "reader/v01reader.py", str(vectors), "out/rerun"], base, log,
             env={"PYTHONHASHSEED": "0"}), "v01reader.py")
    detail = expect_files(base / "out" / "rerun", row["expect"])
    detail["members_in_corpus"] = len(list(vectors.glob("*.json")))
    return detail["ok"], detail


R8_FIGURES = re.compile(
    r"judged (\d+) \| selected (\d+).*?numbered (\d+) \| agree (\d+)(.*?)unnumbered (\d+) \| "
    r"accept (\d+) \| reject (\d+) \| cannot-tell (\d+) \| of which name W3C-R-016 (\d+)", re.S)


def r8_figures(text: str) -> dict[str, Any]:
    """The figures r8_compare.py prints, read back from its own output."""
    found = R8_FIGURES.search(text)
    if not found:
        raise Refused("r8_compare.py printed no figures")
    groups: tuple[str, ...] = found.groups()
    g = [int(x) for x in groups[:4] + groups[5:]]
    return {"judged": g[0], "selected": g[1], "numbered": g[2], "agree": g[3],
            "differs": sorted(re.findall(r"differs (\S+)", groups[4])),
            "unnumbered": {"total": g[4], "accept": g[5], "reject": g[6], "cannot-tell": g[7],
                           "cannot-tell under W3C-R-016": g[8]}}


def section10_selection(manifest: dict[str, Any]) -> set[str]:
    """Members whose subjectType is report and whose requirements are all agreed (0022)."""
    status = {r["id"]: r.get("status") for r in manifest["requirements"]}
    return {v["id"] for v in manifest["vectors"] if v["subjectType"] == "report"
            and all(status.get(r) == "agreed" for r in v["requirements"])}


def row_r8_compare(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p, expect = row["pins"], row["expect"]
    script = w / "r8_compare.py"
    script.write_bytes(attachment(p["script"], w.parent / "_attachments"))
    with tarfile.open(fileobj=io.BytesIO(attachment(p["reader"], w.parent / "_attachments"))) as archive:
        archive.extractall(w / "reader", filter="data")
    verdicts = w / "reader" / p["verdicts"]
    corpus = aev_tree(p["corpus_tag"], w / "aev", log, ["/vectors-w3c-report/MANIFEST.json"])
    manifest_path = corpus / "vectors-w3c-report" / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    family = {v["id"]: v["family"] for v in manifest["vectors"]}
    judged = [line.split("\t", 1)[0] for line in verdicts.read_text(encoding="utf-8").splitlines() if line]
    chosen = section10_selection(manifest)
    outside = sorted({family[k] for k in judged if k not in chosen})
    py = venv(w, "r8c", p["python"], [], log)
    runs: dict[str, Any] = {}
    for label, families in (("0022 selection", outside), ("w3c-f-29 excluded, as in 0188", ["w3c-f-29"])):
        printed = w / f"compare-{len(runs)}.txt"
        args = [a for f in families for a in ("--exclude-family", f)]
        must(run([str(py), "-I", str(script), str(manifest_path), str(verdicts), *args], w, log,
                 stdout=printed), "r8_compare.py")
        runs[label] = {"excluded": families, **r8_figures(printed.read_text(encoding="utf-8"))}
    observed = runs["0022 selection"]
    want = {k: expect[k] for k in ("judged", "selected", "numbered", "agree", "differs", "unnumbered")}
    detail = {"verdicts.tsv": {"posted": expect["verdicts.tsv"], "observed": sha256_file(verdicts)},
              "selection_by_rule": len(chosen & set(judged)),
              "outside_selection_families": {"posted": expect["outside_selection_families"],
                                             "observed": outside},
              "runs": runs}
    ok = (detail["verdicts.tsv"]["posted"] == detail["verdicts.tsv"]["observed"]
          and outside == expect["outside_selection_families"]
          and {k: observed[k] for k in want} == want)
    return ok, detail


def row_script(script: str) -> Callable[[Path, Path, dict[str, Any]], tuple[bool, dict[str, Any]]]:
    def handler(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        result = w / "script-result.json"
        code = run([sys.executable, str(HERE / "rows" / script), str(w), str(result)], w, log)
        detail = json.loads(result.read_text(encoding="utf-8")) if result.exists() else {}
        detail["script_exit"] = code
        return code == 0 and bool(detail.get("ok")), detail
    return handler


def row_r11(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log)
    ids = attachment(p["selection"], w.parent / "_attachments").decode().split()
    corpus = aev_tree(p["corpus_tag"], w / "aev", log, ["/vectors-w3c-report/"])
    manifest = json.loads((corpus / "vectors-w3c-report/MANIFEST.json").read_text(encoding="utf-8"))
    files = {v["id"]: v["file"] for v in manifest["vectors"]}
    members = w / "members"
    members.mkdir()
    for member in ids:
        shutil.copy2(corpus / "vectors-w3c-report" / files[member], members)
    py = venv(w, "r11", p["python"], [], log)
    output = w / "reader-output.jsonl"
    must(run([str(py), "-I", "reader.py", str(members)], src, log,
             env={"PYTHONHASHSEED": "0"}, stdout=output), "reader.py")
    posted = row["expect"]["reader output"]
    detail = {"members": len(ids), "reader output": {"posted": posted,
                                                      "observed": sha256_file(output)}}
    return detail["reader output"]["observed"] == posted, detail


def _tsv_verdict(cell: str) -> str:
    return cell.split(" ", 1)[0]


def row_r12(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    api = fetch_commit(p["repository"], p["commit"], w / "api", log)
    corpus = aev_tree(p["corpus_tag"], w / "aev", log, ["/vectors-w3c-report/"])
    old = aev_tree(p["old_manifest_tag"], w / "aev-old", log, ["/vectors-w3c-report/MANIFEST.json"])
    py = venv(w, "r12", p["python"], p["packages"], log)
    output = w / "scorer.json"
    must(run([str(py), "-I", "tests/conformance/score_w3c_jcs.py", str(api),
              str(corpus / "vectors-w3c-report"), str(old / "vectors-w3c-report/MANIFEST.json")],
             api, log, stdout=output), "score_w3c_jcs.py")
    scored = {r["id"]: r for r in json.loads(output.read_text(encoding="utf-8"))["rows"]}
    tsv = attachment(p["per_member"], w.parent / "_attachments").decode().splitlines()
    header, body = tsv[0].split("\t"), [line.split("\t") for line in tsv[1:] if line]
    columns = {"raw": 3, "signing": 4, "verify": 5}
    mismatches, agree = [], {k: 0 for k in columns}
    for cells in body:
        member = scored.get(cells[0])
        for path, index in columns.items():
            posted = _tsv_verdict(cells[index])
            got = member[path]["verdict"] if member else None
            if posted != got:
                mismatches.append({"id": cells[0], "path": path, "posted": posted, "observed": got})
            if got == cells[2]:
                agree[path] += 1
    detail = {"members_posted": len(body), "members_scored": len(scored),
              "header": header[:6], "agree_with_expected": agree,
              "scorer_output_sha256": sha256_file(output), "mismatches": mismatches}
    return not mismatches and len(body) == len([b for b in body if b[0] in scored]), detail


def row_r13(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    p = row["pins"]
    src = fetch_commit(p["repository"], p["commit"], w / "src", log)
    py = venv(w, "r13", p["python"], [], log)
    experiment = run([str(py), "experiment.py"], src, log)
    test_out = w / "tests.txt"
    tests = run([str(py), "-m", "unittest", "-v", "test_experiment.py"], src, log,
                stdout=test_out, merge=True)
    summary = unittest_summary(test_out.read_text(encoding="utf-8", errors="replace"))
    sums = sha256_check(src, src / "SHA256SUMS")
    detail = {"experiment_exit": experiment, "unittest_exit": tests, "tests": summary,
              "checksums_ok": sums["ok"],
              "files_ok": sums["ok_files"], "files": sums["files"],
              "checksums": sums["results"],
              "results.json": sha256_file(src / "results.json") if (src / "results.json").exists() else None}
    ok = (experiment == 0 and tests == 0 and sums["ok"] and summary["ok"]
          and summary["ran"] == row["expect"]["tests"] and not summary["skipped"]
          and detail["files_ok"] == detail["files"] == row["expect"]["files"])
    return ok, detail


READER = """
import json, sys
from agent_evidence_vectors import w3creport
for path in sys.argv[1:]:
    data = open(path, 'rb').read()
    report = w3creport.load_json(data) if hasattr(w3creport, 'load_json') else json.loads(data)
    shape = w3creport.shape_errors(report)
    rejected = [] if shape else sorted(w3creport.rejections(report))
    print(json.dumps({'report': path.rsplit('/', 1)[-1], 'shape_errors': shape,
                      'rejections': rejected,
                      'verdict': 'accept' if not shape and not rejected else 'reject'}))
"""

R14_REPORTS = {
    "R1": ("R1/out", ["report.json"]),
    "R2": ("R2/out", ["run-residue-v0.2.json", "run-residue-v0.3.json", "run-residue-v0.4.json"]),
    "R3": ("R3-v01/out", ["run-report-v01.json"]),
    "R4": ("R4/out/reports", ["heldfast-profiles.json", "native-verify-mjs.json",
                              "probity-map-reader.json"]),
    "R5": ("R5/out", ["finality-threshold-report.level1.json"]),
}


def row_r14(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    root = w.parent
    detail: dict[str, Any] = {}
    ok = True
    for source, readers in row["expect"].items():
        rel, names = R14_REPORTS[source]
        paths = [root / rel / n for n in names]
        if not all(p.is_file() for p in paths):
            raise Refused(f"{source}: run that row first; missing {[str(p) for p in paths if not p.is_file()]}")
        for version, expected in readers.items():
            out = w / f"{source}-{version}.jsonl"
            code = run(["uv", "run", "-q", "--no-project", "--python", "3.13", "--with",
                        f"agent-evidence-vectors=={version}", "python", "-c", READER,
                        *map(str, paths)], w, log, stdout=out)
            lines = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines() if x]
            verdicts = sorted({line["verdict"] for line in lines})
            observed = verdicts[0] if len(verdicts) == 1 and len(lines) == len(paths) else verdicts
            detail[f"{source} @ {version}"] = {
                "posted": expected, "observed": observed, "exit": code,
                "rejections": sorted({r for line in lines for r in line["rejections"]})}
            ok = ok and code == 0 and observed == expected
    return ok, detail


def row_r15(w: Path, log: Path, row: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """No command was posted: record the served bytes and tally the file's own rows."""
    p = row["pins"]
    try:
        data = fetch_url(p["url"])
    except OSError as exc:
        raise Refused(f"{p['url']}: {exc}") from exc
    (w / "census.json").write_bytes(data)
    census = json.loads(data)
    states: dict[str, int] = {}
    for item in census.get("rows", []):
        states[item.get("state")] = states.get(item.get("state"), 0) + 1
    tally = {"rows": len(census.get("rows", [])), "DEMONSTRATED": states.get("DEMONSTRATED", 0)}
    detail = {"url": p["url"], "fetched": True, "bytes": len(data), "sha256": sha256(data),
              "captured_sha256": p["captured_sha256"],
              "same_bytes_as_captured": sha256(data) == p["captured_sha256"],
              "as_of": census.get("as_of"), "states": states,
              "tally": {"posted": row["expect"]["tally"], "observed": tally}}
    return tally == row["expect"]["tally"], detail


HANDLERS: dict[str, Callable[[Path, Path, dict[str, Any]], tuple[bool, dict[str, Any]]]] = {
    "R1": row_r1, "R2": row_r2, "R3": row_r3, "R3-v01": row_r3_v01, "R4": row_r4, "R4-driver": row_r4_driver,
    "R5": row_r5, "R6": row_r6, "R7": row_r7, "R8": row_r8, "R8-compare": row_r8_compare,
    "R9": row_script("r9_corpus_history.py"), "R10": row_script("r10_minus_zero.py"),
    "R11": row_r11, "R12": row_r12, "R13": row_r13, "R14": row_r14, "R15": row_r15,
}


def rerun(row_id: str, work: Path, results: Path) -> str:
    row = ROWS["rows"][row_id]
    w = work / row_id
    if w.exists():
        shutil.rmtree(w)
    w.mkdir(parents=True)
    log = w / "log.txt"
    log.write_text(f"row {row_id}: {row['result']}\n", encoding="utf-8")
    try:
        ok, detail = HANDLERS[row_id](w, log, row)
        status = (RECORDED if row["kind"] == "no-command" else REPRODUCED) if ok else DIFFERS
    except Refused as exc:
        status, detail = ERROR, {"refused": str(exc)}
    result = {"row": row_id, "status": status, "platform": platform_record(), "result": row["result"],
              "messages": row["messages"], "command": row["command"], "pins": row["pins"],
              "detail": detail}
    results.mkdir(parents=True, exist_ok=True)
    (results / f"{row_id}.json").write_text(json.dumps(result, indent=1, ensure_ascii=True) + "\n",
                                            encoding="utf-8")
    print(f"{row_id}: {status}")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Rerun rows of the v0.1 paper's results-to-inputs table from their pins.")
    parser.add_argument("rows", nargs="*", help="row identifiers, for example R1 R8")
    parser.add_argument("--all", action="store_true", help="every row, R14 last")
    parser.add_argument("--work", type=Path, default=Path(".build/w3c-v01-appendix"))
    parser.add_argument("--results", type=Path, default=None)
    args = parser.parse_args()
    chosen = list(ROWS["rows"]) if args.all else args.rows
    unknown = [r for r in chosen if r not in ROWS["rows"]]
    if not chosen or unknown:
        parser.error(f"name rows from {', '.join(ROWS['rows'])}" + (f"; unknown {unknown}" if unknown else ""))
    if "R14" in chosen:
        chosen = [r for r in chosen if r != "R14"] + ["R14"]
    work = args.work.resolve()
    results = (args.results or work / "results").resolve()
    statuses = [rerun(r, work, results) for r in chosen]
    return 0 if all(s in (REPRODUCED, RECORDED) for s in statuses) else 1


if __name__ == "__main__":
    raise SystemExit(main())
