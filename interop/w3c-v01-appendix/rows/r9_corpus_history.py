#!/usr/bin/env python3
"""R9: the report corpus across v0.17.4, v0.18.0 and v0.18.1.

    python rows/r9_corpus_history.py <work dir> <result.json>

For each release, from the vectors-w3c-report tree at its tagged commit:
recompute corpusDigest (SHA-256 over the member files in identifier order),
count the section 10 selection (subjectType report, every cited requirement
agreed, the rule in gen_vectors.selection), count the selected members rejected
under W3C-R-016, and run the reference readers of that release over the tree:
the Python reader (agent_evidence_vectors.w3creport.judge from PyPI at the same
version), the Go reader (cmd/aee-verify built from the tagged commit) and, from
v0.18.0, the Rust reader (readers/w3c-report-rs built from the tagged commit).

Each reader judges the corpus as shipped, and then a probe copy whose manifest
expects every member to be rejected under a row that does not exist. A reader
prints the rows it found for each member it disagrees with, so the probe makes it
print its own verdict for every member. The verdicts on the members that cite
W3C-R-016 are compared across the readers and with the manifest.

Exits 0 only when every digest and count equals the value posted in 0079, every
reader that exists at the tag finds every member behaving as its manifest says,
and the readers give the same verdict on every member that cites W3C-R-016.
A reader that does not exist at a tag is reported as not run, with that reason.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402

JUDGE = """
import sys
from agent_evidence_vectors import w3creport
judged = w3creport.judge(sys.argv[1])
print(w3creport.render(judged, 'w3c-report-v01-conformance'), end='')
sys.exit(0 if judged.ok() else 1)
"""


ROW = "W3C-R-016"
PROBE_ROW = "W3C-R-999"
GO_ENV = {"GOWORK": "off", "GOFLAGS": "-mod=mod"}
TREE_PATHS = ["/vectors-w3c-report/", "/go.mod", "/cmd/aee-verify/", "/corpora/", "/aee/", "/aeetest/",
              "/observedeffect/", "/readers/w3c-report-rs/"]
REJECTS = re.compile(r"the validator rejects under \[([^\]]*)\] and the manifest expects")
SHAPE = "the subject is not the shape its definition gives"
CLEAN = "verdict: every member behaves as MANIFEST.json declares"


def corpus_digest(directory: Path, manifest: dict) -> str:
    digest = hashlib.sha256()
    for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
        digest.update((directory / entry["file"]).read_bytes())
    return digest.hexdigest()


def selection(manifest: dict) -> tuple[dict[str, int], int]:
    status = {row["id"]: row.get("status") for row in manifest["requirements"]}
    chosen = {"reject": 0, "accept": 0}
    r016 = 0
    for entry in manifest["vectors"]:
        if entry["subjectType"] != "report":
            continue
        if all(status.get(r) == "agreed" for r in entry["requirements"]):
            chosen[entry["kind"]] += 1
            if entry["kind"] == "reject" and "W3C-R-016" in entry["expected"]["rejects"]:
                r016 += 1
    return chosen, r016


def probe_corpus(directory: Path, dest: Path) -> None:
    """A copy of the corpus whose manifest expects every member to be rejected under a row nobody cites."""
    shutil.copytree(directory, dest)
    path = dest / "MANIFEST.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        entry["expected"] = {**entry["expected"], "rejects": [PROBE_ROW]}
    path.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")


def verdicts(text: str) -> dict[str, Any]:
    """Each member's verdict as a reader printed it for the probe: its rows, or "malformed"."""
    found: dict[str, Any] = {}
    for line in text.splitlines():
        if not line.startswith("FAIL v"):
            continue
        member, message = line[5:].split(": ", 1)
        rows = REJECTS.search(message)
        if rows:
            found[member] = sorted(r for r in rows.group(1).split(", ") if r)
        elif message.startswith(SHAPE):
            found[member] = "malformed"
    return found


def verdict_digest(observed: dict[str, Any]) -> str:
    lines = "".join(f"{member}\t{json.dumps(observed[member])}\n" for member in sorted(observed))
    return hashlib.sha256(lines.encode()).hexdigest()


def reader_commands(tag: str, tree: Path, work: Path, log: Path) -> dict[str, dict[str, Any]]:
    """Build the Go and Rust readers at a tag; a reader the tag does not carry is not run."""
    commands: dict[str, dict[str, Any]] = {}
    go_bin = work / f"aee-verify-{tag}"
    go_version = subprocess.run(["go", "version"], capture_output=True, text=True, check=False)
    code = rerun.run(["go", "build", "-o", str(go_bin), "./cmd/aee-verify"], tree, log, env=GO_ENV)
    commands["go"] = ({"argv": [str(go_bin)], "version": go_version.stdout.strip()} if code == 0
                      else {"not_run": f"go build exited {code}"})
    manifest = tree / "readers" / "w3c-report-rs" / "Cargo.toml"
    if not manifest.is_file():
        commands["rust"] = {"not_run": f"readers/w3c-report-rs does not exist at {tag}"}
        return commands
    channel = rerun.ROWS["rows"]["R9"]["pins"]["rust"]
    cargo = rerun.rust_toolchain(channel, work, log)
    target = work / f"rs-target-{tag}"
    code = rerun.run(["cargo", cargo, "build", "--release", "--locked", "--manifest-path", str(manifest),
                      "--target-dir", str(target)], tree, log)
    rustc = subprocess.run(["rustc", cargo, "--version"], capture_output=True, text=True, check=False)
    commands["rust"] = ({"argv": [str(target / "release" / "w3c-report-rs")],
                         "version": rustc.stdout.strip()} if code == 0
                        else {"not_run": f"cargo build exited {code}"})
    return commands


def judge_python(tag: str, corpus: Path, work: Path, log: Path, label: str) -> tuple[int, str]:
    out = work / f"python-{tag}-{label}.txt"
    code = rerun.run(["uv", "run", "-q", "--no-project", "--python", "3.13", "--with",
                      f"agent-evidence-vectors=={tag.lstrip('v')}", "python", "-c", JUDGE, str(corpus)],
                     work, log, stdout=out)
    return code, out.read_text(encoding="utf-8")


def judge_binary(argv: list[str], tag: str, name: str, corpus: Path, work: Path, log: Path,
                 label: str) -> tuple[int, str]:
    out = work / f"{name}-{tag}-{label}.txt"
    code = rerun.run([*argv, str(corpus)], work, log, stdout=out)
    return code, out.read_text(encoding="utf-8")


def compare_readers(tag: str, tree: Path, directory: Path, manifest: dict, work: Path,
                    log: Path) -> dict[str, Any]:
    """Run every reader the tag carries over the corpus and the probe; compare them on the W3C-R-016 members."""
    probe = work / f"probe-{tag}"
    probe_corpus(directory, probe)
    built = reader_commands(tag, tree, work, log)
    cited = {e["id"]: sorted(e["expected"]["rejects"]) for e in manifest["vectors"]
             if ROW in e["requirements"]}
    runs: dict[str, Any] = {"python": {"version": f"agent-evidence-vectors=={tag.lstrip('v')}"}, **built}
    for name, reader in runs.items():
        if "not_run" in reader:
            continue
        if name == "python":
            clean_code, clean = judge_python(tag, directory, work, log, "clean")
            probe_code, printed = judge_python(tag, probe, work, log, "probe")
        else:
            clean_code, clean = judge_binary(reader["argv"], tag, name, directory, work, log, "clean")
            probe_code, printed = judge_binary(reader["argv"], tag, name, probe, work, log, "probe")
        seen = verdicts(printed)
        observed = {member: seen.get(member) for member in cited}
        reader.pop("argv", None)
        reader.update({
            "clean": {"exit": clean_code, "verdict": clean.strip().splitlines()[-1] if clean.strip() else ""},
            "probe_exit": probe_code,
            "members_citing_W3C-R-016": len(cited),
            "agree_with_manifest": sum(1 for m, rows in cited.items() if observed[m] == rows),
            "rejecting_under_W3C-R-016": sum(1 for rows in observed.values()
                                             if isinstance(rows, list) and ROW in rows),
            "disagree": {m: {"manifest": cited[m], "reader": observed[m]} for m in cited
                         if observed[m] != cited[m]},
            "verdicts_sha256": verdict_digest(observed),
        })
        reader["ok"] = (clean_code == 0 and reader["clean"]["verdict"] == CLEAN and probe_code == 1
                        and not reader["disagree"] and len(cited) > 0)
    ran = {name: r for name, r in runs.items() if "not_run" not in r}
    same = len({r["verdicts_sha256"] for r in ran.values() if "verdicts_sha256" in r}) == 1
    return {"readers": runs, "readers_run": sorted(ran), "same_verdicts_on_W3C-R-016_members": same,
            "ok": bool(ran) and same and all(r.get("ok") for r in ran.values())}


def main() -> int:
    work, result = Path(sys.argv[1]), Path(sys.argv[2])
    log = work / "log.txt"
    expect = rerun.ROWS["rows"]["R9"]["expect"]
    out: dict = {"releases": {}}
    ok = True
    for tag, posted in expect.items():
        tree = rerun.aev_tree(tag, work / f"aev-{tag}", log, TREE_PATHS)
        directory = tree / "vectors-w3c-report"
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        chosen, r016 = selection(manifest)
        digest = corpus_digest(directory, manifest)
        reader = work / f"judge-{tag}.txt"
        code = rerun.run(["uv", "run", "-q", "--no-project", "--python", "3.13", "--with",
                          f"agent-evidence-vectors=={tag.lstrip('v')}", "python", "-c", JUDGE,
                          str(directory)], work, log, stdout=reader)
        verdict = reader.read_text(encoding="utf-8").strip().splitlines()[-1:]
        release = {
            "commit": rerun.ROWS["aev_tags"][tag],
            "members": len(manifest["vectors"]),
            "corpusDigest": {"posted": posted["corpusDigest"], "observed": digest,
                             "manifest": manifest.get("corpusDigest")},
            "selected": {"posted": posted["selected"], "observed": chosen},
            "selected_rejected_under_W3C-R-016": r016,
            "reference_reader": {"exit": code, "verdict": verdict[0] if verdict else ""},
            "reader_comparison": compare_readers(tag, tree, directory, manifest, work, log),
        }
        out["releases"][tag] = release
        ok = (ok and digest == posted["corpusDigest"] == manifest.get("corpusDigest")
              and chosen == posted["selected"] and code == 0
              and release["reader_comparison"]["ok"])
    out["ok"] = ok
    result.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
