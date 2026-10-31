#!/usr/bin/env python3
"""Score one implementation from data/board.toml against the pinned corpus, with controls.

    python3 tools/run_board.py --id moltrust-aae --slot pinned --src PATH --out result.json \\
        [--harness agent-evidence-vectors] [--python python3] [--vectors-src PATH]
    python3 tools/run_board.py --list                 print the ids of the scored implementations
    python3 tools/run_board.py --id ID --print-deps   print the dependency file an id needs, or nothing

`--src` is a checkout of the implementation. `--python` runs the adapter and the
implementation (an environment with the implementation's dependencies); `--harness` is the
corpus harness command, installed from the pinned `agent-evidence-vectors` release. The two
are separate environments, so an implementation's dependencies never decide the corpus.

A family verdict is `pass` when the harness executed every vector and none failed, `fail`
when it executed every vector and some failed, and `not runnable` when the implementation
could not be run to completion. Before a verdict is kept the same adapter runs two controls:
the reference canonicalizer must pass every vector (so a failure is not the harness or the
adapter) and a deliberately wrong canonicalizer must fail the ten vectors the corpus expects it
to fail (so the harness can see a failure). A control that does not behave turns the family
into `not runnable` with the control named.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOARD = tomllib.loads((ROOT / "data" / "board.toml").read_text(encoding="utf-8"))
ADAPTERS = {"py": ROOT / "board" / "adapters" / "py_adapter.py", "node": ROOT / "board" / "adapters" / "node_adapter.mjs"}
BAD_CONTROL_FAILS = 10  # scripts/a2a-jcs-rails-test.py in agent-evidence-vectors: json.dumps(sort_keys) fails exactly ten
GOOD_INPUT = '{"b":[3,2,1],"a":"x"}'
GOOD_OUTPUT = b'{"a":"x","b":[3,2,1]}'


def implementation(ident: str) -> dict:
    for item in BOARD["implementation"]:
        if item["id"] == ident:
            return item
    raise SystemExit(f"unknown implementation {ident}")


def expand(args: list[str], src: Path) -> list[str]:
    return [a.replace("{src}", str(src)) for a in args]


def adapter_command(run: dict, src: Path, python: str, node_runner: str | None) -> list[str]:
    kind = run["adapter"]
    if kind == "py":
        return [python, str(ADAPTERS["py"]), *expand(run["args"], src)]
    if kind == "node":
        return [node_runner or "tsx", str(ADAPTERS["node"]), *expand(run["args"], src)]
    raise SystemExit(f"adapter {kind} has no command form")


def harness_run(harness: str, verifier: list[str], report: Path, timeout: int = 900) -> dict:
    env = dict(os.environ, A2A_JCS_TARGET="rfc8785", PYTHONDONTWRITEBYTECODE="1")
    cmd = [*shlex.split(harness), "--corpus", "vectors-a2a-jcs-v01", "--verifier", shlex.join(verifier), "--report", str(report)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout, check=False)
    if not report.exists():
        return {"ran": False, "exit": proc.returncode, "stderr": (proc.stderr or proc.stdout)[-600:]}
    data = json.loads(report.read_text(encoding="utf-8"))
    return {"ran": True, "exit": proc.returncode, "report": data}


def summarize(result: dict) -> dict:
    if not result["ran"]:
        return {"verdict": "not runnable", "why": "the harness produced no report: " + result["stderr"].strip()[-300:]}
    data = result["report"]
    totals, rows = data["totals"], data["vectors"]
    executed = data["verifier"]["vectorsExecuted"]
    failing = [{"id": r["id"], "kind": r["kind"], "outcome": r["outcome"]} for r in rows if r["status"] != "PASS"]
    out = {"vectors": totals["vectors"], "executed": executed, "passed": totals["pass"], "failed": totals["fail"], "failing": failing}
    if executed < totals["vectors"]:
        out["verdict"] = "not runnable"
        out["why"] = f"the implementation answered {executed} of {totals['vectors']} vectors; the rest errored"
    else:
        out["verdict"] = "pass" if totals["fail"] == 0 else "fail"
    return out


def controls(harness: str, python: str, tmp: Path) -> dict:  # python: the harness environment
    """The same adapter, pointed at a correct and a wrong canonicalizer."""
    py = [python, str(ADAPTERS["py"])]
    good = summarize(harness_run(harness, [*py, "--module", "agent_evidence_vectors.a2ajcs", "--func", "canonicalize"], tmp / "good.json"))
    bad = summarize(harness_run(harness, [*py, "--file", str(ROOT / "board" / "adapters" / "bad_control.py"), "--func", "canonicalize"], tmp / "bad.json"))
    ok = good.get("verdict") == "pass" and bad.get("verdict") == "fail" and bad.get("failed") == BAD_CONTROL_FAILS
    return {"ok": ok, "reference": {k: good.get(k) for k in ("verdict", "passed", "vectors")},
            "wrong": {k: bad.get(k) for k in ("verdict", "failed", "vectors")}}


def smoke(command: list[str], tmp: Path) -> dict:
    """One known-good input through the implementation's own adapter."""
    path = tmp / "good-input.json"
    path.write_text(GOOD_INPUT, encoding="utf-8")
    proc = subprocess.run([*command, "rfc8785", str(path)], capture_output=True, text=True, check=False)
    got = None
    if proc.returncode == 0 and proc.stdout.strip():
        got = bytes.fromhex(json.loads(proc.stdout.strip().splitlines()[-1])["canonical_utf8_hex"])
    return {"ok": got == GOOD_OUTPUT, "exit": proc.returncode, "got": None if got is None else got.decode("utf-8", "replace")}


def float_vector_ids(harness_python: str) -> set[str]:
    """Ids of the vectors whose input holds a JSON number with a fraction or an exponent."""
    code = ("import agent_evidence_vectors,os;print(os.path.join(os.path.dirname(agent_evidence_vectors.__file__),"
            "'corpora','vectors-a2a-jcs-v01'))")
    base = Path(subprocess.run([harness_python, "-I", "-c", code], capture_output=True, text=True, check=True).stdout.strip())

    def has_float(node) -> bool:
        if isinstance(node, float):
            return True
        if isinstance(node, dict):
            return any(has_float(v) for v in node.values())
        if isinstance(node, list):
            return any(has_float(v) for v in node)
        return False

    found = set()
    for path in base.glob("*/*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        if "id" not in data:
            continue
        raw = data.get("input_raw")
        value = json.loads(raw, parse_float=lambda t: float(t)) if isinstance(raw, str) and raw.lstrip()[:1] in "{[" else data.get("input")
        if has_float(value):
            found.add(data["id"])
    return found


def declared_subset(entry: dict, rule: str, harness_python: str) -> dict:
    """Score beside the verdict the vectors inside the subset the implementation declares."""
    outside = float_vector_ids(harness_python)
    failing_ids = {r["id"] for r in entry.get("failing", [])}
    inside = entry["vectors"] - len(outside)
    return {"rule": rule, "vectors": inside, "passed": inside - len(failing_ids - outside),
            "failing_inside": sorted(failing_ids - outside), "failing_outside": sorted(failing_ids & outside),
            "outside": len(outside)}


def display(command: list[str], src: Path, args) -> str:
    """The command as published: no machine path survives, only the placeholders and tool names."""
    text = " ".join(shlex.quote(c) for c in command)
    for path, name in ((args.node_runner, "tsx"), (args.python, "python3")):
        if path:
            text = text.replace(str(path), name)
    return text.replace(str(src), "{src}").replace(str(ROOT), "site")


def run_jcs(item: dict, run: dict, args, tmp: Path) -> dict:
    src = Path(args.src)
    command = adapter_command(run, src, args.python, args.node_runner)
    entry = {"family": run["family"], "command": display(command, src, args)}
    ctl = controls(args.harness, args.harness_python or args.python, tmp)
    entry["controls"] = ctl
    sm = smoke(command, tmp)
    entry["known_good_input"] = sm
    if not ctl["ok"]:
        return {**entry, "verdict": "not runnable", "why": "a control did not behave, so no verdict is kept"}
    if not sm["ok"]:
        return {**entry, "verdict": "not runnable", "why": "the implementation did not answer the known-good input through its adapter"}
    scored = {**entry, **summarize(harness_run(args.harness, command, tmp / "report.json"))}
    if run.get("subset") and scored["verdict"] in ("pass", "fail"):
        scored["declared_subset"] = declared_subset(scored, run["subset"], args.harness_python or args.python)
    return scored


def proposed_clauses(vectors_src: Path) -> set[str]:
    """Clauses the corpus marks proposed: the verifier's own contract text leaves them open."""
    index = (vectors_src / "vectors-anchor-stream" / "INDEX.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\| `(ans-c-\d+)` \| proposed \|", index, flags=re.M))


def anchor_control(args, runner: Path, tmp: Path) -> dict:
    """The runner, given the tag the corpus recorded, must reproduce that recording member by member."""
    tag = "anchors-verify-v0.10"
    recording = json.loads((runner.parent / "recordings" / f"{tag}.json").read_text(encoding="utf-8"))[tag]
    show = subprocess.run(["git", "-C", args.src, "show", f"{tag}:anchors_verify.py"], capture_output=True, check=False)
    if show.returncode != 0:
        return {"ok": False, "note": f"the tag {tag} could not be read from the implementation's history"}
    verifier = tmp / "anchors_verify.py"
    verifier.write_bytes(show.stdout)
    proc = subprocess.run([args.python, "-I", str(runner), "--verifier", str(verifier), "--label", tag, "--json"],
                          capture_output=True, text=True, check=False, cwd=runner.parent)
    try:
        rows = json.loads(proc.stdout)[tag]
    except (json.JSONDecodeError, KeyError):
        return {"ok": False, "note": "the runner printed no table for the recorded tag"}
    seen = {row["id"]: bool(row["agrees"]) for row in rows}
    same = all(seen.get(member) == agreed for member, agreed in recording.items())
    return {"ok": same, "note": f"the runner reproduces the corpus's own recording of {tag} on all {len(recording)} recorded members"
            if same else f"the runner disagrees with the recording of {tag}"}


def run_anchor_stream(item: dict, run: dict, args, tmp: Path) -> dict:
    src = Path(args.src)
    vectors_src = Path(args.vectors_src)
    runner = vectors_src / "vectors-anchor-stream" / "run_verifier.py"
    command = [args.python, "-I", str(runner), *expand(run["args"], src)]
    entry = {"family": run["family"], "command": "python3 -I vectors-anchor-stream/run_verifier.py --verifier {src}/anchors_verify.py"}
    ctl = anchor_control(args, runner, tmp)
    if not ctl["ok"]:
        return {**entry, "controls": ctl, "verdict": "not runnable", "why": "the control did not behave, so no verdict is kept: " + ctl["note"]}
    proc = subprocess.run(command, capture_output=True, text=True, check=False, cwd=runner.parent)
    text = proc.stdout + proc.stderr
    found = re.search(r"==\s*\S+:\s*(\d+) of (\d+) agree", text)
    if not found:
        return {**entry, "verdict": "not runnable", "why": "the runner printed no agreement line: " + text.strip()[-300:]}
    agree, total = int(found.group(1)), int(found.group(2))
    lines = [ln.strip() for ln in text.splitlines() if re.match(r"\s+v[0-9a-f]{16} ", ln)]
    # The corpus's own expectation is checked against a verifier that passes: the member lines come from the runner itself.
    return {**entry, "verdict": "pass" if agree == total and proc.returncode == 0 else "fail", "vectors": total, "executed": total,
            "passed": agree, "failed": total - agree, "failing": [{"detail": ln[:240], "clause": (re.search(r"(ans-c-\d+)", ln) or [None, ""])[1],
                         "proposed": bool(re.search(r"(ans-c-\d+)", ln)) and re.search(r"(ans-c-\d+)", ln)[1] in proposed_clauses(vectors_src)} for ln in lines],
            "controls": ctl}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id")
    ap.add_argument("--slot", default="pinned")
    ap.add_argument("--src")
    ap.add_argument("--out")
    ap.add_argument("--harness", default="agent-evidence-vectors")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--harness-python")
    ap.add_argument("--node-runner")
    ap.add_argument("--vectors-src")
    ap.add_argument("--aggregate", help="directory of per-run result files; write them as one results file to --out")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--print-deps", action="store_true")
    args = ap.parse_args()
    if args.list:
        print(json.dumps([i["id"] for i in BOARD["implementation"] if i["status"] == "scored"]))
        return 0
    if args.aggregate:
        records = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(args.aggregate).rglob("*.json"))]
        records.sort(key=lambda r: (r["id"], r["slot"]))
        out = {"generated": datetime.date.today().isoformat(), "vectors_version": BOARD["meta"]["vectors_version"], "results": records}
        Path(args.out).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"aggregated {len(records)} results")
        return 0
    item = implementation(args.id)
    if args.print_deps:
        for run in item.get("run", []):
            if run.get("deps"):
                print(run["deps"].replace("{src}", args.src or "{src}"))
        return 0
    results = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for run in item["run"]:
            results.append((run_anchor_stream if run["adapter"] == "anchor-stream" else run_jcs)(item, run, args, tmp))
    sha = subprocess.run(["git", "-C", args.src, "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    record = {"id": item["id"], "slot": args.slot, "repo": item["repo"], "source_sha": sha, "families": results,
              "run_url": os.environ.get("BOARD_RUN_URL", "")}
    Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"id": item["id"], "slot": args.slot, "verdicts": {r["family"]: r["verdict"] for r in results}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
