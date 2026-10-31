#!/usr/bin/env python3
"""Read frozen public source and original output; do not execute their workload."""
from __future__ import annotations
import ast
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

SPEC = {'source': 'b2800b26ec6cf60fee8e95682660846f674f97c2',
 'run': 38783949790,
 'job': 116591068820,
 'question': 'Did the public guard correct a benign document-writing false alarm while keeping '
             'destructive-push controls, and which broader replay counts remain author reports?',
 'evidenceClass': 'author-reported-history-with-hosted-public-regression'}
PROVENANCE = {'sourceType': 'retained-public-source-and-original-host-output',
 'repository': 'probityai/ratchet',
 'sourceCommit': 'b2800b26ec6cf60fee8e95682660846f674f97c2',
 'runID': 38783949790,
 'jobID': 116591068820,
 'retainedPacketAt': '2026-10-16T00:47:36.224877+00:00',
 'sources': [{'path': 'job.json',
              'url': 'https://api.github.com/repos/probityai/ratchet/actions/jobs/116591068820',
              'bytes': 2986,
              'sha256': 'a923f356e5559590e291029cef55bcba150c6769a3db9b54e38863eebb9f9e9d'},
             {'path': 'job-log.zip',
              'url': 'https://api.github.com/repos/probityai/ratchet/actions/jobs/116591068820/logs',
              'bytes': 719825,
              'sha256': '3f71a2d1e314d2dd94fc54863126ada65c3947dced8f6ae0563ec6e060d30c99',
              'members': [{'path': 'job-log.txt',
                           'bytes': 8008375,
                           'sha256': 'e98010c7bfa4ae18e1f8fccc72da7307681ab6833e9ff2ee3b1cf6f2272fce2e'}],
              'packaging': 'Lossless deterministic ZIP of original public body; 1980 container timestamp is '
                           'not execution time'},
             {'path': 'source/docs/results/hooks-replay.md',
              'url': 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/docs/results/hooks-replay.md',
              'bytes': 1795,
              'sha256': '0719613418dee2c94b93cf137b600e2b521819698fc0bacae268a1d7f0e58584'},
             {'path': 'source/pyproject.toml',
              'url': 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/pyproject.toml',
              'bytes': 3800,
              'sha256': '95c6f7175246cd52be84099d2973c717aaf765a3e5dbe9fa4b84932c5c217cfb'},
             {'path': 'source/workflows/ci.yml',
              'url': 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/.github/workflows/ci.yml',
              'bytes': 9335,
              'sha256': '577b8b33e8d84584ad3bb5e613389cfacd85c3ece45dff049878ae0d06dbf5fc'},
             {'path': 'source/tests/export/test_example.py',
              'url': 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/tests/export/test_example.py',
              'bytes': 8328,
              'sha256': '10e8f9c57eb18618f9b8b0d95d4275753d40a384ceedd43380f00db960e2f8d1'},
             {'path': 'source/examples/claude-code/no_force_push_main.py',
              'url': 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/examples/claude-code/no_force_push_main.py',
              'bytes': 13020,
              'sha256': '93ff0217a5d985a7c5d6bde1a28598ecc5562e535cfc2efcb0ec7129567ee341'},
             {'path': 'source/examples/claude-code/hooks/ratchet_no_force_push_main.py',
              'url': 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/examples/claude-code/hooks/ratchet_no_force_push_main.py',
              'bytes': 63391,
              'sha256': 'b99b090d0805d3745e542dc0d3af5484dd5c6c780bef080eca4e6121bc92515e'}],
 'limit': 'Historical source and original output only. This packet does not execute the original workload, '
          'authenticate a copied operator string or independently repeat a private aggregate.'}

def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def load(raw):
    return json.loads(raw, object_pairs_hook=unique)

def member(raw: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(archive.namelist().count(name) == 1, "archive member missing or repeated")
        info = archive.getinfo(name)
        require(info.file_size <= 16 * 1024 * 1024, "archive member exceeds bound")
        return archive.read(name)

def read_sources(directory: Path) -> dict[str, bytes]:
    raw = {}
    for row in PROVENANCE["sources"]:
        value = (directory / row["path"]).read_bytes()
        require(len(value) == row["bytes"] and hashlib.sha256(value).hexdigest() == row["sha256"],
                "retained public source differs: " + row["path"])
        for item in row.get("members", []):
            decoded = member(value, item["path"])
            require(len(decoded) == item["bytes"] and hashlib.sha256(decoded).hexdigest() == item["sha256"],
                    "decoded public source differs")
        raw[row["path"]] = value
    require(load((directory / "provenance.json").read_bytes()) == PROVENANCE, "source provenance differs")
    return raw

def host_job(raw, identity):
    data = load(raw)
    jobs = data.get("jobs", [data])
    selected = [job for job in jobs if job["id"] == identity]
    require(len(selected) == 1, "host job missing or repeated")
    job = selected[0]
    require(job["head_sha"] == SPEC["source"] and job["run_id"] == SPEC["run"]
            and job["status"] == "completed" and job["conclusion"] == "success", "host identity or result differs")
    return job

def _case_literal(node):
    """Read bounded literal strings without executing captured test source."""
    if isinstance(node, ast.Constant) and type(node.value) in {str, int, bool}:
        value = node.value
    elif isinstance(node, (ast.Tuple, ast.List)):
        values = [_case_literal(item) for item in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else values
    elif isinstance(node, ast.BinOp):
        left, right = _case_literal(node.left), _case_literal(node.right)
        if isinstance(node.op, ast.Add) and type(left) is str and type(right) is str:
            value = left + right
        elif isinstance(node.op, ast.Mult) and type(left) is str and type(right) is int and 0 <= right <= 64:
            value = left * right
        else:
            raise ValueError("source case expression is not a bounded literal")
    else:
        raise ValueError("source case expression is not a bounded literal")
    require(type(value) is not str or len(value) <= 65536, "source case literal exceeds bound")
    return value

def derive(directory: Path) -> dict:
    raw = read_sources(directory)
    report = {"question": SPEC["question"], "evidenceClass": SPEC["evidenceClass"]}
    host_job(raw["job.json"], SPEC["job"])
    log = member(raw["job-log.zip"], "job-log.txt").decode()
    native = re.search(r"Z (\d+) passed, (\d+) skipped, (\d+) deselected in ([0-9.]+)s", log)
    require(native is not None, "original public regression output missing")
    history = raw["source/docs/results/hooks-replay.md"].decode()
    first = re.search(r"checked ([0-9,]+) sessions and ([0-9,]+) tool calls and\nfired (\d+) times: (\d+) real force-pushes to a main branch and (\d+) false alarm, with (\d+) checker crashes, in (\d+) s on four\nworkers", history)
    require(first is not None, "original author-reported adverse run missing")
    first_values = [int(value.replace(",", "")) for value in first.groups()]
    first_report = dict(zip(["sessions", "toolCalls", "fires", "realForcePushes", "falseAlarms", "crashes", "seconds"], first_values, strict=True))
    first_report["workers"] = 4
    table = {}
    for line in history.splitlines():
        if line.startswith("| "):
            parts = [part.strip() for part in line.strip("|").split("|")]
            table[parts[0]] = parts[1]
    fires = re.fullmatch(r"(\d+), all real force-pushes to a main branch; (\d+) false alarms", table["Guard fires"])
    time = re.match(r"(\d+) s on one worker", table["Check time"])
    skip = re.search(r"Unreadable\ntranscript files \((\d+)\) and malformed lines \((\d+)\)", history)
    require(fires is not None and time is not None and skip is not None, "author report accounting missing")
    second_report = {"sessions": int(table["Sessions"].replace(",", "")), "toolCalls": int(table["Tool calls checked"].replace(",", "")),
        "fires": int(fires.group(1)), "realForcePushes": int(fires.group(1)), "falseAlarms": int(fires.group(2)),
        "crashes": int(table["Checker crashes"]), "seconds": int(time.group(1)), "workers": 1,
        "unreadableTranscriptsSkipped": int(skip.group(1)), "malformedLinesSkipped": int(skip.group(2))}
    tree = ast.parse(raw["source/tests/export/test_example.py"])
    cases = [_case_literal(node.value) for node in tree.body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == "CASES" for target in node.targets)]
    require(len(cases) == 1, "public guard cases missing")
    def expected(command):
        selected = [result for text, branch, result in cases[0] if text == command]
        require(len(selected) == 1, "selected guard command missing or repeated")
        return selected[0]
    benign = [result for text, branch, result in cases[0] if "packet.md" in text and "python3 - <<" in text]
    require(len(benign) == 1, "benign document case missing")
    require('testpaths = ["tests"]' in raw["source/pyproject.toml"].decode() and
        'test_guard_blocks_exactly_the_destructive_pushes' in raw["source/tests/export/test_example.py"].decode(), "default regression selection differs")
    report.update(source=SPEC["source"], authorReportedReplay={"first": first_report, "second": second_report},
        publicRegression={"benignPythonDocumentHeredocExpectedFire": benign[0], "mirrorPushExpectedFire": expected("git push --mirror origin"),
        "mirrorDryRunExpectedFire": expected("git push --mirror --dry-run origin"), "shellFedHeredocExpectedFire": expected("bash <<'EOF'\ngit push -f origin main\nEOF")},
        nativeLog={"testsPassed": int(native.group(1)), "skipped": int(native.group(2)), "deselected": int(native.group(3)),
        "elapsedSeconds": float(native.group(4)), "numericNativeExit": None}, privateAggregateIndependentlyReplayed=False)
    return report

def validate(directory: Path | None = None) -> None:
    directory = Path(__file__).resolve().parent if directory is None else directory
    derived = derive(directory)
    actual = load((directory / "report.json").read_bytes())
    require(json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(derived, sort_keys=True, allow_nan=False),
            "report differs from original source and output")

if __name__ == "__main__":
    validate()
    print("retained source and original output match the complete report")
