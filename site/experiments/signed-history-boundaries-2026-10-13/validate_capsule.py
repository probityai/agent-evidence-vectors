#!/usr/bin/env python3
"""Read frozen public source and original output; do not execute their workload."""
from __future__ import annotations
import ast
import hashlib
import io
import zipfile
import json
from pathlib import Path
import re

SPEC = {'source': '33d545104ff2f8c124cff465c96c013eeb809156',
 'run': 38353256915,
 'job': 115150232069,
 'question': 'Did the pinned signed-history tests expose genuine signed histories that a signature-only or '
             'unanchored reader would accept incorrectly?',
 'evidenceClass': 'author-hosted-signed-history-controls'}
PROVENANCE = {'sourceType': 'retained-public-source-and-original-host-output',
 'repository': 'probityai/agent-evidence-vectors',
 'sourceCommit': '33d545104ff2f8c124cff465c96c013eeb809156',
 'runID': 38353256915,
 'jobID': 115150232069,
 'retainedPacketAt': '2026-10-16T00:47:36.224877+00:00',
 'sources': [{'path': 'jobs.json',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/38353256915/jobs?per_page=100',
              'bytes': 39203,
              'sha256': 'b482c084b03786b2a4c591e9a7daa3d3d3cdea832e794104409d22d3159258be'},
             {'path': 'job-log.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/jobs/115150232069/logs',
              'bytes': 57609,
              'sha256': 'c7f56f08fbcdebad0d478c89e1ef912b02bc7a3139ffe95763006f9a436a4a4d',
              'members': [{'path': 'job-log.txt',
                           'bytes': 315701,
                           'sha256': '56a0d47454ed6f34f05736c8bf10ba09bedcbbff5e00b951a0a928477ea6914a'}],
              'packaging': 'Lossless deterministic ZIP of original public body; 1980 container timestamp is '
                           'not execution time'},
             {'path': 'source/workflows/ci.yml',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/.github/workflows/ci.yml',
              'bytes': 83481,
              'sha256': 'a6fe1c331ebcdaab779df225d45b0b837f3c8b545f5bb086f4551eb3bc33dcd9'},
             {'path': 'source/vectors-anchored-chain/README.md',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/vectors-anchored-chain/README.md',
              'bytes': 4332,
              'sha256': '728b909487a522c489526c997d3d68978deca9101af19540265e1b3ff46aeda1'},
             {'path': 'source/vectors-anchored-chain/check_vectors.py',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/vectors-anchored-chain/check_vectors.py',
              'bytes': 466,
              'sha256': '7df26677c48b6bef477f346ac52dec2c79862fdc3ccf08d4e26eecf620ab76d1'},
             {'path': 'source/vectors-anchored-chain/tests/test_corpus.py',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/vectors-anchored-chain/tests/test_corpus.py',
              'bytes': 5449,
              'sha256': 'c0916455353a98b5b73bb4c2477d6fc449029c66fdf085e4ed48be544caa5350'}],
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

def derive(directory: Path) -> dict:
    raw = read_sources(directory)
    report = {"question": SPEC["question"], "evidenceClass": SPEC["evidenceClass"]}
    host_job(raw["jobs.json"], SPEC["job"])
    log = member(raw["job-log.zip"], "job-log.txt").decode()
    command = "uv run --extra dev pytest vectors-anchored-chain/tests -q"
    require(command in log, "case-specific native command missing")
    marker = "##[group]Run " + command
    start = log.find(marker)
    require(start >= 0, "case-specific command group missing")
    end = log.find("##[group]Run ", start + len(marker))
    section = log[start:] if end < 0 else log[start:end]
    summaries = list(re.finditer(r"Z (\d+) passed in ([0-9.]+)s", section))
    require(len(summaries) == 1, "case-specific native result missing or repeated")
    tests = summaries[0]
    tree = ast.parse(raw["source/vectors-anchored-chain/tests/test_corpus.py"])
    sets = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "GENUINE_REJECTS" for target in node.targets)]
    require(len(sets) == 1 and len(sets[0]) == 6, "genuine-history assertion set differs")
    functions = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    required = {"test_eight_rejected_stores_hold_only_genuine_signed_records", "test_signature_only_verifier_is_refused_on_the_genuine_records",
        "test_verifier_without_the_anchor_misses_removal_and_branch_rollback", "test_every_check_is_forced_by_some_case",
        "test_verifier_that_rejects_everything_fails_the_controls", "test_missing_verifier_does_not_count_as_answered", "test_mutated_fixture_is_refused_before_execution"}
    require(required <= functions, "executed control definition missing")
    text = raw["source/vectors-anchored-chain/tests/test_corpus.py"].decode()
    require('"tail-removal-reanchored"' in text and '"rollback-to-abandoned-branch"' in text, "genuine signed boundary cases missing")
    readme = raw["source/vectors-anchored-chain/README.md"].decode()
    rows = [line for line in readme.splitlines() if line.startswith("| ") and not line.startswith(("| Case |", "| ---"))]
    report.update(source=SPEC["source"], nativeLog={"command": command, "testsPassed": int(tests.group(1)),
        "elapsedSeconds": float(tests.group(2)), "numericNativeExit": None}, sourceAssertions={
        "genuineSignedRejectedStores": len(sets[0]) + 2, "signatureOnlyMissedRejects": len(sets[0]) + 1,
        "withoutAnchorMissedRejects": 3, "allSixChecksForced": True, "rejectAllFailsPositiveControls": True,
        "missingVerifierUnanswered": True, "changedFixtureRefused": True}, fixturePopulationDeclared=len(rows), unrelatedDefaultArtifactExcluded=True)
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
