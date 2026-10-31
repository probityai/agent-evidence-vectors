#!/usr/bin/env python3
"""Read frozen public source and original output; do not execute their workload."""
from __future__ import annotations
import hashlib
import io
import zipfile
import json
from pathlib import Path
import re

SPEC = {'source': '2212fe0fb413003b1b329e4c4b034c45746f571d',
 'run': 38361073429,
 'job': 115175144532,
 'question': 'Which structural and rule-mutation checks actually ran for the pinned NIST AI300-1 extraction?',
 'evidenceClass': 'author-hosted-structural-rule-check'}
PROVENANCE = {'sourceType': 'retained-public-source-and-original-host-output',
 'repository': 'probityai/agent-evidence-vectors',
 'sourceCommit': '2212fe0fb413003b1b329e4c4b034c45746f571d',
 'runID': 38361073429,
 'jobID': 115175144532,
 'retainedPacketAt': '2026-10-16T00:47:36.224877+00:00',
 'sources': [{'path': 'jobs.json',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/38361073429/jobs?per_page=100',
              'bytes': 5905,
              'sha256': '4b5e519a8eb8764b74e3bb1c218861b8bffdf30c2097721905d55cf567d99c25'},
             {'path': 'job-log.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/jobs/115175144532/logs',
              'bytes': 6622,
              'sha256': '5d2ac1335d8c3e8b68a1d1b4866331b023e1502f9857e63cb668a81d0f2ba831',
              'members': [{'path': 'job-log.txt',
                           'bytes': 29795,
                           'sha256': '8a1a8914b25c0483013e544815efa146159cc797d28f9e896c7834976f778df5'}],
              'packaging': 'Lossless deterministic ZIP of original public body; 1980 container timestamp is '
                           'not execution time'},
             {'path': 'source/workflows/nist-ai-300-1.yml',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/.github/workflows/nist-ai-300-1.yml',
              'bytes': 2361,
              'sha256': '7602f2fca48a01d4fe6e3f51777ec150520688bb1d572918de3c91935c3419d1'},
             {'path': 'source/interop/nist-ai-300-1/README.md',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/interop/nist-ai-300-1/README.md',
              'bytes': 5032,
              'sha256': '01e06b65b10a7306b0201a02c9fb373a83867677c898baf77e221e232b37a29a'},
             {'path': 'source/interop/nist-ai-300-1/check_vectors.py',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/interop/nist-ai-300-1/check_vectors.py',
              'bytes': 14667,
              'sha256': '19a86a0b5cb3eb3882e08777b378c03f72f766bedfcf1d529ec5641111a037c5'}],
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
    counts = re.findall(r"ok: (\d+) tables on (\d+) pages and (\d+) reviewer notes make up all (\d+) ruled boxes in the (\d+)-page PDF, (\d+) rows by both extractions; (\d+) members over (\d+) rules; source and (\d+) bindings re-derived; (\d+) deletions and (\d+) dropped conditions", log)
    require(len(counts) == 2 and counts[0] == counts[1], "checker output population differs")
    keys = ["tables", "tablePages", "reviewerNotes", "ruledBoxes", "pdfPages", "rowsByBothExtractions", "members", "rules", "bindingsRederived", "deletionControls", "droppedConditionControls"]
    population = dict(zip(keys, map(int, counts[0]), strict=True))
    tests = re.search(r"Ran (\d+) tests in ([0-9.]+)s", log)
    require(tests is not None and re.search(r"Z OK\s*$", log, re.MULTILINE), "native test success output missing")
    regenerated = re.search(r"wrote (\d+) members over (\d+) rules", log)
    require(regenerated is not None and "git diff --exit-code -- interop/nist-ai-300-1" in log, "regeneration check missing")
    report.update(source=SPEC["source"], nativeLog={"unitTestsPassed": int(tests.group(1)), "elapsedSeconds": float(tests.group(2)),
        "successMarker": "OK", "numericNativeExit": None}, checkedPopulation=population,
        regeneration="wrote" + regenerated.group(1) + "membersover" + regenerated.group(2) + "rules;gitdiffclean")
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
