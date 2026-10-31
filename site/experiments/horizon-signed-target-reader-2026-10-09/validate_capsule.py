#!/usr/bin/env python3
"""Read frozen public source and original output; do not execute their workload."""
from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

SPEC = {'source': 'c71095f3062c7411b3a7ed5c628733daf004ba9b',
 'run': 37931782273,
 'job': 113824012738,
 'question': 'What did the outside host CI establish about the supplied signed records and exact endpoint, '
             'and what remained unobserved?',
 'evidenceClass': 'outside-hosted-signed-record-reader'}
PROVENANCE = {'sourceType': 'retained-public-source-and-original-host-output',
 'repository': 'ogasurfproject-jpg/horizon-shield',
 'sourceCommit': 'c71095f3062c7411b3a7ed5c628733daf004ba9b',
 'runID': 37931782273,
 'jobID': 113824012738,
 'retainedPacketAt': '2026-10-16T00:47:36.224877+00:00',
 'sources': [{'path': 'repository.json',
              'url': 'https://api.github.com/repos/ogasurfproject-jpg/horizon-shield',
              'bytes': 6354,
              'sha256': '6f496f08cfe6e2bfe0fd3b1aa4c3539156d130a216bf3dc45729f4df1da9a223'},
             {'path': 'run.json',
              'url': 'https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/runs/37931782273',
              'bytes': 14877,
              'sha256': '1a5e5fc9a1c7c738ba4b1d34e30c3e2e0ff0670b6a27068e0ff19c60bf9b099b'},
             {'path': 'jobs.json',
              'url': 'https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/runs/37931782273/jobs?per_page=100',
              'bytes': 2942,
              'sha256': '60d9ffa4e993becce384b01f3e5b7f14d36a3081c9851cc85727b10adf38b3c1'},
             {'path': 'workflow.yml',
              'url': 'https://raw.githubusercontent.com/ogasurfproject-jpg/horizon-shield/c71095f3062c7411b3a7ed5c628733daf004ba9b/.github/workflows/probity-witness-reader.yml',
              'bytes': 4168,
              'sha256': '9533db6dfef1b344c8d0df61b69a5850c5f15b8e168a62af05b227555b4ddb45'},
             {'path': 'artifact.zip',
              'url': 'https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/artifacts/11616887017/zip',
              'bytes': 13061,
              'sha256': 'bf2720f339dcc7b2fa650835a1459cba4978709cb1e0f032c379e2167722fedf'},
             {'path': 'job-log.zip',
              'url': 'https://api.github.com/repos/ogasurfproject-jpg/horizon-shield/actions/jobs/113824012738/logs',
              'bytes': 6835,
              'sha256': 'e28a10a9f888388419f90b49267768d09854595d787e97377ddb9cee602cce07',
              'members': [{'path': 'job-log.txt',
                           'bytes': 29009,
                           'sha256': '496003aa9cac48bef892a9a5ddbbcba79bbc2de427f89a88b12b2333fac20455'}],
              'packaging': 'Lossless deterministic ZIP of original public body; 1980 container timestamp is '
                           'not execution time'}],
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
    job = host_job(raw["jobs.json"], SPEC["job"])
    run = load(raw["run.json"])
    require(run["head_sha"] == SPEC["source"] and run["id"] == SPEC["run"], "workflow identity differs")
    steps = load(member(raw["artifact.zip"], "steps.json"))
    a = load(member(raw["artifact.zip"], "pair-a-a2a.stdout"))
    b = load(member(raw["artifact.zip"], "pair-b-a2a.stdout"))
    reader = re.search(r"PROBITY_COMMIT: ([0-9a-f]{40})", raw["workflow.yml"].decode())
    require(reader is not None, "reader source pin missing")
    http = [int(code) for code in re.findall(r"[ab] ledger:.*HTTP Error (\d+)", member(raw["job-log.zip"], "job-log.txt").decode())]
    require(len(http) == 2, "ledger fetch output missing")
    report.update(hostCI={"source": job["head_sha"], "jobConclusion": job["conclusion"],
        "workflowActor": run["actor"]["login"], "numericNativeExit": None}, readerSource=reader.group(1),
        recordedSteps=steps, recordedStepCount=len(steps),
        allRecordedExitsMatch=all(step["matched"] is True and step["actual_exit"] == step["expected_exit"] for step in steps),
        pairA={"outcome": a["outcome"], "signatureVerified": a["signature_verified_under_pinned_key"],
               "targetMatches": a["target_matches"], "assertions": {key: a["assertions"][key] for key in
               ["total_assertions", "reported_true", "unevaluated", "all_eight_reported_true"]}},
        pairB={"outcome": b["outcome"], "signatureVerified": b["signature_verified_under_pinned_key"], "targetMatches": b["target_matches"]},
        ledgerFetchHTTP=http, freshNetworkWalkPerformed=a["scope"]["new_network_walk_performed"] or b["scope"]["new_network_walk_performed"])
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
