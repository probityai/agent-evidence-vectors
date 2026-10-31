#!/usr/bin/env python3
"""Read frozen public source and original output; do not execute their workload."""
from __future__ import annotations
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

SPEC = {'source': '16d6c5edc700fea2f22cda6044f90953e01d7d8e',
 'run': 37944695894,
 'job': None,
 'question': 'Which retained SDK serializer outputs matched the selected canonical bytes, differed, or '
             'refused, across the complete recorded input population?',
 'evidenceClass': 'author-hosted-serializer-byte-comparison'}
PROVENANCE = {'sourceType': 'retained-public-source-and-original-host-output',
 'repository': 'probityai/agent-evidence-vectors',
 'sourceCommit': '16d6c5edc700fea2f22cda6044f90953e01d7d8e',
 'runID': 37944695894,
 'jobID': None,
 'retainedPacketAt': '2026-10-16T00:47:36.224877+00:00',
 'sources': [{'path': 'run.json',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/37944695894',
              'bytes': 13570,
              'sha256': '60505227c308f77399af8b030b8bb897dfc9a1ee7a66521d461253f84d1c8c7a'},
             {'path': 'jobs.json',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/37944695894/jobs?per_page=100',
              'bytes': 22777,
              'sha256': '4a322bf0e015111e1663185c4399d23755f3e97e3867a137009eab4bc23419c4'},
             {'path': 'workflow.yml',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/16d6c5edc700fea2f22cda6044f90953e01d7d8e/.github/workflows/mcp-sdk-jcs.yml',
              'bytes': 2856,
              'sha256': 'c0502915d7c8dc3f48fc02a1a1a823e9c1ab7e17489b5367272753c87a0d7c60'},
             {'path': 'source/interop/mcp-sdks/driver.py',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/16d6c5edc700fea2f22cda6044f90953e01d7d8e/interop/mcp-sdks/driver.py',
              'bytes': 11418,
              'sha256': '886c4662f0bcfd78122d9787a0f71b366fd19b852efbf9656a3761bfe2b1dcb6'},
             {'path': 'source/interop/mcp-sdks/run-all.sh',
              'url': 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/16d6c5edc700fea2f22cda6044f90953e01d7d8e/interop/mcp-sdks/run-all.sh',
              'bytes': 1634,
              'sha256': '18e1989ae847e9d22f08c61784395f4f968cded79032fe5e1a1370103d10508a'},
             {'path': 'mcp-sdk-jcs-csharp.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622679170/zip',
              'bytes': 1929,
              'sha256': 'c02a2eb489ae248ee4fff5730518a37f65fa1dc34379589b6e0845badf30f956'},
             {'path': 'mcp-sdk-jcs-go.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622624078/zip',
              'bytes': 1768,
              'sha256': '8167a56d5dcf8ba2d06dd0080798fc00648240cb4387721f35a835bfdf859d7f'},
             {'path': 'mcp-sdk-jcs-java.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622318551/zip',
              'bytes': 1779,
              'sha256': '3d45f451fbb101f3ca91c24597a484e7215ed9d5f626d3094b937de2311f8e34'},
             {'path': 'mcp-sdk-jcs-kotlin.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622889095/zip',
              'bytes': 1876,
              'sha256': '4084d50b2eb7abf3ba04f73181d02afd2af79d0818fd17fc8fbf1168ec467f8e'},
             {'path': 'mcp-sdk-jcs-php.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622903933/zip',
              'bytes': 1839,
              'sha256': '2d3bd1b920e7dcc67b3847f98afad34f725129fd97d138f246c48b7ca9612800'},
             {'path': 'mcp-sdk-jcs-python.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622769171/zip',
              'bytes': 1876,
              'sha256': 'bc1e3749d26138178ba3b5dffc03ddcbc0a28bc833ef91b6bc6f17bd73d33c64'},
             {'path': 'mcp-sdk-jcs-ruby.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11623033985/zip',
              'bytes': 1844,
              'sha256': '0228d00beb645b808b0c97bc425bdb1d7782ab43a74bc0abbc461c84988f445a'},
             {'path': 'mcp-sdk-jcs-rust.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11623213741/zip',
              'bytes': 1812,
              'sha256': 'e0a2a591749ec6520f191f863c95cd21d10adae0b4024a8befa4d6d819b03613'},
             {'path': 'mcp-sdk-jcs-swift.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622023934/zip',
              'bytes': 1773,
              'sha256': '260258980bbb5b7a3e6c3239064ae4f4040398f7f66a4758ee9c0150144603ae'},
             {'path': 'mcp-sdk-jcs-typescript.zip',
              'url': 'https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622228681/zip',
              'bytes': 1785,
              'sha256': 'ba867ef8f3eb81c3ddf572796fa2402f5bc517c110ebfc72cd49cd49535b288c'}],
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
    run = load(raw["run.json"])
    require(run["head_sha"] == SPEC["source"] and run["id"] == SPEC["run"], "workflow identity differs")
    jobs = load(raw["jobs.json"])["jobs"]
    require(len(jobs) == 10, "SDK host population differs")
    for job in jobs:
        host_job(raw["jobs.json"], job["id"])
    sdks = {}
    reference = None
    for name, value in sorted(raw.items()):
        if not name.startswith("mcp-sdk-jcs-") or not name.endswith(".zip"):
            continue
        sdk = name[len("mcp-sdk-jcs-"):-len(".zip")]
        data = load(member(value, sdk + ".json"))
        oracle = member(value, "jcs-admit.json")
        require(data["sdk"] == sdk, "SDK report identity differs")
        ids = [row["id"] for row in data["rows"]]
        require(len(ids) == len(set(ids)) == 27, "SDK raw row population differs")
        require(set(ids) == {row["id"] for row in load(oracle)["rows"]}, "SDK and oracle inputs differ")
        require(reference is None or oracle == reference, "retained oracle copies differ")
        reference = oracle
        sdks[sdk] = {"rows": len(ids), "verdicts": dict(sorted(Counter(row["verdict"] for row in data["rows"]).items()))}
    workflow = raw["workflow.yml"].decode()
    require(workflow.count("fail-on-divergence:") == 2 and
            "if: ${{ inputs.fail-on-divergence }}" in workflow and
            'run: python3 driver.py gate "${{ matrix.sdk }}"' in workflow,
            "workflow gate contract differs")
    defaults = re.findall(r"fail-on-divergence:\n\s+description:[^\n]+\n\s+default: (\w+)", workflow)
    report.update(source=SPEC["source"], sdkCount=len(sdks), perSDK=sdks,
                  workflowReportsDifferencesByDefault=defaults == ["false", "false"], numericNativeExit=None)
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
