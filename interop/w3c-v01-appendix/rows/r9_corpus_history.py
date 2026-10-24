#!/usr/bin/env python3
"""R9: the report corpus across v0.17.4, v0.18.0 and v0.18.1.

    python rows/r9_corpus_history.py <work dir> <result.json>

For each release, from the vectors-w3c-report tree at its tagged commit:
recompute corpusDigest (SHA-256 over the member files in identifier order),
count the section 10 selection (subjectType report, every cited requirement
agreed, the rule in gen_vectors.selection), count the selected members rejected
under W3C-R-016, and run the Python reference reader of that release over the
tree (agent_evidence_vectors.w3creport.judge from PyPI at the same version).

Exits 0 only when every digest and count equals the value posted in 0079 and
the reader of each release finds every member behaving as its manifest says.
The Go and Rust readers are not run here.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402

JUDGE = """
import sys
from agent_evidence_vectors import w3creport
judged = w3creport.judge(sys.argv[1])
print(w3creport.render(judged, 'w3c-report-v01-conformance'), end='')
sys.exit(0 if judged.ok() else 1)
"""


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


def main() -> int:
    work, result = Path(sys.argv[1]), Path(sys.argv[2])
    log = work / "log.txt"
    expect = rerun.ROWS["rows"]["R9"]["expect"]
    out: dict = {"releases": {}}
    ok = True
    for tag, posted in expect.items():
        tree = rerun.aev_tree(tag, work / f"aev-{tag}", log, ["/vectors-w3c-report/"])
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
        }
        out["releases"][tag] = release
        ok = (ok and digest == posted["corpusDigest"] == manifest.get("corpusDigest")
              and chosen == posted["selected"] and code == 0)
    out["ok"] = ok
    result.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
