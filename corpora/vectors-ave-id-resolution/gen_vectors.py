#!/usr/bin/env python3
"""Generate the AVE id resolution corpus: members, MANIFEST.json and INDEX.md.

Each member is one tool output, in SARIF or in JSON findings form, judged
against one AVE records snapshot vendored byte for byte under snapshots/. The
snapshots are AVE's own release assets and are never written here; this
generator reads them, checks them against their release SHA256SUMS and the pins
below, and refuses to write a member the reference checker does not answer as
declared.

    python3 corpora/vectors-ave-id-resolution/gen_vectors.py [--out DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import resolve_ids  # noqa: E402

SUITE = "ave-id-resolution/v1"
SOURCE = "https://github.com/aveproject/ave"
#: The pins: release tag, the commit AVE built it from, and the records digest.
SNAPSHOTS = {
    "v1.2.0": {
        "sourceCommit": "a18315536706365021b514ab940392ed0805897e",
        "recordsSha256": "92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390",
    },
    "v1.3.0": {
        "sourceCommit": "647e1ce2fff39b26957b8f232a42ab3117f5c2ec",
        "recordsSha256": "7d3284314f7ea19af096df2b20e9d715b628a398cf88391d97be90a1ae074e74",
    },
}
ACTIVE_ID = "AVE-2026-00002"
UNKNOWN_ID = "AVE-2026-09999"
MALFORMED_ID = "AVE-2026-0002"
#: Active in v1.2.0 and rejected in v1.3.0: one id, two pins, two verdicts.
REJECTED_ID = "AVE-2026-00052"
TOOL_RULE = "example-rule-7"


def sarif(results: list[tuple[str, str | None]], run_sha: str | None = None) -> dict[str, Any]:
    """A minimal SARIF 2.1.0 log; each result is (ruleId, properties.ave_id or None)."""
    rules, seen = [], set()
    for rule_id, ave_id in results:
        if rule_id not in seen:
            seen.add(rule_id)
            rule: dict[str, Any] = {"id": rule_id, "shortDescription": {"text": f"rule {rule_id}"}}
            if ave_id is not None:
                rule["properties"] = {"ave_id": ave_id}
            rules.append(rule)
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "example-scanner", "version": "0.0.0", "rules": rules}},
        "results": [
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": f"finding for {rule_id} at line {n + 1}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "skills/example.md"},
                            "region": {"startLine": n + 1},
                        }
                    }
                ],
                **({"properties": {"ave_id": ave_id}} if ave_id is not None else {}),
            }
            for n, (rule_id, ave_id) in enumerate(results)
        ],
    }
    if run_sha is not None:
        run["properties"] = {"ave_records_sha256": run_sha}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def findings(ave_ids: list[str], snapshot: str) -> dict[str, Any]:
    """The implementer guide's JSON shape: run-level snapshot fields and one ave_id per finding."""
    return {
        "ave_catalog": snapshot,
        "ave_schema_version": snapshot.lstrip("v"),
        "ave_records_sha256": SNAPSHOTS[snapshot]["recordsSha256"],
        "findings": [
            {"rule_id": f"example-rule-{n + 1}", "ave_id": a, "severity": "HIGH"}
            for n, a in enumerate(ave_ids)
        ],
    }


#: (id, file, snapshot, output, verdict, codes, what it shows)
MEMBERS: list[tuple[str, str, str, dict[str, Any], str, list[str], str]] = [
    (
        "active-resolves-json",
        "output.json",
        "v1.2.0",
        findings([ACTIVE_ID], "v1.2.0"),
        "resolves",
        [],
        "an active id resolves",
    ),
    (
        "active-resolves-sarif",
        "output.sarif",
        "v1.2.0",
        sarif([(ACTIVE_ID, None)]),
        "resolves",
        [],
        "an active id resolves",
    ),
    (
        "unknown-id-json",
        "output.json",
        "v1.2.0",
        findings([UNKNOWN_ID], "v1.2.0"),
        "fails",
        ["id-unknown"],
        "a well-formed id with no record fails",
    ),
    (
        "unknown-id-sarif",
        "output.sarif",
        "v1.2.0",
        sarif([(UNKNOWN_ID, None)]),
        "fails",
        ["id-unknown"],
        "a well-formed id with no record fails",
    ),
    (
        "malformed-id-json",
        "output.json",
        "v1.2.0",
        findings([MALFORMED_ID], "v1.2.0"),
        "fails",
        ["id-malformed"],
        "an id that is not AVE-YYYY-NNNNN fails",
    ),
    (
        "malformed-id-sarif",
        "output.sarif",
        "v1.2.0",
        sarif([(MALFORMED_ID, None)]),
        "fails",
        ["id-malformed"],
        "an id that is not AVE-YYYY-NNNNN fails",
    ),
    (
        "not-active-json",
        "output.json",
        "v1.3.0",
        findings([REJECTED_ID], "v1.3.0"),
        "fails",
        ["id-not-active"],
        "a record whose status is not active fails",
    ),
    (
        "not-active-sarif",
        "output.sarif",
        "v1.3.0",
        sarif([(REJECTED_ID, None)]),
        "fails",
        ["id-not-active"],
        "a record whose status is not active fails",
    ),
    (
        "not-active-sarif-under-v1.2.0",
        "output.sarif",
        "v1.2.0",
        sarif([(REJECTED_ID, None)]),
        "resolves",
        [],
        "the same output against the earlier pin, where that record is active",
    ),
    (
        "property-id-not-active-sarif",
        "output.sarif",
        "v1.3.0",
        sarif([(TOOL_RULE, REJECTED_ID)]),
        "fails",
        ["id-not-active"],
        "an id carried in properties.ave_id under the tool's own rule id",
    ),
    (
        "one-unknown-among-active-sarif",
        "output.sarif",
        "v1.2.0",
        sarif([(ACTIVE_ID, None), (UNKNOWN_ID, None)]),
        "fails",
        ["id-unknown"],
        "one unresolved id fails the whole output",
    ),
    (
        "run-names-other-snapshot-sarif",
        "output.sarif",
        "v1.2.0",
        sarif([(ACTIVE_ID, None)], SNAPSHOTS["v1.3.0"]["recordsSha256"]),
        "fails",
        ["run-snapshot-differs"],
        "the run declares records other than the pinned snapshot",
    ),
    (
        "no-ave-id-sarif",
        "output.sarif",
        "v1.2.0",
        sarif([(TOOL_RULE, None)]),
        "no-ids",
        [],
        "a tool rule with no AVE id leaves nothing to judge",
    ),
]


def dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot_files(root: Path, release: str) -> dict[str, str]:
    """The vendored release assets, checked against their SHA256SUMS and the pin."""
    directory = root / "snapshots" / release
    files = {p.name: sha(p.read_bytes()) for p in sorted(directory.iterdir()) if p.is_file()}
    sums = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        digest, name = line.split(maxsplit=1)
        sums[name.lstrip("*")] = digest
    for name, digest in sums.items():
        if files.get(name) != digest:
            raise ValueError(f"{release}/{name}: does not match the release SHA256SUMS")
    if set(files) != set(sums) | {"SHA256SUMS"}:
        raise ValueError(f"{release}: file set differs from SHA256SUMS")
    if files["ave-records.json"] != SNAPSHOTS[release]["recordsSha256"]:
        raise ValueError(f"{release}: ave-records.json is not the pinned bytes")
    return files


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not from their declared hashes."""
    base, entries = Path(root), []
    for release, pin in manifest["snapshots"].items():
        if snapshot_files(base, release) != pin["files"]:
            raise ValueError(f"snapshot {release}: file digests differ from the manifest")
        entries += [[f"snapshots/{release}/{name}", d] for name, d in pin["files"].items()]
    for entry in manifest["vectors"]:
        path = base / entry["path"]
        if sha(path.read_bytes()) != entry["sha256"]:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append([entry["path"], entry["sha256"]])
    return sha(json.dumps(sorted(entries), separators=(",", ":")).encode("ascii"))


def build(root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    snapshots = {
        release: {
            "tag": f"{SOURCE}/releases/tag/{release}",
            **pin,
            "files": snapshot_files(root, release),
        }
        for release, pin in SNAPSHOTS.items()
    }
    files, vectors = {}, []
    for member_id, name, release, output, verdict, codes, shows in MEMBERS:
        data = dump(output)
        statuses = resolve_ids.load_snapshot(
            root / "snapshots" / release / "ave-records.json", SNAPSHOTS[release]["recordsSha256"]
        )
        got = resolve_ids.judge(json.loads(data), statuses, SNAPSHOTS[release]["recordsSha256"])
        if (got["verdict"], got["codes"]) != (verdict, codes):
            raise ValueError(
                f"{member_id}: checker answers {got['verdict']} {got['codes']}, "
                f"declared {verdict} {codes}"
            )
        path = f"cases/{member_id}/{name}"
        files[path] = data
        vectors.append(
            {
                "id": member_id,
                "path": path,
                "sha256": sha(data),
                "snapshot": release,
                "expected": {"verdict": verdict, "codes": codes},
                "shows": shows,
            }
        )
    counts: dict[str, int] = {}
    for v in vectors:
        counts[v["expected"]["verdict"]] = counts.get(v["expected"]["verdict"], 0) + 1
    manifest = {
        "suite": SUITE,
        "source": {"repository": SOURCE},
        "credit": (
            "chaksaray, for the AVE project: the v1.2.0 pin, the four cases (active, unknown, "
            "malformed, not active) and the rule that any status other than active fails"
        ),
        "checker": "resolve_ids.py",
        "rules": list(resolve_ids.RULES),
        "snapshots": snapshots,
        "counts": dict(sorted(counts.items())),
        "vectors": vectors,
    }
    return manifest, files


def index(manifest: dict[str, Any]) -> str:
    lines = [
        "# Members",
        "",
        "Generated by `gen_vectors.py`; do not edit.",
        "",
        "| Member | Snapshot | Verdict | Codes | Shows |",
        "| --- | --- | --- | --- | --- |",
    ]
    for v in manifest["vectors"]:
        codes = ", ".join(v["expected"]["codes"])
        lines.append(
            f"| `{v['id']}` | {v['snapshot']} | {v['expected']['verdict']} "
            f"| {codes} | {v['shows']} |"
        )
    return "\n".join(lines) + "\n"


def generate(out: Path) -> None:
    manifest, files = build(HERE)
    for path, data in files.items():
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if out != HERE:
        for release in SNAPSHOTS:
            (out / "snapshots" / release).mkdir(parents=True, exist_ok=True)
            for name in manifest["snapshots"][release]["files"]:
                (out / "snapshots" / release / name).write_bytes(
                    (HERE / "snapshots" / release / name).read_bytes()
                )
    manifest["corpusDigest"] = corpus_digest(manifest, str(out))
    (out / "MANIFEST.json").write_bytes(dump(manifest))
    (out / "INDEX.md").write_text(index(manifest), encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--out", type=Path, default=HERE)
    generate(parser.parse_args().out.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
