#!/usr/bin/env python3
"""Build the ACI conformance corpus from the deployment fixtures beside it.

A member of this corpus is one ACI deployment: the set of files an organization
publishes at its domain, which is `identity.json`, `capabilities.json`,
`knowledge.json`, `trust.json`, `agents.json`, `llms.txt` and `.well-known/aci`,
as many of them as the deployment has. Every other corpus in this repository
names a member after the digest of ONE file, so a deployment is serialised into
one file here: a JSON object mapping each relative path to that file's exact
text. That keeps the identifier a function of the member's own bytes, which is
what lets a flipped byte name the member it was flipped in.

The sources are declared in SOURCES below rather than discovered, so a fixture
directory that stops being built is an absence this file's own output reveals
instead of a silence.

Run from the corpus directory or the repository root; both work.
Regenerates byte-identically.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

SUITE = "aci"
SPEC_VERSION = "0.9"
# The commit of narko4u/aci-spec the vendored example deployments were taken at.
# A corpus that pins nothing certifies against text nobody published.
SPEC_COMMIT = "9fb47bbb6b04d92270320786a5c16178e3fe1642"

# Every file an ACI deployment may publish, in the order a reader meets them.
DEPLOYMENT_FILES = (
    "identity.json",
    "capabilities.json",
    "knowledge.json",
    "trust.json",
    "agents.json",
    "llms.txt",
    ".well-known/aci",
)

# The nineteen normative requirements this corpus exercises, each with the
# SPEC.md section it comes from. The reader carries the same table and the
# corpus-level check below asserts the two agree, because a check that exists in
# one and not the other is a requirement nothing forces.
CHECKS = {
    "ACI-SER-001": "13.1",
    "ACI-LVL-001": "3.1-3.3",
    "ACI-LVL-002": "3.3",
    "ACI-REQ-001": "5.2, 6.2, 7.2, 8.2, 9.2",
    "ACI-IDF-001": "5.2",
    "ACI-IDF-002": "10.1",
    "ACI-IDF-003": "10.1",
    "ACI-TS-001": "5.2, 16",
    "ACI-CON-001": "17.2",
    "ACI-CON-002": "17.2",
    "ACI-DIS-001": "4.1",
    "ACI-DIS-002": "4.2",
    "ACI-DIS-003": "4.2",
    "ACI-EXT-001": "12.2",
    "ACI-EXT-002": "12.2",
    "ACI-AGT-001": "9.4",
    "ACI-BLK-001": "6.4, 7.4, 8.4, 9.4",
    "ACI-LIF-001": "11.1",
    "ACI-LIF-002": "11.3",
}

# One source per member: the fixture directory, the level the member is judged
# at, the verdict it must produce, and the codes it must emit at that level.
#
# The six `spec-example-*` members are the deployments shipped with ACI Draft
# Specification v0.9 itself, vendored at SPEC_COMMIT. Four of them do not
# satisfy the text they illustrate, and each is pinned here as an expected
# reject naming the finding it demonstrates rather than corrected: a corpus that
# quietly fixed the specification's own examples would certify against a
# document nobody published.
# The checks whose sentence is a SHOULD. Breaking one is reported and does not
# refuse the deployment, which is the difference between the specification's
# own Level 1 example being usable and being called non-conformant.
# ACI-DIS-002 is deliberately absent: section 4.2 makes PUBLISHING the discovery
# file a SHOULD, but the three fields it must carry once published are a MUST,
# and the fixture below breaks the second of those.
SHOULD_CHECKS = {"ACI-BLK-001", "ACI-LIF-001", "ACI-LIF-002"}

SOURCES = (
    {
        "source": "deployments/conformant",
        "level": 3,
        "kind": "accept",
        "codes": [],
        "note": "A Level 3 deployment that meets every normative requirement in the table.",
    },
    *[
        {
            "source": f"deployments/violates-{code.lower()}",
            "level": 3,
            # A fixture breaking a SHOULD reports and does not refuse, so its
            # verdict is indeterminate rather than reject. Which of the three a
            # code produces is the severity the specification gives it.
            "kind": "indeterminate" if code in SHOULD_CHECKS else "reject",
            "codes": [code],
            "note": f"The conformant deployment with exactly the {section} requirement broken.",
        }
        for code, section in CHECKS.items()
    ],
    {
        "source": "deployments/spec-example-minimal",
        "level": 1,
        "kind": "reject",
        "codes": ["ACI-DIS-001", "ACI-DIS-002", "ACI-LVL-001", "ACI-TS-001"],
        "specFinding": "S-11",
        "note": "examples/minimal publishes an Identity Manifest alone, so Level 1 is unreachable. "
        "It also links no capability manifest, publishes no discovery file, and dates rather than "
        "timestamps last_updated.",
    },
    {
        "source": "deployments/spec-example-level1",
        "level": 1,
        "kind": "indeterminate",
        "codes": ["ACI-DIS-002", "ACI-TS-001"],
        "specFinding": "S-3",
        "note": "examples/level1 meets every MUST at Level 1 and is the one example "
        "of the specification's own six that does. It still carries two SHOULD-level "
        "findings: no discovery file, and a date where sections 5.2 and 16 ask for a "
        "timestamp.",
    },
    {
        "source": "deployments/spec-example-level2",
        "level": 2,
        "kind": "reject",
        "codes": ["ACI-DIS-002", "ACI-EXT-001", "ACI-TS-001"],
        "specFinding": "S-4",
        "note": "knowledge.json carries relationships and trust.json carries security, "
        "neither defined in normative text and neither using the x- prefix section 12.2 requires.",
    },
    {
        "source": "deployments/spec-example-level3",
        "level": 3,
        "kind": "reject",
        "codes": ["ACI-DIS-002", "ACI-EXT-001", "ACI-TS-001"],
        "specFinding": "S-4",
        "note": "The same two undefined fields, at the level the specification calls Interaction.",
    },
    {
        "source": "deployments/spec-example-level4",
        "level": 3,
        "kind": "reject",
        "codes": ["ACI-BLK-001", "ACI-DIS-002", "ACI-EXT-001", "ACI-TS-001"],
        "specFinding": "S-4",
        "note": "Eight undefined top-level fields across three manifests, none x- prefixed, and a "
        "knowledge manifest carrying no concepts at a level that supersets Level 2.",
    },
    {
        "source": "deployments/spec-example-empirelabs",
        "level": 1,
        "kind": "reject",
        "codes": ["ACI-DIS-001", "ACI-DIS-002", "ACI-EXT-001", "ACI-LVL-001", "ACI-TS-001"],
        "specFinding": "S-11",
        "note": "The directory examples/README.md calls a real-world implementation holds one "
        "capability manifest and no identity manifest, so no conformance level is reachable.",
    },
)


def corpus_digest(manifest: dict, root: Path = HERE) -> str:
    """The digest this corpus publishes, recomputed from the files on disk.

    It lives with the GENERATOR because the generator owns the preimage. Its
    one caller besides this file is scripts/release-digests.py, which loads it
    by path rather than restating the concatenation: a second spelling of one
    preimage drifts from the first, and a release signature over a drifted
    digest certifies the drift instead of the corpus.
    """
    digest = hashlib.sha256()
    for entry in sorted(manifest["vectors"], key=lambda entry: entry["id"]):
        digest.update((Path(root) / entry["file"]).read_bytes())
    return digest.hexdigest()


def member_payload(source: Path) -> bytes:
    """One deployment, serialised as the corpus member's own bytes."""
    files = {}
    for rel in DEPLOYMENT_FILES:
        path = source / rel
        if path.is_file():
            files[rel] = path.read_text()
    document = {"aciVersion": SPEC_VERSION, "files": files}
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def identifier(payload: bytes) -> str:
    return "v" + hashlib.sha256(payload).hexdigest()[:16]


def main() -> None:
    out_dir = HERE / "deployment-members"
    out_dir.mkdir(exist_ok=True)
    for stale in out_dir.glob("v*.json"):
        stale.unlink()

    vectors = []
    for entry in SOURCES:
        source = HERE / entry["source"]
        if not source.is_dir():
            raise SystemExit(
                f"{entry['source']} is not in the tree. A member whose fixture is gone is "
                "an absence, and an absence is what a digest over what was produced never sees."
            )
        payload = member_payload(source)
        member_id = identifier(payload)
        rel = f"deployment-members/{member_id}.json"
        (HERE / rel).write_bytes(payload)
        vector = {
            "id": member_id,
            "kind": entry["kind"],
            "file": rel,
            "level": entry["level"],
            "expected": {"codes": entry["codes"]},
            "note": entry["note"],
        }
        if "specFinding" in entry:
            vector["specFinding"] = entry["specFinding"]
        vectors.append(vector)

    vectors.sort(key=lambda v: v["id"])

    digest = hashlib.sha256()
    for vector in vectors:
        digest.update((HERE / vector["file"]).read_bytes())

    counts: dict[str, int] = {}
    for vector in vectors:
        counts[vector["kind"]] = counts.get(vector["kind"], 0) + 1

    manifest = {
        "suite": SUITE,
        "specVersion": SPEC_VERSION,
        "specCommit": SPEC_COMMIT,
        "checks": CHECKS,
        "counts": dict(sorted(counts.items())),
        "corpusDigest": digest.hexdigest(),
        "vectors": vectors,
    }
    (HERE / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    )
    print(f"{len(vectors)} member(s): {dict(sorted(counts.items()))}")


if __name__ == "__main__":
    main()
