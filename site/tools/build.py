#!/usr/bin/env python3
"""Build the site from Markdown into docs/, with pandoc, and fail on any warning.

    python3 tools/build.py            build into docs/
    python3 tools/build.py --check    build into a scratch directory and fail if docs/ differs

Sources: every src/*.md becomes docs/<name>.html, and CLAIMS.md at the repository
root becomes docs/claims.html. The site's navigation lists only the pages that were
built, so a page whose source is not in the repository is never linked; the version
ledger shows such an artifact as held. Every page carries a canonical link under
BASE_URL, the site's published home. A line of the form

    <!-- include: relative/path -->

is replaced by that file's contents before pandoc runs. Files a page links to for
download (the verifier demonstration's sources) are copied under docs/ so every
link resolves on the published site and in a local preview alike.

Requires pandoc 3.x. Source pins and read times come from checked-in data.
"""

from __future__ import annotations

import filecmp
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter
from pathlib import Path

import discovery
import markdown_mirrors
import run_browser
import social_metadata

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
OUT = ROOT / "docs"
TEMPLATE = ROOT / "tools" / "template.html"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
BASE_URL = "https://probityai.github.io/agent-evidence-atlas/"
SITE_NAME = "Agent Evidence Conformance Board"

# Navigation order and labels. A page appears only when it is built.
NAV = [
    ("start", "Choose a component"),
    ("lab", "Open Evidence Lab"),
    ("status", "Claim status"),
    ("runs", "Find a run"),
    ("board", "Conformance board"),
    ("pilot", "Pilot status"),
    ("atlas", "Atlas"),
    ("essay", "Essay"),
    ("demo", "Verifier"),
    ("experiments", "Experiments"),
    ("series", "Series"),
    ("claims", "Claims"),
    ("versions", "Versions"),
]

# Published copies of files the pages link to: (source, destination under docs/, the
# page whose links need it, or None for every page). A copy is made exactly when its
# page is built, and a missing source for a built page fails the build.
COPIES = [
    ("experiments/aps-corrected20-2026-10-10/README.md", "experiments/aps-corrected20-2026-10-10/README.md", "lab"),
    ("experiments/aps-corrected20-2026-10-10/job-runtime-provenance.json", "experiments/aps-corrected20-2026-10-10/job-runtime-provenance.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/native-resource-profile.json", "experiments/aps-corrected20-2026-10-10/native-resource-profile.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/node-runtime.json", "experiments/aps-corrected20-2026-10-10/node-runtime.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/npm-audit.json", "experiments/aps-corrected20-2026-10-10/npm-audit.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/npm-runtime.json", "experiments/aps-corrected20-2026-10-10/npm-runtime.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/original-native-result.json", "experiments/aps-corrected20-2026-10-10/original-native-result.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/producer/LICENSE", "experiments/aps-corrected20-2026-10-10/producer/LICENSE", "lab"),
    ("experiments/aps-corrected20-2026-10-10/producer/README.md", "experiments/aps-corrected20-2026-10-10/producer/README.md", "lab"),
    ("experiments/aps-corrected20-2026-10-10/producer/agent-passport-vectors-v2.json", "experiments/aps-corrected20-2026-10-10/producer/agent-passport-vectors-v2.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/provenance.json", "experiments/aps-corrected20-2026-10-10/provenance.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/python-runtime-advisories.json", "experiments/aps-corrected20-2026-10-10/python-runtime-advisories.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/python-runtime.json", "experiments/aps-corrected20-2026-10-10/python-runtime.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/read_corpus.py", "experiments/aps-corrected20-2026-10-10/read_corpus.py", "lab"),
    ("experiments/aps-corrected20-2026-10-10/reader-requirements.txt", "experiments/aps-corrected20-2026-10-10/reader-requirements.txt", "lab"),
    ("experiments/aps-corrected20-2026-10-10/reader.stderr", "experiments/aps-corrected20-2026-10-10/reader.stderr", "lab"),
    ("experiments/aps-corrected20-2026-10-10/reader.stdout", "experiments/aps-corrected20-2026-10-10/reader.stdout", "lab"),
    ("experiments/aps-corrected20-2026-10-10/report.json", "experiments/aps-corrected20-2026-10-10/report.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/sdk-348.stderr", "experiments/aps-corrected20-2026-10-10/sdk-348.stderr", "lab"),
    ("experiments/aps-corrected20-2026-10-10/sdk-c31.stderr", "experiments/aps-corrected20-2026-10-10/sdk-c31.stderr", "lab"),
    ("experiments/aps-corrected20-2026-10-10/sdk-source-after.json", "experiments/aps-corrected20-2026-10-10/sdk-source-after.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/sdk-source-before.json", "experiments/aps-corrected20-2026-10-10/sdk-source-before.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/selected-source.zip", "experiments/aps-corrected20-2026-10-10/selected-source.zip", "lab"),
    ("experiments/aps-corrected20-2026-10-10/source-after.json", "experiments/aps-corrected20-2026-10-10/source-after.json", "lab"),
    ("experiments/aps-corrected20-2026-10-10/source-manifest.json", "experiments/aps-corrected20-2026-10-10/source-manifest.json", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/README.md", "experiments/aps-corrected20-r2-2026-10-27/README.md", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/producer/LICENSE", "experiments/aps-corrected20-r2-2026-10-27/producer/LICENSE", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/producer/agent-passport-vectors-v2-r2.json", "experiments/aps-corrected20-r2-2026-10-27/producer/agent-passport-vectors-v2-r2.json", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/provenance.json", "experiments/aps-corrected20-r2-2026-10-27/provenance.json", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/read_corpus.py", "experiments/aps-corrected20-r2-2026-10-27/read_corpus.py", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/reader-diff-from-r1.diff", "experiments/aps-corrected20-r2-2026-10-27/reader-diff-from-r1.diff", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/reader-requirements.txt", "experiments/aps-corrected20-r2-2026-10-27/reader-requirements.txt", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/reader.stderr", "experiments/aps-corrected20-r2-2026-10-27/reader.stderr", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/reader.stdout", "experiments/aps-corrected20-r2-2026-10-27/reader.stdout", "lab"),
    ("experiments/aps-corrected20-r2-2026-10-27/report.json", "experiments/aps-corrected20-r2-2026-10-27/report.json", "lab"),
    ("examples/authority-effect/bin/probity-authority-effect-cases", "examples/authority-effect/bin/probity-authority-effect-cases", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/errors.py", "examples/authority-effect/authority_effect/errors.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/isolated.py", "examples/authority-effect/authority_effect/isolated.py", "authority-effect-cases"),
    ("examples/authority-effect/scripts/cache_controls.py", "examples/authority-effect/scripts/cache_controls.py", "authority-effect-cases"),
    ("examples/authority-effect/tests/test_isolated.py", "examples/authority-effect/tests/test_isolated.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_claims.py", "examples/authority-effect/authority_effect/frequency_claims.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/authorized-not-reported-differs-from-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/authorized-not-reported-differs-from-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/authorized-not-reported-matches-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/authorized-not-reported-matches-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/authorized-not-reported-not-established.json", "examples/authority-effect/authority_effect/frequency_fixtures/authorized-not-reported-not-established.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/authorized-reported-differs-from-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/authorized-reported-differs-from-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/authorized-reported-matches-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/authorized-reported-matches-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/authorized-reported-not-established.json", "examples/authority-effect/authority_effect/frequency_fixtures/authorized-reported-not-established.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/denied-not-reported-differs-from-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/denied-not-reported-differs-from-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/denied-not-reported-matches-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/denied-not-reported-matches-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/denied-not-reported-not-established.json", "examples/authority-effect/authority_effect/frequency_fixtures/denied-not-reported-not-established.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/denied-reported-differs-from-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/denied-reported-differs-from-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/denied-reported-matches-request.json", "examples/authority-effect/authority_effect/frequency_fixtures/denied-reported-matches-request.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/denied-reported-not-established.json", "examples/authority-effect/authority_effect/frequency_fixtures/denied-reported-not-established.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-array.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-array.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-false-string.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-false-string.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-float.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-float.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-null.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-null.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-object.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-object.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-one.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-one.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-true-string.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-true-string.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-zero.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-decision-zero.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-array.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-array.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-false-string.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-false-string.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-float.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-float.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-null.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-null.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-object.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-object.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-one.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-one.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-true-string.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-true-string.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-zero.json", "examples/authority-effect/authority_effect/frequency_fixtures/invalid-report-zero.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/frequency_fixtures/manifest.json", "examples/authority-effect/authority_effect/frequency_fixtures/manifest.json", "authority-effect-cases"),
    ("examples/authority-effect/docs/FREQUENCY-CONTROL.md", "examples/authority-effect/docs/FREQUENCY-CONTROL.md", "authority-effect-cases"),
    ("examples/authority-effect/scripts/generate_frequency_fixtures.py", "examples/authority-effect/scripts/generate_frequency_fixtures.py", "authority-effect-cases"),
    ("examples/authority-effect/tests/test_frequency_claims.py", "examples/authority-effect/tests/test_frequency_claims.py", "authority-effect-cases"),
    ("examples/authority-effect/.gitignore", "examples/authority-effect/.gitignore", "authority-effect-cases"),
    ("examples/authority-effect/LICENSE", "examples/authority-effect/LICENSE", "authority-effect-cases"),
    ("examples/authority-effect/README.md", "examples/authority-effect/README.md", "authority-effect-cases"),
    ("examples/authority-effect/SOURCE-PINS.json", "examples/authority-effect/SOURCE-PINS.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/__init__.py", "examples/authority-effect/authority_effect/__init__.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/cli.py", "examples/authority-effect/authority_effect/cli.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/coverage_bridge.py", "examples/authority-effect/authority_effect/coverage_bridge.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/authorization-expired-at-use.json", "examples/authority-effect/authority_effect/fixtures/cases/authorization-expired-at-use.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/authorization-not-yet-valid.json", "examples/authority-effect/authority_effect/fixtures/cases/authorization-not-yet-valid.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/authorized-a-runtime-b.json", "examples/authority-effect/authority_effect/fixtures/cases/authorized-a-runtime-b.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/changed-signature.json", "examples/authority-effect/authority_effect/fixtures/cases/changed-signature.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/complete-scan-with-finding.json", "examples/authority-effect/authority_effect/fixtures/cases/complete-scan-with-finding.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/empty-consumer-inventory.json", "examples/authority-effect/authority_effect/fixtures/cases/empty-consumer-inventory.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/future-observation.json", "examples/authority-effect/authority_effect/fixtures/cases/future-observation.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/matching-supplied-records.json", "examples/authority-effect/authority_effect/fixtures/cases/matching-supplied-records.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/missing-observation.json", "examples/authority-effect/authority_effect/fixtures/cases/missing-observation.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/missing-report.json", "examples/authority-effect/authority_effect/fixtures/cases/missing-report.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/missing-scan.json", "examples/authority-effect/authority_effect/fixtures/cases/missing-scan.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/no-units-scanned.json", "examples/authority-effect/authority_effect/fixtures/cases/no-units-scanned.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/reported-b-runtime-a.json", "examples/authority-effect/authority_effect/fixtures/cases/reported-b-runtime-a.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/reported-failure-current-effect-matches.json", "examples/authority-effect/authority_effect/fixtures/cases/reported-failure-current-effect-matches.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/reported-success-current-state-differs.json", "examples/authority-effect/authority_effect/fixtures/cases/reported-success-current-state-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/runtime-a-observation-b.json", "examples/authority-effect/authority_effect/fixtures/cases/runtime-a-observation-b.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/runtime-calldatahash-differs.json", "examples/authority-effect/authority_effect/fixtures/cases/runtime-calldatahash-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/runtime-chainid-differs.json", "examples/authority-effect/authority_effect/fixtures/cases/runtime-chainid-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/runtime-operation-differs.json", "examples/authority-effect/authority_effect/fixtures/cases/runtime-operation-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/runtime-value-differs.json", "examples/authority-effect/authority_effect/fixtures/cases/runtime-value-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/silent-truncation-exit-zero.json", "examples/authority-effect/authority_effect/fixtures/cases/silent-truncation-exit-zero.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/stale-observation.json", "examples/authority-effect/authority_effect/fixtures/cases/stale-observation.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/tampered-intent-retains-hash-and-signature.json", "examples/authority-effect/authority_effect/fixtures/cases/tampered-intent-retains-hash-and-signature.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/target-trailing-slash.json", "examples/authority-effect/authority_effect/fixtures/cases/target-trailing-slash.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/truncation-notice-exit-one.json", "examples/authority-effect/authority_effect/fixtures/cases/truncation-notice-exit-one.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/truncation-notice-exit-zero.json", "examples/authority-effect/authority_effect/fixtures/cases/truncation-notice-exit-zero.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/cases/wrong-selected-principal-key.json", "examples/authority-effect/authority_effect/fixtures/cases/wrong-selected-principal-key.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/manifest.json", "examples/authority-effect/authority_effect/fixtures/manifest.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/authorization-expired-at-use.json", "examples/authority-effect/authority_effect/fixtures/policies/authorization-expired-at-use.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/authorization-not-yet-valid.json", "examples/authority-effect/authority_effect/fixtures/policies/authorization-not-yet-valid.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/authorized-a-runtime-b.json", "examples/authority-effect/authority_effect/fixtures/policies/authorized-a-runtime-b.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/changed-signature.json", "examples/authority-effect/authority_effect/fixtures/policies/changed-signature.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/complete-scan-with-finding.json", "examples/authority-effect/authority_effect/fixtures/policies/complete-scan-with-finding.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/empty-consumer-inventory.json", "examples/authority-effect/authority_effect/fixtures/policies/empty-consumer-inventory.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/future-observation.json", "examples/authority-effect/authority_effect/fixtures/policies/future-observation.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/matching-supplied-records.json", "examples/authority-effect/authority_effect/fixtures/policies/matching-supplied-records.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/missing-observation.json", "examples/authority-effect/authority_effect/fixtures/policies/missing-observation.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/missing-report.json", "examples/authority-effect/authority_effect/fixtures/policies/missing-report.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/missing-scan.json", "examples/authority-effect/authority_effect/fixtures/policies/missing-scan.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/no-units-scanned.json", "examples/authority-effect/authority_effect/fixtures/policies/no-units-scanned.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/reported-b-runtime-a.json", "examples/authority-effect/authority_effect/fixtures/policies/reported-b-runtime-a.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/reported-failure-current-effect-matches.json", "examples/authority-effect/authority_effect/fixtures/policies/reported-failure-current-effect-matches.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/reported-success-current-state-differs.json", "examples/authority-effect/authority_effect/fixtures/policies/reported-success-current-state-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/runtime-a-observation-b.json", "examples/authority-effect/authority_effect/fixtures/policies/runtime-a-observation-b.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/runtime-calldatahash-differs.json", "examples/authority-effect/authority_effect/fixtures/policies/runtime-calldatahash-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/runtime-chainid-differs.json", "examples/authority-effect/authority_effect/fixtures/policies/runtime-chainid-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/runtime-operation-differs.json", "examples/authority-effect/authority_effect/fixtures/policies/runtime-operation-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/runtime-value-differs.json", "examples/authority-effect/authority_effect/fixtures/policies/runtime-value-differs.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/silent-truncation-exit-zero.json", "examples/authority-effect/authority_effect/fixtures/policies/silent-truncation-exit-zero.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/stale-observation.json", "examples/authority-effect/authority_effect/fixtures/policies/stale-observation.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/tampered-intent-retains-hash-and-signature.json", "examples/authority-effect/authority_effect/fixtures/policies/tampered-intent-retains-hash-and-signature.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/target-trailing-slash.json", "examples/authority-effect/authority_effect/fixtures/policies/target-trailing-slash.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/truncation-notice-exit-one.json", "examples/authority-effect/authority_effect/fixtures/policies/truncation-notice-exit-one.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/truncation-notice-exit-zero.json", "examples/authority-effect/authority_effect/fixtures/policies/truncation-notice-exit-zero.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policies/wrong-selected-principal-key.json", "examples/authority-effect/authority_effect/fixtures/policies/wrong-selected-principal-key.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/fixtures/policy.json", "examples/authority-effect/authority_effect/fixtures/policy.json", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/reader.py", "examples/authority-effect/authority_effect/reader.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/distribution.py", "examples/authority-effect/authority_effect/distribution.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/runner.py", "examples/authority-effect/authority_effect/runner.py", "authority-effect-cases"),
    ("examples/authority-effect/authority_effect/scanner.py", "examples/authority-effect/authority_effect/scanner.py", "authority-effect-cases"),
    ("examples/authority-effect/controls/priorseal-tampered-intent.mjs", "examples/authority-effect/controls/priorseal-tampered-intent.mjs", "authority-effect-cases"),
    ("examples/authority-effect/docs/INPUT-CONTRACT.md", "examples/authority-effect/docs/INPUT-CONTRACT.md", "authority-effect-cases"),
    ("examples/authority-effect/docs/SOURCE-MAP.md", "examples/authority-effect/docs/SOURCE-MAP.md", "authority-effect-cases"),
    ("examples/authority-effect/pyproject.toml", "examples/authority-effect/pyproject.toml", "authority-effect-cases"),
    ("examples/authority-effect/scripts/audit_inventory.py", "examples/authority-effect/scripts/audit_inventory.py", "authority-effect-cases"),
    ("examples/authority-effect/scripts/check_coverage.py", "examples/authority-effect/scripts/check_coverage.py", "authority-effect-cases"),
    ("examples/authority-effect/scripts/generate_fixtures.py", "examples/authority-effect/scripts/generate_fixtures.py", "authority-effect-cases"),
    ("examples/authority-effect/scripts/qualify.py", "examples/authority-effect/scripts/qualify.py", "authority-effect-cases"),
    ("examples/authority-effect/scripts/run-gate.sh", "examples/authority-effect/scripts/run-gate.sh", "authority-effect-cases"),
    ("examples/authority-effect/tests/test_process_contracts.py", "examples/authority-effect/tests/test_process_contracts.py", "authority-effect-cases"),
    ("examples/authority-effect/tests/test_reader.py", "examples/authority-effect/tests/test_reader.py", "authority-effect-cases"),
    ("examples/authority-effect/tests/test_distribution.py", "examples/authority-effect/tests/test_distribution.py", "authority-effect-cases"),
    ("examples/authority-effect/uv.lock", "examples/authority-effect/uv.lock", "authority-effect-cases"),
    ("examples/nenrin-witness-pair/.gitignore", "examples/nenrin-witness-pair/.gitignore", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/AGENTS.md", "examples/nenrin-witness-pair/AGENTS.md", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/INTEGRATION.json", "examples/nenrin-witness-pair/INTEGRATION.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/README.md", "examples/nenrin-witness-pair/README.md", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/docs/INPUT-CONTRACT.md", "examples/nenrin-witness-pair/docs/INPUT-CONTRACT.md", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/docs/QUALIFICATION.md", "examples/nenrin-witness-pair/docs/QUALIFICATION.md", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/docs/SOURCE-MAP.md", "examples/nenrin-witness-pair/docs/SOURCE-MAP.md", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/fixtures/a.api.json", "examples/nenrin-witness-pair/fixtures/a.api.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/fixtures/a.key.json", "examples/nenrin-witness-pair/fixtures/a.key.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/fixtures/b.api.json", "examples/nenrin-witness-pair/fixtures/b.api.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/fixtures/b.key.json", "examples/nenrin-witness-pair/fixtures/b.key.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/fixtures/ledger73.ots", "examples/nenrin-witness-pair/fixtures/ledger73.ots", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/fixtures/pins.json", "examples/nenrin-witness-pair/fixtures/pins.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/pyproject.toml", "examples/nenrin-witness-pair/pyproject.toml", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/RESULT.json", "examples/nenrin-witness-pair/qualification/RESULT.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/coverage.json", "examples/nenrin-witness-pair/qualification/coverage.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/original-r1/diagnosis.json", "examples/nenrin-witness-pair/qualification/original-r1/diagnosis.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/original-r1/per-file-coverage.stderr", "examples/nenrin-witness-pair/qualification/original-r1/per-file-coverage.stderr", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/original-r1/steps.json", "examples/nenrin-witness-pair/qualification/original-r1/steps.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/original-r1/tests.xml", "examples/nenrin-witness-pair/qualification/original-r1/tests.xml", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/pair-a-a2a.json", "examples/nenrin-witness-pair/qualification/pair-a-a2a.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/pair-a-slash.json", "examples/nenrin-witness-pair/qualification/pair-a-slash.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/pair-b-a2a.json", "examples/nenrin-witness-pair/qualification/pair-b-a2a.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/pair-b-slash.json", "examples/nenrin-witness-pair/qualification/pair-b-slash.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/per-file-coverage.json", "examples/nenrin-witness-pair/qualification/per-file-coverage.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/preparation-AGENTS.md", "examples/nenrin-witness-pair/qualification/preparation-AGENTS.md", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/steps.json", "examples/nenrin-witness-pair/qualification/steps.json", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/qualification/tests.xml", "examples/nenrin-witness-pair/qualification/tests.xml", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/scripts/check_coverage.py", "examples/nenrin-witness-pair/scripts/check_coverage.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/scripts/qualify.py", "examples/nenrin-witness-pair/scripts/qualify.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/scripts/readme-lint.py", "examples/nenrin-witness-pair/scripts/readme-lint.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/scripts/run-gate.sh", "examples/nenrin-witness-pair/scripts/run-gate.sh", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/tests/test_io.py", "examples/nenrin-witness-pair/tests/test_io.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/tests/test_reader.py", "examples/nenrin-witness-pair/tests/test_reader.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/uv.lock", "examples/nenrin-witness-pair/uv.lock", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/witness_case/__init__.py", "examples/nenrin-witness-pair/witness_case/__init__.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/witness_case/io.py", "examples/nenrin-witness-pair/witness_case/io.py", "nenrin-witness-pair"),
    ("examples/nenrin-witness-pair/witness_case/reader.py", "examples/nenrin-witness-pair/witness_case/reader.py", "nenrin-witness-pair"),
    ("examples/e030-corrected-wrapper/.gitignore", "examples/e030-corrected-wrapper/.gitignore", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/AGENTS.md", "examples/e030-corrected-wrapper/AGENTS.md", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/INTEGRATION.json", "examples/e030-corrected-wrapper/INTEGRATION.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/QUALIFICATION.json", "examples/e030-corrected-wrapper/QUALIFICATION.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/README.md", "examples/e030-corrected-wrapper/README.md", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/docs/CONTRACT.md", "examples/e030-corrected-wrapper/docs/CONTRACT.md", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/docs/SOURCE-MAP.md", "examples/e030-corrected-wrapper/docs/SOURCE-MAP.md", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/e030_case/__init__.py", "examples/e030-corrected-wrapper/e030_case/__init__.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/e030_case/expected.json", "examples/e030-corrected-wrapper/e030_case/expected.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/e030_case/faults.py", "examples/e030-corrected-wrapper/e030_case/faults.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/e030_case/regression.py", "examples/e030-corrected-wrapper/e030_case/regression.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/e030_case/report.py", "examples/e030-corrected-wrapper/e030_case/report.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/pyproject.toml", "examples/e030-corrected-wrapper/pyproject.toml", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/qualification/coverage.json", "examples/e030-corrected-wrapper/qualification/coverage.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/qualification/demonstration.json", "examples/e030-corrected-wrapper/qualification/demonstration.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/qualification/per-file-coverage.json", "examples/e030-corrected-wrapper/qualification/per-file-coverage.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/qualification/preparation-AGENTS.md", "examples/e030-corrected-wrapper/qualification/preparation-AGENTS.md", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/qualification/steps.json", "examples/e030-corrected-wrapper/qualification/steps.json", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/qualification/tests.xml", "examples/e030-corrected-wrapper/qualification/tests.xml", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/scripts/check_coverage.py", "examples/e030-corrected-wrapper/scripts/check_coverage.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/scripts/fetch_inputs.py", "examples/e030-corrected-wrapper/scripts/fetch_inputs.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/scripts/qualify.py", "examples/e030-corrected-wrapper/scripts/qualify.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/scripts/readme-lint.py", "examples/e030-corrected-wrapper/scripts/readme-lint.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/scripts/run-gate.sh", "examples/e030-corrected-wrapper/scripts/run-gate.sh", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/tests/test_regression.py", "examples/e030-corrected-wrapper/tests/test_regression.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/tests/test_report.py", "examples/e030-corrected-wrapper/tests/test_report.py", "e030-corrected-wrapper"),
    ("examples/e030-corrected-wrapper/uv.lock", "examples/e030-corrected-wrapper/uv.lock", "e030-corrected-wrapper"),
    ('experiments/w3c-report-replay-2026-10-06/LICENSE', 'experiments/w3c-report-replay-2026-10-06/LICENSE', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/README.md', 'experiments/w3c-report-replay-2026-10-06/README.md', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/SOURCE-ORIGIN.json', 'experiments/w3c-report-replay-2026-10-06/SOURCE-ORIGIN.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/checker-and-configuration.mutant.py', 'experiments/w3c-report-replay-2026-10-06/checker-and-configuration.mutant.py', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/checker-and-configuration.per-case.json', 'experiments/w3c-report-replay-2026-10-06/checker-and-configuration.per-case.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/control-summary.json', 'experiments/w3c-report-replay-2026-10-06/control-summary.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/historical-summary.json', 'experiments/w3c-report-replay-2026-10-06/historical-summary.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/logic-control-configuration.json', 'experiments/w3c-report-replay-2026-10-06/logic-control-configuration.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/logic-control-evidence.json', 'experiments/w3c-report-replay-2026-10-06/logic-control-evidence.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/logic-mutation-summary.json', 'experiments/w3c-report-replay-2026-10-06/logic-mutation-summary.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/negative-witness-state.mutant.py', 'experiments/w3c-report-replay-2026-10-06/negative-witness-state.mutant.py', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/negative-witness-state.per-case.json', 'experiments/w3c-report-replay-2026-10-06/negative-witness-state.per-case.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/original-RUN.json', 'experiments/w3c-report-replay-2026-10-06/original-RUN.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/original-conformance-report.json', 'experiments/w3c-report-replay-2026-10-06/original-conformance-report.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/original-report.json', 'experiments/w3c-report-replay-2026-10-06/original-report.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/per-case-outcomes.csv', 'experiments/w3c-report-replay-2026-10-06/per-case-outcomes.csv', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/per-case-outcomes.json', 'experiments/w3c-report-replay-2026-10-06/per-case-outcomes.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/provenance.json', 'experiments/w3c-report-replay-2026-10-06/provenance.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/report-replay-configuration.json', 'experiments/w3c-report-replay-2026-10-06/report-replay-configuration.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/report.json', 'experiments/w3c-report-replay-2026-10-06/report.json', 'lab'),
    ('experiments/w3c-report-replay-2026-10-06/source-manifest.json', 'experiments/w3c-report-replay-2026-10-06/source-manifest.json', 'lab'),

    ("assets/run-browser.css", "assets/run-browser.css", "runs"),
    ("assets/run-browser.js", "assets/run-browser.js", "runs"),
    ('experiments/aeoess-receipt-signature-2026-10-05/README.md', 'experiments/aeoess-receipt-signature-2026-10-05/README.md', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/RUN.md', 'experiments/aeoess-receipt-signature-2026-10-05/RUN.md', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/report1.json', 'experiments/aeoess-receipt-signature-2026-10-05/report1.json', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/report2.json', 'experiments/aeoess-receipt-signature-2026-10-05/report2.json', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/report.json', 'experiments/aeoess-receipt-signature-2026-10-05/report.json', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/provenance.json', 'experiments/aeoess-receipt-signature-2026-10-05/provenance.json', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/source-manifest.json', 'experiments/aeoess-receipt-signature-2026-10-05/source-manifest.json', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/selected-public-source.zip', 'experiments/aeoess-receipt-signature-2026-10-05/selected-public-source.zip', 'lab'),
    ('experiments/aeoess-receipt-signature-2026-10-05/validate_capsule.py', 'experiments/aeoess-receipt-signature-2026-10-05/validate_capsule.py', 'lab'),
    ("assets/admission-social.png", "assets/admission-social.png", "replay-an-evidence-decision"),
    ("assets/admission-social.svg", "assets/admission-social.svg", "replay-an-evidence-decision"),
    ("assets/README.md", "assets/README.md", "replay-an-evidence-decision"),
    ("assets/component-tasks.svg", "assets/component-tasks.svg", "index"),
    ('experiments/ag2-push-authority-2026-10-04/AG2-PR70-FIRST-FAILED-ARTIFACTS.json', 'experiments/ag2-push-authority-2026-10-04/AG2-PR70-FIRST-FAILED-ARTIFACTS.json', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/AG2-PR70-FIRST-FAILED-JOB.log', 'experiments/ag2-push-authority-2026-10-04/AG2-PR70-FIRST-FAILED-JOB.log', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/AG2-PR70-FIRST-FAILED-JOBS.json', 'experiments/ag2-push-authority-2026-10-04/AG2-PR70-FIRST-FAILED-JOBS.json', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/README.md', 'experiments/ag2-push-authority-2026-10-04/README.md', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/first-local-original.zip', 'experiments/ag2-push-authority-2026-10-04/first-local-original.zip', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/main-artifact.zip', 'experiments/ag2-push-authority-2026-10-04/main-artifact.zip', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/original-artifact.zip', 'experiments/ag2-push-authority-2026-10-04/original-artifact.zip', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/provenance.json', 'experiments/ag2-push-authority-2026-10-04/provenance.json', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/report.json', 'experiments/ag2-push-authority-2026-10-04/report.json', 'lab'),
    ('experiments/ag2-push-authority-2026-10-04/validate_capsule.py', 'experiments/ag2-push-authority-2026-10-04/validate_capsule.py', 'lab'),
    ('experiments/remora-boundary-2026-10-04/README.md', 'experiments/remora-boundary-2026-10-04/README.md', 'lab'),
    ('experiments/remora-boundary-2026-10-04/effect-evidence-v1.external-run-record-v1.json', 'experiments/remora-boundary-2026-10-04/effect-evidence-v1.external-run-record-v1.json', 'lab'),
    ('experiments/remora-boundary-2026-10-04/exact-call-binding-v1.external-run-record-v1.json', 'experiments/remora-boundary-2026-10-04/exact-call-binding-v1.external-run-record-v1.json', 'lab'),
    ('experiments/remora-boundary-2026-10-04/fresh-authority-v1.external-run-record-v1.json', 'experiments/remora-boundary-2026-10-04/fresh-authority-v1.external-run-record-v1.json', 'lab'),
    ('experiments/remora-boundary-2026-10-04/provenance.json', 'experiments/remora-boundary-2026-10-04/provenance.json', 'lab'),
    ('experiments/remora-boundary-2026-10-04/python-3.13.15-artifact.zip', 'experiments/remora-boundary-2026-10-04/python-3.13.15-artifact.zip', 'lab'),
    ('experiments/remora-boundary-2026-10-04/python-3.14.7-artifact.zip', 'experiments/remora-boundary-2026-10-04/python-3.14.7-artifact.zip', 'lab'),
    ('experiments/remora-boundary-2026-10-04/report.json', 'experiments/remora-boundary-2026-10-04/report.json', 'lab'),
    ('experiments/remora-boundary-2026-10-04/validate_capsule.py', 'experiments/remora-boundary-2026-10-04/validate_capsule.py', 'lab'),
    ('experiments/aps-jcs-2026-10-04/README.md', 'experiments/aps-jcs-2026-10-04/README.md', 'lab'),
    ('experiments/aps-jcs-2026-10-04/native-manifest.json', 'experiments/aps-jcs-2026-10-04/native-manifest.json', 'lab'),
    ('experiments/aps-jcs-2026-10-04/original-node20.zip', 'experiments/aps-jcs-2026-10-04/original-node20.zip', 'lab'),
    ('experiments/aps-jcs-2026-10-04/original-node22.zip', 'experiments/aps-jcs-2026-10-04/original-node22.zip', 'lab'),
    ('experiments/aps-jcs-2026-10-04/provenance.json', 'experiments/aps-jcs-2026-10-04/provenance.json', 'lab'),
    ('experiments/aps-jcs-2026-10-04/report.json', 'experiments/aps-jcs-2026-10-04/report.json', 'lab'),
    ('experiments/aps-jcs-2026-10-04/runtime-comparison.json', 'experiments/aps-jcs-2026-10-04/runtime-comparison.json', 'lab'),
    ('experiments/aps-jcs-2026-10-04/selected-source.zip', 'experiments/aps-jcs-2026-10-04/selected-source.zip', 'lab'),
    ('experiments/aps-jcs-2026-10-04/source-lock.json', 'experiments/aps-jcs-2026-10-04/source-lock.json', 'lab'),
    ('experiments/aps-jcs-2026-10-04/source-manifest.json', 'experiments/aps-jcs-2026-10-04/source-manifest.json', 'lab'),
    ('experiments/aps-jcs-2026-10-04/validate_capsule.py', 'experiments/aps-jcs-2026-10-04/validate_capsule.py', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/README.md', 'experiments/google-adk-responses-2026-10-04/README.md', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/first-failed-artifact.zip', 'experiments/google-adk-responses-2026-10-04/first-failed-artifact.zip', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/label-correction-artifact.zip', 'experiments/google-adk-responses-2026-10-04/label-correction-artifact.zip', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/main-artifact.zip', 'experiments/google-adk-responses-2026-10-04/main-artifact.zip', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/native-manifest.json', 'experiments/google-adk-responses-2026-10-04/native-manifest.json', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/original-artifact.zip', 'experiments/google-adk-responses-2026-10-04/original-artifact.zip', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/provenance.json', 'experiments/google-adk-responses-2026-10-04/provenance.json', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/report.json', 'experiments/google-adk-responses-2026-10-04/report.json', 'lab'),
    ('experiments/google-adk-responses-2026-10-04/validate_capsule.py', 'experiments/google-adk-responses-2026-10-04/validate_capsule.py', 'lab'),
    ('experiments/go-jcs-2026-10-04/README.md', 'experiments/go-jcs-2026-10-04/README.md', 'lab'),
    ('experiments/go-jcs-2026-10-04/main-go1.25.5-report.json', 'experiments/go-jcs-2026-10-04/main-go1.25.5-report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/main-go1.25.5.zip', 'experiments/go-jcs-2026-10-04/main-go1.25.5.zip', 'lab'),
    ('experiments/go-jcs-2026-10-04/main-go1.27.1-report.json', 'experiments/go-jcs-2026-10-04/main-go1.27.1-report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/main-go1.27.1.zip', 'experiments/go-jcs-2026-10-04/main-go1.27.1.zip', 'lab'),
    ('experiments/go-jcs-2026-10-04/provenance.json', 'experiments/go-jcs-2026-10-04/provenance.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/pull-request-go1.25.5-report.json', 'experiments/go-jcs-2026-10-04/pull-request-go1.25.5-report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/pull-request-go1.25.5.zip', 'experiments/go-jcs-2026-10-04/pull-request-go1.25.5.zip', 'lab'),
    ('experiments/go-jcs-2026-10-04/pull-request-go1.27.1-report.json', 'experiments/go-jcs-2026-10-04/pull-request-go1.27.1-report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/pull-request-go1.27.1.zip', 'experiments/go-jcs-2026-10-04/pull-request-go1.27.1.zip', 'lab'),
    ('experiments/go-jcs-2026-10-04/push-go1.25.5-report.json', 'experiments/go-jcs-2026-10-04/push-go1.25.5-report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/push-go1.25.5.zip', 'experiments/go-jcs-2026-10-04/push-go1.25.5.zip', 'lab'),
    ('experiments/go-jcs-2026-10-04/push-go1.27.1-report.json', 'experiments/go-jcs-2026-10-04/push-go1.27.1-report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/push-go1.27.1.zip', 'experiments/go-jcs-2026-10-04/push-go1.27.1.zip', 'lab'),
    ('experiments/go-jcs-2026-10-04/report.json', 'experiments/go-jcs-2026-10-04/report.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/source-pins.json', 'experiments/go-jcs-2026-10-04/source-pins.json', 'lab'),
    ('experiments/go-jcs-2026-10-04/validate_capsule.py', 'experiments/go-jcs-2026-10-04/validate_capsule.py', 'lab'),
    ("examples/provael-task-controls/source-record.json", "examples/provael-task-controls/source-record.json", "provael-task-controls"),
    ("examples/provael-task-controls/contract.json", "examples/provael-task-controls/contract.json", "provael-task-controls"),
    ("examples/provael-task-controls/report.json", "examples/provael-task-controls/report.json", "provael-task-controls"),
    ("examples/provael-task-controls/README.md", "examples/provael-task-controls/README.md", "provael-task-controls"),
    ("examples/provael-task-controls/PROVAEL-LICENSE", "examples/provael-task-controls/PROVAEL-LICENSE", "provael-task-controls"),
    ("examples/provael-task-controls/PROVAEL-NOTICE", "examples/provael-task-controls/PROVAEL-NOTICE", "provael-task-controls"),
    ("tools/check_provael_controls.py", "examples/provael-task-controls/check_provael_controls.py", "provael-task-controls"),
    ("examples/task-grouped-rates/input.json", "examples/task-grouped-rates/input.json", "task-grouped-rates"),
    ("examples/task-grouped-rates/contract.json", "examples/task-grouped-rates/contract.json", "task-grouped-rates"),
    ("examples/task-grouped-rates/report.json", "examples/task-grouped-rates/report.json", "task-grouped-rates"),
    ("examples/task-grouped-rates/source-record.json", "examples/task-grouped-rates/source-record.json", "task-grouped-rates"),
    ("examples/task-grouped-rates/README.md", "examples/task-grouped-rates/README.md", "task-grouped-rates"),
    ("tools/check_grouped_rates.py", "examples/task-grouped-rates/check_grouped_rates.py", "task-grouped-rates"),
    ("experiments/model-tool-arguments-cpu-2026-10-03/original-artifact.zip", "experiments/model-tool-arguments-cpu-2026-10-03/original-artifact.zip", "lab"),
    ("experiments/model-tool-arguments-cpu-2026-10-03/native-report.json", "experiments/model-tool-arguments-cpu-2026-10-03/native-report.json", "lab"),
    ("experiments/model-tool-arguments-cpu-2026-10-03/provenance.json", "experiments/model-tool-arguments-cpu-2026-10-03/provenance.json", "lab"),
    ("experiments/model-tool-arguments-cpu-2026-10-03/source-contract.json", "experiments/model-tool-arguments-cpu-2026-10-03/source-contract.json", "lab"),
    ("experiments/model-tool-arguments-cpu-2026-10-03/README.md", "experiments/model-tool-arguments-cpu-2026-10-03/README.md", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/original-artifact.zip", "experiments/model-vocabulary-cpu-2026-10-03/original-artifact.zip", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/installed-capsule.zip", "experiments/model-vocabulary-cpu-2026-10-03/installed-capsule.zip", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/provider-inventory.json", "experiments/model-vocabulary-cpu-2026-10-03/provider-inventory.json", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/source-contract.json", "experiments/model-vocabulary-cpu-2026-10-03/source-contract.json", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/native-report.json", "experiments/model-vocabulary-cpu-2026-10-03/native-report.json", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/installed-replay.json", "experiments/model-vocabulary-cpu-2026-10-03/installed-replay.json", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/provenance.json", "experiments/model-vocabulary-cpu-2026-10-03/provenance.json", "lab"),
    ("experiments/model-vocabulary-cpu-2026-10-03/report.json", "experiments/model-vocabulary-cpu-2026-10-03/report.json", "lab"),
    ("experiments/atomic-delegation-2026-10-02/native-run-capsule.zip", "experiments/atomic-delegation-2026-10-02/native-run-capsule.zip", "lab"),
    ("experiments/atomic-delegation-2026-10-02/provenance.json", "experiments/atomic-delegation-2026-10-02/provenance.json", "lab"),
    ("experiments/atomic-delegation-2026-10-02/report.json", "experiments/atomic-delegation-2026-10-02/report.json", "lab"),
    ("experiments/installed-boundary-policy-2026-10-02/report.json", "experiments/installed-boundary-policy-2026-10-02/report.json", "lab"),
    ("experiments/installed-boundary-policy-2026-10-02/provenance.json", "experiments/installed-boundary-policy-2026-10-02/provenance.json", "lab"),
    ("experiments/installed-boundary-policy-2026-10-02/selected-capsule.zip", "experiments/installed-boundary-policy-2026-10-02/selected-capsule.zip", "lab"),
    ("experiments/installed-boundary-policy-2026-10-02/source-contract.json", "experiments/installed-boundary-policy-2026-10-02/source-contract.json", "lab"),
    ("experiments/model-boundary-cpu-2026-10-02/original-artifact.zip", "experiments/model-boundary-cpu-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/model-boundary-cpu-2026-10-02/provenance.json", "experiments/model-boundary-cpu-2026-10-02/provenance.json", "lab"),
    ("experiments/model-boundary-cpu-2026-10-02/report.json", "experiments/model-boundary-cpu-2026-10-02/report.json", "lab"),
    ("experiments/model-boundary-cpu-2026-10-02/finite-findings.json", "experiments/model-boundary-cpu-2026-10-02/finite-findings.json", "lab"),
    ("experiments/google-adk-ticket-2026-10-02/original-artifact.zip", "experiments/google-adk-ticket-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/google-adk-ticket-2026-10-02/provenance.json", "experiments/google-adk-ticket-2026-10-02/provenance.json", "lab"),
    ("experiments/google-adk-ticket-2026-10-02/report.json", "experiments/google-adk-ticket-2026-10-02/report.json", "lab"),
    ("experiments/installed-format-policy-2026-10-02/original-artifact.zip", "experiments/installed-format-policy-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/installed-format-policy-2026-10-02/provenance.json", "experiments/installed-format-policy-2026-10-02/provenance.json", "lab"),
    ("experiments/installed-format-policy-2026-10-02/report.json", "experiments/installed-format-policy-2026-10-02/report.json", "lab"),
    ("experiments/model-format-cpu-2026-10-02/original-artifact.zip", "experiments/model-format-cpu-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/model-format-cpu-2026-10-02/provenance.json", "experiments/model-format-cpu-2026-10-02/provenance.json", "lab"),
    ("experiments/model-format-cpu-2026-10-02/report.json", "experiments/model-format-cpu-2026-10-02/report.json", "lab"),
    ("experiments/execsurface-state-2026-10-02/original-artifact.zip", "experiments/execsurface-state-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/execsurface-state-2026-10-02/provenance.json", "experiments/execsurface-state-2026-10-02/provenance.json", "lab"),
    ("experiments/execsurface-state-2026-10-02/report.json", "experiments/execsurface-state-2026-10-02/report.json", "lab"),
    ("experiments/authority-recovery-2026-10-02/original-artifact.zip", "experiments/authority-recovery-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/authority-recovery-2026-10-02/provenance.json", "experiments/authority-recovery-2026-10-02/provenance.json", "lab"),
    ("experiments/authority-recovery-2026-10-02/report.json", "experiments/authority-recovery-2026-10-02/report.json", "lab"),
    ("experiments/target-process-recovery-2026-10-02/original-artifact.zip", "experiments/target-process-recovery-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/target-process-recovery-2026-10-02/provenance.json", "experiments/target-process-recovery-2026-10-02/provenance.json", "lab"),
    ("experiments/target-process-recovery-2026-10-02/report.json", "experiments/target-process-recovery-2026-10-02/report.json", "lab"),
    ("experiments/model-paired-cpu-2026-10-02/original-artifact.zip", "experiments/model-paired-cpu-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/model-paired-cpu-2026-10-02/provenance.json", "experiments/model-paired-cpu-2026-10-02/provenance.json", "lab"),
    ("experiments/model-paired-cpu-2026-10-02/report.json", "experiments/model-paired-cpu-2026-10-02/report.json", "lab"),
    ("experiments/openai-agents-ticket-2026-10-02/original-artifact.zip", "experiments/openai-agents-ticket-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/openai-agents-ticket-2026-10-02/provenance.json", "experiments/openai-agents-ticket-2026-10-02/provenance.json", "lab"),
    ("experiments/openai-agents-ticket-2026-10-02/report.json", "experiments/openai-agents-ticket-2026-10-02/report.json", "lab"),
    ("experiments/langgraph-durable-2026-10-02/original-artifact.zip", "experiments/langgraph-durable-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/langgraph-durable-2026-10-02/provenance.json", "experiments/langgraph-durable-2026-10-02/provenance.json", "lab"),
    ("experiments/langgraph-durable-2026-10-02/report.json", "experiments/langgraph-durable-2026-10-02/report.json", "lab"),
    ("experiments/pydantic-failure-2026-10-02/original-artifact.zip", "experiments/pydantic-failure-2026-10-02/original-artifact.zip", "lab"),
    ("experiments/pydantic-failure-2026-10-02/provenance.json", "experiments/pydantic-failure-2026-10-02/provenance.json", "lab"),
    ("experiments/pydantic-failure-2026-10-02/report.json", "experiments/pydantic-failure-2026-10-02/report.json", "lab"),
    ("experiments/model-operational-2026-10-02/provenance.json", "experiments/model-operational-2026-10-02/provenance.json", "lab"),
    ("experiments/model-operational-2026-10-02/report.json", "experiments/model-operational-2026-10-02/report.json", "lab"),
    ("experiments/model-operational-2026-10-02/selected-capsule.zip", "experiments/model-operational-2026-10-02/selected-capsule.zip", "lab"),
    ('experiments/jep-core07-2026-10-02/original-artifact.zip', 'experiments/jep-core07-2026-10-02/original-artifact.zip', 'lab'),
    ('experiments/jep-core07-2026-10-02/provenance.json', 'experiments/jep-core07-2026-10-02/provenance.json', 'lab'),
    ('experiments/jep-core07-2026-10-02/report.json', 'experiments/jep-core07-2026-10-02/report.json', 'lab'),
    ('experiments/remora-e7-2026-10-02/external-run-record-v1.json', 'experiments/remora-e7-2026-10-02/external-run-record-v1.json', 'lab'),
    ('experiments/remora-e7-2026-10-02/original-artifact.zip', 'experiments/remora-e7-2026-10-02/original-artifact.zip', 'lab'),
    ('experiments/remora-e7-2026-10-02/provenance.json', 'experiments/remora-e7-2026-10-02/provenance.json', 'lab'),
    ('experiments/remora-e7-2026-10-02/report.json', 'experiments/remora-e7-2026-10-02/report.json', 'lab'),

    ("data/readouts/rederive-2026-10-01.txt", "readouts/rederive-2026-10-01.txt", "claims"),
    ("data/lab-register.json", "lab/register.json", "lab"),
    ("assets/site.css", "assets/site.css", None),
    ("assets/admission-replay.svg", "assets/admission-replay.svg", "replay-an-evidence-decision"),
    ("experiments/observer-vantage/run.py", "experiments/observer-vantage/run.py", "experiments"),
    ("experiments/observer-vantage/recorded.json", "experiments/observer-vantage/recorded.json", "experiments"),
    ("experiments/trace-transcript/run.py", "experiments/trace-transcript/run.py", "experiments"),
    ("experiments/trace-transcript/recorded.json", "experiments/trace-transcript/recorded.json", "experiments"),
    ("experiments/observer-admission/run.py", "experiments/observer-admission/run.py", "experiments"),
    ("experiments/observer-admission/source-pins.json", "experiments/observer-admission/source-pins.json", "experiments"),
    ("experiments/observer-admission/recorded.json", "experiments/observer-admission/recorded.json", "experiments"),
    ("experiments/observer-admission/provenance.json", "experiments/observer-admission/provenance.json", "experiments"),
    ("experiments/observer-admission/README.md", "experiments/observer-admission/README.md", "replay-an-evidence-decision"),
    ("experiments/observer-admission/presentation.json", "experiments/observer-admission/presentation.json", "replay-an-evidence-decision"),
    ("experiments/observer-admission/retained/demo-report.json", "experiments/observer-admission/retained/demo-report.json", "experiments"),
    ("experiments/observer-admission/retained/consumer/policy.json", "experiments/observer-admission/retained/consumer/policy.json", "experiments"),
    ("experiments/observer-admission/retained/consumer/decision.json", "experiments/observer-admission/retained/consumer/decision.json", "experiments"),
    ("experiments/observer-admission/retained/consumer/state.json", "experiments/observer-admission/retained/consumer/state.json", "experiments"),
    ("experiments/observer-admission/retained/producer/packet.json", "experiments/observer-admission/retained/producer/packet.json", "experiments"),
    ("experiments/observer-admission/retained/producer/history.jsonl", "experiments/observer-admission/retained/producer/history.jsonl", "experiments"),
    ("experiments/observer-admission/retained/producer/ledger.jsonl", "experiments/observer-admission/retained/producer/ledger.jsonl", "experiments"),
    ("experiments/observer-admission/retained/producer/workspace/result.txt", "experiments/observer-admission/retained/producer/workspace/result.txt", "experiments"),
    ("demo/verifier/Cargo.toml", "demo/verifier/Cargo.toml", "demo"),
    ("demo/verifier/Cargo.lock", "demo/verifier/Cargo.lock", "demo"),
    ("demo/verifier/src/main.rs", "demo/verifier/src/main.rs", "demo"),
    ("demo/verifier/run-demo.sh", "demo/verifier/run-demo.sh", "demo"),
    ("demo/verifier/inputs/vcc938c6038536dcb.json", "demo/verifier/inputs/vcc938c6038536dcb.json", "demo"),
    ("demo/TRANSCRIPT.txt", "demo/TRANSCRIPT.txt", "demo"),
    ("demo/NEGATIVE-CONTROL.txt", "demo/NEGATIVE-CONTROL.txt", "demo"),
    ("examples/approved-sql/QUALIFICATION.json", "examples/approved-sql/QUALIFICATION.json", "approved-sql"),
    ("examples/approved-sql/README.md", "examples/approved-sql/README.md", "approved-sql"),
    ("examples/approved-sql/SOURCE-MAP.md", "examples/approved-sql/SOURCE-MAP.md", "approved-sql"),
    ("examples/approved-sql/docs/INPUT-CONTRACT.md", "examples/approved-sql/docs/INPUT-CONTRACT.md", "approved-sql"),
    ("examples/approved-sql/docs/architecture/DESIGN_DECISIONS.md", "examples/approved-sql/docs/architecture/DESIGN_DECISIONS.md", "approved-sql"),
    ("examples/approved-sql/fixtures/ambiguous-execution.json", "examples/approved-sql/fixtures/ambiguous-execution.json", "approved-sql"),
    ("examples/approved-sql/fixtures/application-record-missing.json", "examples/approved-sql/fixtures/application-record-missing.json", "approved-sql"),
    ("examples/approved-sql/fixtures/approval-not-granted.json", "examples/approved-sql/fixtures/approval-not-granted.json", "approved-sql"),
    ("examples/approved-sql/fixtures/approved-audit-incomplete.json", "examples/approved-sql/fixtures/approved-audit-incomplete.json", "approved-sql"),
    ("examples/approved-sql/fixtures/approved-no-match-declared-scope.json", "examples/approved-sql/fixtures/approved-no-match-declared-scope.json", "approved-sql"),
    ("examples/approved-sql/fixtures/commit-unknown.json", "examples/approved-sql/fixtures/commit-unknown.json", "approved-sql"),
    ("examples/approved-sql/fixtures/different-database.json", "examples/approved-sql/fixtures/different-database.json", "approved-sql"),
    ("examples/approved-sql/fixtures/different-parameters.json", "examples/approved-sql/fixtures/different-parameters.json", "approved-sql"),
    ("examples/approved-sql/fixtures/different-principal.json", "examples/approved-sql/fixtures/different-principal.json", "approved-sql"),
    ("examples/approved-sql/fixtures/different-schema.json", "examples/approved-sql/fixtures/different-schema.json", "approved-sql"),
    ("examples/approved-sql/fixtures/different-sql.json", "examples/approved-sql/fixtures/different-sql.json", "approved-sql"),
    ("examples/approved-sql/fixtures/manifest.json", "examples/approved-sql/fixtures/manifest.json", "approved-sql"),
    ("examples/approved-sql/fixtures/matching-commit-later-change.json", "examples/approved-sql/fixtures/matching-commit-later-change.json", "approved-sql"),
    ("examples/approved-sql/fixtures/matching-commit.json", "examples/approved-sql/fixtures/matching-commit.json", "approved-sql"),
    ("examples/approved-sql/fixtures/outcome-disagreement.json", "examples/approved-sql/fixtures/outcome-disagreement.json", "approved-sql"),
    ("examples/approved-sql/fixtures/rolled-back.json", "examples/approved-sql/fixtures/rolled-back.json", "approved-sql"),
    ("examples/approved-sql/fixtures/statement-failed.json", "examples/approved-sql/fixtures/statement-failed.json", "approved-sql"),
    ("examples/approved-sql/pyproject.toml", "examples/approved-sql/pyproject.toml", "approved-sql"),
    ("examples/approved-sql/qualification/coverage.json", "examples/approved-sql/qualification/coverage.json", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-00.stderr", "examples/approved-sql/qualification/fixture-00.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-00.stdout", "examples/approved-sql/qualification/fixture-00.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-01.stderr", "examples/approved-sql/qualification/fixture-01.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-01.stdout", "examples/approved-sql/qualification/fixture-01.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-02.stderr", "examples/approved-sql/qualification/fixture-02.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-02.stdout", "examples/approved-sql/qualification/fixture-02.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-03.stderr", "examples/approved-sql/qualification/fixture-03.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-03.stdout", "examples/approved-sql/qualification/fixture-03.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-04.stderr", "examples/approved-sql/qualification/fixture-04.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-04.stdout", "examples/approved-sql/qualification/fixture-04.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-05.stderr", "examples/approved-sql/qualification/fixture-05.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-05.stdout", "examples/approved-sql/qualification/fixture-05.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-06.stderr", "examples/approved-sql/qualification/fixture-06.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-06.stdout", "examples/approved-sql/qualification/fixture-06.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-07.stderr", "examples/approved-sql/qualification/fixture-07.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-07.stdout", "examples/approved-sql/qualification/fixture-07.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-08.stderr", "examples/approved-sql/qualification/fixture-08.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-08.stdout", "examples/approved-sql/qualification/fixture-08.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-09.stderr", "examples/approved-sql/qualification/fixture-09.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-09.stdout", "examples/approved-sql/qualification/fixture-09.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-10.stderr", "examples/approved-sql/qualification/fixture-10.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-10.stdout", "examples/approved-sql/qualification/fixture-10.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-11.stderr", "examples/approved-sql/qualification/fixture-11.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-11.stdout", "examples/approved-sql/qualification/fixture-11.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-12.stderr", "examples/approved-sql/qualification/fixture-12.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-12.stdout", "examples/approved-sql/qualification/fixture-12.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-13.stderr", "examples/approved-sql/qualification/fixture-13.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-13.stdout", "examples/approved-sql/qualification/fixture-13.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-14.stderr", "examples/approved-sql/qualification/fixture-14.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-14.stdout", "examples/approved-sql/qualification/fixture-14.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-15.stderr", "examples/approved-sql/qualification/fixture-15.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/fixture-15.stdout", "examples/approved-sql/qualification/fixture-15.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/steps.json", "examples/approved-sql/qualification/steps.json", "approved-sql"),
    ("examples/approved-sql/qualification/tests.stderr", "examples/approved-sql/qualification/tests.stderr", "approved-sql"),
    ("examples/approved-sql/qualification/tests.stdout", "examples/approved-sql/qualification/tests.stdout", "approved-sql"),
    ("examples/approved-sql/qualification/tests.xml", "examples/approved-sql/qualification/tests.xml", "approved-sql"),
    ("examples/approved-sql/scripts/check_coverage.py", "examples/approved-sql/scripts/check_coverage.py", "approved-sql"),
    ("examples/approved-sql/scripts/qualify.py", "examples/approved-sql/scripts/qualify.py", "approved-sql"),
    ("examples/approved-sql/scripts/readme-lint.py", "examples/approved-sql/scripts/readme-lint.py", "approved-sql"),
    ("examples/approved-sql/sql_illustration/__init__.py", "examples/approved-sql/sql_illustration/__init__.py", "approved-sql"),
    ("examples/approved-sql/sql_illustration/check.py", "examples/approved-sql/sql_illustration/check.py", "approved-sql"),
    ("examples/approved-sql/tests/test_check.py", "examples/approved-sql/tests/test_check.py", "approved-sql"),
    ("examples/approved-sql/uv.lock", "examples/approved-sql/uv.lock", "approved-sql"),
    ("examples/request-effect-join/CASE-TABLE.md", "examples/request-effect-join/CASE-TABLE.md", "request-effect-join"),
    ("interop/trace-m1/INPUT-MANIFEST.json", "interop/trace-m1/INPUT-MANIFEST.json", "trace-m1-consumer"),
    ("interop/trace-m1/retained/public-report.json", "interop/trace-m1/retained/public-report.json", "trace-m1-consumer"),
    ("interop/trace-m1/retained/QUALIFICATION.json", "interop/trace-m1/retained/QUALIFICATION.json", "trace-m1-consumer"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/README.md", "experiments/packslip-dsse-host-ci-2026-10-11/README.md", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/report.json", "experiments/packslip-dsse-host-ci-2026-10-11/report.json", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/provenance.json", "experiments/packslip-dsse-host-ci-2026-10-11/provenance.json", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/validate_capsule.py", "experiments/packslip-dsse-host-ci-2026-10-11/validate_capsule.py", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/raw/host-job.json", "experiments/packslip-dsse-host-ci-2026-10-11/raw/host-job.json", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/raw/host-workflow.yml", "experiments/packslip-dsse-host-ci-2026-10-11/raw/host-workflow.yml", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/raw/regression.rs", "experiments/packslip-dsse-host-ci-2026-10-11/raw/regression.rs", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/raw/contribution-pr.json", "experiments/packslip-dsse-host-ci-2026-10-11/raw/contribution-pr.json", "lab"),
    ("experiments/packslip-dsse-host-ci-2026-10-11/raw/reverse-dependencies.json", "experiments/packslip-dsse-host-ci-2026-10-11/raw/reverse-dependencies.json", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/README.md", "experiments/horizon-signed-target-reader-2026-10-09/README.md", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/artifact.zip", "experiments/horizon-signed-target-reader-2026-10-09/artifact.zip", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/job-log.zip", "experiments/horizon-signed-target-reader-2026-10-09/job-log.zip", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/jobs.json", "experiments/horizon-signed-target-reader-2026-10-09/jobs.json", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/provenance.json", "experiments/horizon-signed-target-reader-2026-10-09/provenance.json", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/report.json", "experiments/horizon-signed-target-reader-2026-10-09/report.json", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/repository.json", "experiments/horizon-signed-target-reader-2026-10-09/repository.json", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/run.json", "experiments/horizon-signed-target-reader-2026-10-09/run.json", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/validate_capsule.py", "experiments/horizon-signed-target-reader-2026-10-09/validate_capsule.py", "lab"),
    ("experiments/horizon-signed-target-reader-2026-10-09/workflow.yml", "experiments/horizon-signed-target-reader-2026-10-09/workflow.yml", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/README.md", "experiments/nist-ai300-1-checker-2026-10-13/README.md", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/job-log.zip", "experiments/nist-ai300-1-checker-2026-10-13/job-log.zip", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/jobs.json", "experiments/nist-ai300-1-checker-2026-10-13/jobs.json", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/provenance.json", "experiments/nist-ai300-1-checker-2026-10-13/provenance.json", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/report.json", "experiments/nist-ai300-1-checker-2026-10-13/report.json", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/source/workflows/nist-ai-300-1.yml", "experiments/nist-ai300-1-checker-2026-10-13/source/workflows/nist-ai-300-1.yml", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/source/interop/nist-ai-300-1/README.md", "experiments/nist-ai300-1-checker-2026-10-13/source/interop/nist-ai-300-1/README.md", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/source/interop/nist-ai-300-1/check_vectors.py", "experiments/nist-ai300-1-checker-2026-10-13/source/interop/nist-ai-300-1/check_vectors.py", "lab"),
    ("experiments/nist-ai300-1-checker-2026-10-13/validate_capsule.py", "experiments/nist-ai300-1-checker-2026-10-13/validate_capsule.py", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/README.md", "experiments/ratchet-benign-heredoc-2026-10-15/README.md", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/job-log.zip", "experiments/ratchet-benign-heredoc-2026-10-15/job-log.zip", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/job.json", "experiments/ratchet-benign-heredoc-2026-10-15/job.json", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/provenance.json", "experiments/ratchet-benign-heredoc-2026-10-15/provenance.json", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/report.json", "experiments/ratchet-benign-heredoc-2026-10-15/report.json", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/source/workflows/ci.yml", "experiments/ratchet-benign-heredoc-2026-10-15/source/workflows/ci.yml", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/source/docs/results/hooks-replay.md", "experiments/ratchet-benign-heredoc-2026-10-15/source/docs/results/hooks-replay.md", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/source/examples/claude-code/hooks/ratchet_no_force_push_main.py", "experiments/ratchet-benign-heredoc-2026-10-15/source/examples/claude-code/hooks/ratchet_no_force_push_main.py", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/source/examples/claude-code/no_force_push_main.py", "experiments/ratchet-benign-heredoc-2026-10-15/source/examples/claude-code/no_force_push_main.py", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/source/pyproject.toml", "experiments/ratchet-benign-heredoc-2026-10-15/source/pyproject.toml", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/source/tests/export/test_example.py", "experiments/ratchet-benign-heredoc-2026-10-15/source/tests/export/test_example.py", "lab"),
    ("experiments/ratchet-benign-heredoc-2026-10-15/validate_capsule.py", "experiments/ratchet-benign-heredoc-2026-10-15/validate_capsule.py", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/README.md", "experiments/signed-history-boundaries-2026-10-13/README.md", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/job-log.zip", "experiments/signed-history-boundaries-2026-10-13/job-log.zip", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/jobs.json", "experiments/signed-history-boundaries-2026-10-13/jobs.json", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/provenance.json", "experiments/signed-history-boundaries-2026-10-13/provenance.json", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/report.json", "experiments/signed-history-boundaries-2026-10-13/report.json", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/source/workflows/ci.yml", "experiments/signed-history-boundaries-2026-10-13/source/workflows/ci.yml", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/source/vectors-anchored-chain/README.md", "experiments/signed-history-boundaries-2026-10-13/source/vectors-anchored-chain/README.md", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/source/vectors-anchored-chain/check_vectors.py", "experiments/signed-history-boundaries-2026-10-13/source/vectors-anchored-chain/check_vectors.py", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/source/vectors-anchored-chain/tests/test_corpus.py", "experiments/signed-history-boundaries-2026-10-13/source/vectors-anchored-chain/tests/test_corpus.py", "lab"),
    ("experiments/signed-history-boundaries-2026-10-13/validate_capsule.py", "experiments/signed-history-boundaries-2026-10-13/validate_capsule.py", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/README.md", "experiments/ten-sdk-json-bytes-2026-10-09/README.md", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/jobs.json", "experiments/ten-sdk-json-bytes-2026-10-09/jobs.json", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-csharp.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-csharp.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-go.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-go.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-java.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-java.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-kotlin.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-kotlin.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-php.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-php.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-python.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-python.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-ruby.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-ruby.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-rust.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-rust.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-swift.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-swift.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-typescript.zip", "experiments/ten-sdk-json-bytes-2026-10-09/mcp-sdk-jcs-typescript.zip", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/provenance.json", "experiments/ten-sdk-json-bytes-2026-10-09/provenance.json", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/report.json", "experiments/ten-sdk-json-bytes-2026-10-09/report.json", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/run.json", "experiments/ten-sdk-json-bytes-2026-10-09/run.json", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/source/interop/mcp-sdks/driver.py", "experiments/ten-sdk-json-bytes-2026-10-09/source/interop/mcp-sdks/driver.py", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/source/interop/mcp-sdks/run-all.sh", "experiments/ten-sdk-json-bytes-2026-10-09/source/interop/mcp-sdks/run-all.sh", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/validate_capsule.py", "experiments/ten-sdk-json-bytes-2026-10-09/validate_capsule.py", "lab"),
    ("experiments/ten-sdk-json-bytes-2026-10-09/workflow.yml", "experiments/ten-sdk-json-bytes-2026-10-09/workflow.yml", "lab"),
]

INCLUDE = re.compile(r"^<!-- include: (\S+) -->$", re.MULTILINE)
TR = re.compile(r"<tr([^>]*)>(.*?)</tr>", re.DOTALL)
CELL = re.compile(r"<t[hd][^>]*>(.*?)</t[hd]>", re.DOTALL)
TABLE = re.compile(r"<table.*?</table>", re.DOTALL)
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")

# Marks each stamped row stale once the reader's clock passes read date plus cadence. The
# page is built without a clock, so the comparison happens where the reader is.
STALE_SCRIPT = """<script>
(function () {
  var now = Date.now(), stale = 0;
  document.querySelectorAll("tr[data-read][data-cadence-days]").forEach(function (row) {
    var due = Date.parse(row.dataset.read + "T00:00:00Z") + Number(row.dataset.cadenceDays) * 864e5;
    if (now > due) {
      stale += 1;
      row.classList.add("stale");
      var mark = document.createElement("span");
      mark.className = "label stale";
      mark.textContent = "stale";
      row.cells[0].appendChild(document.createTextNode(" "));
      row.cells[0].appendChild(mark);
    }
  });
  var note = document.getElementById("stale-count");
  if (note) {
    note.textContent = stale === 0 ? "Today no row is past its cadence."
      : "Today " + stale + (stale === 1 ? " row is past its cadence" : " rows are past their cadence") + " and marked stale.";
  }
})();
</script>
"""
FRONT_TOC = re.compile(r"^toc:\s*true\s*$", re.MULTILINE)


def expand(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        return (ROOT / m.group(1)).read_text(encoding="utf-8").rstrip("\n")
    return INCLUDE.sub(repl, text)


def nav_html(built: set[str]) -> tuple[str, str]:
    """The home link and the navigation links for the set of page stems being built."""
    home = (f'<a class="home" href="index.html">{SITE_NAME}</a>' if "index" in built
            else f'<span class="home">{SITE_NAME}</span>')
    links = "\n".join(f'      <a href="{stem}.html">{label}</a>' for stem, label in NAV if stem in built)
    return home, links


def render(source: Path, dest: Path, built: set[str]) -> None:
    text = expand(source.read_text(encoding="utf-8"))
    if dest.stem == "runs":
        marker = "<!-- run-register -->"
        if text.count(marker) != 1:
            raise ValueError("The run page needs exactly one register marker")
        text = text.replace(marker, run_browser.markdown(json.loads((ROOT / "data/lab-register.json").read_bytes())))
    home, links = nav_html(built)
    canonical = BASE_URL if dest.stem == "index" else f"{BASE_URL}{dest.stem}.html"
    published = {dst: src for src, dst, page in COPIES if page is None or page == dest.stem}
    headmetadata = social_metadata.render(text, ROOT, published, BASE_URL, canonical, SITE_NAME)
    if dest.stem == "runs":
        headmetadata += '\n<link rel="stylesheet" href="assets/run-browser.css" />'
        headmetadata += '\n<script src="assets/run-browser.js" defer></script>'
    args = [
        "pandoc",
        # Recorded claim identifiers and declarations must remain literal.
        "--from=markdown-smart" if dest.stem == "runs" else "--from=markdown+smart",
        "--to=html5",
        "--standalone",
        f"--template={TEMPLATE}",
        f"--lua-filter={ROOT / 'tools' / 'accessible-scroll.lua'}",
        "--fail-if-warnings",
        "--variable=root:",
        f"--variable=build:{VERSION}",
        f"--variable=sitename:{SITE_NAME}",
        # The home page title is the site name alone; every other page adds it as a suffix.
        *([] if dest.stem == "index" else [f"--variable=titlesuffix:{SITE_NAME}"]),
        f"--variable=canonical:{canonical}",
        f"--variable=markdown:{BASE_URL}{dest.stem}.md",
        f"--variable=agentguide:{BASE_URL}llms.txt",
        f"--variable=headmetadata:{headmetadata}",
        f"--variable=homelink:{home}",
        f"--variable=navlinks:{links}",
        "--wrap=none",
        f"--output={dest}",
    ]
    if FRONT_TOC.search(text.split("\n---", 1)[0] if text.startswith("---") else ""):
        args += ["--toc", "--toc-depth=2"]
    proc = subprocess.run(args, input=text, text=True, capture_output=True, check=False)
    if proc.returncode != 0 or proc.stderr.strip():
        sys.stderr.write(f"pandoc failed or warned on {source.relative_to(ROOT)}:\n{proc.stderr}")
        raise SystemExit(1)
    # Pandoc 3.1 emits table-row parity classes that 3.3 omits. Keep the
    # published HTML byte-stable across those writers; site CSS does not use
    # these classes, and claim-ledger cadence stamping uses plain <tr> rows.
    html = dest.read_text(encoding="utf-8")
    dest.write_text(re.sub(r'<tr class="(?:header|odd|even)">', "<tr>", html), encoding="utf-8")
    mirror = markdown_mirrors.render(text, dest.stem, built, BASE_URL)
    dest.with_suffix(".md").write_text(mirror, encoding="utf-8")


def versions_markdown(built: set[str], versions: list[dict[str, str]]) -> str:
    """The version ledger page, with each source file's SHA-256 computed now.

    An artifact whose page is not built from this repository is listed as held,
    with no link, so the ledger never points at a page that does not exist."""
    data = tomllib.loads((ROOT / "data" / "versions.toml").read_text(encoding="utf-8"))
    components = ["| Component and artifact | Publication role | Version | Source commit | Read (UTC) | Scope |",
                  "| --- | --- | --- | --- | --- | --- |"]
    for version in versions:
        role = discovery.component_publication_role(version)
        components.append(
            f"| [{version['display_name']}](start.html#{version.get('profile', version['component'])}) / {version['artifact']} | "
            f"{role} | [{version['version']}]({version['url']}) | "
            f"[`{version['commit'][:12]}`]({version['source_url']}) | {version['read']} | {version['note']} |"
        )
    rows = ["| artifact | version | date | status | source SHA-256 (first 16) | note |", "|---|---|---|---|---|---|"]
    for a in data["artifact"]:
        source = ROOT / a["source"]
        page_stem = Path(a["page"]).stem
        if page_stem in built and source.exists():
            digest = hashlib.sha256(source.read_bytes()).hexdigest()[:16]
            rows.append(f"| [{a['name']}]({a['page']}) | {a['version']} | {a['date']} | "
                        f"[{a['status']}]{{.label .{a['status']}}} | `{digest}` `{a['source']}` | {a['note']} |")
        else:
            rows.append(f"| {a['name']} | {a['version']} | {a['date']} | [held]{{.label .draft}} | "
                        f"page not built in this repository yet | Held until it passes its release criteria |")
    return "\n".join([
        "---",
        'title: "Version ledger"',
        'subtitle: "Component releases, source tags and the documentation built from them"',
        f'status: "Draft. Site version {VERSION}. Rebuilt on every change; the digests let a reader check that a page matches the version recorded here."',
        "---",
        "",
        "## Component versions {#component-versions}",
        "",
        "These are publication records at the read time shown. The source column names the commit "
        "behind each release or tag. Registry releases do not imply a GitHub tag; "
        "source tags name the peeled commit. "
        "A repository can publish a harness and a case package at different versions.",
        "",
        *components,
        "",
        "### Choose the pin for your task",
        "",
        "- **Install or integrate:** use a component's [reviewed guide](start.html), then keep the exact "
        "package version or source commit its recipe selects. A guide can deliberately use an older release.",
        "- **Repeat a tested installation:** use the recipe's recorded source, environment, command and "
        "retained output. A release number alone is not an install result.",
        "- **Cite or replay a result:** retain the source and artifact digests in that result. "
        "[Lab records](lab.html), historical examples and citation snapshots do not move when a new release appears.",
        "",
        "## Documentation revisions",
        "",
        "A digest here is the SHA-256 of the artifact's source file in the site's repository, "
        "truncated to 16 hexadecimal characters for display. A change to the source changes the digest, "
        "and a change that alters what a page claims also gets a new version and a note.",
        "",
        *rows,
        "",
    ])


def plain(cell: str) -> str:
    return re.sub(r"<[^>]+>", "", cell).strip()


CURRENT_RELEASE = re.compile(r"\b(current|latest)\s+releases?\b", re.IGNORECASE)
LEDGER_ROW = re.compile(r"^\| ([A-Z]-[0-9A-Za-z]+) \| ([^|]*)\|", re.MULTILINE)
MAX_RELEASE_CADENCE = 7


def check_rendered_claim_rows(source: str, rendered: list[str]) -> None:
    """Require every source claim to survive Markdown as exactly one row."""
    expected = Counter(re.findall(r"(?m)^\|\s*([A-Z]+-[A-Za-z0-9]+)\s*\|", source))
    observed = Counter(rendered)
    if not expected or any(count != 1 for count in expected.values()) or observed != expected:
        missing = sorted((expected - observed).elements())
        extra = sorted((observed - expected).elements())
        repeated = sorted(cid for cid, count in expected.items() if count != 1)
        sys.stderr.write(f"claim ledger rows did not render exactly once: missing={missing}, extra={extra}, repeated_source={repeated}\n")
        raise SystemExit(1)


def release_cadence_violations(claims: str, cadence: dict[str, object]) -> list[str]:
    """Rows whose claim names a current or latest release but whose cadence lets it outlive one.

    A current release is a state: the row is wrong the day a newer release ships, so it
    needs the weekly cadence of other states, never a monthly one or "none"."""
    bad = []
    for cid, claim in LEDGER_ROW.findall(claims):
        if not CURRENT_RELEASE.search(claim):
            continue
        c = cadence.get(cid)
        if not isinstance(c, int) or c > MAX_RELEASE_CADENCE:
            bad.append(f"{cid} names a current or latest release but has cadence {c!r}; "
                       f"it needs {MAX_RELEASE_CADENCE} days or less")
    return bad


def stamp_cadence(html: str) -> str:
    """Stamp every claim row that has a read time with its read date and cadence.

    A row gets data-read (its earliest date) and, when its cadence expires, data-cadence-days;
    its read cell gains the cadence in words. A read-dated row with no cadence entry, or a read
    cell with no date, fails the build rather than going unmarked."""
    cadence = tomllib.loads((ROOT / "data" / "claim_cadence.toml").read_text(encoding="utf-8"))["cadence"]
    missing: list[str] = []
    rendered: list[str] = []

    def one_table(tm: re.Match[str]) -> str:
        table = tm.group(0)
        rows = TR.findall(table)
        if not rows:
            return table
        header = [plain(c) for c in CELL.findall(rows[0][1])]
        if "id" not in header or "read (UTC)" not in header:
            return table
        i_id, i_read = header.index("id"), header.index("read (UTC)")

        def one_row(rm: re.Match[str]) -> str:
            attrs, body = rm.group(1), rm.group(2)
            cells = CELL.findall(body)
            if len(cells) <= max(i_id, i_read) or "<th" in body:
                return rm.group(0)
            cid, read = plain(cells[i_id]), plain(cells[i_read])
            rendered.append(cid)
            dates = sorted(DATE.findall(read))
            if not dates or cid not in cadence:
                missing.append(f"{cid} (read {read!r}, cadence {cadence.get(cid)!r})")
                return rm.group(0)
            c = cadence[cid]
            extra = f' data-read="{dates[0]}"'
            words = "does not expire"
            if c != "none":
                extra += f' data-cadence-days="{int(c)}"'
                words = f"{int(c)}-day cadence"
            parts = re.split(r"(<t[hd][^>]*>.*?</t[hd]>)", body, flags=re.DOTALL)
            cell_parts = [k for k, s in enumerate(parts) if s.startswith("<td")]
            k = cell_parts[i_read]
            parts[k] = parts[k].replace("</td>", f' <span class="cadence">({words})</span></td>')
            return f"<tr{attrs}{extra}>" + "".join(parts) + "</tr>"

        return TR.sub(one_row, table)

    html = TABLE.sub(one_table, html)
    if missing:
        sys.stderr.write("claim rows with a read time but no usable date or cadence:\n  " + "\n  ".join(missing) + "\n")
        raise SystemExit(1)
    check_rendered_claim_rows((ROOT / "CLAIMS.md").read_text(encoding="utf-8"), rendered)
    return html.replace("</body>", STALE_SCRIPT + "</body>")


def copy_public_files(out: Path, built: set[str]) -> None:
    """Refuse destinations removed by the deployed Pages artifact uploader."""
    # Pinned deploy contract: actions/upload-pages-artifact at
    # 56afc609e74202658d3ffba0e8f6dda462b719fa excludes these names at any depth.
    for src, dst, page in COPIES:
        if page is not None and page not in built:
            continue
        if {".git", ".github"}.intersection(Path(dst).parts):
            raise ValueError("Public copy destination is excluded by the Pages uploader: " + dst)
        target = out / dst
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / src, target)


def build(out: Path) -> None:
    pages = sorted(SRC.glob("*.md"))
    if (SRC / "lab.md").exists():
        registry = subprocess.run([sys.executable, str(ROOT / "tools" / "check_lab.py")],
                                  capture_output=True, text=True, check=False)
        if registry.returncode != 0:
            sys.stderr.write(registry.stdout + registry.stderr)
            raise SystemExit(1)
    if (SRC / "atlas.md").exists():
        gen = subprocess.run([sys.executable, str(ROOT / "tools" / "gen_atlas.py"), "--check"],
                             capture_output=True, text=True, check=False)
        if gen.returncode != 0:
            sys.stderr.write(gen.stdout + gen.stderr)
            raise SystemExit(1)
    if (SRC / "status.md").exists():
        gen = subprocess.run([sys.executable, str(ROOT / "tools" / "gen_status.py"), "--check"],
                             capture_output=True, text=True, check=False)
        if gen.returncode != 0:
            sys.stderr.write(gen.stdout + gen.stderr)
            raise SystemExit(1)
    built = {p.stem for p in pages} | {"claims", "versions", "start"}
    public = discovery.load_public(ROOT)
    versions = discovery.component_versions(public, ROOT)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for page in pages:
        render(page, out / f"{page.stem}.html", built)
    cadence = tomllib.loads((ROOT / "data" / "claim_cadence.toml").read_text(encoding="utf-8"))["cadence"]
    violations = release_cadence_violations((ROOT / "CLAIMS.md").read_text(encoding="utf-8"), cadence)
    if violations:
        sys.stderr.write("claim rows that can outlive the release they name:\n  " + "\n  ".join(violations) + "\n")
        raise SystemExit(1)
    render(ROOT / "CLAIMS.md", out / "claims.html", built)
    claims = out / "claims.html"
    claims.write_text(stamp_cadence(claims.read_text(encoding="utf-8")), encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        start = Path(tmp) / "start.md"
        start.write_text(discovery.start_markdown(public, versions), encoding="ascii")
        render(start, out / "start.html", built)
        ledger = Path(tmp) / "versions.md"
        ledger.write_text(versions_markdown(built, versions), encoding="utf-8")
        render(ledger, out / "versions.html", built)
    copy_public_files(out, built)
    (out / ".nojekyll").write_text("", encoding="utf-8")
    assets = discovery.site_assets(public, built)
    for name, content in assets.items():
        (out / name).write_text(content, encoding="ascii")
    if out == OUT:
        (ROOT / "llms.txt").write_text(assets["llms.txt"], encoding="ascii")


def same_tree(a: Path, b: Path) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.funny_files:
        return False
    _, mismatch, errors = filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)
    if mismatch or errors:
        return False
    return all(same_tree(a / d, b / d) for d in cmp.common_dirs)


def main() -> int:
    if "--check" in sys.argv[1:]:
        with tempfile.TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "docs"
            build(fresh)
            index = ROOT / "llms.txt"
            index_matches = index.is_file() and index.read_bytes() == (fresh / "llms.txt").read_bytes()
            if not OUT.exists() or not same_tree(fresh, OUT) or not index_matches:
                print("docs/ is out of date with its sources: run python3 tools/build.py")
                return 1
        print("docs/ matches its sources")
        return 0
    build(OUT)
    print(f"built {len(list(OUT.glob('*.html')))} pages into docs/ (version {VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
