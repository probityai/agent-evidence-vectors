"""Re-mint corpora/vectors-open-weight-art53 from its published case table.

    python -I -S vectors-open-weight-art53.py OUT

A second generator: it shares no code with the corpus generator and is run alone, so the
committed bytes are shown to follow from the README's case table and the published layout.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from _layout import pretty, write_case, write_manifest

MODEL_HOME = "https://example.org/models/example-7b"


def base_release() -> dict[str, Any]:
    """The release that meets every condition of Article 53(2)."""
    weights_digest = hashlib.sha256(b"example-7b weights").hexdigest()
    return {
        "architecture": {"url": MODEL_HOME + "/architecture.md"},
        "copyright_policy": {"url": MODEL_HOME + "/copyright-policy.md"},
        "licence": {"spdx": "Apache-2.0", "url": MODEL_HOME + "/LICENSE"},
        "model": "example-7b",
        "monetisation": [],
        "provider": "Example Lab",
        "released": "2026-01-15",
        "schema_version": "open-weight-release/v1",
        "systemic_risk": {},
        "training": {"compute_flop": 3e24},
        "training_summary": {"url": MODEL_HOME + "/training-summary.md"},
        "usage": {"url": MODEL_HOME + "/usage.md"},
        "weights": {
            "access": "public",
            "sha256": weights_digest,
            "url": MODEL_HOME + "/weights.safetensors",
        },
    }


DROP = object()


def edited(**changes: Any) -> dict[str, Any]:
    """Return the base release with top-level members replaced, or removed for DROP."""
    release = base_release()
    for member, value in changes.items():
        if value is DROP:
            del release[member]
        else:
            release[member] = value
    return release


def table() -> list[tuple[str, dict[str, Any], str, str]]:
    """The README's case table: name, release, decision, reason."""
    weights = base_release()["weights"]
    return [
        ("exempt-open-release", edited(), "exempt", "all_conditions_evidenced"),
        (
            "exempt-attribution-licence",
            edited(licence={"spdx": "CC-BY-4.0", "url": MODEL_HOME + "/LICENSE"}),
            "exempt",
            "all_conditions_evidenced",
        ),
        (
            "exempt-without-copyright-policy",
            edited(copyright_policy=DROP, training_summary=DROP),
            "exempt",
            "all_conditions_evidenced",
        ),
        (
            "exempt-systemic-presumption-rebutted",
            edited(
                training={"compute_flop": 2e25},
                systemic_risk={
                    "commission_decision_not_systemic": MODEL_HOME + "/commission-decision"
                },
            ),
            "exempt",
            "all_conditions_evidenced",
        ),
        (
            "noncommercial-licence",
            edited(licence={"spdx": "CC-BY-NC-4.0", "url": MODEL_HOME + "/LICENSE"}),
            "not-exempt",
            "licence_restricts_use",
        ),
        (
            "licence-not-recognised",
            edited(licence={"spdx": "LicenseRef-example-custom"}),
            "not-established",
            "licence_not_recognised",
        ),
        (
            "weights-private",
            edited(weights={"access": "private"}),
            "not-exempt",
            "weights_not_public",
        ),
        (
            "weights-gated",
            edited(weights={**weights, "access": "gated"}),
            "not-established",
            "weights_access_gated",
        ),
        (
            "weights-without-digest",
            edited(weights={"access": "public", "url": MODEL_HOME + "/w.safetensors"}),
            "not-established",
            "weights_not_digest_bound",
        ),
        (
            "architecture-missing",
            edited(architecture=DROP),
            "not-established",
            "architecture_not_evidenced",
        ),
        (
            "usage-information-missing",
            edited(usage=DROP),
            "not-established",
            "usage_information_not_evidenced",
        ),
        (
            "monetised-by-personal-data",
            edited(monetisation=["access-requires-personal-data"]),
            "not-exempt",
            "monetised_release",
        ),
        (
            "monetisation-not-stated",
            edited(monetisation=DROP),
            "not-established",
            "monetisation_not_stated",
        ),
        (
            "systemic-risk-presumed",
            edited(training={"compute_flop": 2e25}),
            "not-exempt",
            "systemic_risk_presumed",
        ),
        (
            "systemic-risk-designated",
            edited(systemic_risk={"commission_designation": MODEL_HOME + "/designation"}),
            "not-exempt",
            "systemic_risk_designated",
        ),
        (
            "training-compute-not-stated",
            edited(training=DROP),
            "not-established",
            "training_compute_not_stated",
        ),
    ]


def mint(out: Path) -> None:
    """Write the corpus under ``out``."""
    entries = []
    for name, release, decision, reason in table():
        case = {"case_id": name, "release": "release.json", "schema_version": "open-weight-case/v1"}
        files = write_case(out, name, {"case.json": pretty(case), "release.json": pretty(release)})
        entries.append(
            {
                "expected": {"decision": decision, "reason": reason},
                "files": files,
                "id": name,
                "path": "cases/" + name,
            }
        )
    write_manifest(
        out, entries, suite="open-weight-art53/v1", verifierContract="verifier case.json --json"
    )


if __name__ == "__main__":
    mint(Path(sys.argv[1]))
