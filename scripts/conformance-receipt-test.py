#!/usr/bin/env python3
"""Release-blocking refusals of the reusable conformance workflow's signer.

Each test is one way a caller could try to get a Verified by Probity grant it
did not earn. The test builds the attempt and requires the signer
(`build_receipt`) or the badge verifier (`verify_receipt`) to refuse it with the
reason that names it. A genuine run is built first and must be accepted, so a
signer that refuses everything cannot pass either.

The altered-case-set test replays a real corpus through the harness with one
answer removed from the transcript, so it also proves that the case set comes
from the pinned corpus and not from what the execution job chose to answer.

Run with: python3 scripts/conformance-receipt-test.py
Exit 0 when every attempt is refused and the genuine run is accepted.
"""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
_spec = importlib.util.spec_from_file_location(
    "conformance_receipt", HERE / "conformance_receipt.py"
)
assert _spec and _spec.loader
cr = importlib.util.module_from_spec(_spec)
sys.modules["conformance_receipt"] = cr
_spec.loader.exec_module(cr)

CORPUS = "vectors-a2a-jcs-v01"
DIGESTS = (ROOT / "release" / "CORPUS-DIGESTS.txt").read_text(encoding="utf-8")
PINNED = cr.read_digests(DIGESTS)[CORPUS]
WF_SHA = "a" * 40
CALLER_SHA = "b" * 40
RUN_ID, ATTEMPT = 9100, 1
TRANSCRIPT = json.dumps(
    {"schema": cr.TRANSCRIPT_SCHEMA, "command": '["./verify"]', "records": []}
).encode()


def claims() -> dict[str, Any]:
    return {
        "iss": cr.ISSUER,
        "repository": "example/impl",
        "repository_id": "42",
        "repository_owner_id": "7",
        "ref": "refs/heads/main",
        "sha": CALLER_SHA,
        "run_id": str(RUN_ID),
        "run_attempt": str(ATTEMPT),
        "event_name": "push",
        "workflow_ref": "example/impl/.github/workflows/ci.yml@refs/heads/main",
        "job_workflow_ref": f"{cr.WORKFLOW}@{WF_SHA}",
        "job_workflow_sha": WF_SHA,
        "runner_environment": "github-hosted",
    }


def report(
    n: int | None = None, executed: int | None = None, conform: int | None = None
) -> dict[str, Any]:
    want = PINNED["vectors"] if n is None else n
    return {
        "corpus": {"corpusDigest": PINNED["corpusDigest"]},
        "totals": {
            "vectors": want,
            "conform": want if conform is None else conform,
            "suiteRefusals": 0,
        },
        "verifier": {"vectorsExecuted": want if executed is None else executed},
    }


def zipped(transcript: bytes = TRANSCRIPT, name: str = "transcript.json") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(name, transcript)
    return buf.getvalue()


ZIP = zipped()


def artifact(zip_bytes: bytes = ZIP, run: int = RUN_ID) -> dict[str, Any]:
    return {
        "id": 555,
        "workflow_run": {"id": run},
        "digest": cr.sha256_bytes(zip_bytes),
        "expired": False,
    }


def signing_request(**over: Any) -> dict[str, Any]:
    base = {
        "claims": claims(),
        "report": report(),
        "status": 0,
        "artifact_zip": ZIP,
        "artifact": artifact(),
        "digests_text": DIGESTS,
        "corpus": CORPUS,
        "default_branch": "main",
    }
    base.update(over)
    return base


def cert(**over: Any) -> dict[str, Any]:
    base = {
        "issuer": cr.ISSUER,
        "build_signer_uri": f"https://github.com/{cr.WORKFLOW}@{WF_SHA}",
        "source_repository_uri": "https://github.com/example/impl",
        "source_repository_id": "42",
        "source_digest": CALLER_SHA,
        "source_ref": "refs/heads/main",
        "build_trigger": "push",
        "run_invocation_uri": f"https://github.com/example/impl/actions/runs/{RUN_ID}/attempts/{ATTEMPT}",
    }
    base.update(over)
    return base


LEDGER = {"workflows": [{"sha": WF_SHA, "activated": "2026-11-06T00:00:00Z"}]}


def refused(action: Callable[[], Any], needle: str) -> str | None:
    """None when the action is refused for the named reason, else what went wrong."""
    try:
        action()
    except cr.Refused as exc:
        if any(needle in reason for reason in exc.reasons):
            return None
        return f"refused, but not for {needle!r}: {exc.reasons}"
    return "accepted"


def sign(**over: Any) -> Callable[[], Any]:
    return lambda: cr.build_receipt(**signing_request(**over))


def verify(receipt: dict[str, Any], **over: Any) -> Callable[[], Any]:
    return lambda: cr.verify_receipt(receipt, cert(**over), LEDGER, DIGESTS)


def _replay_without_one_answer() -> tuple[dict[str, Any], int]:
    """Record a perfect candidate on the pinned corpus, drop one answer, replay."""
    script, oracle = HERE / "conformance_receipt.py", HERE / "oracle-verifier.py"
    harness = ROOT / "packaging" / "run_vectors.py"
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp) / "t.json"
        rec = (
            f"{sys.executable} {script} record --transcript {t} -- "
            f"{sys.executable} {oracle} --aev-harness-args"
        )
        subprocess.run(
            [
                sys.executable,
                str(harness),
                "--corpus",
                CORPUS,
                "--verifier",
                rec,
                "--report",
                f"{tmp}/e.json",
            ],
            capture_output=True,
            check=True,
            cwd=tmp,
        )
        data = json.loads(t.read_text(encoding="utf-8"))
        assert len(data["records"]) == PINNED["vectors"], (
            "the perfect candidate was not recorded whole"
        )
        data["records"].pop()
        t.write_text(json.dumps(data), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable,
                str(harness),
                "--corpus",
                CORPUS,
                "--verifier",
                f"{sys.executable} {script} replay --transcript {t}",
                "--report",
                f"{tmp}/r.json",
            ],
            capture_output=True,
            check=False,
            cwd=tmp,
        )
        return json.loads(Path(f"{tmp}/r.json").read_text(encoding="utf-8")), proc.returncode


def main() -> int:
    failures: list[str] = []
    receipt = cr.build_receipt(**signing_request())
    try:
        cr.verify_receipt(receipt, cert(), LEDGER, DIGESTS)
    except cr.Refused as exc:
        failures.append(f"genuine run: the verifier refused it: {exc.reasons}")

    tagged = claims() | {"job_workflow_ref": f"{cr.WORKFLOW}@refs/tags/v0.36.0"}
    other_run = claims() | {"run_id": "9099"}
    altered_report, altered_status = _replay_without_one_answer()
    attempts: list[tuple[str, Callable[[], Any], str]] = [
        (
            "1 substituted artifact",
            sign(artifact_zip=zipped(b"{}")),
            "not the artifact the execution job uploaded",
        ),
        (
            "2 altered case set (one pinned member left unanswered)",
            sign(report=altered_report, status=altered_status),
            "conformed on 56",
        ),
        (
            "3 results injected from the execution job",
            sign(
                artifact_zip=zipped(TRANSCRIPT[:-1] + b',"result":"pass"}'),
                artifact=artifact(zipped(TRANSCRIPT[:-1] + b',"result":"pass"}')),
            ),
            "never a result",
        ),
        (
            "4 unauthorized signing request (caller's own workflow signed)",
            verify(
                receipt,
                build_signer_uri="https://github.com/example/impl/.github/workflows/ci.yml@refs/heads/main",
            ),
            "not the conformance workflow",
        ),
        (
            "5 wrong repository or commit",
            verify(receipt, source_digest="c" * 40),
            "sha is not the one",
        ),
        (
            "6 zero-count report",
            sign(report=report(n=0, executed=0, conform=0)),
            "holds no members",
        ),
        ("7 stale-run replay", sign(claims=other_run), "not uploaded by this workflow run"),
        ("8 unpinned profile", sign(corpus="vectors-my-own-cases"), "not pinned"),
        ("9 wrong ref (workflow called at a tag)", sign(claims=tagged), "full commit SHA"),
    ]
    # Siblings of the nine, each a second door into the same refusal.
    siblings: list[tuple[str, Callable[[], Any], str]] = [
        (
            "1c archive with a second file",
            sign(
                artifact_zip=zipped(name="report.json"),
                artifact=artifact(zipped(name="report.json")),
            ),
            "exactly transcript.json",
        ),
        (
            "1b artifact from another run",
            sign(artifact=artifact(run=1)),
            "not uploaded by this workflow run",
        ),
        (
            "3b exec-side pass with failing answers",
            sign(report=report(conform=56)),
            "conformed on 56",
        ),
        (
            "4b signer SHA not on the allowlist",
            verify(
                receipt | {"verifier": {"id": "x", "sha": "d" * 40}},
                build_signer_uri=f"https://github.com/{cr.WORKFLOW}@{'d' * 40}",
            ),
            "not on the allowlist",
        ),
        (
            "5b other repository",
            verify(receipt, source_repository_uri="https://github.com/evil/impl"),
            "repository is not the one",
        ),
        (
            "7b receipt replayed under another run's certificate",
            verify(
                receipt,
                run_invocation_uri="https://github.com/example/impl/actions/runs/1/attempts/1",
            ),
            "run is not the one",
        ),
        (
            "8b corpus digest that is not the release digest",
            sign(report={**report(), "corpus": {"corpusDigest": "0" * 64}}),
            "not the pinned release digest",
        ),
        (
            "8c runtime corpus",
            sign(
                corpus="vectors-uncertain-effect",
                digests_text=DIGESTS
                + "\n"
                + "1" * 64
                + "  vectors-uncertain-effect/MANIFEST.json  s  vectors=3\n",
            ),
            "runtime contract",
        ),
        (
            "9b non-default branch",
            sign(claims=claims() | {"ref": "refs/heads/feature"}),
            "not the default branch",
        ),
        (
            "9c pull_request_target",
            sign(claims=claims() | {"event_name": "pull_request_target"}),
            "may not request",
        ),
        (
            "9d self-hosted runner",
            sign(claims=claims() | {"runner_environment": "self-hosted"}),
            "GitHub-hosted",
        ),
    ]
    for name, action, needle in attempts + siblings:
        problem = refused(action, needle)
        if problem:
            failures.append(f"{name}: {problem}")
    tampered = copy.deepcopy(receipt)
    tampered["result"]["conform"] -= 1
    problem = refused(verify(tampered), "every pinned member")
    if problem:
        failures.append(f"tampered receipt result: {problem}")
    if altered_status == 0:
        failures.append("2: the harness replay passed with a pinned member unanswered")
    for failure in failures:
        print(f"conformance-receipt-test: FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        f"conformance-receipt-test: the genuine run is accepted and all {len(attempts)} "
        f"refusals (plus {len(siblings) + 1} siblings) refuse"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
