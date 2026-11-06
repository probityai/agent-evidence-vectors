#!/usr/bin/env python3
"""The signer and the badge verifier of the reusable conformance workflow.

`.github/workflows/conformance.yml` runs in two jobs. The execution job holds no
signing capability: no secret, no `id-token: write`. It runs the candidate
verifier against a released corpus through the `record` shim below, which keeps
every invocation's arguments (each file argument by its SHA-256), exit status
and stdout in a transcript. That transcript is the only thing the execution job
hands on, and it is data: the signer never reads a verdict, a count or a report
from it.

The signer job runs no candidate code. It builds the corpus release from this
repository at the workflow's own commit (`job_workflow_sha` from its OIDC
token, never an input), replays the transcript through the harness with the
`replay` shim, and reads the verdict from that replay. The case set is the
pinned corpus manifest, so a vector the transcript does not answer is an
execution error, and an answer to a vector the corpus does not hold is never
asked for. `sign-check` then refuses unless every rule below holds, and only
then does the workflow ask for the signing token.

`verify` is the badge verifier: it checks a signed receipt against the claims
in its Fulcio certificate and the workflow allowlist in docs/badge-grants.json.

Usage:
  conformance_receipt.py record --transcript T -- <candidate command...> <args from the harness>
  conformance_receipt.py replay --transcript T <args from the harness>
  conformance_receipt.py sign-check --claims C --report R --transcript T --artifact A
      --digests release/CORPUS-DIGESTS.txt --corpus ID --default-branch B --out receipt.json
  conformance_receipt.py verify --receipt R --bundle B [--ledger docs/badge-grants.json]

Exit 0 when the action succeeded, 1 on a refusal (each reason printed), 2 when
an input could not be read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKFLOW_REPOSITORY = "probityai/agent-evidence-vectors"
WORKFLOW_PATH = ".github/workflows/conformance.yml"
WORKFLOW = f"{WORKFLOW_REPOSITORY}/{WORKFLOW_PATH}"
ISSUER = "https://token.actions.githubusercontent.com"
EVENTS = ("push", "schedule", "workflow_dispatch")
RUNNER_ENVIRONMENT = "github-hosted"
RECEIPT_SCHEMA = "conformance-receipt-v1"
TRANSCRIPT_SCHEMA = "conformance-transcript-v1"
TRANSCRIPT_KEYS = {"schema", "command", "records"}
RECORD_KEYS = {"key", "exit", "stdout"}
# The corpora whose contract is a runtime path against a counting endpoint: the
# endpoint's state is the evidence, and a transcript of stdout cannot carry it.
RUNTIME_CORPORA = ("vectors-uncertain-effect", "vectors-decision-client-failure-modes")
# The environment variables the harness sets for a candidate. Their presence and
# file contents are part of an invocation's identity, so the two key passes the
# harness makes on one vector are recorded and replayed apart.
KEYED_ENV = ("AEE_SUBSTRATE_KEYS", "AEE_CONSUMER_POLICY", "AEV_RECEIPT_JWKS", "AEV_RECEIPT_CONTEXT")
MAX_STDOUT = 1 << 20
MISSING_EXIT = 125

FULL_SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
HEX64 = re.compile(r"[0-9a-f]{64}")


class Refused(Exception):
    """One or more rules a receipt or a signing request fails."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _token(value: str) -> str:
    if os.path.isfile(value):
        return "file:" + sha256_bytes(Path(value).read_bytes())
    return "arg:" + value


def invocation_key(args: list[str], env: dict[str, str]) -> str:
    """The identity of one harness invocation, the same on every runner.

    A file argument is named by the digest of its bytes, never by its path, so
    the key does not depend on where the corpus was unpacked and an altered
    vector cannot answer for the pinned one.
    """
    parts = [_token(a) for a in args]
    for name in KEYED_ENV:
        if name in env:
            parts.append(f"env:{name}=" + _token(env[name]))
    return sha256_bytes(json.dumps(parts, separators=(",", ":")).encode())


def _load_transcript(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": TRANSCRIPT_SCHEMA, "command": "", "records": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("the transcript must be a JSON object")
    return data


def record(transcript: Path, command: list[str], harness_args: list[str]) -> int:
    """Run the candidate once and append what it did to the transcript."""
    proc = subprocess.run(command + harness_args, capture_output=True, check=False)
    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    data = _load_transcript(transcript)
    data["command"] = json.dumps(command)
    data["records"].append(
        {
            "key": invocation_key(harness_args, dict(os.environ)),
            "exit": proc.returncode,
            "stdout": proc.stdout[:MAX_STDOUT].decode("utf-8", "replace"),
        }
    )
    transcript.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    return proc.returncode


def transcript_errors(data: Any) -> list[str]:
    """Every way a transcript steps outside what the execution job may hand on."""
    if not isinstance(data, dict):
        return ["the transcript must be a JSON object"]
    errors = []
    if data.get("schema") != TRANSCRIPT_SCHEMA:
        errors.append(f"the transcript schema must be {TRANSCRIPT_SCHEMA!r}")
    extra = sorted(set(data) - TRANSCRIPT_KEYS)
    if extra:
        errors.append(
            "the execution job may hand on only its transcript, never a result: "
            f"refused keys {', '.join(extra)}"
        )
    records = data.get("records")
    if not isinstance(records, list):
        return errors + ["the transcript records must be a list"]
    seen: dict[str, tuple[Any, Any]] = {}
    for index, rec in enumerate(records):
        if not isinstance(rec, dict) or set(rec) != RECORD_KEYS:
            errors.append(f"record {index} must hold exactly key, exit and stdout")
            continue
        if not isinstance(rec["exit"], int) or isinstance(rec["exit"], bool):
            errors.append(f"record {index} exit must be an integer")
        answer = (rec["exit"], rec["stdout"])
        if rec["key"] in seen and seen[rec["key"]] != answer:
            errors.append(f"record {index} answers one invocation two different ways")
        seen[rec["key"]] = answer
    return errors


def replay(transcript: Path, harness_args: list[str]) -> int:
    """Answer one harness invocation from the transcript, or fail it."""
    data = json.loads(transcript.read_text(encoding="utf-8"))
    key = invocation_key(harness_args, dict(os.environ))
    for rec in data["records"]:
        if rec["key"] == key:
            sys.stdout.write(rec["stdout"])
            return int(rec["exit"])
    print("conformance-replay: the execution job never answered this vector", file=sys.stderr)
    return MISSING_EXIT


def read_digests(text: str) -> dict[str, dict[str, Any]]:
    """The release manifest: corpus id to its digest and member count."""
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        digest, manifest = fields[0], fields[1]
        counts = dict(f.split("=", 1) for f in fields[3:] if "=" in f)
        out[manifest.split("/")[0]] = {
            "corpusDigest": digest,
            "vectors": int(counts.get("vectors", "0")),
        }
    return out


def _run_errors(claims: dict[str, Any], default_branch: str) -> list[str]:
    errors = []
    if claims.get("iss") != ISSUER:
        errors.append("the token issuer is not GitHub Actions")
    if claims.get("event_name") not in EVENTS:
        errors.append(f"event {claims.get('event_name')!r} may not request a grant")
    if claims.get("runner_environment") != RUNNER_ENVIRONMENT:
        errors.append("the signer must run on a GitHub-hosted runner")
    sha = str(claims.get("job_workflow_sha", ""))
    if claims.get("job_workflow_ref") != f"{WORKFLOW}@{sha}" or not FULL_SHA.fullmatch(sha):
        errors.append(
            "the workflow must be called as "
            f"{WORKFLOW}@<full commit SHA>, not {claims.get('job_workflow_ref')!r}"
        )
    if claims.get("ref") != f"refs/heads/{default_branch}":
        errors.append(f"ref {claims.get('ref')!r} is not the default branch {default_branch!r}")
    if not FULL_SHA.fullmatch(str(claims.get("sha", ""))):
        errors.append("the caller commit must be a full SHA")
    return errors


def _profile_errors(
    corpus: str, digests: dict[str, dict[str, Any]], report: dict[str, Any]
) -> tuple[list[str], dict[str, Any]]:
    pinned = digests.get(corpus)
    if pinned is None:
        return [f"corpus {corpus!r} is not in this release's manifest, so it is not pinned"], {}
    if corpus in RUNTIME_CORPORA:
        return [f"corpus {corpus!r} is a runtime contract a transcript cannot carry"], {}
    errors = []
    reported = (report.get("corpus") or {}).get("corpusDigest")
    if reported != pinned["corpusDigest"]:
        errors.append("the replayed corpus digest is not the pinned release digest")
    return errors, pinned


def replay_totals(report: dict[str, Any]) -> dict[str, Any]:
    """The counts the signer's own replay produced, read from its own report."""
    totals = report.get("totals") or {}
    return {
        "vectors": totals.get("vectors"),
        "executed": (report.get("verifier") or {}).get("vectorsExecuted"),
        "conform": totals.get("conform"),
        "suiteRefusals": totals.get("suiteRefusals", 0),
    }


def _result_errors(report: dict[str, Any], pinned: dict[str, Any], status: int) -> list[str]:
    totals = replay_totals(report)
    want = pinned.get("vectors", 0)
    if want < 1 or not totals.get("vectors"):
        return ["the profile holds no members, so there is nothing to grant"]
    errors = []
    if totals.get("vectors") != want:
        errors.append(f"the replay judged {totals.get('vectors')} members, the profile holds {want}")
    if totals.get("executed") != want:
        errors.append(f"the candidate answered {totals.get('executed')} of {want} members")
    if totals.get("conform") != want:
        errors.append(f"the candidate conformed on {totals.get('conform')} of {want} members")
    if totals.get("suiteRefusals"):
        errors.append("the signer's own replay raised a suite-level refusal")
    if status != 0:
        errors.append(f"the signer's own replay exited {status}")
    return errors


def _artifact_errors(
    artifact: dict[str, Any], claims: dict[str, Any], transcript_digest: str
) -> list[str]:
    errors = []
    run = (artifact.get("workflow_run") or {}).get("id")
    if run != int(claims.get("run_id", 0) or 0):
        errors.append("the transcript artifact was not uploaded by this workflow run")
    if artifact.get("digest") != transcript_digest:
        errors.append("the transcript bytes are not the artifact the execution job uploaded")
    if artifact.get("expired"):
        errors.append("the transcript artifact has expired")
    return errors


def build_receipt(
    *,
    claims: dict[str, Any],
    report: dict[str, Any],
    status: int,
    transcript_bytes: bytes,
    artifact: dict[str, Any],
    digests_text: str,
    corpus: str,
    default_branch: str,
) -> dict[str, Any]:
    """The receipt to sign, or Refused with every reason it may not be signed."""
    transcript_digest = sha256_bytes(transcript_bytes)
    try:
        transcript = json.loads(transcript_bytes)
    except ValueError:
        transcript = None
    errors = transcript_errors(transcript)
    errors += _run_errors(claims, default_branch)
    profile_errors, pinned = _profile_errors(corpus, read_digests(digests_text), report)
    errors += profile_errors
    if pinned:
        errors += _result_errors(report, pinned, status)
    errors += _artifact_errors(artifact, claims, transcript_digest)
    if errors:
        raise Refused(errors)
    run_keys = (
        "repository", "repository_id", "repository_owner_id", "ref", "sha", "run_id",
        "run_attempt", "event_name", "workflow_ref", "job_workflow_ref", "job_workflow_sha",
        "runner_environment",
    )  # fmt: skip
    return {
        "schema": RECEIPT_SCHEMA,
        "basis": "applicant-originated",
        "verifier": {"id": f"https://github.com/{WORKFLOW}", "sha": claims["job_workflow_sha"]},
        "profile": {
            "corpus": corpus,
            "corpusDigest": pinned["corpusDigest"],
            "members": pinned["vectors"],
            "releaseManifestDigest": sha256_bytes(digests_text.encode()),
        },
        "run": {key: claims.get(key) for key in run_keys},
        "execution": {
            "artifactId": artifact.get("id"),
            "transcriptDigest": transcript_digest,
            "commandDigest": sha256_bytes(str(transcript["command"]).encode()),
        },
        "result": {
            "verdict": "pass",
            **{k: replay_totals(report)[k] for k in ("vectors", "executed", "conform")},
        },
    }


def _signer_errors(receipt: dict[str, Any], cert: dict[str, Any], ledger: dict[str, Any]) -> list[str]:
    signer = str(cert.get("build_signer_uri", ""))
    prefix = f"https://github.com/{WORKFLOW}@"
    sha = signer[len(prefix) :] if signer.startswith(prefix) else ""
    if not FULL_SHA.fullmatch(sha):
        return [f"the signature was made by {signer!r}, not the conformance workflow at a full SHA"]
    errors = []
    if cert.get("issuer") != ISSUER:
        errors.append("the certificate issuer is not GitHub Actions")
    if sha not in {w.get("sha") for w in ledger.get("workflows", []) if isinstance(w, dict)}:
        errors.append(f"workflow SHA {sha} is not on the allowlist")
    if (receipt.get("verifier") or {}).get("sha") != sha:
        errors.append("the receipt names a different workflow SHA than its signature")
    return errors


def _binding_errors(receipt: dict[str, Any], cert: dict[str, Any]) -> list[str]:
    run = receipt.get("run") or {}
    pairs = (
        ("repository", f"https://github.com/{run.get('repository')}", cert.get("source_repository_uri")),
        ("repository_id", str(run.get("repository_id")), str(cert.get("source_repository_id"))),
        ("sha", run.get("sha"), cert.get("source_digest")),
        ("ref", run.get("ref"), cert.get("source_ref")),
        ("event_name", run.get("event_name"), cert.get("build_trigger")),
        (
            "run",
            f"https://github.com/{run.get('repository')}/actions/runs/{run.get('run_id')}"
            f"/attempts/{run.get('run_attempt')}",
            cert.get("run_invocation_uri"),
        ),
    )
    return [
        f"the receipt's {name} is not the one its certificate was issued to"
        for name, mine, theirs in pairs
        if mine != theirs
    ]


def verify_receipt(
    receipt: dict[str, Any], cert: dict[str, Any], ledger: dict[str, Any], digests_text: str
) -> None:
    """Refused unless a signed receipt can stand behind a grant."""
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise Refused([f"the receipt schema must be {RECEIPT_SCHEMA!r}"])
    errors = _signer_errors(receipt, cert, ledger) + _binding_errors(receipt, cert)
    run = receipt.get("run") or {}
    if run.get("event_name") not in EVENTS:
        errors.append(f"event {run.get('event_name')!r} may not stand behind a grant")
    profile = receipt.get("profile") or {}
    pinned = read_digests(digests_text).get(str(profile.get("corpus")))
    if pinned is None or pinned["corpusDigest"] != profile.get("corpusDigest"):
        errors.append("the receipt's corpus digest is not the pinned release digest")
    result = receipt.get("result") or {}
    members = profile.get("members")
    if not members or result.get("verdict") != "pass" or not all(
        result.get(k) == members for k in ("vectors", "executed", "conform")
    ):
        errors.append("the receipt does not record every pinned member answered and conformant")
    if errors:
        raise Refused(errors)


# The Fulcio certificate extensions this verifier reads (OID 1.3.6.1.4.1.57264.1.N).
FULCIO_EXTENSIONS = {
    8: "issuer", 9: "build_signer_uri", 12: "source_repository_uri", 13: "source_digest",
    14: "source_ref", 15: "source_repository_id", 20: "build_trigger", 21: "run_invocation_uri",
}  # fmt: skip


def cert_claims(bundle: dict[str, Any]) -> dict[str, Any]:
    """The Fulcio extensions of a Sigstore bundle's leaf certificate."""
    from cryptography import x509  # imported here: only the verify path needs it

    material = bundle["verificationMaterial"]
    raw = material.get("certificate", {}).get("rawBytes") or (
        material["x509CertificateChain"]["certificates"][0]["rawBytes"]
    )
    cert = x509.load_der_x509_certificate(base64.b64decode(raw))
    out: dict[str, Any] = {}
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid.startswith("1.3.6.1.4.1.57264.1."):
            name = FULCIO_EXTENSIONS.get(int(oid.rsplit(".", 1)[1]))
            if name:
                value = ext.value.value  # type: ignore[attr-defined]
                out[name] = value[2:].decode() if value[:1] == b"\x0c" else value.decode()
    return out


def _cosign_verify(receipt_path: Path, bundle_path: Path) -> None:
    pattern = "^https://github\\.com/" + re.escape(WORKFLOW) + "@[0-9a-f]{40}$"
    proc = subprocess.run(
        ["cosign", "verify-blob", str(receipt_path), "--bundle", str(bundle_path),
         "--certificate-identity-regexp", pattern, "--certificate-oidc-issuer", ISSUER],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if proc.returncode != 0:
        raise Refused([f"cosign refused the signature: {proc.stderr.strip()}"])


def _cmd_sign_check(args: argparse.Namespace) -> int:
    claims = json.loads(Path(args.claims).read_text(encoding="utf-8"))
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    receipt = build_receipt(
        claims=claims,
        report=report,
        status=args.status,
        transcript_bytes=Path(args.transcript).read_bytes(),
        artifact=json.loads(Path(args.artifact).read_text(encoding="utf-8")),
        digests_text=Path(args.digests).read_text(encoding="utf-8"),
        corpus=args.corpus,
        default_branch=args.default_branch,
    )
    Path(args.out).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"conformance-receipt: {receipt['profile']['corpus']} {receipt['result']['conform']}/"
          f"{receipt['profile']['members']} conformant; receipt ready to sign")  # fmt: skip
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    receipt_path, bundle_path = Path(args.receipt), Path(args.bundle)
    _cosign_verify(receipt_path, bundle_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    ledger = json.loads(Path(args.ledger).read_text(encoding="utf-8"))
    verify_receipt(receipt, cert_claims(bundle), ledger, Path(args.digests).read_text(encoding="utf-8"))
    print("conformance-receipt: the receipt stands behind a grant")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("--transcript", required=True)
    rec.add_argument("rest", nargs=argparse.REMAINDER)
    rep = sub.add_parser("replay")
    rep.add_argument("--transcript", required=True)
    rep.add_argument("rest", nargs=argparse.REMAINDER)
    sc = sub.add_parser("sign-check")
    for name in ("claims", "report", "transcript", "artifact", "digests", "corpus", "default-branch", "out"):
        sc.add_argument(f"--{name}", required=True)
    sc.add_argument("--status", type=int, required=True)
    ver = sub.add_parser("verify")
    ver.add_argument("--receipt", required=True)
    ver.add_argument("--bundle", required=True)
    root = Path(__file__).resolve().parent.parent
    ver.add_argument("--ledger", default=str(root / "docs/badge-grants.json"))
    ver.add_argument("--digests", default=str(root / "release/CORPUS-DIGESTS.txt"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.cmd == "record":
            # The candidate command is quoted once by the workflow; the harness
            # appends its own arguments after a literal `--aev-harness-args`.
            rest = args.rest[1:] if args.rest[:1] == ["--"] else args.rest
            split = rest.index("--aev-harness-args") if "--aev-harness-args" in rest else len(rest)
            return record(Path(args.transcript), rest[:split], rest[split + 1 :])
        if args.cmd == "replay":
            return replay(Path(args.transcript), args.rest)
        if args.cmd == "sign-check":
            return _cmd_sign_check(args)
        return _cmd_verify(args)
    except Refused as refused:
        for reason in refused.reasons:
            print(f"conformance-receipt: refused: {reason}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"conformance-receipt: cannot read an input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
