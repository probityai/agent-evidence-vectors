#!/usr/bin/env python3
"""Tests for the owner-path permit and the encoded-carrier scan in
pre-push-identity-scan.py.

WHY THIS FILE EXISTS. The scanner refuses first-party names in this public,
product-neutral repository. The organisation that owns the repository is named
in its own clone URL, its badge targets and its citation file, and a URL cannot
avoid naming its owner, so one narrow permit was added: the handle passes where
a slash and one of the three repository names follow it, and nowhere else.

A permit on a refusal is the one change that can only ever loosen, and a
loosening that goes unnoticed is indistinguishable from the control working. So
every case below asserts a direction. The permitted shapes are here to prove the
push is possible at all; the refused ones are the point, and they outnumber them.

THE SECOND HALF OF THIS FILE IS ABOUT ENCODINGS, and it is a different kind of
case. The permit cases above ask what a pattern matches. These ask what the
scanner can SEE AT ALL: a signed statement carries its payload base64-encoded,
signed statements are the product, and a guard that matches text reads straight
past a forbidden string inside a payload. That was measured on a real range --
31 statement files whose signed payloads each held a forbidden host produced 31
findings, 20 naming plain-text files and none naming a statement -- so each case
below is run END TO END through the scanner's own command line over a throwaway
repository's history, not through its matching helpers. A helper can be made to
agree with itself; only the real range proves the push would be refused.

The control matters as much as the refusals. A base64 payload that decodes to
text with no forbidden term must still PASS, or the fix is just a guard that
refuses everything, and a large base64 blob must not make the scan cost more
than it is worth.

The tokens are built from hex at run time, exactly as the scanner holds its own,
so this file can be read by anyone without carrying the strings it is about --
including the encoded fixtures, which are built by encoding those tokens here
rather than by pasting a payload that would carry one past this repository's own
content scan.

Usage: python3 scripts/pre-push-identity-scan-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("scan", HERE / "pre-push-identity-scan.py")
assert _spec is not None and _spec.loader is not None
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _hex(value: str) -> str:
    return bytes.fromhex(value).decode("ascii")


OWNER = _hex("70726f626974796169")
COMPANY = _hex("70726f62697479")
SITE = _hex("67657470726f62697479") + ".dev"
OTHER = _hex("6d617463686c6f636b")

_sidecar = scan.Sidecar()

# `views`, `GUARD_SPANS` and `GUARD_MATERIAL` are reached through the scanner
# module rather than imported again here, so these cases exercise the objects
# the scanner actually runs with and cannot drift onto a second copy.


def refused(line: str) -> bool:
    """Whether the scanner would report this as an added line."""
    scanned = scan.permit("+" + line)
    if any(rule.search(scanned) for _, rule in scan.RULES):
        return True
    return bool(_sidecar.labels(scanned[1:]))


PERMITTED = (
    ("an owner-qualified path", f"{OWNER}/agent-evidence-vectors"),
    ("a web URL", f"https://github.com/{OWNER}/agent-evidence-vocabulary/blob/main/README.md"),
    ("an ssh URL", f"git@github.com:{OWNER}/agent-evidence-admission.git"),
    ("a package source URL", f"git+https://github.com/{OWNER}/agent-evidence-vectors@v0.11.1"),
    ("an action reference", f"uses: {OWNER}/agent-evidence-vectors@v0.11.1"),
)

REFUSED = (
    ("the handle with no repository after it", f"maintainer of the {OWNER} organisation"),
    ("the handle before a repository not ours", f"{OWNER}/something-else"),
    ("the handle ending a sentence", f"the owner is {OWNER}."),
    ("an organisation page, which is not a repository URL", f"https://github.com/{OWNER}"),
    ("the company word alone", f"built by {COMPANY} in 2026"),
    (
        "the company word beside a permitted path",
        f"{OWNER}/agent-evidence-vectors run by {COMPANY}",
    ),
    ("the website in a sentence", f"see {SITE} for more"),
    ("the website inside a link", f"[docs](https://{SITE}/predicate/v1/)"),
    ("the website bare", SITE),
    ("another first-party product", f"the {OTHER} runtime"),
)


# The sibling scanner. `forbidden-word-scan.py` reads tracked CONTENT where the
# hook above reads pushed HISTORY, and the two share one rule file, so they need
# the same permit or the repository passes one guard and fails the other. It is
# exercised through a file because that is its only input. Where a repository
# does not carry it, these cases report as skipped and never as passed.
CONTENT_SCANNER = HERE / "forbidden-word-scan.py"


def content_refuses(line: str) -> bool:
    """Whether the content scanner refuses a file containing `line`."""
    with tempfile.TemporaryDirectory() as raw:
        probe = Path(raw) / "probe.txt"
        probe.write_text(line + "\n", encoding="utf-8")
        done = subprocess.run(
            [sys.executable, str(CONTENT_SCANNER), str(probe)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    return done.returncode != 0


def _run_cases(
    refuses: Callable[[str], bool],
    permitted: Sequence[tuple[str, str]],
    refused_cases: Sequence[tuple[str, str]],
    label: str,
) -> tuple[int, list[str]]:
    """Run one scanner over both populations, and return its count and failures.

    The count is of cases that RAN, never of the list handed in: a skipped
    loop must not report full coverage, which is what an earlier version did
    when a mutation emptied the loop and it still printed every case held.

    Both scanners are checked against the same cases, so the loop was written
    twice and `main` went over the complexity ceiling. The bodies were already
    identical apart from which scanner was called and what the line said.
    """
    bad: list[str] = []
    ran = 0
    for what, line in permitted:
        ran += 1
        if refuses(line):
            bad.append(f"{what}{label}: refused, but the permit exists for this shape")
        else:
            print(f"ok   permitted  {what}{label}")
    for what, line in refused_cases:
        ran += 1
        if refuses(line):
            print(f"ok   refused    {what}{label}")
        else:
            bad.append(f"{what}{label}: PASSED, which widens the permit to the bare name")
    return ran, bad


# ---------------------------------------------------------------------------
# The encoded-carrier cases. Each runs the scanner over one commit of a
# throwaway repository, because the question is whether a PUSH would be refused.
# ---------------------------------------------------------------------------
SCANNER = HERE / "pre-push-identity-scan.py"
FORBIDDEN_URI = f"https://{SITE}/predicate/v1/observed-effect"
HARMLESS_URI = "https://in-toto.io/attestation/link/v0.3"


def _statement(uri: str) -> str:
    """An in-toto statement whose predicate type is `uri`."""
    return json.dumps(
        {"_type": "https://in-toto.io/Statement/v1", "predicateType": uri, "subject": []}
    )


def _envelope(payload: str, *, urlsafe: bool = False, padded: bool = True) -> str:
    """A DSSE envelope carrying `payload` base64-encoded, pretty-printed.

    Pretty-printed on purpose: a diff line of a pretty-printed file is not
    parseable JSON on its own, which is the shape the scanner actually meets and
    the shape a whole-document parser would miss.
    """
    alphabet = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = alphabet(payload.encode("utf-8")).decode("ascii")
    if not padded:
        encoded = encoded.rstrip("=")
    body = {"payloadType": "application/vnd.in-toto+json", "payload": encoded, "signatures": []}
    return json.dumps(body, indent=2)


def _bundle(envelope: str) -> str:
    """A bundle carrying an envelope base64-encoded: two layers, not one."""
    encoded = base64.b64encode(envelope.encode("utf-8")).decode("ascii")
    body = {"mediaType": "application/vnd.dev.sigstore.bundle+json", "dsseEnvelope": encoded}
    return json.dumps(body, indent=2)


def _blob(lines: int) -> str:
    """A large base64 text blob, the shape a certificate or an image takes."""
    chunk = base64.b64encode(os.urandom(57)).decode("ascii")
    return "\n".join(chunk for _ in range(lines))


def history_status(contents: str) -> int:
    """The scanner's exit status over a one-commit range adding `contents`.

    Three-valued, like the scanner: 0 clean, 1 a hit, 2 it could not look. The
    status is returned rather than turned into a boolean here so a case that
    never ran can never read as a case that passed.
    """
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}

    def git(*args: str, cwd: Path) -> None:
        subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)

    with tempfile.TemporaryDirectory() as raw:
        repo = Path(raw) / "repo"
        repo.mkdir()
        git("init", "-q", cwd=repo)
        git("config", "user.email", "encoding-test@invalid", cwd=repo)
        git("config", "user.name", "Encoding Test", cwd=repo)
        git("config", "commit.gpgsign", "false", cwd=repo)
        (repo / "base.txt").write_text("base\n", encoding="utf-8")
        git("add", "-A", cwd=repo)
        git("commit", "-q", "-m", "add a base commit", cwd=repo)
        (repo / "fixture.json").write_text(contents + "\n", encoding="utf-8")
        git("add", "-A", cwd=repo)
        git("commit", "-q", "-m", "add a fixture", cwd=repo)
        done = subprocess.run(
            [sys.executable, str(SCANNER), "--range", "HEAD~1..HEAD"],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    if done.returncode == 2:
        print(done.stderr.strip(), file=sys.stderr)
    return done.returncode


ENCODED_REFUSED = (
    ("plain text, the case that already worked", _statement(FORBIDDEN_URI)),
    ("base64, standard alphabet, padded", _envelope(_statement(FORBIDDEN_URI))),
    ("base64, URL-safe alphabet", _envelope(_statement(FORBIDDEN_URI), urlsafe=True)),
    ("base64, unpadded", _envelope(_statement(FORBIDDEN_URI), padded=False)),
    (
        "base64, URL-safe and unpadded",
        _envelope(_statement(FORBIDDEN_URI), urlsafe=True, padded=False),
    ),
    ("base64 nested two layers deep", _bundle(_envelope(_statement(FORBIDDEN_URI)))),
    ("hex, the encoding this repository's own guards use", json.dumps(
        {"note": FORBIDDEN_URI.encode("utf-8").hex()}, indent=2)),
    ("percent-encoding", json.dumps({"href": f"https%3A%2F%2F{SITE}%2Fdocs"}, indent=2)),
)

# THE PERMIT MUST BE THE SAME ON BOTH SIDES OF A DECODE, and these cases are
# generated from the permitted shapes above rather than written out, so they
# cannot drift apart from them. A decoding step with a narrower permit than the
# text step is a guard that refuses a legitimate clone URL, a badge target or a
# predicate type URI the moment it travels inside a signed payload -- which is
# where every one of them ends up, because the payload is the product. Writing
# the cases by hand would mean every future widening of the permit has to be
# remembered twice; derived, a shape admitted in prose is admitted encoded on
# the same day, including the organisation's Pages host once that lands.
ENCODED_PERMITTED = (
    ("a payload that decodes to a harmless statement", _envelope(_statement(HARMLESS_URI))),
    (
        "a nested payload that decodes to a harmless statement",
        _bundle(_envelope(_statement(HARMLESS_URI))),
    ),
    *(
        (f"a payload carrying {what}", _envelope(_statement(line)))
        for what, line in PERMITTED
    ),
    # A percent escape that is not valid UTF-8. This is here because it CRASHED
    # the first full-tree run -- the scan died after 1.6 seconds and printed
    # nothing, which is indistinguishable from a clean tree.
    ("a percent span that decodes to bytes that are not text", json.dumps(
        {"opaque": "%d1%80%d0%ff%fe%fd%fc%fb%fa%f9"}, indent=2)),
)


def _material_cases() -> tuple[int, list[str]]:
    """The rule-material exemption covers the declared spans and nothing beside.

    An exemption on a refusal is the change that can only ever loosen, so both
    directions are asserted: every declared span is skipped, and a span that
    decodes to the SAME forbidden term while differing by case is still
    reported. The second case is the one that matters -- it is the difference
    between exempting a literal and exempting a word.
    """
    bad: list[str] = []
    ran = 0
    for span in scan.GUARD_SPANS:
        ran += 1
        if scan.views(json.dumps({"rule": span}), scan.GUARD_MATERIAL):
            bad.append("a declared rule span was decoded; the guard refuses its own source")
        else:
            print("ok   exempt     a declared rule span")
    ran += 1
    variant = json.dumps({"rule": scan.GUARD_SPANS[1].upper()})
    if scan.views(variant, scan.GUARD_MATERIAL):
        print("ok   decoded    the same term spelled in upper-case hex is not exempt")
    else:
        bad.append("an upper-case spelling of a declared span was exempt; that is a word permit")
    ran += 1
    declared = set(scan.IDENTITY_SPANS) | {scan.OWNER_SPAN}
    if declared <= set(scan.GUARD_SPANS):
        print("ok   declared   every rule span this scanner holds is in the shared list")
    else:
        bad.append("a rule span is undeclared; the sibling scan would refuse this file")
    return ran, bad


def _encoding_cases() -> tuple[int, list[str]]:
    """Run every encoded-carrier case, and the runtime bound with them."""
    bad: list[str] = []
    ran = 0
    for what, contents in ENCODED_REFUSED:
        ran += 1
        status = history_status(contents)
        if status == 1:
            print(f"ok   refused    {what}")
        elif status == 0:
            bad.append(f"{what}: the scan PASSED a forbidden string it could not decode")
        else:
            bad.append(f"{what}: the scan did not run (exit {status}); nothing was verified")
    for what, contents in ENCODED_PERMITTED:
        ran += 1
        status = history_status(contents)
        if status == 0:
            print(f"ok   permitted  {what}")
        elif status == 1:
            bad.append(f"{what}: refused, so the decoding step refuses harmless payloads")
        else:
            bad.append(f"{what}: the scan did not run (exit {status}); nothing was verified")
    ran += 1
    started = time.monotonic()
    blob = json.dumps({"certificate": "REPLACED"}).replace("REPLACED", _blob(4000))
    status = history_status(blob)
    elapsed = time.monotonic() - started
    if status != 0:
        bad.append(f"a large base64 blob: exit {status}, expected a clean 0")
    elif elapsed > 120:
        bad.append(f"a large base64 blob: {elapsed:.0f}s, over the 120s bound")
    else:
        print(f"ok   bounded    a large base64 blob scanned in {elapsed:.0f}s")
    return ran, bad


def main() -> int:
    total, failures = _run_cases(refused, PERMITTED, REFUSED, "")
    if CONTENT_SCANNER.exists():
        # A host shape is a URL, which only the history scanner rules on.
        host_only = ("organisation page", "repository not ours")
        for_content = [
            (what, line) for what, line in REFUSED if not any(h in what for h in host_only)
        ]
        more, bad = _run_cases(content_refuses, PERMITTED, for_content, " (content scanner)")
        total += more
        failures += bad
    else:
        print("skip content scanner: this repository does not carry one")
    for cases in (_material_cases, _encoding_cases):
        more, bad = cases()
        total += more
        failures += bad
    for line in failures:
        print(f"FAIL {line}", file=sys.stderr)
    print(f"{total - len(failures)}/{total} cases held")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
