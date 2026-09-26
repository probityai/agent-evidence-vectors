#!/usr/bin/env python3
"""Tests for the owner-path permit three guards share, and for the
encoded-carrier scan in pre-push-identity-scan.py.

WHY THIS FILE EXISTS. The guards refuse first-party names in this public,
product-neutral repository. The organisation that owns the repository is named
in its own clone URL, its badge targets and its citation file, and a URL cannot
avoid naming its owner, so one narrow permit was added: the handle passes where
a slash and one of the three repository names follow it, and nowhere else.

A permit on a refusal is the one change that can only ever loosen, and a
loosening that goes unnoticed is indistinguishable from the control working. So
every case below asserts a direction. The permitted shapes are here to prove the
push is possible at all; the refused ones are the point, and they outnumber them.

THREE guards rule on these strings and every one of them is exercised below,
against the same two populations: `pre-push-identity-scan.py` on pushed history,
`forbidden-word-scan.py` on tracked content, and `.githooks/commit-msg` on
commit messages. They read ONE permit, `.githooks/commit-msg.permitted-paths`,
because they did not always: the two scanners each held a hand-copied regex and
the hook held none, so the hook refused a Go module path the scanners explicitly
permitted, and the commit that renamed the module path could not name the path
it was renaming. A disagreement between guards is invisible from inside any one
of them, which is what this file is for.

The tokens are built from hex at run time, exactly as the sidecar holds its own,
so this file can be read by anyone without carrying the strings it is about.

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
text with no forbidden term must still PASS, or the fix is merely a guard that
refuses everything, and a large base64 blob must not make the scan cost more
than it is worth.

The tokens are built from hex at run time, exactly as the scanner holds its own,
so this file can be read by anyone without carrying the strings it is about --
including the encoded fixtures, which are built by encoding those tokens here
and never by pasting a payload that would carry one past this repository's own
content scan.

Usage: python3 scripts/pre-push-identity-scan-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path

# The scanner only imports `views`, `GUARD_SPANS` and `GUARD_MATERIAL` from
# `_decoding`; `_descend` and `Budget` are reached here directly, for the
# nested-document cases below that assert the cycle guard at the mechanism
# and not only through the scanner's own surface. This resolves because
# Python puts this file's own directory -- `scripts/` -- at the front of
# `sys.path` when the file is run directly, which is the only way this suite
# is ever invoked (see the module docstring's Usage line).
import _decoding as decoding

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
# module and not imported again here, so these cases exercise the objects
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
    (
        "a predicate type URI on the organisation's pages host",
        f"https://{OWNER}.github.io/agent-evidence-vectors/predicate/v1/observed-effect",
    ),
    ("a crate repository URL", f"https://github.com/{OWNER}/jcs-admit"),
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


# The commit-message gate, the third reader of the same permit. It is exercised
# through a message file because that is its contract with git, and every case
# rides in the BODY under a fixed clean subject: the subject-length rule would
# otherwise refuse the longer URLs for a reason that has nothing to do with the
# permit, and a refusal counted for the wrong reason is a case that proves
# nothing. `_hook_control` asserts that fixed message passes on its own, so any
# refusal below is attributable to the line under test and not to the harness.
HOOK = HERE.parent / ".githooks" / "commit-msg"
HOOK_SUBJECT = "chore: probe the identity permit"


def _hook(body: str) -> int:
    with tempfile.TemporaryDirectory() as raw:
        message = Path(raw) / "COMMIT_EDITMSG"
        message.write_text(f"{HOOK_SUBJECT}\n\n{body}\n", encoding="utf-8")
        done = subprocess.run(
            [sys.executable, str(HOOK), str(message)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        return done.returncode


def hook_refuses(line: str) -> bool:
    """Whether the commit-message gate refuses a message whose body is `line`."""
    return _hook(line) != 0


def _hook_control() -> list[str]:
    """The harness itself must pass a message that names nothing."""
    if _hook("a body that names nothing at all") != 0:
        return [
            "the commit-message harness failed its own control: a message naming "
            "nothing was refused, so every hook case below would be meaningless"
        ]
    return []


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


def _corpus(*members: str) -> str:
    """A corpus holding each member as a JSON STRING, the way a vector set does.

    This is the carrier the decoder used to see and refuse to follow: a member
    is a whole JSON document held inside another JSON document, so no decode
    applies to it and the walk stopped with the candidate offered and discarded.
    """
    return json.dumps(
        [{"name": f"vector-{n}", "bundle": member}
         for n, member in enumerate(members, 1)], indent=2)


def _blob(lines: int) -> str:
    """A large base64 text blob, the shape a certificate or an image takes."""
    chunk = base64.b64encode(os.urandom(57)).decode("ascii")
    return "\n".join(chunk for _ in range(lines))


def history_status(contents: str) -> int:
    """The scanner's exit status over a one-commit range adding `contents`.

    Three-valued, like the scanner: 0 clean, 1 a hit, 2 it could not look. The
    status is returned, never turned into a boolean here, so a case that
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
    ("an envelope embedded as a JSON string in a corpus", _corpus(
        _envelope(_statement(FORBIDDEN_URI)))),
    ("one envelope among several corpus members", _corpus(
        _envelope(_statement(HARMLESS_URI)),
        _envelope(_statement(FORBIDDEN_URI)),
        _envelope(_statement(HARMLESS_URI)))),
    ("a corpus of bundles, a JSON layer over two base64 ones", _corpus(
        _bundle(_envelope(_statement(FORBIDDEN_URI))))),
    ("a corpus nested inside another corpus", json.dumps(
        {"sets": _corpus(_envelope(_statement(FORBIDDEN_URI)))}, indent=2)),
)

# THE PERMIT MUST BE THE SAME ON BOTH SIDES OF A DECODE, and these cases are
# generated from the permitted shapes above and never written out, so they
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
    (
        "a corpus whose every member is harmless",
        _corpus(_envelope(_statement(HARMLESS_URI)), _envelope(_statement(HARMLESS_URI))),
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


# --- The nested-document layer, measured at the decoder and not the gate ---
#
# WHY THESE ARE SEPARATE FROM THE GATE CASES ABOVE. A gate case in
# ENCODED_REFUSED proves the whole chain refuses; it cannot say WHY, so it
# passes equally well if the host is found by the plain-text matcher for an
# unrelated reason. These call `scan.views` directly, so each one names the
# layer it needs and would fail if the nested document stopped being followed
# even while a gate case stayed green for some other cause.


def _nested_document_control() -> str | None:
    """The control that makes the repro mean something.

    Without this, a corpus case failing to find the host is indistinguishable
    from a decoder that never worked on an envelope at all.
    """
    alone = scan.views(_envelope(_statement(FORBIDDEN_URI)))
    if any(SITE in dec for _, dec in alone):
        return None
    return "an envelope alone found nothing; the control itself is broken"


def _nested_document_repro() -> tuple[str | None, str]:
    """THE REPRO. Same envelope, one JSON string layer added, host still found.

    Measured before the fix: the envelope alone yielded one view and found the
    host; embedded as `$[0].bundle` in a corpus array it yielded ZERO views,
    with that exact candidate offered to the decoder and discarded because it
    is not base64, not hex and not percent-encoded. Returns the failure (or
    None) and the corpus text, which the caller reuses for the double-nesting
    case below.
    """
    corpus = _corpus(_envelope(_statement(FORBIDDEN_URI)))
    layers = scan.views(corpus)
    hits = [lay for lay, dec in layers if SITE in dec]
    if not layers:
        return "a corpus carrying an envelope yielded no views at all", corpus
    if not hits:
        return f"the host was missed in {len(layers)} views: {[lay for lay, _ in layers]}", corpus
    if not any("json" in lay and "base64" in lay for lay in hits):
        return f"the host was found but not through the nested document: {hits}", corpus
    if SITE in corpus:
        return "the fixture leaks the host in plain text; this would pass unconditionally", corpus
    return None, corpus


def _nested_document_double(corpus: str) -> str | None:
    """Two JSON string layers over a base64 one, over the repro's own corpus.

    One level of recursion is not enough to reach the payload, so the depth
    cap must allow three.
    """
    outer = json.dumps({"sets": corpus}, indent=2)
    hits = [lay for lay, dec in scan.views(outer) if SITE in dec]
    if hits and any(lay.count("json") >= 2 for lay in hits):
        return None
    return f"the host was missed two documents deep: {hits}"


def _nested_document_every_member() -> str | None:
    """A walk that stops after the first member reports one host and looks fine.

    70 is not arbitrary: it caps decodes per input, a nested member costs TWO
    of them, so 70 members need 140 and the cap this module shipped with was
    128 -- a cap sized against one envelope per input silently becomes a cap
    on MEMBERS the moment the same bytes are repacked as a corpus. Under the
    old cap this reaches 64 of 70 and fails.
    """
    n = 70
    many = _corpus(*(_envelope(_statement(FORBIDDEN_URI)) for _ in range(n)))
    found = sum(1 for _, dec in scan.views(many) if SITE in dec)
    if found == n:
        return None
    return f"reached {found} of {n} corpus members"


def _nested_document_not_a_document() -> str | None:
    """Prose, a path and a bare number are not documents.

    A branch that walked every long string value would parse ordinary text
    as JSON.
    """
    plain = json.dumps({
        "note": "this is an ordinary sentence and not a document at all",
        "path": "scripts/pre-push-identity-scan-test.py",
        "brace": "{ this starts like one but does not parse as one",
        "number": "1234567890123456",
    }, indent=2)
    if [lay for lay, _ in scan.views(plain) if "json" in lay] == []:
        return None
    return "an ordinary string was parsed and walked as a document"


def _nested_document_cases() -> tuple[int, list[str]]:
    """Assert the nested-JSON-string branch of `_decoding._walk`, directly.

    WHY THESE ARE SEPARATE FROM THE GATE CASES ABOVE. A gate case in
    ENCODED_REFUSED proves the whole chain refuses; it cannot say WHY, so it
    passes equally well if the host is found by the plain-text matcher for an
    unrelated reason. These call `scan.views` directly, so each one names the
    layer it needs and would fail if the nested document stopped being
    followed even while a gate case stayed green for some other cause.
    """
    bad: list[str] = []
    labels = (
        "an envelope alone is seen through",
        "an envelope inside a corpus is seen through",
        "a document nested twice is walked twice",
        "every member of a 70-item corpus is reached",
        "a string that is not a document is not walked",
    )
    control = _nested_document_control()
    repro, corpus = _nested_document_repro()
    failures = (
        control,
        repro,
        _nested_document_double(corpus),
        _nested_document_every_member(),
        _nested_document_not_a_document(),
    )
    for label, failure in zip(labels, failures, strict=True):
        if failure is None:
            print(f"ok   nested     {label}")
        else:
            bad.append(failure)
    return len(labels), bad


def _cycle_guard_cases() -> tuple[int, list[str]]:
    """Assert the cycle guard: a self-referring document, and its mechanism."""
    bad: list[str] = []
    ran = 0

    # The cycle guard, asserted by the one thing a loop cannot do: return. A
    # document whose member is the document itself cannot be built in one
    # pass, so it is built by fixed point: wrap, then substitute the wrapper
    # back in. The depth cap alone would also stop this, which is why the
    # assertion is on the layer list and not only on returning.
    ran += 1
    seed = _envelope(_statement(FORBIDDEN_URI))
    self_embedding = json.dumps({"self": seed, "member": seed})
    started = time.monotonic()
    layers = scan.views(self_embedding)
    elapsed = time.monotonic() - started
    if elapsed >= 5:
        bad.append("a self-referring document did not settle within 5s")
    elif not any(SITE in dec for _, dec in layers):
        bad.append("a self-referring document settled but found nothing")
    else:
        print(f"ok   nested     a self-embedding document terminates ({elapsed:.2f}s)")

    # The cycle guard itself, asserted at the mechanism and not at the
    # fixture above, which the termination case does NOT cover: a
    # self-embedding payload cannot be built by hand (every carrier is longer
    # than what it carries), and the depth cap would stop a loop anyway. Hand
    # `_descend` a text whose digest is already on the path and it must record
    # the layer and stop; it must not walk the same subtree again.
    ran += 1
    nested = _corpus(_envelope(_statement(FORBIDDEN_URI)))
    digest = hashlib.sha256(nested.encode("utf-8")).hexdigest()
    fresh: list[tuple[str, str]] = []
    decoding._descend("$.x -> json", nested, 0, fresh, decoding.Budget(), frozenset(), frozenset())
    looped: list[tuple[str, str]] = []
    decoding._descend(
        "$.x -> json", nested, 0, looped, decoding.Budget(), frozenset(), frozenset({digest}))
    if len(looped) == 1 and looped[0][0] == "$.x -> json" and len(fresh) > 1:
        print("ok   nested     an ancestor already on the path is recorded but not rewalked")
    else:
        bad.append(f"the cycle guard did not hold: fresh={len(fresh)} looped={len(looped)}")

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
    for cases in (_material_cases, _nested_document_cases, _cycle_guard_cases, _encoding_cases):
        more, bad = cases()
        total += more
        failures += bad
    if HOOK.exists():
        control = _hook_control()
        failures += control
        if not control:
            # Every shape applies here. The content scanner is handed a file and
            # rules on words alone, so the two URL-host shapes mean nothing to
            # it; the hook rules on the same text a human wrote, so a host shape
            # is exactly as refusable in a message as it is in history.
            more, bad = _run_cases(hook_refuses, PERMITTED, REFUSED, " (commit-message gate)")
            total += more
            failures += bad
    else:
        print("skip commit-message gate: this repository does not carry one")
    for line in failures:
        print(f"FAIL {line}", file=sys.stderr)
    print(f"{total - len(failures)}/{total} cases held")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
