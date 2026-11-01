#!/usr/bin/env python3
"""Refuse a tracked file that references a host or an address this repository does not publish.

This bundle was derived from a working tree that is not published, and the
derivation deleted every reference to a host, a path and an internal identifier
belonging to that tree. A deletion holds for exactly as long as nobody puts one
back, and the way one comes back is not a decision: it is a paragraph copied
across, a comment restored from an older revision, a generator whose header still
carries the URL it was written under.

So the check here is a POSITIVE one. Every hostname any tracked file mentions must
appear in the allowlist below, or be a name RFC 2606 reserves so that a document
can carry a host that resolves to nobody; every local filesystem path and mail
address is refused outright. A negative check would have to spell the strings it forbids,
which puts them in the repository that must not carry them; this one never names
anything it is protecting against, and it catches a host nobody thought to forbid.

    scripts/host-allowlist-gate.py
    scripts/host-allowlist-gate.py --list      # what was seen, and how often

Exit codes:
    0  every referenced host is on the allowlist and no local path or address
       appears
    1  at least one reference is not allowed; each is printed with its file, its
       line number and the line
    2  could not check: this is not a git checkout, or `git ls-files` returned
       nothing, which is a broken read and never a clean one
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

# Hosts this repository is allowed to name. Add one only when the repository
# genuinely references it, and never to make a failure go away.
ALLOWED_HOSTS = frozenset(
    {
        # the predicate and its home
        "in-toto.io",
        "github.com",
        # the host the done receipt predicate type is minted on
        "probityai.github.io",
        "raw.githubusercontent.com",
        "doi.org",
        "orcid.org",
        # the advisory database the engine gate resolves the pins against
        "api.osv.dev",
        # the engines
        "openpolicyagent.org",
        "www.openpolicyagent.org",
        "kyverno.io",
        "policies.kyverno.io",
        "release.kyverno.io",
        "policy.sigstore.dev",
        "sigstore.dev",
        "www.sigstore.dev",
        "cuelang.org",
        "cue-lang.org",
        # the CycloneDX schema namespace the digest check parses BOMs under
        "cyclonedx.org",
        # the SPDX 3 context and license namespace the coverage check parses
        "spdx.org",
        # kubernetes api groups and schema hosts that appear in manifests
        "kubernetes.io",
        "apps.kubernetes.io",
        "json-schema.org",
        # license and citation
        "www.apache.org",
        "apache.org",
        "citation-file-format.github.io",
        # the specification vocabulary
        "www.w3.org",
        "www.rfc-editor.org",
        "datatracker.ietf.org",
        # a registry host in a sample manifest
        "ghcr.io",
        # the client documentation the generated allowlist formats are written from
        "code.claude.com",
        "cursor.com",
        "docs.windsurf.com",
        "docs.github.com",
        # the registry server.json schema namespace the generated registry files carry
        "static.modelcontextprotocol.io",
    }
)

# RFC 2606 reserves names that exist so a document can name a host or an address
# without naming anything real: the top-level domains .test, .example, .invalid
# and .localhost (section 2), and the second-level names example.com, example.net
# and example.org (section 3). None of them resolves to anybody, by IETF
# reservation rather than by anyone's promise, and not resolving to anybody is
# exactly the property this gate spends its effort establishing. So a reference
# under one of those names is admitted BY RULE, and a file that needs a host or an
# address to prove a rule with has a correct name to reach for.
#
# The permit is on the SHAPE OF THE NAME and never on the file that carries it,
# which is what makes it narrower than the path exemption it replaced. Nothing
# below asks which file a line sits in: an ordinary document may name
# example.invalid, and a self-test naming a host that is not reserved is refused
# exactly like any other line would be. Every admission is counted and printed, so
# the permit can be read off a passing run rather than inferred from the source.
RESERVED_NAME_RE = re.compile(
    r"(?:^|\.)(?:test|example|invalid|localhost)\Z"
    r"|(?:^|\.)example\.(?:com|net|org)\Z",
    re.IGNORECASE,
)

# A backslash before a dot is a regular-expression escape (an allowlist pattern
# such as https://mcp\\.example\\.com), so it belongs to the host and is removed.
URL_RE = re.compile(r"\b(?:https?|ftp)://((?:[A-Za-z0-9._~%-]|\\+(?=\.))+(?::[0-9]+)?)")
# A bare hostname carrying a public suffix, outside a URL. Deliberately narrow:
# it must have at least two labels and end in letters, so version strings, file
# names and digests do not register as hosts.
BARE_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9@._/-])"
    r"((?:[a-z0-9][a-z0-9-]*\.)+(?:dev|com|io|org|net|ai|app|sh|cloud|xyz|co))"
    r"(?![A-Za-z0-9_-])"
)
MAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(?:/home/|/Users/|/mnt/|/blue/|~/)")

# File names, not hosts. A bare-host match against one of these is the regex
# being too eager rather than a reference, so they are removed before matching.
NOT_A_HOST = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:json|yaml|yml|md|py|rego|cff|txt|pub|sh|toml|lock|cfg|ini|ts|go|mod|sum)\b"
)

# Where the allowlist itself lives, plus anything binary enough that a line is
# not a meaningful unit. The allowlist file is skipped because a list of allowed
# hosts is a list of hosts, and checking it against itself measures nothing.
SKIP = {
    "scripts/host-allowlist-gate.py",
    # The same argument as the line above, for three more instruments. A guard
    # that detects local filesystem paths has to contain the pattern for one; a
    # commit-message hook proves its refusals with messages carrying the shapes
    # it rejects; and the permit test asserts which repository URLs pass, which
    # it can only do by containing them. Each is a file whose subject IS the
    # thing this gate looks for, so checking it here measures the instrument and
    # never the prose. Ordinary files stay checked, which is the point.
    ".githooks/commit-msg",
    "scripts/pre-push-identity-scan.py",
    "scripts/pre-push-identity-scan-test.py",
    # The decoder the identity scan imports to read encoded payloads. Its
    # percent-encoding pattern is a character class that spells the two
    # characters of a home-relative path, so the path rule fires on the
    # instrument. It is a shared file kept identical to its source copy, so the
    # exemption lives here rather than as an edit that forks it.
    "scripts/_decoding.py",
}

# A citation file carries the author's address because the format requires one,
# and a repository with no contact is worse than one with a personal address. So
# the address is permitted THERE and nowhere else, and its domain is still
# checked: the failure this whole file guards against is an organisational
# address arriving where a personal one belongs.
MAIL_ALLOWED_IN = {"CITATION.cff"}
MAIL_ALLOWED_DOMAINS = frozenset({"gmail.com"})
BINARYISH_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".gz", ".zip"}


def listing_mark(host: str) -> str:
    """How `host` reached a passing run: on the allowlist, by rule, or not at all."""
    if host in ALLOWED_HOSTS:
        return " "
    if RESERVED_NAME_RE.search(host):
        return "~"
    return "!"


def reserved_report(hosts: Counter[str], mail: Counter[str]) -> str | None:
    """One line naming every reference the reserved-name rule admitted, or None."""
    if not hosts and not mail:
        return None
    parts = []
    for label, counter in (("host reference(s)", hosts), ("mail address(es)", mail)):
        if counter:
            spelled = ", ".join(f"{n} x{c}" for n, c in sorted(counter.items()))
            parts.append(f"{sum(counter.values())} {label} ({spelled})")
    return (
        "host-allowlist-gate: admitted under the RFC 2606 reserved-name rule: "
        + " and ".join(parts)
    )


def passing_summary(scanned: int, seen: Counter[str], reserved_hosts: Counter[str]) -> str:
    """The line a clean run ends on, saying how each host was admitted.

    It used to say every host was on the allowlist. With the rule in place that is
    not what a pass means, and a summary overstating its own check is the defect
    this gate exists to catch in prose.
    """
    if reserved_hosts:
        how = (
            f"{len(seen) - len(reserved_hosts)} on the allowlist and the rest "
            "reserved by RFC 2606"
        )
    else:
        how = "every one on the allowlist"
    return (
        f"host-allowlist-gate: {scanned} tracked file(s), {len(seen)} distinct host(s), "
        f"{how}, no unreserved mail address and no local path."
    )


def cannot(msg: str) -> None:
    print(f"host-allowlist-gate: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def tracked_files() -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=HERE,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        cannot(f"could not run git: {exc}")
    if proc.returncode != 0:
        cannot(f"git ls-files exited {proc.returncode}: {proc.stderr.decode().strip()}")
    names = [n for n in proc.stdout.decode("utf-8").split("\0") if n]
    if not names:
        cannot(
            "git ls-files listed no files. A repository of zero files passes every "
            "check here vacuously, which is why an empty listing is a refusal."
        )
    return names


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print every host seen")
    args = parser.parse_args(argv[1:])

    problems: list[str] = []
    seen: Counter[str] = Counter()
    # What the reserved-name rule let through, by the name that carried it, with
    # hosts and addresses apart: the listing below counts hosts, so one total
    # covering both would read as a contradiction of it. Kept at all so a passing
    # run can say what it admitted -- an exemption nobody can read off the output
    # is the kind that grows.
    reserved_hosts: Counter[str] = Counter()
    reserved_mail: Counter[str] = Counter()
    scanned = 0

    for name in tracked_files():
        if name in SKIP or Path(name).suffix.lower() in BINARYISH_SUFFIXES:
            continue
        path = HERE / name
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = NOT_A_HOST.sub(" ", line)
            hosts = {m.group(1).replace("\\", "").split(":")[0].lower() for m in URL_RE.finditer(line)}
            hosts |= {m.group(1).lower() for m in BARE_HOST_RE.finditer(stripped)}
            for host in hosts:
                seen[host] += 1
                if host in ALLOWED_HOSTS:
                    continue
                if RESERVED_NAME_RE.search(host):
                    reserved_hosts[host] += 1
                    continue
                problems.append(f"{name}:{lineno}: host {host!r} is not allowed: {line.strip()}")
            for m in MAIL_RE.finditer(line):
                address = m.group(0)
                domain = address.rsplit("@", 1)[1].lower()
                if name in MAIL_ALLOWED_IN and domain in MAIL_ALLOWED_DOMAINS:
                    continue
                # An address under a reserved name is a fixture and cannot be a
                # contact: RFC 2606 guarantees the domain is nobody's. The check
                # this gate exists for -- an organisational address arriving where
                # a personal one belongs -- is untouched, because an
                # organisational address has a domain that resolves.
                if RESERVED_NAME_RE.search(domain):
                    reserved_mail[domain] += 1
                    continue
                problems.append(f"{name}:{lineno}: mail address {address!r}: {line.strip()}")
            if LOCAL_PATH_RE.search(line):
                problems.append(f"{name}:{lineno}: local filesystem path: {line.strip()}")

    if args.list:
        for host, count in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"{listing_mark(host)} {count:5d}  {host}")

    # Printed whether or not --list was asked for, and whether or not the run
    # passes. The rule is the one way a reference reaches a passing run without
    # being named in the allowlist above, so a run that used it says so.
    admitted = reserved_report(reserved_hosts, reserved_mail)
    if admitted:
        print(admitted)

    if problems:
        for p in problems:
            print(p, file=sys.stderr)
        print(
            f"\nhost-allowlist-gate: {len(problems)} disallowed reference(s) across "
            f"{scanned} tracked file(s).",
            file=sys.stderr,
        )
        return 1

    print(passing_summary(scanned, seen, reserved_hosts))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
