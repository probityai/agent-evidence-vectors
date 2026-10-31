#!/usr/bin/env python3
"""Refuse prose that names a vectors release other than the one these rails measure.

The corpus pin lives in three machine-read places: the package version and wheel
hash in `requirements-vectors.txt`, the measured corpus digest in the workflow's
`VECTORS_CORPUS_DIGEST`, and the digest the vendored registry was read at. The
same facts are also written in prose, in the README, `llms.txt`, `PROVENANCE.md`
and `docs/DESIGN.md`, and nothing held the prose to the pin: the README and four
other pages named tag v0.10.1 for weeks after the workflow had moved to a later
package, and a reader following the recipe there measured a different corpus.

This gate reads the pin and refuses:

  * a requirements file that is not exactly one hashed `agent-evidence-vectors`
    line;
  * a registry or a measurement file read at a corpus digest other than the
    workflow's;
  * in any checked file, a package version, a vectors tag, a corpus digest or a
    corpus obligation count that differs from the pin;
  * a checked page that states no vectors version at all, so the pin cannot be
    dropped from the prose silently.

    scripts/vectors-pin-gate.py
    scripts/vectors-pin-gate.py --selftest

Exit codes:
    0  every checked statement agrees with the pin
    1  at least one statement disagrees; each is printed with its file and line
    2  could not check: a pin source is missing or unreadable. Never a pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
REQUIREMENTS = HERE / "requirements-vectors.txt"
WORKFLOW = HERE / "../../.github/workflows/package-admission.yml"
REGISTRY = HERE / "registry" / "conditions.json"
MEASUREMENTS = HERE / "profiles" / "MEASUREMENTS.json"

# Pages a reader follows to reproduce the measurement. Each must state the pinned
# version or tag at least once; the workflow is checked for disagreement only.
PAGES = ("README.md", "llms.txt", "PROVENANCE.md", "docs/DESIGN.md")

PIN_LINE = re.compile(
    r"^agent-evidence-vectors==(\d+\.\d+\.\d+) --hash=sha256:([0-9a-f]{64})$"
)
DIGEST_ENV = re.compile(
    r"^\s*VECTORS_CORPUS_DIGEST:\s*([0-9a-f]{64})\s*$", re.MULTILINE
)

# What a page can state, each with the group that must equal the pin.
VERSION_RES = (re.compile(r"agent-evidence-vectors(?:==|`? )(\d+\.\d+\.\d+)"),)
TAG_RES = (
    re.compile(r"\btag(?:\s+is)?\s+`?v(\d+\.\d+\.\d+)"),
    re.compile(r"--branch\s+v(\d+\.\d+\.\d+)"),
    re.compile(r"\bcorpus of tag\s+`?v(\d+\.\d+\.\d+)"),
)
DIGEST_RE = re.compile(r"corpus\s+digest[\s:`*]*([0-9a-f]{12,64})\b", re.IGNORECASE)
COUNT_RE = re.compile(r"\b(\d+) obligations\b")


def cannot(msg: str) -> None:
    print(f"vectors-pin-gate: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def read_pin(requirements: str) -> tuple[str, str]:
    lines = [
        ln.strip()
        for ln in requirements.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if len(lines) != 1:
        raise ValueError(f"expected one requirement line, found {len(lines)}")
    m = PIN_LINE.match(lines[0])
    if not m:
        raise ValueError(f"not a hashed agent-evidence-vectors pin: {lines[0]!r}")
    return m.group(1), m.group(2)


def check_text(
    name: str, text: str, version: str, digest: str, count: int, *, page: bool
) -> list[str]:
    """Every disagreement in one file, as `name:line: message`."""
    problems: list[str] = []
    stated = False
    for lineno, line in enumerate(text.splitlines(), 1):
        for rx in VERSION_RES + TAG_RES:
            for m in rx.finditer(line):
                stated = True
                if m.group(1) != version:
                    problems.append(
                        f"{name}:{lineno}: states vectors {m.group(0)!r}; the pin is {version}"
                    )
        for m in COUNT_RE.finditer(line):
            if int(m.group(1)) != count:
                problems.append(
                    f"{name}:{lineno}: states {m.group(0)!r}; the registry carries {count}"
                )
    # A digest is often wrapped onto the line after its label, so it is read
    # across the whole text rather than line by line.
    for m in DIGEST_RE.finditer(text):
        if not digest.startswith(m.group(1)):
            lineno = text.count("\n", 0, m.start()) + 1
            problems.append(
                f"{name}:{lineno}: states corpus digest {m.group(1)}; the pin is {digest}"
            )
    if page and not stated:
        problems.append(
            f"{name}: states no vectors version or tag; it must name {version}"
        )
    return problems


def gather() -> tuple[str, str, int, list[str]]:
    for path in (REQUIREMENTS, WORKFLOW, REGISTRY, MEASUREMENTS):
        if not path.is_file():
            cannot(f"missing {path}")
    try:
        version, _ = read_pin(REQUIREMENTS.read_text(encoding="utf-8"))
    except ValueError as exc:
        cannot(f"{REQUIREMENTS.name}: {exc}")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    env = DIGEST_ENV.findall(workflow)
    if len(env) != 1:
        cannot(f"expected one VECTORS_CORPUS_DIGEST in the workflow, found {len(env)}")
    digest = env[0]
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    measurements = json.loads(MEASUREMENTS.read_text(encoding="utf-8"))
    count = len(registry["conditions"])
    problems: list[str] = []
    for label, got in (
        ("registry/conditions.json", registry["source"]["corpusDigest"]),
        ("profiles/MEASUREMENTS.json", measurements.get("corpusDigest")),
    ):
        if got != digest:
            problems.append(
                f"{label}: read at corpus digest {got}; the workflow pins {digest}"
            )
    problems += check_text("workflow", workflow, version, digest, count, page=False)
    for rel in PAGES:
        path = HERE / rel
        if not path.is_file():
            cannot(f"missing {path}")
        problems += check_text(
            rel, path.read_text(encoding="utf-8"), version, digest, count, page=True
        )
    return version, digest, count, problems


def selftest() -> int:
    """Positive and negative controls: the gate must pass the first and fail each other."""
    v, d, n = "1.2.3", "ab" * 32, 7
    good = (
        f"Measured against the corpus at tag `v{v}`, installed as agent-evidence-vectors=={v},\n"
        f"corpus digest\n`{d}`. The registry carries {n} obligations.\n"
        f"git clone --depth 1 --branch v{v} https://example.invalid/vectors\n"
    )
    cases = {
        "a consistent page passes": (good, 0),
        "an old package version fails": (good.replace(f"=={v}", "==1.2.2"), 1),
        "an old tag fails": (good.replace(f"tag `v{v}`", "tag `v0.10.1`"), 1),
        "an old clone branch fails": (
            good.replace(f"--branch v{v}", "--branch v0.10.1"),
            1,
        ),
        "a different corpus digest fails": (good.replace(d, "cd" * 32), 1),
        "a different short digest fails": (good.replace(f"`{d}`", "`8b035678def9`"), 1),
        "a stale obligation count fails": (
            good.replace(f"{n} obligations", "93 obligations"),
            1,
        ),
        "a page naming no version fails": ("This page names nothing.\n", 1),
    }
    failed = 0
    for label, (text, want) in cases.items():
        got = 1 if check_text("selftest", text, v, d, n, page=True) else 0
        if got != want:
            failed += 1
            print(f"selftest: {label}: expected {'a refusal' if want else 'a pass'}")
    for label, req, ok in (
        (
            "a hashed pin parses",
            f"# c\nagent-evidence-vectors=={v} --hash=sha256:{d}\n",
            True,
        ),
        ("an unhashed pin is refused", f"agent-evidence-vectors=={v}\n", False),
        (
            "two pins are refused",
            f"agent-evidence-vectors=={v} --hash=sha256:{d}\n" * 2,
            False,
        ),
    ):
        try:
            read_pin(req)
            parsed = True
        except ValueError:
            parsed = False
        if parsed != ok:
            failed += 1
            print(f"selftest: {label}: wrong answer")
    if failed:
        print(
            f"vectors-pin-gate selftest: {failed} control(s) answered wrongly",
            file=sys.stderr,
        )
        return 1
    print(f"vectors-pin-gate selftest: {len(cases) + 3} controls answered as expected")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv[1:])
    if args.selftest:
        return selftest()
    version, digest, count, problems = gather()
    if problems:
        for p in problems:
            print(f"  {p}")
        print(
            f"\nvectors-pin-gate: {len(problems)} statement(s) disagree with the pin.",
            file=sys.stderr,
        )
        return 1
    print(
        f"vectors-pin-gate: agent-evidence-vectors {version}, corpus digest {digest[:12]}, "
        f"{count} obligations; the registry, the measurement, the workflow and "
        f"{len(PAGES)} pages agree."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
