#!/usr/bin/env python3
"""Run the worked example in CONTRIBUTING.md through the real validator.

WHY THIS EXISTS. The "Required shape" section of CONTRIBUTING.md shows a filer a
complete crosswalk and tells them to build one like it. On 2026-08-30 that
example was checked against the validator for the first time and failed with
three errors: `system_url`, `crosswalk_version` and `vocabulary_version_targeted`
were all missing. The template beside it validated cleanly, so the defect was
confined to the guide's own prose.

The example also wrote `system` as a block. That was reported at the time as a
fourth thing the validator rejects, and it was not: the validator accepted a
block at zero errors until the scalar check was added later the same day. A
correct repair carried an invented cause, which is why the account here now
separates what the validator refused from what the guide had wrong.

Four frontier models read that file across two adversarial rounds and none of
them found it, which is the useful part. They were reading the document. The
defect only appears when somebody DOES what the document says. A guide is a
claim about what happens when its instructions are followed, and the only way to
check that claim is to follow them.

So this extracts the example from the markdown, writes it into `crosswalk/` under
a name the validator will pick up, and runs the validator exactly as CI does. No
reimplementation of any rule: if the validator changes, this follows.

Exit 0 the example validates, 1 it does not, 2 the check could not run.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_GUIDE = _ROOT / "CONTRIBUTING.md"
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_CROSSWALK_DIR = _ROOT / "crosswalk"

#: The section whose example is a promise to a filer. Anchored on the heading so
#: a fenced block added elsewhere in the guide is not mistaken for this one.
_SECTION = "## Required shape"


def _example() -> str | None:
    """The first fenced yaml block under the Required shape heading."""
    try:
        text = _GUIDE.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(
        re.escape(_SECTION) + r".*?```yaml\n(.*?)```", text, re.DOTALL
    )
    return match.group(1) if match else None


def main() -> int:
    if not _VALIDATOR.exists():
        print(
            f"test_contributing_example: REFUSED -- {_VALIDATOR} is missing, so "
            "nothing was checked.",
            file=sys.stderr,
        )
        return 2

    example = _example()
    if example is None:
        print(
            "test_contributing_example: REFUSED -- found no fenced yaml block "
            f"under '{_SECTION}' in CONTRIBUTING.md. Either the heading moved or "
            "the example was deleted. Nothing was checked, and an example that "
            "cannot be found is not an example that passed.",
            file=sys.stderr,
        )
        return 2

    # A real file in the real directory, because the validator globs that
    # directory and skipping it would test a different code path than CI runs.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", prefix="zz-contributing-example-",
        dir=_CROSSWALK_DIR, delete=False, encoding="utf-8",
    ) as handle:
        probe = Path(handle.name)
        handle.write(example)

    try:
        # Offline, because the example carries an https source_path on an
        # emitted claim and the validator resolves those with a live HEAD
        # request. Running this test in CI is what put a network call into
        # every build. Shape is what this test checks; resolvability is the
        # human reviewer's job under GOVERNANCE, and the validator says so
        # itself when it skips.
        run = subprocess.run(
            [sys.executable, str(_VALIDATOR)],
            capture_output=True, text=True, check=False, cwd=_ROOT,
            env={**os.environ, "VALIDATE_CROSSWALKS_OFFLINE": "1"},
        )
    finally:
        probe.unlink(missing_ok=True)

    if run.returncode == 0:
        print(
            "test_contributing_example: the worked example in CONTRIBUTING.md "
            "validates. A filer who copies it gets a file this repository accepts."
        )
        return 0

    print(
        "test_contributing_example: the worked example in CONTRIBUTING.md does "
        f"NOT validate (validator exit {run.returncode}).\n"
        "Fix the EXAMPLE, never the validator: the example is a promise about "
        "what happens when a filer follows this guide, and the validator is what "
        "actually happens.\n",
        file=sys.stderr,
    )
    for line in (run.stdout + run.stderr).splitlines():
        if line.startswith(("ERROR", "WARNING", "Validated", "validate_crosswalks")):
            print(f"  {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
