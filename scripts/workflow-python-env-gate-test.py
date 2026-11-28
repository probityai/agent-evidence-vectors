#!/usr/bin/env python3
"""The workflow Python-environment gate passes the repository and fails each mistake it names."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "workflow-python-env-gate.py"

PYPROJECT = """[project]
name = "fx"
version = "0"
dependencies = []

[project.optional-dependencies]
dev = ["markdown>=3.9", "pyyaml>=6"]
generators = ["cryptography>=43"]

[dependency-groups]
dev = ["pytest==9.2.0"]
"""

# The shape of the 24 Nov 2026 defect: a gate that is stdlib itself and launches the site build,
# which imports a package that only the lock provides.
GATE_SCRIPT = (
    "import subprocess, sys\n"
    "from pathlib import Path\n"
    "ROOT = Path(__file__).resolve().parent.parent\n"
    'subprocess.run([sys.executable, str(ROOT / "docs" / "site" / "build.py")], check=False)\n'
)
BUILD_SCRIPT = "import markdown\n"

SYNC = "      - run: uv sync --locked --extra dev\n"


def workflow(steps: str, job_extra: str = "") -> str:
    return (
        "name: x\non: [push]\njobs:\n  resolve:\n    runs-on: ubuntu-latest\n"
        f"{job_extra}    steps:\n{steps}"
    )


def run_step(command: str, name: str = "gate") -> str:
    return f"      - name: {name}\n        run: |\n          {command}\n"


def fixture(
    steps: str,
    *,
    scripts: dict[str, str] | None = None,
    pyproject: str = PYPROJECT,
    extra_files: dict[str, str] | None = None,
    job_extra: str = "",
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="wf-pyenv-") as d:
        root = Path(d)
        (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        files = {
            "scripts/gate.py": GATE_SCRIPT,
            "docs/site/build.py": BUILD_SCRIPT,
            **(scripts or {}),
            **(extra_files or {}),
        }
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "x.yml").write_text(workflow(steps, job_extra), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(GATE), "--root", d],
            capture_output=True,
            text=True,
            check=False,
        )


def refused(result: subprocess.CompletedProcess[str], *needles: str) -> None:
    assert result.returncode == 1, result.stdout + result.stderr
    for needle in needles:
        assert needle in result.stdout, (needle, result.stdout)


def passed(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, result.stdout + result.stderr


def main() -> int:
    real = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True, check=False)
    assert real.returncode == 0, real.stdout + real.stderr

    # The pages.yml defect: sync installs into .venv, a bare python3 never reads it.
    refused(
        fixture(SYNC + run_step("python3 scripts/gate.py --live")),
        "needs markdown",
        "imported by docs/site/build.py",
        "bare interpreter",
        "uv run --locked --extra dev",
    )
    # The fix: the same script under `uv run` with the extra that declares the package.
    passed(fixture(SYNC + run_step("uv run --locked --extra dev python scripts/gate.py --live")))
    # `uv run` is inexact, so an earlier sync's extras stay.
    passed(fixture(SYNC + run_step("uv run python scripts/gate.py")))
    # No extra anywhere: the package is missing from the environment `uv run` builds.
    refused(
        fixture(
            run_step("uv run python scripts/gate.py"),
            pyproject=PYPROJECT.replace('dev = ["markdown>=3.9", ', "dev = ["),
        ),
        "needs markdown",
        "declare it in pyproject.toml",
    )
    # A package declared in a different extra than the one the job installs is named with its extra.
    refused(
        fixture(
            "      - run: uv sync --locked\n" + run_step("uv run --no-dev python scripts/gate.py"),
            scripts={"docs/site/build.py": "import cryptography\n"},
        ),
        "needs cryptography",
        "--extra generators",
    )
    # `.venv/bin/python` reads what the job synced, and only that.
    passed(fixture(SYNC + run_step(".venv/bin/python -B scripts/gate.py")))
    refused(
        fixture(
            "      - run: uv sync --locked\n" + run_step(".venv/bin/python -B scripts/gate.py")
        ),
        "needs markdown",
        "the `.venv` the job's `uv sync` builds",
    )
    refused(
        fixture(run_step(".venv/bin/python -B scripts/gate.py")),
        "never runs `uv sync`",
    )
    # A bare python3 sees the job's own pip installs, by name and through a requirements file.
    passed(
        fixture(
            run_step("python -m pip install markdown==3.11.3") + run_step("python3 scripts/gate.py")
        )
    )
    passed(
        fixture(
            run_step("python -m pip install --require-hashes -r req.txt")
            + run_step("python3 scripts/gate.py"),
            extra_files={"req.txt": "markdown==3.11.3 \\\n    --hash=sha256:00\n"},
        )
    )
    # The standard library alone needs nothing.
    passed(
        fixture(
            run_step("python3 scripts/gate.py"),
            scripts={"docs/site/build.py": "import json\n"},
        )
    )
    # An import in a function, behind an ImportError guard or for type checking is not asked for.
    for body in (
        "def f():\n    import markdown\n",
        "try:\n    import markdown\nexcept ImportError:\n    markdown = None\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import markdown\n",
    ):
        passed(fixture(run_step("python3 scripts/gate.py"), scripts={"docs/site/build.py": body}))
    # An import of a module the repository holds is local, whatever else is installed.
    passed(
        fixture(
            run_step("python3 scripts/gate.py"),
            scripts={
                "docs/site/build.py": "import helper\n",
                "docs/site/helper.py": "import json\n",
            },
        )
    )
    # A step in its own locked project is judged against that project's dependencies.
    nested = '[project]\nname = "n"\nversion = "0"\ndependencies = ["markdown==3.11.3"]\n'
    passed(
        fixture(
            run_step("uv run --locked python gate.py") + "        working-directory: sub\n",
            extra_files={"sub/pyproject.toml": nested, "sub/gate.py": "import markdown\n"},
        )
    )
    refused(
        fixture(
            run_step("uv run --locked python gate.py") + "        working-directory: sub\n",
            extra_files={
                "sub/pyproject.toml": nested.replace("markdown", "other"),
                "sub/gate.py": "import markdown\n",
            },
        ),
        "needs markdown",
    )
    # `uv run --no-project --with` has exactly what it names.
    passed(fixture(run_step("uv run --no-project --with markdown==3.11.3 python scripts/gate.py")))
    refused(
        fixture(run_step("uv run --no-project python scripts/gate.py")),
        "needs markdown",
    )
    # A script under an interpreter built in the job is not this gate's to judge.
    passed(fixture(run_step('"$RUNNER_TEMP/venv/bin/python" scripts/gate.py')))
    # Nothing to read is an error, never a pass.
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        empty = subprocess.run(
            [sys.executable, str(GATE), "--root", d], capture_output=True, text=True, check=False
        )
        assert empty.returncode == 2, empty.stdout + empty.stderr
    print("workflow-python-env-gate-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
