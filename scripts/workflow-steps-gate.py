#!/usr/bin/env python3
"""Run every shell step of every GitHub workflow locally, before the push.

The bug this exists to stop, observed 2026-08-01: a change was pushed after its
author opened `.github/workflows/no-internal-drafts.yml`, read the first two
steps, ran those two by hand, and saw them pass. The guard has three steps. The
third one rejects first-party product names, it was the one the change broke,
and it never ran locally because nobody read that far down the file. The push
went red on a public repository and the tag cut from it had to be withdrawn.

Running "the checks I happened to read" is not running the checks. So this
reads the workflows themselves and runs every shell step in them, in file and
step order, and it is deliberately noisy about the ones it cannot run.

    .venv/bin/python -B scripts/workflow-steps-gate.py            # every workflow
    .venv/bin/python -B scripts/workflow-steps-gate.py --list     # show the plan, run nothing
    .venv/bin/python -B scripts/workflow-steps-gate.py --only no-internal-drafts

Exit 0 only when every runnable step exited 0. Any native step failure, unknown
action or expression, invalid source binding,
or workflow parse failure returns non-zero. Runner-only actions and unavailable
provisioned capabilities are explicit NOT_RUN records, never reported as passed.
A native process that actually fails keeps its original status and output.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterator, Mapping
from typing import Any, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from _branch_authority import (  # noqa: E402
    capture_authority,
    frozen_refs,
    git_environment,
    require_frozen_commit,
    require_packet,
)
from _gate_json import decode_json  # noqa: E402
from _go_selector import (
    SETUP_GO_REVISION,  # noqa: E402
    go_selector,  # noqa: E402
)
from _lockfile import single_instance  # noqa: E402
from _native_provider import digest as provider_digest  # noqa: E402
from _native_provider import ensure as ensure_provider  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"


def git(root: pathlib.Path, *args: str) -> bytes:
    """Read or change only the Git repository explicitly named by the caller."""
    return subprocess.run(  # noqa: S603 -- fixed Git commands, explicit repository
        ["git", "-C", str(root), *args], capture_output=True, check=True, env=git_environment(root)
    ).stdout


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def optional_git(root: pathlib.Path, *args: str) -> str:
    proc = subprocess.run(  # noqa: S603 -- read an optional local Git binding
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
        env=git_environment(root),
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def tags(root: pathlib.Path) -> dict[str, str]:
    return dict(
        line.split(" ", 1)
        for line in git(root, "for-each-ref", "--format=%(refname) %(objectname)", "refs/tags")
        .decode()
        .splitlines()
    )


def inventory(root: pathlib.Path) -> dict[str, dict[str, str]]:
    """Record tracked bytes, including symlink text rather than its target."""
    files: dict[str, dict[str, str]] = {}
    for row in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, _, stage = metadata.decode().split()
        if stage != "0" or mode == "160000":
            raise ValueError("unmerged entries and submodules need an explicit checkout contract")
        relative = os.fsdecode(name)
        path = root / relative
        if not path.exists() and not path.is_symlink():
            files[relative] = {"mode": mode, "state": "missing"}
            continue
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        actual_mode = (
            "120000"
            if path.is_symlink()
            else ("100755" if path.stat().st_mode & 0o111 else "100644")
        )
        files[relative] = {"mode": actual_mode, "sha256": hashlib.sha256(data).hexdigest()}
    return files


def committed_inventory(root: pathlib.Path, revision: str) -> dict[str, dict[str, str]]:
    """Hash every selected Git blob, including files omitted by sparse checkout."""
    entries = []
    for row in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if row:
            metadata, name = row.split(b"\t", 1)
            mode, kind, identity = metadata.decode().split()
            if kind != "blob":
                raise ValueError("submodules need an explicit checkout contract")
            entries.append((mode, identity, os.fsdecode(name)))
    proc = subprocess.run(  # noqa: S603 -- read precisely the selected tree's Git blobs
        ["git", "-C", str(root), "cat-file", "--batch"],
        input="".join(f"{identity}\n" for _, identity, _ in entries).encode(),
        capture_output=True,
        check=True,
        env=git_environment(root),
    )
    cursor = 0
    files = {}
    for mode, identity, relative in entries:
        end = proc.stdout.index(b"\n", cursor)
        header = proc.stdout[cursor:end].decode().split()
        if header[:2] != [identity, "blob"]:
            raise ValueError("Git batch response does not identify the selected blob")
        size = int(header[2])
        data = proc.stdout[end + 1 : end + 1 + size]
        if len(data) != size or proc.stdout[end + 1 + size : end + 2 + size] != b"\n":
            raise ValueError("Git batch response is incomplete")
        files[relative] = {"mode": mode, "sha256": hashlib.sha256(data).hexdigest()}
        cursor = end + 2 + size
    if cursor != len(proc.stdout):
        raise ValueError("unexpected trailing Git batch response")
    return files


class Source:
    """An immutable input revision; every job gets its own Git database and files."""

    def __init__(self, root: pathlib.Path, branch_authority: dict[str, Any]) -> None:
        self.root = root.resolve()
        self.head = git(root, "rev-parse", "HEAD").decode().strip()
        self.tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
        self.tags = tags(root)
        self.input_files = inventory(root)
        self.files = committed_inventory(root, self.head)
        if any(
            value.get("state") != "missing" and value != self.files.get(path)
            for path, value in self.input_files.items()
        ):
            raise ValueError("present input bytes differ from the selected Git tree")
        if git(root, "status", "--porcelain", "--untracked-files=no"):
            raise ValueError("input tracked bytes differ from the selected commit")
        for key in ("GITHUB_SHA", "GITHUB_HEAD_SHA"):
            if os.environ.get(key) and os.environ[key] != self.head:
                raise ValueError(f"{key} does not identify the selected source commit")
        if os.environ.get("GITHUB_EVENT_NAME", "push") != "push":
            raise ValueError("this mirror only supports its declared local push simulation")
        self.ref = optional_git(root, "symbolic-ref", "-q", "HEAD")
        self.origin = optional_git(root, "remote", "get-url", "origin")
        match = re.fullmatch(
            r"(?:https://github\.com/|git@github\.com:)([^/]+/[^/]+?)(?:\.git)?", self.origin
        )
        self.repository = match.group(1) if match else ""
        self.branch_authority = branch_authority
        self.authority = require_packet(root, branch_authority)
        self.default_branch = self.authority["default_branch"]

    def verify(self) -> None:
        require_packet(self.root, self.branch_authority)
        if (
            git(self.root, "rev-parse", "HEAD").decode().strip() != self.head
            or git(self.root, "rev-parse", "HEAD^{tree}").decode().strip() != self.tree
            or tags(self.root) != self.tags
            or inventory(self.root) != self.input_files
            or git(self.root, "status", "--porcelain", "--untracked-files=no")
        ):
            raise ValueError("the input source or tag refs changed during the mirror")

    def checkout(self, destination: pathlib.Path) -> None:
        self.verify()
        subprocess.run(  # noqa: S603 -- independent clone of the verified local input
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                "--dissociate",
                "--no-checkout",
                str(self.root),
                str(destination),
            ],
            capture_output=True,
            check=True,
            env=git_environment(self.root),
        )
        git(
            destination,
            "fetch",
            "--quiet",
            str(self.root),
            "+refs/tags/*:refs/tags/*",
            "+refs/remotes/origin/*:refs/remotes/origin/*",
        )
        git(destination, "checkout", "--quiet", "--detach", self.head)
        alternates = destination / ".git" / "objects" / "info" / "alternates"
        if alternates.exists() and alternates.read_bytes().strip():
            raise ValueError("job checkout still depends on another repository's object store")
        if self.origin:
            git(destination, "remote", "set-url", "origin", self.origin)
        if (
            git(destination, "rev-parse", "HEAD^{tree}").decode().strip() != self.tree
            or tags(destination) != self.tags
            or inventory(destination) != self.files
        ):
            raise ValueError("job checkout does not reproduce the selected source and tags")
        require_packet(destination, self.branch_authority)

    def context(self, temp: pathlib.Path) -> dict[str, str]:
        return {
            "github.sha": self.head,
            "github.event.pull_request.head.sha || github.sha": self.head,
            "github.ref": self.ref,
            "github.repository": self.repository,
            "github.server_url": "https://github.com" if self.repository else "",
            "github.event.repository.default_branch": self.default_branch,
            "runner.temp": str(temp),
            **LOCAL_ABSENT,
        }


# These fields have no value in a local push mirror. Unknown contexts are faults.
LOCAL_ABSENT = dict.fromkeys(
    (
        "github.event.before",
        "github.event.pull_request.base.sha",
        "github.event.pull_request.head.sha",
        "github.event.pull_request.title",
        "github.event.pull_request.number",
        "github.token",
        "github.run_id",
    ),
    "",
)

# A marketplace step is one with `uses:` and no shell body. Every one of them
# used to be printed as SKIP and left at that, and on 2026-09-11 that cost three
# red pushes in a row: `golangci-lint (core module)` is a marketplace step, this
# gate skipped it on every push, and the remote failed it on every push with a
# finding a locally installed golangci-lint reports in under a second.
#
# So a marketplace step is now asked whether this workstation can do the same
# work, and the three answers are kept apart on purpose.
#
#   MIRRORED    -- there is a local equivalent, and it RUNS. A failure here is a
#                  failure of the gate, exactly as a shell step's is.
#   CANNOT_RUN  -- the step does something only a runner can do: provision a
#                  toolchain, upload to the run's artifact store, open a pull
#                  request. It is printed NOT RUN, by name, with the reason.
#   neither     -- an action nobody has classified. That is a FAULT rather than
#                  a skip. An action added to a workflow would otherwise remove
#                  itself from this gate's coverage silently, which is the whole
#                  defect above in its next costume.


class Local(NamedTuple):
    """What this workstation can do about one marketplace step."""

    run: str | None  # the shell to run, when there is a local equivalent
    reason: str  # why there is not, when `run` is None
    fault: bool = False  # an unclassified action, which fails the gate


def installed_golangci_version() -> str:
    """The golangci-lint version on PATH, or "" when there is none."""
    binary = shutil.which("golangci-lint")
    if binary is None:
        return ""
    proc = subprocess.run(  # noqa: S603 -- reading the version of a binary we are about to run
        [binary, "version"], capture_output=True, text=True, check=False
    )
    found = re.search(r"version\s+v?(\S+)", proc.stdout + proc.stderr)
    return found.group(1) if found else "unknown"


def golangci_lint(inputs: dict[str, Any]) -> Local:
    """Mirror golangci/golangci-lint-action with the binary on PATH.

    The pinned version is not a detail. golangci-lint adds, removes and retunes
    linters between patch releases, so a mirror running a different version
    reports on a different tool and its silence means nothing. A mismatch is
    therefore NOT RUN with both versions named, never a quiet pass.
    """
    wanted = str(inputs.get("version", "")).strip().lstrip("v")
    installed = installed_golangci_version()
    if not installed:
        return Local(None, f"golangci-lint is not on PATH; the workflow pins v{wanted}")
    if wanted and installed != wanted:
        return Local(
            None,
            f"the workflow pins v{wanted} and this workstation has v{installed}, "
            "which is a different set of linters",
        )
    directory = str(inputs.get("working-directory", "") or ".")
    # `golangci-lint run`, with nothing added. Narrowing the concurrency or the
    # linter set would make this a mirror of a command the remote never runs.
    return Local(f"cd {shlex.quote(directory)}\ngolangci-lint run", "")


def own_action(inputs: dict[str, Any]) -> Local:
    """Mirror `uses: ./`, this repository's composite action, from the checkout.

    The action installs the package from its own checkout and replays one corpus
    against the verifier named in its inputs, then derives its outputs from the
    report. Both halves are mirrored here, and the second half matters as much
    as the first: a step later in the workflow reads this action's outputs, and
    a mirror that replayed the corpus but produced no outputs would leave that
    step comparing against empty strings and failing a push the remote accepts.

    The harness is packaging/run_vectors.py and the output arithmetic is
    scripts/action-summary.py -- the same file the action itself runs, not a
    second copy of it here, so the mirror cannot drift from what it mirrors.

    The installation step is the runner's: it pip-installs the package into the
    job's environment, and the harness it installs is the file on disk here.
    A verifier the action names as `python -m agent_evidence_vectors.<module>`
    imports that installed package, so the mirror puts this checkout's package
    first on PYTHONPATH. Without it the import resolved to whatever older copy
    the first interpreter on PATH had installed, and a replay the remote passed
    failed every vector here. The job summary is written to a scratch file, and
    the artifact upload is not mirrored at all.
    """
    verifier = str(inputs.get("verifier", "")).strip()
    if not verifier:
        return Local(None, "the action was used without a verifier input")
    corpus = str(inputs.get("corpus", "") or "vectors")
    report = str(inputs.get("report-path", "") or "agent-evidence-vectors-report.json")
    report_name = pathlib.Path(report).name
    # The replay's status is captured rather than allowed to abort the block:
    # the action writes its summary and its outputs for a failing run too, and
    # the mirror has to reach the same place. The status is re-raised at the end
    # so a failing replay still fails this step, as the action's last step does.
    return Local(
        ': "${RUNNER_TEMP:?RUNNER_TEMP is required}"\n'
        f'report_path="$RUNNER_TEMP"/{shlex.quote(report_name)}\n'
        'export PYTHONPATH="$PWD/packaging${PYTHONPATH:+:$PYTHONPATH}"\n'
        "status=0\n"
        "python3 packaging/run_vectors.py"
        f" --corpus {shlex.quote(corpus)}"
        f" --verifier {shlex.quote(verifier)}"
        ' --report "$report_path" || status=$?\n'
        'echo "report=$report_path" >> "$GITHUB_OUTPUT"\n'
        f'REPORT="$report_path" STATUS="$status" CORPUS={shlex.quote(corpus)} \\\n'
        "  python3 scripts/action-summary.py\n"
        # The action's last step fails the job on the exit status OR on a
        # summary verdict other than pass, so the mirror does both.
        'if [ "$status" != 0 ]; then exit "$status"; fi\n'
        'grep -qx "result=pass" "$GITHUB_OUTPUT" || exit 1\n',
        "",
    )


def uv_python_available(version: str) -> bool:
    """Whether uv can provide a CPython release the pin accepts, installed or downloadable.

    A three-part pin (3.13.15) accepts that release and nothing else. A two-part
    pin (3.12) is what setup-python reads as "the newest 3.12", so any 3.12.x
    satisfies it, on the runner and here alike.
    """
    if shutil.which("uv") is None:
        return False
    proc = subprocess.run(  # noqa: S603 -- asking uv what it can install
        ["uv", "python", "list", "--all-versions", version],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    if re.fullmatch(r"\d+\.\d+", version):
        return f"cpython-{version}." in proc.stdout
    return f"cpython-{version}-" in proc.stdout


def setup_python(inputs: dict[str, Any]) -> Local:
    """Mirror actions/setup-python with a fresh, pip-seeded interpreter from uv.

    The runner's step puts a Python WITH pip on PATH, and the workflows that use
    it start with `python -m pip install ...`. Leaving the step NOT RUN meant the
    next steps ran against the hook's uv-built project venv, which has no pip,
    and three workflows failed here on 2026-10-01 while passing on the remote.

    The interpreter is announced through $GITHUB_PATH, exactly as the action
    does, so it lasts for the rest of the job and no longer. The pinned release
    is used or nothing is: when uv cannot provide that exact version, the step
    is NOT RUN and so is the rest of its job (see `execute`). A nearby release
    is not a mirror -- the WIMSE reproduction refuses any interpreter but its
    pinned one, so a fallback fails a push the remote accepts.
    """
    wanted = str(inputs.get("python-version", "")).strip()
    if not wanted:
        return Local(None, "actions/setup-python was used without a python-version input", True)
    if not uv_python_available(wanted):
        return Local(
            None,
            f"actions/setup-python pins CPython {wanted}, which uv on this workstation "
            "cannot provide; the job's later steps are not run on a different interpreter",
            True,
        )
    return Local(
        f'uv venv -q --clear --seed --python {shlex.quote(wanted)} "$GITHUB_WORKSPACE/.venv"\n'
        'echo "$GITHUB_WORKSPACE/.venv/bin" >> "$GITHUB_PATH"\n',
        "",
    )


MIRRORED: dict[str, Callable[[dict[str, Any]], Local]] = {
    "golangci/golangci-lint-action": golangci_lint,
    "actions/setup-python": setup_python,
    "./": own_action,
}

# Steps that belong to the runner rather than to the repository. Each reason
# says what the step does there, so a reader can judge the gap rather than
# taking "not runnable" on trust.
CANNOT_RUN = {
    "actions/checkout": (
        "materialises the repository on the runner; this gate already runs "
        "inside a checkout of the revision under test"
    ),
    "actions/setup-go": "provisions a Go toolchain on the runner; the one on PATH is used here",
    "actions/setup-node": "provisions Node.js on the runner; the one on PATH is used here",
    "pypa/gh-action-pypi-publish": (
        "uploads the built distributions to PyPI under the workflow's OIDC "
        "identity, which only the runner holds"
    ),
    "astral-sh/setup-uv": "provisions uv on the runner; the one on PATH is used here",
    "sigstore/cosign-installer": "provisions cosign on the runner; the one on PATH is used here",
    "actions/upload-artifact": "writes to the run's artifact store, which is only on the remote",
    "peter-evans/create-pull-request": "opens a pull request on the remote",
    "ossf/scorecard-action": "reads the repository's remote metadata and needs a token",
    "github/codeql-action/init": "builds a CodeQL database with a toolchain provisioned per run",
    "github/codeql-action/analyze": "queries a CodeQL database built by the step above",
    "github/codeql-action/upload-sarif": "uploads to code scanning on the remote",
    "actions/configure-pages": (
        "reads the repository's Pages settings from the remote to tell the build "
        "what base URL the site will be served from"
    ),
    "actions/upload-pages-artifact": (
        "packs the built directory into the run's artifact store, which is only on the remote"
    ),
    "actions/deploy-pages": (
        "publishes an uploaded artifact to the repository's Pages site, which "
        "only the remote can do"
    ),
}


def local_equivalent(uses: str, inputs: dict[str, Any]) -> Local:
    """Classify one marketplace step. Never returns a silent skip."""
    action = uses.split("@", 1)[0]
    if action == "oven-sh/setup-bun":
        return Local(None, "Bun needs the declared native provider bound to this job")
    builder = MIRRORED.get(action)
    if builder is not None:
        return builder(inputs)
    reason = CANNOT_RUN.get(action)
    if reason is not None:
        return Local(None, f"{action} {reason}")
    return Local(
        None,
        f"{action} is not classified in this gate. Add it to MIRRORED with a "
        "local equivalent, or to CANNOT_RUN with the reason a runner is needed. "
        "An unclassified action drops out of local coverage without saying so.",
        fault=True,
    )


def load_yaml(path: pathlib.Path) -> Any:
    """Parse a workflow, or fail loudly. Never return a partial parse."""
    try:
        import yaml  # noqa: PLC0415 -- optional dependency, reported explicitly below
    except ImportError:
        sys.exit(
            "workflow-steps-gate: PyYAML is not importable.\n"
            "  Install it, or run this gate through uv:\n"
            "    uv run --with pyyaml python scripts/workflow-steps-gate.py\n"
            "  Refusing to continue: a gate that cannot read the workflows cannot\n"
            "  report that they passed."
        )
    try:
        return yaml.safe_load(path.read_text())
    except Exception as exc:  # noqa: BLE001 -- any parse failure is fatal by design
        sys.exit(f"workflow-steps-gate: {path.name} did not parse: {exc}")


class Step(NamedTuple):
    """One workflow step: a shell body, or a marketplace action and its inputs."""

    job: str
    # Not `index`: a NamedTuple field of that name overrides tuple.index().
    position: int
    name: str
    run: str | None
    uses: str
    inputs: dict[str, Any]
    # `ident` rather than `id`: the step's own `id:`, which is how a later step
    # names this one's outputs. Empty when the step declares none.
    ident: str = ""
    # The step's `env:` block, verbatim. Dropping it used to be silent: a step
    # whose assertions read variables set here ran with none of them set, which
    # is a check reporting a verdict on an input it never received.
    env: dict[str, Any] = {}
    # `continue-on-error: true`. A failing step so marked does not fail the job
    # on the runner; its `outcome` is failure and its `conclusion` is success,
    # which is how a workflow asserts that something MUST fail. Ignoring the key
    # made every such negative step a red push the remote would accept.
    continue_on_error: bool = False
    # The directory a `run:` block starts in, relative to the checkout: the
    # step's own `working-directory`, else the job's `defaults.run`, else the
    # workflow's. Ignoring it ran every step of a job declaring a default
    # directory from the repository root, where its scripts are not found.
    workdir: str = ""
    # The step's `if:` expression, verbatim, or "" when it has none.
    condition: str = ""

    matrix: dict[str, str] = {}
    unexpanded: str = ""

    @property
    def label(self) -> str:
        return f"{self.job}[{self.position}] {self.name}"


def scalar(value: Any) -> str:
    """A YAML scalar as an expression reads it: booleans are `true`/`false`."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _cross(axes: dict[str, list[Any]]) -> list[dict[str, str]]:
    """The cross product of the matrix's list keys; empty when there are none."""
    if not axes:
        return []
    combos: list[dict[str, str]] = [{}]
    for key, values in axes.items():
        combos = [{**combo, key: scalar(value)} for combo in combos for value in values]
    return combos


def _literal(text: str) -> tuple[bool, Any]:
    """(is a literal, its value) for one operand of an expression."""
    if re.fullmatch(r"'(?:[^']|'')*'", text):
        return True, text[1:-1].replace("''", "'")
    if text in ("true", "false"):
        return True, text == "true"
    if text == "null":
        return True, None
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return True, float(text) if "." in text else int(text)
    return False, None


def _rendered(value: Any) -> str:
    """An expression value as Actions writes it into text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def expression_number(value: Any) -> float:
    """Actions loose comparisons coerce unlike scalar types to JSON numbers."""
    if value is None or value == "":
        return 0.0
    if isinstance(value, (bool, int, float)):
        return float(value)
    try:
        number = json.loads(value)
    except (TypeError, ValueError):
        return float("nan")
    return float(number) if type(number) in (int, float) else float("nan")


def expression_equal(left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.lower() == right.lower()
    if type(left) is type(right):
        return bool(left == right)
    return expression_number(left) == expression_number(right)


def _split_top(expression: str, operator: str) -> list[str]:
    """Split on an operator outside single-quoted strings."""
    parts: list[str] = []
    depth_quote = False
    current = ""
    i = 0
    while i < len(expression):
        ch = expression[i]
        if ch == "'":
            depth_quote = not depth_quote
        if not depth_quote and expression.startswith(operator, i):
            parts.append(current)
            current = ""
            i += len(operator)
            continue
        current += ch
        i += 1
    parts.append(current)
    return [part.strip() for part in parts]


class _Evaluator:
    """One expression body, evaluated the way Actions does for the subset used here.

    Supported: references, string, number and boolean literals, `==`, `!=`, `!`,
    `&&` and `||` with Actions' short-circuit values (`a || b` is a when a is
    truthy, else b). A parenthesis or a function call is outside that and is
    refused by name rather than approximated.
    """

    def __init__(
        self,
        expression: str,
        outputs: dict[str, dict[str, str]],
        statuses: dict[str, dict[str, str]] | None,
        context: Mapping[str, str] | None,
        where: str,
    ) -> None:
        self.expression = expression
        self.outputs = outputs
        self.statuses = statuses or {}
        self.context = {**LOCAL_ABSENT, **(context or {})}
        self.where = where
        self.shown = f"${{{{ {expression.strip()} }}}}"

    def run(self) -> tuple[Any, str]:
        if len(_split_top(self.expression, "(")) > 1 or len(_split_top(self.expression, "[")) > 1:
            return None, (
                f"{self.where} {self.shown}, which calls a function or indexes a value; "
                "this gate evaluates references, literals, ==, !=, !, && and || only "
                "and will not approximate the rest"
            )
        value: Any = None
        for part in _split_top(self.expression, "||"):
            value, missing = self.conjunction(part)
            if missing or value:
                return value, missing
        return value, ""

    def conjunction(self, text: str) -> tuple[Any, str]:
        value: Any = True
        for part in _split_top(text, "&&"):
            value, missing = self.comparison(part)
            if missing or not value:
                return value, missing
        return value, ""

    def comparison(self, text: str) -> tuple[Any, str]:
        for operator in ("==", "!="):
            sides = _split_top(text, operator)
            if len(sides) > 2:
                return None, f"{self.where} {self.shown}, which chains `{operator}`; not evaluated"
            if len(sides) == 2:
                left, missing = self.operand(sides[0])
                right, missing_right = self.operand(sides[1])
                if missing or missing_right:
                    return None, missing or missing_right
                same = expression_equal(left, right)
                return (same if operator == "==" else not same), ""
        return self.operand(text)

    def operand(self, text: str) -> tuple[Any, str]:
        text = text.strip()
        negate = False
        while text.startswith("!"):
            negate = not negate
            text = text[1:].strip()
        value, missing = self.atom(text)
        return (not value if negate else value), missing

    def atom(self, text: str) -> tuple[Any, str]:
        is_literal, value = _literal(text)
        if is_literal:
            return value, ""
        if not REFERENCE.match(text):
            return None, (
                f"{self.where} {self.shown}, and `{text}` is not an expression this gate can read"
            )
        if STEP_STATUS.match(text) or STEP_OUTPUT.match(text):
            return self.step_reference(text)
        if text in self.context:
            return self.context[text], ""
        return None, (
            f"unsupported expression {self.shown}: `{text}` has no verified local context"
        )

    def step_reference(self, text: str) -> tuple[Any, str]:
        """A step's outcome or output, as recorded when this gate ran the step.

        One that was not run here, or ran without writing the name, is not
        guessed: the reason names the step and what is missing.
        """
        status = STEP_STATUS.match(text)
        if status is not None:
            step_id, which = status.groups()
            recorded_status = self.statuses.get(step_id)
            if recorded_status is None:
                return None, (
                    f"{self.where} {self.shown}, and step `{step_id}` was not run here, so "
                    "this gate has no outcome for it and will not invent one"
                )
            return recorded_status[which], ""
        reference = STEP_OUTPUT.match(text)
        assert reference is not None
        step_id, name = reference.groups()
        recorded = self.outputs.get(step_id)
        if recorded is None:
            return None, (
                f"{self.where} {self.shown}, and step `{step_id}` was not run here, so "
                "this gate has no value for it and will not invent one"
            )
        if name not in recorded:
            return None, (
                f"{self.where} {self.shown}, and step `{step_id}` ran here without writing "
                f"`{name}` to $GITHUB_OUTPUT. Either the action declares an output its "
                "local mirror does not produce, or the name is wrong"
            )
        return recorded[name], ""


def evaluate(
    expression: str,
    outputs: dict[str, dict[str, str]],
    statuses: dict[str, dict[str, str]] | None = None,
    context: Mapping[str, str] | None = None,
    where: str = "its env reads",
) -> tuple[Any, str]:
    """Evaluate one expression body. Returns (value, reason it could not be)."""
    return _Evaluator(expression, outputs, statuses, context, where).run()


def trigger_excludes(doc: Any, tags: list[str]) -> str:
    """The reason a workflow never runs for this revision, or "" when it may.

    Only one case is decided: a workflow whose sole automatic trigger is a push
    of matching TAGS (release.yml: `push: tags: ['v*']`, plus manual dispatch).
    The remote runs it when a release tag is pushed and at no other time, so
    running it on an untagged commit verifies a release that does not exist:
    the signed digest list legitimately changes between releases and is signed
    again when the next one is cut. Every other trigger shape runs as before,
    because skipping a workflow the remote does run would be the silent gap
    this gate exists to close.
    """
    on = (doc or {}).get("on", (doc or {}).get(True))
    if not isinstance(on, dict):
        return ""
    automatic = {k: v for k, v in on.items() if k not in ("workflow_dispatch",)}
    push = automatic.get("push")
    if set(automatic) != {"push"} or not isinstance(push, dict):
        return ""
    if set(push) != {"tags"}:
        return ""
    patterns = [str(t) for t in (push.get("tags") or [])]
    if any(fnmatch.fnmatchcase(tag, pattern) for tag in tags for pattern in patterns):
        return ""
    return (
        f"the workflow runs only on a push of tags {patterns}, and no such tag "
        "points at the revision under test"
    )


def matrix_combinations(job: Any) -> tuple[list[dict[str, str]], str]:
    """Expand static axes, exclude first, and apply includes to original rows."""
    matrix = ((job or {}).get("strategy") or {}).get("matrix")
    if matrix is None:
        return [{}], ""
    if not isinstance(matrix, dict):
        return [], f"its matrix is the expression {matrix!r}, which is not evaluated"
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    if any(
        not isinstance(v, list) or any(isinstance(x, (dict, list)) for x in v)
        for v in axes.values()
    ):
        return [], "matrix axes must be lists of scalar values"
    for key in ("include", "exclude"):
        if not matrix_entries(matrix.get(key, [])):
            return [], f"matrix {key} must be a list of scalar-valued objects"
    original = _cross(axes)
    for entry in matrix.get("exclude") or []:
        drop = {str(k): scalar(v) for k, v in entry.items()}
        original = [c for c in original if not all(c.get(k) == v for k, v in drop.items())]
    added = []
    for entry in matrix.get("include") or []:
        row = {str(k): scalar(v) for k, v in entry.items()}
        if not include_original(original, row, set(axes)):
            added.append(row)
    combos = original + added
    return (combos, "") if combos else ([], "its matrix expands to no combination")


def matrix_entries(entries: Any) -> bool:
    """Reject dynamic or nested matrix entries instead of inventing scalar values."""
    return isinstance(entries, list) and all(
        isinstance(e, dict) and all(not isinstance(v, (dict, list)) for v in e.values())
        for e in entries
    )


def include_original(original: list[dict[str, str]], entry: dict[str, str], axes: set[str]) -> bool:
    matched = False
    for combo in original:
        if all(combo.get(k) == v for k, v in entry.items() if k in axes):
            combo.update({k: v for k, v in entry.items() if k not in axes})
            matched = True
    return matched


def steps_of(doc: Any, path: pathlib.Path) -> Iterator[Step]:
    """Yield every step, in declaration order, once per matrix combination."""
    jobs = (doc or {}).get("jobs") or {}
    if not jobs:
        sys.exit(f"workflow-steps-gate: {path.name} declares no jobs. Refusing to call it covered.")
    workflow_dir = default_directory(doc)
    for job_name, job in jobs.items():
        job_dir = default_directory(job) or workflow_dir
        combos, unexpanded = matrix_combinations(job)
        seen: set[str] = set()
        for index, combo in enumerate(combos or [{}]):
            label = job_name
            if combo:
                label = f"{job_name} ({', '.join(f'{k}={v}' for k, v in combo.items())})"
            if label in seen:
                label += f" [combination {index}]"
            seen.add(label)
            for i, step in enumerate(job.get("steps") or []):
                name = step.get("name") or f"step {i}"
                yield Step(
                    job=label,
                    position=i,
                    name=name,
                    run=None if step.get("run") is None else scalar(step.get("run")),
                    uses=str(step.get("uses") or ""),
                    inputs=step.get("with") or {},
                    ident=str(step.get("id") or ""),
                    env={
                        **((doc or {}).get("env") or {}),
                        **(job.get("env") or {}),
                        **(step.get("env") or {}),
                    },
                    continue_on_error=step.get("continue-on-error") is True,
                    workdir=str(step.get("working-directory") or job_dir),
                    condition=str(step.get("if") or ""),
                    matrix=combo,
                    unexpanded=unexpanded,
                )


def default_directory(node: Any) -> str:
    """`defaults.run.working-directory` of a workflow or a job, or ""."""
    defaults = (node or {}).get("defaults") or {}
    return str((defaults.get("run") or {}).get("working-directory") or "")


# The runner's default shell is bash, and workflow steps rely on it: `set -o pipefail`
# is a bashism that dash rejects outright, so running a step under /bin/sh reports a
# failure the remote would never see. A local gate that fails differently from the gate
# it mirrors is worse than none, because it trains its reader to ignore it.
SHELL = "/bin/bash"

# GitHub Actions runs every `run:` block under `bash -e {0}` -- its own logs print
# that line above each step. Without `-e`, a multi-command block reports only the
# LAST command's status, so a step whose first command fails and whose remaining
# commands pass exits 0 here and non-zero on the remote. That is not a cosmetic
# divergence: it is this gate reporting a clean mirror of a workflow that is
# about to go red, which is the exact failure the gate was written to prevent,
# one level up. Origin 2026-08-07: the four-command forcing step failed its first
# command, passed the other three, and this gate passed the push.
#
# `pipefail` is NOT added. Actions does not set it, and a mirror stricter than
# the thing it mirrors fails pushes the remote would have accepted -- the job is
# to match, not to improve. scripts/workflow-steps-gate-test.py pins both halves.
SHELL_FLAGS = ("-e",)


# `${{ ... }}`, the only interpolation Actions performs in an `env:` value.
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
REFERENCE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_*-]+)*$")
STEP_OUTPUT = re.compile(r"^steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)$")
STEP_STATUS = re.compile(r"^steps\.([A-Za-z0-9_-]+)\.(outcome|conclusion)$")


def expand(
    value: str,
    outputs: dict[str, dict[str, str]],
    statuses: dict[str, dict[str, str]] | None = None,
    context: Mapping[str, str] | None = None,
    where: str = "its env reads",
) -> tuple[str, str]:
    """Resolve bounded expressions; unknown context refuses before the shell."""
    missing = ""

    def one(match: re.Match[str]) -> str:
        nonlocal missing
        result, reason = evaluate(match.group(1), outputs, statuses, context, where)
        missing = missing or reason
        return _rendered(result)

    expanded = EXPRESSION.sub(one, value)
    if "${{" in expanded and not missing:
        missing = "unterminated or unresolved GitHub expression; no shell was run"
    return expanded, missing


def step_environment(
    step: Step,
    outputs: dict[str, dict[str, str]],
    scratch: str,
    statuses: dict[str, dict[str, str]] | None = None,
    context: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], str]:
    """The environment for one step, or the reason it cannot be assembled.

    Every step is given its own $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY, the way
    the runner does, so a step that writes outputs can be read by the next one
    and a step that writes a summary is not writing to a variable that is unset.
    """
    env: dict[str, str] = {
        "GITHUB_OUTPUT": str(pathlib.Path(scratch) / f"output-{step.job}-{step.position}"),
        "GITHUB_STEP_SUMMARY": str(pathlib.Path(scratch) / f"summary-{step.job}-{step.position}"),
        "GITHUB_ENV": str(pathlib.Path(scratch) / f"env-{step.job}-{step.position}"),
        "GITHUB_PATH": str(pathlib.Path(scratch) / f"path-{step.job}-{step.position}"),
    }
    for key, raw in step.env.items():
        value, missing = expand(str(raw), outputs, statuses, context)
        if missing:
            return env, missing
        env[str(key)] = value
    for key in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_ENV", "GITHUB_PATH"):
        pathlib.Path(env[key]).write_text("", encoding="utf-8")
    return env, ""


def read_github_env(text: str) -> dict[str, str]:
    """Parse a $GITHUB_ENV file: `NAME=value` lines and `NAME<<DELIM` blocks."""
    found: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = line.split("<<", 1)
            body: list[str] = []
            while i < len(lines) and lines[i] != delimiter:
                body.append(lines[i])
                i += 1
            i += 1
            found[name.strip()] = "\n".join(body)
            continue
        key, sep, value = line.partition("=")
        if sep:
            found[key.strip()] = value
    return found


class JobState:
    """What one job carries between its steps on a runner and nowhere else.

    $RUNNER_TEMP is a directory private to the job; $GITHUB_ENV and $GITHUB_PATH
    are how one step sets variables and PATH entries for the steps after it in
    the same job. None of the three existed here, so a step that wrote a binary
    to $RUNNER_TEMP and named it through $GITHUB_ENV crashed on the KeyError,
    and the steps that read the variable failed after it.
    """

    def __init__(self, scratch: str, label: str, root: pathlib.Path | None = None) -> None:
        self.root = root or REPO
        self.temp = pathlib.Path(scratch) / f"runner-temp-{label}"
        self.temp.mkdir(parents=True, exist_ok=True)
        self.env: dict[str, str] = {}
        self.path: list[str] = []
        # Set when a required binding or an unclassified action is unresolved;
        # every later step of the job is then NOT RUN with this reason.
        self.blocked = ""
        self.outputs: dict[str, dict[str, str]] = {}
        self.statuses: dict[str, dict[str, str]] = {}
        self.ran = 0
        self.failed = 0
        self.not_run: list[str] = []
        self.provider_probes: list[dict[str, Any]] = []
        self.repository = ""
        self.foreign: dict[str, dict[str, Any]] = {}

    def block_failed_python_setup(self, step: Step, reason: str) -> bool:
        """A failed interpreter binding blocks consumers, even when continued."""
        if step.uses.split("@", 1)[0] != "actions/setup-python":
            return False
        self.blocked = f"the job's interpreter was not provisioned: {reason}"
        return True

    def environment(self, base: dict[str, str]) -> dict[str, str]:
        project_env = str(self.root / ".venv")
        env = {
            **base,
            **self.env,
            "RUNNER_TEMP": str(self.temp),
            "GITHUB_WORKSPACE": str(self.root),
            "UV_PROJECT_ENVIRONMENT": project_env,
            "VIRTUAL_ENV": project_env,
            "UV_PYTHON": str(self.root / ".venv/bin/python"),
            "UV_LINK_MODE": "copy",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
        if self.path:
            env["PATH"] = os.pathsep.join([*reversed(self.path), env.get("PATH", "")])
        env["PATH"] = os.pathsep.join([str(self.root / ".venv/bin"), env.get("PATH", "")])
        return git_environment(base=env)

    def provision_baseline(self, evidence: pathlib.Path) -> None:
        """Isolate the actual local interpreter, including fallback pip installs."""
        retained = evidence / "baseline-python"
        retained.mkdir()
        command = [
            "uv",
            "venv",
            "--seed",
            "--python",
            sys.executable,
            str(self.root / ".venv"),
        ]
        with (retained / "stdout").open("wb") as stdout, (retained / "stderr").open("wb") as stderr:
            proc = subprocess.run(  # noqa: S603 -- seed only this job's baseline environment
                command,
                stdout=stdout,
                stderr=stderr,
                check=False,
                env={**os.environ, "UV_LINK_MODE": "copy", "PYTHONDONTWRITEBYTECODE": "1"},
            )
        write_json(
            retained / "result.json",
            {
                "command": command,
                "returncode": proc.returncode,
                "selected_local_python": sys.version,
                "hosted_provisioning": False,
            },
        )
        if proc.returncode:
            raise ValueError(
                "job-owned baseline Python could not be provisioned; see retained output"
            )
        self.path.append(str(self.root / ".venv/bin"))

    def absorb(self, env: dict[str, str]) -> None:
        """Carry what the step just wrote to $GITHUB_ENV and $GITHUB_PATH forward."""
        self.env.update(
            read_github_env(pathlib.Path(env["GITHUB_ENV"]).read_text(encoding="utf-8"))
        )
        for line in pathlib.Path(env["GITHUB_PATH"]).read_text(encoding="utf-8").splitlines():
            if line.strip():
                self.path.append(line.strip())


def record_outputs(step: Step, env: dict[str, str], outputs: dict[str, dict[str, str]]) -> None:
    """Keep what a step wrote to $GITHUB_OUTPUT, so a later step can read it."""
    if not step.ident:
        return
    written: dict[str, str] = {}
    for line in pathlib.Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            written[key.strip()] = value
    outputs[step.ident] = written


def run_step(
    run: str,
    env: dict[str, str],
    workdir: str = "",
    root: pathlib.Path | None = None,
    evidence: pathlib.Path | None = None,
) -> subprocess.CompletedProcess[str]:
    workspace = (root or REPO).resolve()
    directory = (workspace / workdir).resolve()
    if not directory.is_relative_to(workspace):
        raise ValueError("working-directory escapes the job checkout")
    if not directory.is_dir():
        raise ValueError(f"working-directory {workdir!r} does not exist in the job checkout")
    if evidence is not None:
        with (evidence / "stdout").open("wb") as stdout, (evidence / "stderr").open("wb") as stderr:
            proc = subprocess.run(  # noqa: S603 -- retained original workflow process bytes
                [SHELL, *SHELL_FLAGS, "-c", run],
                cwd=directory,
                env=env,
                stdout=stdout,
                stderr=stderr,
                check=False,
            )
        return subprocess.CompletedProcess(
            proc.args,
            proc.returncode,
            (evidence / "stdout").read_bytes().decode("utf-8", "replace"),
            (evidence / "stderr").read_bytes().decode("utf-8", "replace"),
        )
    return subprocess.run(  # noqa: S603 -- running the repo's own workflow steps is the point
        [SHELL, *SHELL_FLAGS, "-c", run],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
    )


PROVIDES: dict[str, tuple[str, ...]] = {
    "sigstore/cosign-installer": ("cosign",),
    "actions/setup-go": ("go", "gofmt"),
    "actions/setup-node": ("node", "npm", "npx"),
    "oven-sh/setup-bun": ("bun",),
    "astral-sh/setup-uv": ("uv", "uvx"),
}
CHECKOUT_BASE = "https://github.com"


def unclassified_action(step: Step) -> bool:
    """An unknown action can change every later command's unbound environment."""
    action = step.uses.split("@", 1)[0]
    return (
        step.run is None
        and action not in MIRRORED
        and action not in CANNOT_RUN
        and action not in PROVIDES
    )


def interpolate_inputs(step: Step, job: JobState, context: Mapping[str, str]) -> tuple[Step, str]:
    inputs = {}
    for key, raw in step.inputs.items():
        if isinstance(raw, str):
            raw, missing = expand(raw, job.outputs, job.statuses, context, f"its with:{key} reads")
            if missing:
                return step, missing
        inputs[key] = raw
    return step._replace(inputs=inputs), ""


def fetch_checkout(repository: str, ref: str, path: str, job: JobState) -> str:
    """Fetch selected foreign bytes inside the job; retain identity before disposal."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return "repository must be a concrete owner/name"
    target = (job.root / path).resolve()
    if target == job.root.resolve() or not target.is_relative_to(job.root.resolve()):
        return "checkout path must be a contained non-root job subdirectory"
    if target.exists():
        return "checkout destination already exists; it is not overwritten"
    target.mkdir(parents=True)
    url = f"{CHECKOUT_BASE}/{repository}.git"
    fetch_evidence = job.temp / "foreign-fetch" / str(len(job.foreign))
    problem = _fetch_into("git", url, ref, target, fetch_evidence)
    if problem:
        return problem
    landed = git(target, "rev-parse", "HEAD").decode().strip()
    if re.fullmatch(r"[0-9a-f]{40}", ref) and landed != ref:
        return f"fetch landed at {landed}, not the selected {ref}"
    path = str(target.relative_to(job.root.resolve()))
    job.foreign[path] = {
        "repository": repository,
        "requested_ref": ref or "HEAD",
        "origin": url,
        "head": landed,
        "tree": git(target, "rev-parse", "HEAD^{tree}").decode().strip(),
        "files": inventory(target),
    }
    return ""


def retain_foreign(job: JobState, evidence: pathlib.Path) -> None:
    """Retain selected and final foreign bytes, including added/deleted tracked files."""
    faults = []
    for path, selected in job.foreign.items():
        root = job.root / path
        destination = evidence / "foreign" / path
        destination.mkdir(parents=True)
        final = inventory(root)
        final_head = git(root, "rev-parse", "HEAD").decode().strip()
        write_json(
            destination / "identity.json",
            {"selected": selected, "final_files": final, "final_head": final_head},
        )
        (destination / "tracked.diff").write_bytes(git(root, "diff", "--binary", selected["head"]))
        for name in selected["files"]:
            original = git(root, "show", f"{selected['head']}:{name}")
            copy = destination / "selected" / name
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_bytes(original)
        retain_foreign_final(root, destination, final)
        if final_head != selected["head"]:
            faults.append(path)
    if faults:
        raise ValueError(f"foreign selected commits changed in {faults}; evidence retained")


def retain_foreign_final(
    root: pathlib.Path, destination: pathlib.Path, files: dict[str, dict[str, str]]
) -> None:
    for name, metadata in files.items():
        if metadata.get("state") == "missing":
            continue
        present = root / name
        data = os.fsencode(os.readlink(present)) if present.is_symlink() else present.read_bytes()
        copy = destination / "final" / name
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(data)


def _fetch_into(
    git_binary: str, url: str, ref: str, target: pathlib.Path, evidence: pathlib.Path
) -> str:
    """Fetch a selected foreign checkout and retain all auxiliary process bytes."""
    evidence.mkdir(parents=True)
    commands = (
        [git_binary, "init", "-q", str(target)],
        [git_binary, "-C", str(target), "fetch", "-q", "--depth", "1", url, ref or "HEAD"],
        [git_binary, "-C", str(target), "checkout", "-q", "--detach", "FETCH_HEAD"],
    )
    for index, command in enumerate(commands):
        try:
            proc = subprocess.run(  # noqa: S603 -- selected foreign checkout
                command, capture_output=True, check=False, timeout=900, env=git_environment()
            )
        except subprocess.TimeoutExpired as exc:
            (evidence / f"{index}.stdout.txt").write_bytes(exc.stdout or b"")
            (evidence / f"{index}.stderr.txt").write_bytes(exc.stderr or b"")
            write_json(evidence / f"{index}.json", {"command": command, "status": "TIMEOUT"})
            return "the selected checkout fetch timed out after 900 seconds"
        (evidence / f"{index}.stdout.txt").write_bytes(proc.stdout)
        (evidence / f"{index}.stderr.txt").write_bytes(proc.stderr)
        write_json(evidence / f"{index}.json", {"command": command, "returncode": proc.returncode})
        if proc.returncode:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            return f"fetching {url} at {ref or 'HEAD'} failed: {detail}"
    return ""


def report_failure(label: str, proc: subprocess.CompletedProcess[str]) -> None:
    print(f"  FAIL  {label}  (exit {proc.returncode})")
    for stream in (proc.stdout, proc.stderr):
        for line in (stream or "").splitlines():
            print(f"        {line}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print the plan and run nothing")
    ap.add_argument("--only", metavar="NAME", help="run one workflow, by file stem")
    ap.add_argument(
        "--branch-authority",
        type=pathlib.Path,
        help="use the source-bound primary metadata packet retained by the producer",
    )
    ap.add_argument(
        "--evidence-dir",
        type=pathlib.Path,
        help="retain job source, mutations and process bytes here",
    )
    args = ap.parse_args()

    if not WORKFLOWS.is_dir():
        sys.exit(f"workflow-steps-gate: {WORKFLOWS} does not exist.")

    files = sorted(p for p in WORKFLOWS.glob("*.yml") if not args.only or p.stem == args.only)
    if not files:
        sys.exit(
            f"workflow-steps-gate: no workflow matched {args.only!r}. "
            "An empty selection is a typo, not a pass."
        )

    if args.list:
        return plan(files)

    # One mirror at a time. This runs the repository's real workflow steps, some
    # of which are heavyweight parallel campaigns, so two mirrors do not finish
    # in the time of one -- they oversubscribe the machine and both crawl. The
    # lock is taken here rather than left to the individual steps so the refusal
    # arrives before any work starts, instead of partway through a long run.
    with single_instance("aee-workflow-steps-gate"):
        authority = (
            decode_json(args.branch_authority.read_bytes()) if args.branch_authority else None
        )
        return execute(files, args.evidence_dir, authority)


def plan(files: list[pathlib.Path]) -> int:
    planned = 0
    not_run: list[str] = []
    for path in files:
        doc = load_yaml(path)
        print(f"\n=== {path.name} ===")
        for step in steps_of(doc, path):
            if step.run is not None:
                planned += 1
                print(f"  PLAN  {step.label}")
                continue
            local = local_equivalent(step.uses, step.inputs)
            if local.run is not None:
                planned += 1
                print(f"  PLAN  {step.label}  (marketplace action, mirrored locally)")
            else:
                not_run.append(f"{step.label}  ({local.reason})")
                print(f"  NOT RUN  {step.label}  ({local.reason})")
    return summarise("planned", planned, 0, not_run)


def step_base_environment(ambient: Mapping[str, str]) -> dict[str, str]:
    """The environment every step starts from.

    The hook runs this gate through `uv run --with pyyaml ...`, which exports
    VIRTUAL_ENV naming a throwaway environment. Steps inherited it, so a
    workflow's `uv pip install --no-deps .` installed the package into that
    throwaway environment while every later `uv run` used the project one,
    which never received it. A runner sets no VIRTUAL_ENV at all; its `uv pip`
    finds the project's environment. So VIRTUAL_ENV here is the project
    environment the hook names in UV_PROJECT_ENVIRONMENT, or nothing.
    """
    base = {**ambient, "CI": "1", "GITHUB_ACTIONS": ""}
    base.pop("VIRTUAL_ENV", None)
    project_env = ambient.get("UV_PROJECT_ENVIRONMENT", "")
    if project_env:
        base["VIRTUAL_ENV"] = project_env
    return base


def retain_job(job: JobState, source: Source, evidence: pathlib.Path) -> None:
    """Preserve mutations and small native reports before deleting the checkout."""
    write_json(evidence / "provider-probes.json", job.provider_probes)
    final = inventory(job.root)
    final_tags = tags(job.root)
    write_json(
        evidence / "source-final.json",
        {
            "head": git(job.root, "rev-parse", "HEAD").decode().strip(),
            "tree": git(job.root, "rev-parse", "HEAD^{tree}").decode().strip(),
            "tags": final_tags,
            "branch_refs": frozen_refs(job.root),
            "files": final,
            "event_scope": local_context_scope(),
        },
    )
    (evidence / "tracked.diff").write_bytes(git(job.root, "diff", "--binary", source.head, "--"))
    (evidence / "status.raw").write_bytes(git(job.root, "status", "--porcelain", "-z"))
    retain_tracked_changes(job, source, evidence, final)
    retain_reports(job, evidence)
    retain_foreign(job, evidence)
    if (
        git(job.root, "rev-parse", "HEAD").decode().strip() != source.head
        or final_tags != source.tags
    ):
        raise ValueError("job changed its source commit or selected tag refs; evidence retained")
    source.verify()
    require_frozen_commit(job.root, source.authority)


def retain_tracked_changes(
    job: JobState,
    source: Source,
    evidence: pathlib.Path,
    final: dict[str, dict[str, str]],
) -> None:
    for relative in sorted(source.files.keys() | final.keys()):
        if source.files.get(relative) == final.get(relative):
            continue
        path = job.root / relative
        if relative in source.files:
            original = evidence / "original-tracked" / relative
            original.parent.mkdir(parents=True, exist_ok=True)
            original.write_bytes(git(source.root, "show", f"{source.head}:{relative}"))
        if path.is_file() or path.is_symlink():
            target = evidence / "changed-tracked" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(
                os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
            )


def retain_reports(job: JobState, evidence: pathlib.Path) -> None:
    for label, directory in (
        ("workspace", job.root / ".build"),
        ("runner-temp", job.temp),
        ("release", job.root / "release"),
    ):
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            relative = path.relative_to(directory)
            if (
                path.is_symlink()
                or not path.is_file()
                or any(
                    part
                    in {
                        "project-env",
                        "setup-python",
                        "baseline-python",
                        "provider-runtime",
                        "node_modules",
                        "target",
                        ".git",
                        "__pycache__",
                    }
                    for part in relative.parts
                )
            ):
                continue
            if path.suffix not in {
                ".json",
                ".jsonl",
                ".txt",
                ".log",
                ".md",
                ".csv",
                ".xml",
                ".ots",
                ".bak",
            }:
                continue
            target = evidence / "reports" / label / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
    retain_provider_archives(job, evidence)
    # Retain the original reports even if a declared public input later refuses.
    retain_timestamp_inputs(job, evidence)


def retain_provider_archives(job: JobState, evidence: pathlib.Path) -> None:
    """Retain only the checksum-bound official archives selected by this job."""
    for probe in job.provider_probes:
        if "actualSha256" not in probe:
            continue
        kind, wanted = probe["kind"], probe["wanted"]
        if kind not in {"go", "node", "bun"} or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", wanted):
            raise ValueError("provider archive has no bounded input identity")
        directory = probe["inputDirectory"]
        if not re.fullmatch(
            rf"provider-inputs/{kind}-{re.escape(wanted)}-[A-Za-z0-9_]+", directory
        ):
            raise ValueError("provider archive directory has no owned canonical identity")
        name = "archive.zip" if kind == "bun" else "archive.tar.gz"
        relative = pathlib.Path(directory) / name
        source = job.temp / relative
        if any(
            (job.temp / pathlib.Path(*relative.parts[:i])).is_symlink()
            for i in range(1, len(relative.parts) + 1)
        ):
            raise ValueError("provider archive input is a symbolic link")
        if (
            not source.is_file()
            or type(probe["archiveBytes"]) is not int
            or source.stat().st_size != probe["archiveBytes"]
            or provider_digest(source) != probe["actualSha256"]
        ):
            raise ValueError("provider archive differs from the actual selected download")
        target = evidence / "reports/runner-temp" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def retain_timestamp_inputs(job: JobState, evidence: pathlib.Path) -> None:
    """Keep only declared fixed public validation inputs, never arbitrary keys."""
    candidate = job.temp / "timestamp-candidate"
    manifest = candidate / "manifest.json"
    if candidate.is_symlink() or manifest.is_symlink():
        raise ValueError("timestamp capture manifest is a symbolic link")
    if not manifest.exists():
        return
    if not manifest.is_file():
        raise ValueError("timestamp capture manifest is not a regular file")
    report = decode_json(manifest.read_bytes())
    if (
        report["sourceCommit"] != git(job.root, "rev-parse", "HEAD").decode().strip()
        or report["sourceTree"] != git(job.root, "rev-parse", "HEAD^{tree}").decode().strip()
    ):
        raise ValueError("timestamp capture does not name the selected public source")
    members = {member["path"]: member for member in report["members"]}
    if len(members) != len(report["members"]):
        raise ValueError("timestamp capture repeats a member")
    for relative in (
        "release/CORPUS-DIGESTS.txt.sig",
        "release/CORPUS-DIGESTS.txt.sig.tsr",
        "spec/tsa-roots.pem",
    ):
        member = members[relative]
        if member["state"] not in {"present", "empty", "missing", "refused", "unreadable"}:
            raise ValueError("timestamp capture has an unknown member state")
        if member["state"] != "present":
            continue
        raw = timestamp_public_input(job, candidate, relative, member)
        target = evidence / "reports/runner-temp/timestamp-candidate" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def timestamp_public_input(
    job: JobState,
    candidate: pathlib.Path,
    relative: str,
    member: dict[str, Any],
) -> bytes:
    """Read only a fixed public member with no symbolic-link path component."""
    path = candidate
    for part in pathlib.PurePosixPath(relative).parts:
        path /= part
        if path.is_symlink():
            raise ValueError("declared timestamp input is a symbolic link")
    if not path.is_file():
        raise ValueError("declared timestamp input is not a regular file")
    raw = path.read_bytes()
    public = git(job.root, "show", f"HEAD:{relative}")
    if (
        raw != public
        or type(member["bytes"]) is not int
        or len(raw) != member["bytes"]
        or hashlib.sha256(raw).hexdigest() != member["sha256"]
    ):
        raise ValueError("declared timestamp input differs from its public source or manifest")
    return raw


def resolve_inputs(
    step: Step, job: JobState, context: Mapping[str, str]
) -> tuple[Step, str | None, str, bool]:
    action = step.uses.split("@", 1)[0]
    binds_job = (
        action in PROVIDES
        or action in ("actions/checkout", "actions/setup-python")
        or unclassified_action(step)
    )
    # A proven false setup condition needs no inputs or provider. An attempted
    # setup with unresolved inputs cannot leave consumers on ambient tools.
    excluded = event_excludes(step.condition) if binds_job else ""
    if excluded:
        return step, None, excluded, False
    # Remote-only inputs cannot affect a command this mirror never runs.
    # Checkout and providers still need their local source/tool bindings.
    if (
        step.run is None
        and action in CANNOT_RUN
        and action not in PROVIDES
        and action != "actions/checkout"
    ):
        return step, *resolve_in_job(step, job)
    selected, problem = interpolate_inputs(step, job, context)
    if problem:
        if binds_job:
            job.blocked = problem
        return selected, None, problem, True
    block, suffix, fault = resolve_in_job(selected, job)
    return selected, block, suffix, fault


def local_context_scope() -> dict[str, Any]:
    """A declared local simulation, distinct from an observed hosted event."""
    return {
        "event_name": LOCAL_EVENT,
        "event_origin": "declared_local_push_simulation",
        "hosted_event_verified": False,
    }


def job_context(steps: list[Step], job: JobState, source: Source) -> dict[str, str]:
    context = {
        **source.context(job.temp),
        "github.workspace": str(job.root),
        "github.event_name": LOCAL_EVENT,
        "runner.os": {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}.get(
            sys.platform, sys.platform
        ),
        **{f"matrix.{k}": v for k, v in steps[0].matrix.items()},
    }
    if steps[0].unexpanded:
        job.blocked = steps[0].unexpanded
        job.failed += 1
    return context


def execute_job(
    steps: list[Step],
    job: JobState,
    source: Source,
    evidence: pathlib.Path,
    base: dict[str, str],
) -> None:
    context = job_context(steps, job, source)
    for step in steps:
        require_frozen_commit(job.root, source.authority)
        retained = evidence / "steps" / str(step.position)
        retained.mkdir(parents=True)
        write_json(
            retained / "input.json",
            {"uses": step.uses, "with": step.inputs, "if": step.condition},
        )
        failed_before_resolution = job.failed
        step, block, suffix, fault = resolve_inputs(step, job, context)
        env: dict[str, str] = {}
        directory = ""
        if block is not None:
            env, missing = step_environment(step, job.outputs, str(job.temp), job.statuses, context)
            block, unresolved = expand(block, job.outputs, job.statuses, context)
            directory, missing_directory = expand(step.workdir, job.outputs, job.statuses, context)
            missing = missing or unresolved or missing_directory
            if missing:
                block, suffix, fault = None, missing, True
        if block is None:
            job.failed += int(fault and job.failed == failed_before_resolution)
            job.not_run.append(f"{step.label}  ({suffix})")
            write_json(
                retained / "result.json",
                {"label": step.label, "status": "NOT_RUN", "reason": suffix, "fault": fault},
            )
            print(f"  NOT RUN  {step.label}  ({suffix})")
            continue
        print(f"  RUN   {step.label}{suffix}")
        (retained / "command.sh").write_text(block, encoding="utf-8")
        try:
            proc = run_step(
                block,
                {**job.environment(base), **env},
                directory if step.run is not None else "",
                job.root,
                retained,
            )
        except (OSError, ValueError) as exc:
            job.failed += 1
            job.block_failed_python_setup(step, str(exc))
            write_json(
                retained / "result.json",
                {"label": step.label, "status": "NOT_RUN", "reason": str(exc), "fault": True},
            )
            job.not_run.append(f"{step.label}  ({exc})")
            print(f"  NOT RUN  {step.label}  ({exc})")
            continue
        job.ran += 1
        provision_fault = proc.returncode != 0 and job.block_failed_python_setup(
            step, f"actions/setup-python exited {proc.returncode}"
        )
        job.failed += int(proc.returncode != 0 and (provision_fault or not step.continue_on_error))
        outcome = "success" if proc.returncode == 0 else "failure"
        write_json(
            retained / "result.json",
            {
                "label": step.label,
                "status": "EXECUTED",
                "returncode": proc.returncode,
                "continue_on_error": step.continue_on_error,
                "stdout_sha256": hashlib.sha256((retained / "stdout").read_bytes()).hexdigest(),
                "stderr_sha256": hashlib.sha256((retained / "stderr").read_bytes()).hexdigest(),
            },
        )
        if proc.returncode != 0 and step.continue_on_error and not provision_fault:
            print(f"  FAILED, continue-on-error  {step.label}  (exit {proc.returncode})")
        elif proc.returncode != 0:
            report_failure(step.label, proc)
        for key in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_ENV", "GITHUB_PATH"):
            (retained / key).write_bytes(pathlib.Path(env[key]).read_bytes())
        record_outputs(step, env, job.outputs)
        job.absorb(env)
        if step.ident:
            job.statuses[step.ident] = {
                "outcome": outcome,
                "conclusion": "success" if step.continue_on_error else outcome,
            }


def execute_owned_job(
    source: Source,
    scratch: str,
    label: str,
    steps: list[Step],
    evidence: pathlib.Path,
    base: dict[str, str],
) -> tuple[int, int, list[str]]:
    """Run and retain one independent job even when another job failed."""
    retained = evidence / label
    retained.mkdir()
    root = pathlib.Path(scratch) / label / "checkout"
    setup_start = time.monotonic()
    source.checkout(root)
    setup_seconds = time.monotonic() - setup_start
    job = JobState(scratch, label, root)
    job.repository = source.repository
    git_bytes = sum(p.stat().st_size for p in (root / ".git").rglob("*") if p.is_file())
    print(
        f"JOB_SOURCE {label} HEAD {source.head} TREE {source.tree} FILES {len(source.files)} "
        f"TAGS {len(source.tags)} GIT_BYTES {git_bytes} CHECKOUT_SECONDS {setup_seconds:.6f}"
    )
    write_json(
        retained / "source-initial.json",
        {
            "head": source.head,
            "tree": source.tree,
            "tags": tags(root),
            "branch_authority": source.branch_authority,
            "files": inventory(root),
            "event_scope": local_context_scope(),
            "checkout_seconds": setup_seconds,
            "git_directory_bytes": git_bytes,
        },
    )
    try:
        job.provision_baseline(retained)
        execute_job(steps, job, source, retained, base)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        job.failed += 1
        print(f"FAULT: {label}: {exc}")
        write_json(retained / "fault.json", {"reason": str(exc)})
        for step in steps:
            if not (retained / "steps" / str(step.position) / "result.json").exists():
                stopped = f"{step.label}  (job stopped: {exc})"
                job.not_run.append(stopped)
    finally:
        try:
            retain_job(job, source, retained)
        except (OSError, ValueError, subprocess.CalledProcessError) as exc:
            job.failed += 1
            print(f"FAULT: {label}: {exc}")
            write_json(retained / "retention-fault.json", {"reason": str(exc)})
        shutil.rmtree(root.parent)
        shutil.rmtree(job.temp)
    source.verify()
    return job.ran, job.failed, job.not_run


def execute(
    files: list[pathlib.Path],
    evidence_dir: pathlib.Path | None = None,
    branch_authority: dict[str, Any] | None = None,
) -> int:
    ran = failed = 0
    not_run: list[str] = []
    base = step_base_environment(os.environ)
    evidence = (
        evidence_dir or pathlib.Path(tempfile.mkdtemp(prefix="aee-workflow-evidence-"))
    ).resolve()
    if evidence.is_relative_to(REPO.resolve()):
        print("FAULT: evidence-dir must be outside the input checkout")
        return 1
    evidence.mkdir(parents=True, exist_ok=True)
    if any(evidence.iterdir()):
        print("FAULT: evidence-dir must be empty; existing evidence will not be overwritten")
        return 1
    print(f"Evidence retained at {evidence}")
    try:
        packet = (
            capture_authority(REPO, evidence / "branch-authority")
            if branch_authority is None
            else branch_authority
        )
        source = Source(REPO, packet)
        print("CONTEXT_SCOPE declared_local_push_simulation event=push hosted_event_verified=false")
        write_json(
            evidence / "source-input.json",
            {
                "head": source.head,
                "tree": source.tree,
                "tags": source.tags,
                "files": source.files,
                "input_files": source.input_files,
                "branch_authority": source.branch_authority,
                "event": LOCAL_EVENT,
                "event_scope": local_context_scope(),
            },
        )
        with tempfile.TemporaryDirectory(prefix="aee-workflow-steps-") as scratch:
            ordinal = 0
            for path in files:
                relative = path.resolve().relative_to(source.root)
                if str(relative) not in source.files:
                    raise ValueError("workflow must be a tracked file of the selected source")
                doc = load_yaml(path)
                print(f"\n=== {path.name} ===")
                selected_tags = git(source.root, "tag", "--points-at", source.head).decode().split()
                excluded = trigger_excludes(doc, selected_tags)
                grouped: dict[str, list[Step]] = {}
                for step in steps_of(doc, path):
                    if excluded:
                        reason = f"{step.label}  ({excluded})"
                        not_run.append(reason)
                        skipped = (
                            evidence
                            / "trigger-excluded"
                            / path.stem
                            / re.sub(r"[^A-Za-z0-9_.-]", "_", step.job)
                        )
                        skipped.mkdir(parents=True, exist_ok=True)
                        write_json(
                            skipped / f"{step.position}.json",
                            {
                                "label": step.label,
                                "status": "NOT_RUN",
                                "reason": excluded,
                                "fault": False,
                            },
                        )
                        print(f"  NOT RUN  {reason}")
                    else:
                        grouped.setdefault(step.job, []).append(step)
                for job_name, steps in grouped.items():
                    ordinal += 1
                    label = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{ordinal:03d}-{path.stem}-{job_name}")
                    count, faults, missing = execute_owned_job(
                        source,
                        scratch,
                        label,
                        steps,
                        evidence,
                        base,
                    )
                    ran += count
                    failed += faults
                    not_run.extend(missing)
        source.verify()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        failed += 1
        print(f"FAULT: {exc}")
        write_json(evidence / "fault.json", {"reason": str(exc)})
    write_json(evidence / "result.json", {"ran": ran, "failed": failed, "not_run": not_run})
    return summarise("ran", ran, failed, not_run)


def resolve_in_job(step: Step, job: JobState) -> tuple[str | None, str, bool]:
    """Resolve only this job's source, inputs and actual toolchain capabilities."""
    if job.blocked:
        return None, job.blocked, False
    action = step.uses.split("@", 1)[0]
    foreign = str(step.inputs.get("repository") or "") if action == "actions/checkout" else ""
    if action == "actions/checkout" and not event_excludes(step.condition):
        if not foreign or foreign == job.repository:
            problem = self_checkout_problem(step, job)
            if problem:
                job.blocked = problem
                return None, problem, True
        else:
            ref, where = str(step.inputs.get("ref", "")), str(step.inputs.get("path") or ".")
            problem = fetch_checkout(foreign, ref, where, job)
            if problem:
                job.blocked = problem
                return None, problem, True
            return ":", f"  (checked out {foreign} at {ref or 'HEAD'} into {where})", False
    block, suffix, fault = resolve(step)
    if fault and unclassified_action(step):
        job.blocked = f"the job has an unclassified action with unbound effects: {suffix}"
        return None, job.blocked, True
    if block is None and action == "actions/setup-python" and not event_excludes(step.condition):
        job.blocked = f"the job's interpreter was not provisioned: {suffix}"
    if block is None and action in PROVIDES and not event_excludes(step.condition):
        job.blocked = provider_problem(step, job)
        fault = fault or bool(job.blocked)
        if not job.blocked and action == "oven-sh/setup-bun":
            block = ":"
            suffix = "  (declared native Bun runtime bound; hosted action not executed)"
            return block, suffix, fault
        suffix = job.blocked or (
            f"{action} hosted action is not run here; declared native tools are bound, "
            "with original capability probes retained"
        )
    return block, suffix, fault


def self_checkout_problem(step: Step, job: JobState) -> str:
    if str(step.inputs.get("path") or ".") != ".":
        return "self checkout into another path is not mirrored by the job root"
    ref = str(step.inputs.get("ref", ""))
    if not ref:
        return ""
    try:
        target = git(job.root, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    except subprocess.CalledProcessError:
        target = ""
    selected = git(job.root, "rev-parse", "HEAD").decode().strip()
    return "" if target == selected else "checkout ref does not select the frozen source commit"


def provider_problem(step: Step, job: JobState) -> str:
    """Bind declared tools before dependent shells; required setup failures fail the gate."""
    action = step.uses.split("@", 1)[0]
    env = job.environment(step_base_environment(os.environ))
    tools = {tool: shutil.which(tool, path=env.get("PATH")) for tool in PROVIDES[action]}
    probe: dict[str, Any] = {
        "action": action,
        "uses": step.uses,
        "tools": tools,
        "hosted_provisioning": False,
    }
    job.provider_probes.append(probe)
    selector = {
        "actions/setup-node": ("node-version", "node"),
        "actions/setup-go": ("go-version", "go"),
        "oven-sh/setup-bun": ("bun-version", "bun"),
    }.get(action)
    if selector is None:
        if not all(tools.values()):
            job.failed += 1
            return f"{action} supplies tools not installed here: {tools}; no dependent shell ran"
        return ""
    wanted = str(step.inputs.get(selector[0], ""))
    try:
        if action == "actions/setup-go":
            if step.uses != f"actions/setup-go@{SETUP_GO_REVISION}":
                raise ValueError("native setup-go binding requires the captured action revision")
            probe["selector_contract_revision"] = SETUP_GO_REVISION
            wanted = go_selector(step.inputs, job.root, probe)
        if selector[1] != "bun":
            wanted = wanted.removesuffix(".x")
        if action == "oven-sh/setup-bun" and set(step.inputs) != {"bun-version"}:
            raise ValueError("native Bun binding supports only an explicit bun-version input")
        binary, goroot = ensure_provider(selector[1], wanted, env, job.temp, probe)
        if binary is not None:
            job.path.append(str(binary))
        if goroot is not None:
            job.env["GOROOT"] = str(goroot)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        job.failed += 1
        probe["failure"] = str(exc)
        return f"{action} could not bind version {wanted!r}: {exc}; no dependent shell ran"
    return ""


# The event a local run stands for. The pre-push hook mirrors a push, so a step
# guarded to another event would not run on the remote for this push either.
LOCAL_EVENT = "push"
EVENT_TEST = re.compile(
    r"^\s*(?:\$\{\{\s*)?github\.event_name\s*(==|!=)\s*'([a-z_]+)'\s*(?:\}\})?\s*$"
)


def event_excludes(condition: str) -> str:
    """The reason a step's `if:` is false for a push, or "" when it is not.

    Only a bare comparison of github.event_name is decided here. Any other
    expression is left to run as before, because deciding it wrongly would turn
    a step the remote runs into one this gate silently skips.
    """
    match = EVENT_TEST.match(condition)
    if not match:
        return ""
    operator, event = match.groups()
    holds = (LOCAL_EVENT == event) if operator == "==" else (LOCAL_EVENT != event)
    if holds:
        return ""
    return f"its condition `{condition.strip()}` is false for a {LOCAL_EVENT}"


def resolve(step: Step) -> tuple[str | None, str, bool]:
    """(shell to run, the parenthetical or reason, whether it is a fault)."""
    excluded = event_excludes(step.condition)
    if excluded:
        return None, excluded, False
    if step.run is not None:
        return step.run, "", False
    local = local_equivalent(step.uses, step.inputs)
    if local.run is not None:
        return local.run, "  (marketplace action, mirrored locally)", False
    return None, local.reason, local.fault


def summarise(verb: str, count: int, failed: int, not_run: list[str]) -> int:
    print(f"\n{verb} {count} steps, {failed} failed, {len(not_run)} not run here")
    if not_run:
        print("\nNOT RUN by this gate, each with the reason:")
        for line in not_run:
            print(f"  {line}")
        print(
            "\nThis run says nothing about the steps above. A push is therefore not\n"
            "finished when this gate passes: it is finished when the remote run for\n"
            "the pushed commit has CONCLUDED. Watch it, do not assume it:\n"
            '    gh run list --commit "$(git rev-parse HEAD)"\n'
            "    gh run watch <run-id>"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
