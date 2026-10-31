"""Start a target module after an actual private fresh-cache interpreter boundary.

Execute this file as a source script. Importing a library through an arbitrary
interpreter leaves that interpreter and its existing imports with the caller.
"""

import argparse
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

PROBE = """
import json, os, pathlib, runpy, stat, sys
prefix, record, kind, target = sys.argv[1:5]
directory = pathlib.Path(prefix)
info = directory.lstat()
targets = ('authority_effect', 'probity_verify', 'agent_evidence_vectors')
preloaded = [name for name in sys.modules if name.split('.')[0] in targets]
if (not sys.flags.isolated or not sys.dont_write_bytecode
        or sys.pycache_prefix != prefix or preloaded
        or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.geteuid() or any(directory.iterdir())):
    raise RuntimeError('fresh private cache profile not established before target import')
profile = {'schema':'probity.fresh-import-profile/v1', 'beforeTargetImport':True,
           'isolated':bool(sys.flags.isolated), 'dontWriteBytecode':sys.dont_write_bytecode,
           'actualPycachePrefix':sys.pycache_prefix, 'privateEmptyPrefix':True,
           'preloadedTargets':preloaded, 'selectedTarget':target, 'targetKind':kind, 'imports':{}}
if record:
    with pathlib.Path(record).open('x') as output:
        json.dump(profile, output, indent=2)
        output.write('\\n')
sys.argv = [target, *sys.argv[5:]]
try:
    if kind == 'module':
        runpy.run_module(target, run_name='__main__', alter_sys=True)
    elif kind == 'script':
        runpy.run_path(target, run_name='__main__')
    else:
        raise RuntimeError('unsupported target kind')
finally:
    for name, value in tuple(sys.modules.items()):
        if name.split('.')[0] in targets:
            cached = getattr(value, '__cached__', None)
            if cached is not None and not pathlib.Path(cached).is_relative_to(directory):
                raise RuntimeError('target cache location escaped selected fresh prefix')
            profile['imports'][name] = {'source':getattr(value, '__file__', None), 'cached':cached}
    profile['prefixStillEmpty'] = not any(directory.iterdir())
    if record:
        pathlib.Path(record).write_text(json.dumps(profile, indent=2) + '\\n')
"""


def command(module: str, *, record: Path | None = None) -> list[str]:
    """Return a source-script route that creates a new prefix for each child."""
    argv = [sys.executable, "-I", str(Path(__file__).resolve()), "--module", module]
    if record is not None:
        argv.extend(["--cache-record", str(record.resolve())])
    return [*argv, "--"]


def _prefix_profile(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.geteuid()
        or any(path.iterdir())
    ):
        raise RuntimeError("cache prefix must be new, empty and private")


def main() -> int:
    """Preserve the target's streams and exit while recording its import profile."""
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--module")
    target.add_argument("--script", type=Path)
    parser.add_argument("--cache-record", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    with tempfile.TemporaryDirectory(prefix="authority-effect-import-") as temporary:
        prefix = Path(temporary)
        _prefix_profile(prefix)
        argv = [
            sys.executable,
            "-I",
            "-B",
            "-X",
            "pycache_prefix=" + str(prefix),
            "-c",
            PROBE,
            str(prefix),
            str(args.cache_record) if args.cache_record else "",
            "module" if args.module else "script",
            args.module or str(args.script.resolve()),
            *arguments,
        ]
        result = subprocess.run(argv, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
