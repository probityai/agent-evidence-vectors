#!/usr/bin/env python3
"""Tests for check-jcs-admit-python-release.py: a good file set passes, each fault is refused."""
import importlib.util
import io
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check", HERE / "check-jcs-admit-python-release.py")
if spec is None or spec.loader is None:
    raise ImportError("cannot load check-jcs-admit-python-release.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

# The binding's own pyproject.toml is written to a temporary file, so the test
# does not depend on the crate's directory being present.
PV = "0.1.0"
_PYPROJECT_DIR = tempfile.mkdtemp()
PYPROJECT = Path(_PYPROJECT_DIR, "pyproject.toml")
PYPROJECT.write_text(f'[project]\nname = "jcs-admit"\nversion = "{PV}"\n')
STEM = f"jcs_admit-{PV}"
WHEELS = [
    "manylinux_2_28_x86_64", "manylinux_2_28_aarch64", "musllinux_1_2_x86_64",
    "musllinux_1_2_aarch64", "macosx_10_12_x86_64", "macosx_11_0_arm64", "win_amd64",
]


def meta(name, version):
    return f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"


def wheel(path, name, version):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{name.replace('-', '_')}-{version}.dist-info/METADATA", meta(name, version))


def sdist(path, name, version):
    data = meta(name, version).encode()
    with tarfile.open(path, "w:gz") as t:
        info = tarfile.TarInfo(f"{name.replace('-', '_')}-{version}/PKG-INFO")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))


def build(dist):
    for tag in WHEELS:
        wheel(dist / f"{STEM}-cp310-abi3-{tag}.whl", "jcs-admit", PV)
    sdist(dist / f"{STEM}.tar.gz", "jcs-admit", PV)


def run(dist, tag, out):
    try:
        check.main([str(dist), "--tag", tag, "--out", str(out), "--pyproject", str(PYPROJECT)])
    except SystemExit as exit_:
        return str(exit_)
    return None


def case(label, mutate, tag=f"jcs-admit-py-v{PV}", expect=None):
    with tempfile.TemporaryDirectory() as tmp:
        dist, out = Path(tmp, "dist"), Path(tmp, "out")
        dist.mkdir()
        build(dist)
        mutate(dist)
        err = run(dist, tag, out)
        ok = (err is None) if expect is None else (err is not None and expect in err)
        print(("ok   " if ok else "FAIL ") + label + ("" if ok else f": {err}"))
        return ok


def main():
    results = [
        case("a complete set passes", lambda d: None),
        case("a wrong tag is refused", lambda d: None, tag="jcs-admit-py-v9.9.9", expect="is not jcs-admit-py-v"),
        case("a missing wheel is refused", lambda d: next(d.glob("*win_amd64.whl")).unlink(), expect="win_amd64"),
        case("an extra file is refused", lambda d: (d / "stray.txt").write_text("x"), expect="extra"),
        case("a wrong version inside a wheel is refused",
             lambda d: wheel(next(d.glob("*musllinux_1_2_x86_64.whl")), "jcs-admit", "0.0.1"), expect="Version"),
        case("a wrong name inside the sdist is refused",
             lambda d: sdist(d / f"{STEM}.tar.gz", "probityai", PV), expect="Name"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        dist, out = Path(tmp, "dist"), Path(tmp, "out")
        dist.mkdir()
        build(dist)
        err = run(dist, f"jcs-admit-py-v{PV}", out)
        staged = sorted(p.name for p in out.iterdir())
        ok = err is None and len(staged) == len(WHEELS) + 1
        print(("ok   " if ok else "FAIL ") + f"the upload directory holds the seven wheels and the sdist {staged}")
        results.append(ok)
    results.append(case("the old py-v tag form is refused", lambda d: None, tag=f"py-v{PV}",
                        expect="is not jcs-admit-py-v"))
    sys.exit(0 if all(results) else 1)


main()
