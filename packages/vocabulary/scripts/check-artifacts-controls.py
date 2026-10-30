"""Prove that owned artifact bytes and metadata are checked, including under -O."""

import argparse
import base64
import copy
import csv
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from zipfile import ZipFile


def run(wheel, sdist, source_root):
    scripts = Path(__file__).resolve().parent
    checker = scripts / ("check-distribution.py" if (scripts / "check-distribution.py").exists() else "check-artifacts.py")
    with ZipFile(wheel) as archive:
        entries = {item.filename: (item, archive.read(item)) for item in archive.infolist()}
    metadata = next(name for name in entries if name.endswith(".dist-info/METADATA"))
    info = metadata.rsplit("/", 1)[0]
    record = info + "/RECORD"
    resource = next(name for name in entries if name.endswith(("vocabulary.yaml", "samples/source.html"))
                    or name == "probity_observer/cli.py")
    license_file = next(name for name in entries if name.startswith(info + "/licenses/"))
    points = info + "/entry_points.txt"
    point_bytes = entries[points][1].replace(b":main", b":wrong", 1) if points in entries else b"[console_scripts]\nunowned = unowned:main\n"
    cases = {
        "missing-resource": {resource: None},
        "changed-resource": {resource: entries[resource][1] + b"changed"},
        "stale-version": {metadata: entries[metadata][1].replace(b"\nVersion: ", b"\nVersion: 999", 1)},
        "bad-record": {record: entries[record][1] + b"unowned,sha256=bad,1\n"},
        "extra-dist-info": {info + "/unowned.txt": b"not a declared artifact member"},
        "changed-license": {license_file: b"different grant"},
        "wrong-wheel-tag": {info + "/WHEEL": entries[info + "/WHEEL"][1].replace(b"py3-none-any", b"cp312-none-any")},
        "undeclared-dependency": {metadata: entries[metadata][1].replace(b"\n\n", b"\nRequires-Dist: unowned-package==1\n\n", 1)},
        "undeclared-metadata": {metadata: entries[metadata][1].replace(b"\n\n", b"\nUnowned-Field: value\n\n", 1)},
        "reordered-classifier": {metadata: entries[metadata][1].replace(b"Classifier: Development Status :: 3 - Alpha\n", b"", 1).replace(b"Classifier: Topic :: Security\n", b"Classifier: Topic :: Security\nClassifier: Development Status :: 3 - Alpha\n", 1)},
        "undeclared-classifier": {metadata: entries[metadata][1].replace(b"Classifier: Topic :: Security\n", b"Classifier: Topic :: Security\nClassifier: Framework :: Unowned\n", 1)},
        "wrong-dynamic-field": {metadata: entries[metadata][1].replace(b"Dynamic: license-file", b"Dynamic: version")},
        "changed-entry-points": {points: point_bytes},
        "escaped-wheel-path": {"../unowned.txt": b"outside"},
    }
    for name in entries:
        if name.startswith(info + "/licenses/"):
            cases["changed-grant-" + name.rsplit("/", 1)[1]] = {name: b"different grant"}
    with tarfile.open(sdist) as archive:
        source_entries = [(copy.copy(item), archive.extractfile(item).read() if item.isfile() else None)
                          for item in archive]
    prefix = source_entries[0][0].name.split("/", 1)[0]
    authored = next(item.name for item, _ in source_entries if item.name.endswith("/pyproject.toml"))
    egg_info = next(item.name.rsplit("/", 1)[0] for item, _ in source_entries if item.name.endswith(".egg-info/SOURCES.txt"))
    source_cases = {
        "missing-authored-source": ("remove", authored),
        "changed-authored-source": ("change", authored),
        "extra-source-file": ("add", prefix + "/unowned.txt"),
        "extra-egg-info": ("add", egg_info + "/unowned.txt"),
        "noncanonical-source-path": ("rename", authored),
        "wrong-source-root": ("root", authored),
        "source-symlink": ("symlink", authored),
        "duplicate-source-member": ("duplicate", authored),
        "extra-source-directory": ("directory", prefix + "/unowned"),
        "changed-generated-config": ("change", prefix + "/setup.cfg"),
        "changed-source-metadata": ("change", prefix + "/PKG-INFO"),
        "changed-source-inventory": ("change", egg_info + "/SOURCES.txt"),
        "changed-dependency-links": ("change", egg_info + "/dependency_links.txt"),
        "changed-source-top-level": ("change", egg_info + "/top_level.txt"),
    }
    for suffix in ["requires.txt", "entry_points.txt"]:
        name = egg_info + "/" + suffix
        if any(item.name == name for item, _ in source_entries):
            source_cases["changed-source-" + suffix] = ("change", name)
    with tempfile.TemporaryDirectory(prefix="distribution-refusals-") as directory:
        root = Path(directory)
        for optimized in [False, True]:
            command = [sys.executable, *( ["-O"] if optimized else []), str(checker)]
            def expect(label, candidate_wheel, candidate_source, accepted=False,
                       command=command, optimized=optimized):
                argv = command + [str(candidate_wheel), str(candidate_source)]
                if source_root is not None:
                    argv += ["--source-root", str(source_root)]
                result = subprocess.run(argv, capture_output=True, check=False)
                expected = 0 if accepted else 1
                if result.returncode != expected:
                    raise ValueError(f"{label}: expected {expected}, got {result.returncode}\n" + result.stdout.decode() + result.stderr.decode())
                print(f"{label}: {'accepted' if accepted else 'refused'}; optimized={optimized}")
            expect("original-artifacts", wheel, sdist, accepted=True)
            for label, changes in cases.items():
                payload = {name: value for name, (_, value) in entries.items()}
                for name, value in changes.items():
                    if value is None:
                        payload.pop(name)
                    else:
                        payload[name] = value
                if label != "bad-record":
                    rows = []
                    for name, value in payload.items():
                        digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
                        rows.append([name, "sha256=" + digest, str(len(value))] if name != record else [name, "", ""])
                    output = io.StringIO(newline="")
                    csv.writer(output, lineterminator="\n").writerows(rows)
                    payload[record] = output.getvalue().encode()
                damaged = root / (label + ".whl")
                with ZipFile(damaged, "w") as archive:
                    for name, value in payload.items():
                        archive.writestr(entries[name][0] if name in entries else name, value)
                expect(label, damaged, sdist)
            for label, (operation, target) in source_cases.items():
                damaged = root / (label + ".tar.gz")
                with tarfile.open(damaged, "w:gz") as archive:
                    for original, original_raw in source_entries:
                        member, raw = copy.copy(original), original_raw
                        if member.name == target:
                            if operation == "remove":
                                continue
                            if operation == "change":
                                raw += b"\nunowned-change\n"
                                member.size = len(raw)
                            if operation == "rename":
                                member.name = prefix + "/./" + member.name[len(prefix) + 1:]
                            if operation == "root":
                                member.name = "other/" + member.name[len(prefix) + 1:]
                            if operation == "symlink":
                                member.type, member.linkname, member.size, raw = tarfile.SYMTYPE, "unowned", 0, None
                        archive.addfile(member, io.BytesIO(raw) if raw is not None else None)
                        if original.name == target and operation == "duplicate":
                            archive.addfile(copy.copy(original), io.BytesIO(original_raw))
                    if operation in {"add", "directory"}:
                        member = tarfile.TarInfo(target)
                        raw = b"not a declared source member"
                        if operation == "directory":
                            member.type, member.mode, member.size = tarfile.DIRTYPE, 0o755, 0
                            archive.addfile(member)
                        else:
                            member.size = len(raw)
                            archive.addfile(member, io.BytesIO(raw))
                expect(label, wheel, damaged)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args()
    run(args.wheel.resolve(), args.sdist.resolve(), args.source_root)
