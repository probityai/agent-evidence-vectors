"""Explicit source inputs and members of the portable DSSE npm artifact."""
import hashlib
import json
from pathlib import PurePosixPath

GENERATED = {'dsse.js', 'dsse.d.ts', 'dsse_bg.wasm', 'dsse_bg.wasm.d.ts'}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_identity(root):
    names = [
        'Cargo.toml', 'Cargo.lock', 'LICENSE', 'PROVENANCE.md',
        'examples/wasm_oracle.rs', 'docs/NPM.md',
        'vectors/cross_lang_signing.json', 'tests/spec_vector.rs',
        'interop/sigstore-js-threshold-2026-10-04/cases.json',
        # The workflows that qualify and publish the package live at the
        # repository root, two levels above the crate.
        '../../.github/workflows/crate-dsse-npm.yml',
        '../../.github/workflows/release.yml',
    ]
    paths = [root / name for name in names]
    paths += sorted((root / 'src').rglob('*.rs'))
    paths += sorted((root / 'tests').glob('*.rs'))
    paths += [root / 'npm' / name for name in [
        'package.json', 'package-lock.json', 'README.md', 'artifact.py',
        'build.py', 'check_release.py', 'wasm/Cargo.toml', 'wasm/Cargo.lock',
    ]]
    for directory in ['lib', 'test', 'wasm/src']:
        paths += sorted(p for p in (root / 'npm' / directory).rglob('*')
                        if p.is_file() and p.suffix in {'.rs', '.py', '.mjs', '.ts', '.json'})
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError('Source population contains a missing file or symlink.')
    hashes = {str(p.relative_to(root)): sha256(p.read_bytes()) for p in sorted(set(paths))}
    identity = sha256(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode())
    return hashes, identity


def published_manifest(root):
    manifest = json.loads((root / 'npm/package.json').read_text())
    manifest.pop('scripts', None)
    manifest.pop('devDependencies', None)
    return manifest


def published_manifest_bytes(root):
    return (json.dumps(published_manifest(root), indent=2) + '\n').encode()


def copied_files(root):
    files = {str(p.relative_to(root / 'npm')): p
             for p in (root / 'npm/lib').rglob('*') if p.is_file()}
    files['README.md'] = root / 'npm/README.md'
    files['LICENSE'] = root / 'LICENSE'
    return files


def artifact_population(root):
    return set(copied_files(root)) | {'package.json'} | {'generated/' + name for name in GENERATED}


def member_path(name):
    if '\\' in name or not name.startswith('package/'):
        raise ValueError('Packed names must use the package/ POSIX prefix.')
    relative = name[len('package/'):]
    path = PurePosixPath(relative)
    if not relative or path.is_absolute() or '..' in path.parts or str(path) != relative:
        raise ValueError('Packed member name is not canonical.')
    return relative
