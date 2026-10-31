"""Shared, explicit source and output populations for the npm artifact."""
import hashlib
import json
from pathlib import PurePosixPath

GENERATED = {'jcs_admit.js', 'jcs_admit.d.ts', 'jcs_admit_bg.wasm', 'jcs_admit_bg.wasm.d.ts'}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_identity(root):
    paths = [root/name for name in ['Cargo.toml', 'Cargo.lock', 'LICENSE-MIT', 'LICENSE-APACHE']]
    paths += sorted((root/'src').rglob('*.rs'))
    paths += [root/'npm'/name for name in ['package.json', 'README.md', 'artifact.py', 'build.py', 'check_release.py', 'wasm/Cargo.toml', 'wasm/Cargo.lock']]
    paths += sorted(p for p in (root/'npm/lib').rglob('*') if p.is_file())
    paths += sorted((root/'npm/wasm/src').rglob('*.rs'))
    # The release validator reads these exact qualification inputs. Keep their
    # population in the same source identity as the validator and generator.
    # The qualification workflow lives at the repository root, two levels up.
    paths += [root/'npm/test/cases.mjs', root/'../../.github/workflows/crate-jcs-admit-npm.yml']
    for directory in ['rfc8785/input', 'rfc8785/output', 'cross-rail/input', 'cross-rail/canonical']:
        paths += sorted((root/'tests/vectors'/directory).glob('*.json'))
    paths += [root/'tests/vectors'/name for name in ['attack/strings-keys-members.tsv', 'es-number-ties.tsv']]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError('Source population contains a missing file or symlink.')
    hashes = {str(p.relative_to(root)):sha256(p.read_bytes()) for p in paths}
    identity = sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode())
    return hashes,identity


def published_manifest(root):
    manifest = json.loads((root/'npm/package.json').read_text())
    manifest.pop('scripts',None)
    manifest.pop('devDependencies',None)
    return manifest


def published_manifest_bytes(root):
    return (json.dumps(published_manifest(root),indent=2)+'\n').encode()


def copied_files(root):
    files = {str(p.relative_to(root/'npm')):p for p in (root/'npm/lib').rglob('*') if p.is_file()}
    files['README.md'] = root/'npm/README.md'
    files.update({name:root/name for name in ['LICENSE-MIT','LICENSE-APACHE']})
    return files


def artifact_population(root):
    return set(copied_files(root)) | {'package.json'} | {'generated/'+name for name in GENERATED}


def member_path(name):
    if '\\' in name or not name.startswith('package/'):
        raise ValueError('Packed names must use the package/ POSIX prefix.')
    relative = name[len('package/'):]
    path = PurePosixPath(relative)
    if not relative or path.is_absolute() or '..' in path.parts or str(path) != relative:
        raise ValueError('Packed member name is not canonical.')
    return relative
