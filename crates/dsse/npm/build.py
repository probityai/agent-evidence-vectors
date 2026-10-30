#!/usr/bin/env python3
"""Build one portable WASM artifact and an installable ESM npm package."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from artifact import artifact_population, published_manifest_bytes, source_identity

NPM = Path(__file__).resolve().parent
ROOT = NPM.parent
BINDGEN = '0.2.129'
GENERATOR = 'dsse/npm/build.py'


def run(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, **kwargs).decode().strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-clean', action='store_true')
    parser.add_argument('--output', type=Path, default=NPM / 'dist')
    args = parser.parse_args()
    output = args.output.resolve()
    try:
        revision = run(['git', 'rev-parse', 'HEAD'], stderr=subprocess.DEVNULL)
        dirty = bool(run(['git', 'status', '--porcelain=v1']))
    except subprocess.CalledProcessError:
        revision, dirty = None, True
    if args.require_clean and (not revision or dirty):
        raise SystemExit('A release build requires a clean Git checkout.')
    bindgen_version = run(['wasm-bindgen', '--version'])
    if bindgen_version != 'wasm-bindgen ' + BINDGEN:
        raise SystemExit('Install wasm-bindgen-cli ' + BINDGEN + ' for this locked build.')
    env = os.environ.copy()
    flags = env.get('CARGO_ENCODED_RUSTFLAGS', '').split('\x1f') if env.get('CARGO_ENCODED_RUSTFLAGS') else shlex.split(env.get('RUSTFLAGS', ''))
    flags += ['--remap-path-prefix=' + str(ROOT) + '=.']
    for key in ['CARGO_HOME', 'RUSTUP_HOME']:
        actual = env.get(key, str(Path.home() / ('.cargo' if key == 'CARGO_HOME' else '.rustup')))
        flags += ['--remap-path-prefix=' + actual + '=' + key.lower()]
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    # An explicit argument vector avoids interpreting caller flags as shell code.
    subprocess.run(['cargo', 'build', '--manifest-path', 'npm/wasm/Cargo.toml', '--locked', '--release', '--target', 'wasm32-unknown-unknown'], cwd=ROOT, env=env, check=True)
    target = Path(env.get('CARGO_TARGET_DIR', NPM / 'wasm/target')).resolve()
    source_wasm = target / 'wasm32-unknown-unknown/release/dsse_wasm.wasm'
    input_hashes, source_digest = source_identity(ROOT)
    build_root = NPM / '.build'
    build_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='package-', dir=build_root) as temporary:
        stage = Path(temporary) / 'package'
        stage.mkdir()
        generated = stage / 'generated'
        subprocess.run(['wasm-bindgen', '--target', 'web', '--out-dir', str(generated), '--out-name', 'dsse', '--remove-name-section', '--remove-producers-section', str(source_wasm)], cwd=ROOT, check=True)
        shutil.copytree(NPM / 'lib', stage / 'lib')
        for name in ['LICENSE']:
            shutil.copyfile(ROOT / name, stage / name)
        shutil.copyfile(NPM / 'README.md', stage / 'README.md')
        # Installed consumers need no build tool, install script or dependency.
        (stage / 'package.json').write_bytes(published_manifest_bytes(ROOT))
        files = {str(p.relative_to(stage)): digest(p) for p in stage.rglob('*') if p.is_file()}
        if set(files) != artifact_population(ROOT):
            raise SystemExit('Generated artifact population differs from the pinned build contract.')
        record = {'generator':GENERATOR,'source_commit':revision,'source_dirty':dirty,
                  'source_sha256':source_digest,'source_files':input_hashes,
                  'rustc':run(['rustc','--version']),'wasm_bindgen':bindgen_version,
                  'one_wasm_artifact':True,'artifact_files':files}
        (stage / 'BUILD.json').write_text(json.dumps(record, indent=2) + '\n')
        forbidden = [str(ROOT).encode()]
        forbidden += [env.get(k, str(Path.home() / ('.cargo' if k == 'CARGO_HOME' else '.rustup'))).encode() for k in ['CARGO_HOME','RUSTUP_HOME']]
        for p in stage.rglob('*'):
            if p.is_file() and any(prefix in p.read_bytes() for prefix in forbidden):
                raise SystemExit('Local build path escaped remapping: ' + str(p.relative_to(stage)))
        if output.exists():
            marker = output / 'BUILD.json'
            if not marker.is_file() or output.is_symlink():
                raise SystemExit('Refusing to overwrite an unmarked output directory.')
            old = json.loads(marker.read_text())
            if old.get('generator') != GENERATOR:
                raise SystemExit('Output directory belongs to another generator.')
            expected = set(old['artifact_files']) | {'BUILD.json'}
            present = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
            if present != expected or any(p.is_symlink() for p in output.rglob('*')):
                raise SystemExit('Output has unrecognized files; preserve them before rebuilding.')
            shutil.rmtree(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage, output)
    print(json.dumps({'package':str(output),'source_commit':revision,'source_dirty':dirty,'source_sha256':source_digest,'wasm_sha256':digest(output/'generated/dsse_bg.wasm')}))


if __name__ == '__main__':
    main()
