#!/usr/bin/env python3
"""Mutation controls for artifact/report validators, never consumer evidence."""
import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

NPM = Path(__file__).resolve().parents[1]
ROOT = NPM.parent
sys.path.insert(0, str(NPM))
from check_release import expected_evidence, validate_artifact, validate_consumer_report


def change(path, value=None, delete=False):
    def mutate(record):
        target = record
        for key in path[:-1]:
            target = target[key]
        if delete:
            del target[path[-1]]
        else:
            target[path[-1]] = value
    return mutate


def observed(call):
    try:
        call()
        return None
    except SystemExit as error:
        # An arbitrary crash cannot pass a refusal control.
        if not isinstance(error.code, str):
            raise
        return error.code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consumer-receipts', type=Path)
    args = parser.parse_args()
    base = Path(os.environ.get('DSSE_TEST_RECEIPTS', NPM/'test-results'))
    receipts = base/'release-guard'
    receipts.mkdir(parents=True, exist_ok=True)
    source = args.consumer_receipts or base
    raw_report = (source/'RESULT.json').read_bytes()
    actual = json.loads(raw_report)
    actual_tar = source/actual['tarball']['filename']
    raw_tar = actual_tar.read_bytes()
    assert hashlib.sha256(raw_tar).hexdigest() == actual['tarball']['sha256']
    assert len(raw_tar) == actual['tarball']['bytes']
    assert 'sha512-'+base64.b64encode(hashlib.sha512(raw_tar).digest()).decode() == actual['tarball']['integrity']
    with tarfile.open(actual_tar) as archive:
        actual_build = json.loads(archive.extractfile('package/BUILD.json').read())
        actual_manifest = json.loads(archive.extractfile('package/package.json').read())
    expected = expected_evidence()
    rows = [('real-report-positive', None, None)]

    def add(label, path, value, message, delete=False):
        rows.append((label, change(path, value, delete), message))

    final_error = 'Packed consumer qualification did not finish with integer exit zero.'
    installed_error = 'Actual installed consumer proof or cleanup is missing.'
    stage_error = 'A consumer stage did not finish with integer exit zero and no signal.'
    node_error = 'Installed Node byte-input or realm proof is missing.'
    browser_error = 'Installed browser byte-input, realm or module proof is missing.'
    package_error = 'Consumer package or source identity differs.'
    add('missing-final-exit', ['nativeExit'], None, final_error, True)
    add('boolean-final-exit', ['nativeExit'], False, final_error)
    add('explicit-synthetic-report', ['synthetic'], True, 'Synthetic evidence cannot qualify consumers.')
    for label, value in [('false', False), ('numeric', 1)]:
        add(label+'-installed-proof', ['actualInstalledArtifact'], value, installed_error)
    add('missing-installed-proof', ['actualInstalledArtifact'], None, installed_error, True)
    add('empty-stages', ['steps'], [], 'Consumer stage population differs.')
    add('missing-stage', ['steps', 0], None, 'Consumer stage population differs.', True)
    for label, value in [('boolean', False), ('nonzero', 1)]:
        add(label+'-stage-exit', ['steps', 0, 'nativeExit'], value, stage_error)
    add('missing-signal', ['steps', 0, 'signal'], None, stage_error, True)
    add('false-signal', ['steps', 0, 'signal'], False, stage_error)
    add('empty-node-results', ['node'], [], 'Consumer Node runtime population differs.')
    add('missing-node-runtime', ['node', 0], None, 'Consumer Node runtime population differs.', True)
    add('wrong-node-runtime', ['node', 0, 'runtime'], 'v0.0.0', 'Consumer Node runtime population differs.')
    add('false-node-realm', ['node', 0, 'crossRealm'], False, node_error)
    add('synthetic-node-result', ['node', 0, 'synthetic'], True, node_error)
    add('missing-node-module', ['node', 0, 'installedPackage'], None, node_error, True)
    add('empty-typescript', ['typescript'], {}, 'TypeScript consumer proof differs.')
    add('boolean-typescript-exit', ['typescript', 'nativeExit'], False, 'TypeScript consumer proof differs.')
    add('wrong-typescript-version', ['typescript', 'version'], '0.0.0', 'TypeScript consumer proof differs.')
    add('empty-browser', ['browser'], {}, browser_error)
    for name in ['inputContract', 'crossRealm', 'actualPackageModule']:
        add('false-browser-'+name, ['browser', name], False, browser_error)
    add('numeric-browser-module', ['browser', 'actualPackageModule'], 1, browser_error)
    for label, value in [('boolean', True), ('truncated', 2)]:
        add(label+'-profile-calls', ['callsPerRuntime'], value, 'Consumer call population differs.')
    add('boolean-retained-count', ['retainedCounts', 'referenceVerify'], False, 'Retained consumer case counts differ.')
    add('missing-fixture-hashes', ['sourceFixtureSha256'], {}, 'Consumer fixture hashes differ.')
    add('wrong-operations', ['rawOperations'], ['verify'], 'Consumer operations differ.')
    for path, value, label in [(['node', 0, 'counts', 'accepted'], True, 'boolean-accepted-count'),
                               (['browser', 'counts', 'accepted'], 1, 'truncated-browser-count')]:
        add(label, path, value, 'Consumer acceptance and refusal totals differ.')
    documentation_error = 'The documented example did not run against the installed package or its source differs.'
    add('missing-documented-example', ['documentationExample'], None, documentation_error, True)
    add('wrong-documented-source', ['documentationExample', 'source'], 'README.md', documentation_error)
    add('wrong-documented-bytes', ['documentationExample', 'sha256'], '0'*64, documentation_error)
    add('boolean-documented-exit', ['documentationExample', 'nativeExit'], False, documentation_error)
    add('nonzero-documented-exit', ['documentationExample', 'nativeExit'], 1, documentation_error)
    add('wrong-package-source', ['package', 'sourceCommit'], 'f'*40, package_error)
    add('numeric-package-dirty', ['package', 'sourceDirty'], 1, package_error)
    add('boolean-file-count', ['package', 'filesVerified'], True, package_error)
    outcomes = []
    for label, mutation, message in rows:
        report = copy.deepcopy(actual)
        if mutation:
            mutation(report)
        refusal = observed(lambda: validate_consumer_report(report, actual_build, actual_manifest, expected))
        outcomes.append({'control': label, 'expected_guard': message, 'observed_guard': refusal, 'passed': refusal == message})
    incomplete = {'nativeExit': 0, 'node': [{'synthetic': True}], 'browser': {'synthetic': True},
                  'typescript': {'synthetic': True}, 'steps': []}
    refusal = observed(lambda: validate_consumer_report(incomplete, actual_build, actual_manifest, expected))
    outcomes.append({'control': 'synthetic-incomplete-report', 'observed_guard': refusal,
                     'passed': refusal == installed_error})

    # Synthetic artifact-only fixtures never call the composed release CLI and
    # never claim an installed consumer result or an actual clean commit.
    original = {str(p.relative_to(NPM/'dist')): p.read_bytes() for p in (NPM/'dist').rglob('*') if p.is_file()}
    commit = 'f'*40
    build = json.loads(original['BUILD.json'])
    build.update(source_commit=commit, source_dirty=False)
    original['BUILD.json'] = json.dumps(build).encode()
    mutations = [
        ('artifact-positive', None, None),
        ('metadata-exports', 'metadata', 'Release manifest differs from the exact source transform.'),
        ('metadata-provenance', 'provenance', 'Release manifest differs from the exact source transform.'),
        ('metadata-boolean-type', 'boolean-type', 'Release manifest differs from the exact source transform.'),
        ('unexpected-member', 'member', 'Packed file set differs from the build manifest.'),
        ('dot-component', 'dot', 'Packed member name is not canonical.'),
        ('parent-component', 'parent', 'Packed member name is not canonical.'),
        ('duplicate-slash', 'slash', 'Packed member name is not canonical.'),
        ('backslash', 'backslash', 'Packed names must use the package/ POSIX prefix.'),
        ('source-subset', 'subset', 'Source input population or identity differs.'),
    ]
    artifact_outcomes = []
    for label, mutation, message in mutations:
        files = copy.deepcopy(original)
        metadata = json.loads(files['package.json'])
        record = json.loads(files['BUILD.json'])
        if mutation == 'metadata':
            metadata['exports']['.']['node']['default'] = './lib/altered.mjs'
            files['package.json'] = json.dumps(metadata).encode()
        elif mutation == 'provenance':
            metadata['publishConfig']['provenance'] = False
            files['package.json'] = json.dumps(metadata).encode()
        elif mutation == 'boolean-type':
            metadata['publishConfig']['provenance'] = 1
            files['package.json'] = json.dumps(metadata).encode()
        elif mutation == 'member':
            files['extra.mjs'] = b'export const unexpected = true;\n'
        elif mutation == 'subset':
            del record['source_files'][sorted(record['source_files'])[0]]
            record['source_sha256'] = hashlib.sha256(json.dumps(record['source_files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        record['artifact_files'] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items() if name != 'BUILD.json'}
        files['BUILD.json'] = json.dumps(record).encode()
        with tempfile.TemporaryDirectory(prefix='dsse-release-control-') as temporary:
            directory = Path(temporary)
            artifact = directory/'dsse-0.1.0.tgz'
            with tarfile.open(artifact, 'w:gz') as archive:
                for name, data in sorted(files.items()):
                    member = 'package/'+name
                    if name == 'lib/api.mjs':
                        replacements = {'dot': 'package/./lib/api.mjs', 'parent': 'package/lib/../lib/api.mjs',
                                        'slash': 'package//lib/api.mjs', 'backslash': 'package/lib\\api.mjs'}
                        member = replacements.get(mutation, member)
                    entry = tarfile.TarInfo(member)
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
            data = artifact.read_bytes()
            package = {'filename': artifact.name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                       'integrity': 'sha512-'+base64.b64encode(hashlib.sha512(data).digest()).decode()}
            refusal = observed(lambda: validate_artifact(directory, package, commit))
            artifact_outcomes.append({'control': label, 'expected_guard': message, 'observed_guard': refusal,
                                      'passed': refusal == message, 'fixture_tarball_sha256': package['sha256']})
    integration = {'state': 'UNRUN', 'reason': 'Historical-report fixture mode tests validators separately; it cannot establish current clean-head release composition.'}
    if args.consumer_receipts is None:
        # Mirror the release job: both downloaded inputs and shell redirection
        # stay outside the source checkout before the strict CLI checks Git.
        before = subprocess.check_output(['git', 'status', '--porcelain=v1'], cwd=ROOT)
        with tempfile.TemporaryDirectory(prefix='dsse-external-release-') as temporary:
            directory = Path(temporary).resolve()
            if directory == ROOT or ROOT in directory.parents:
                raise RuntimeError('Release integration receipts must be outside the checkout.')
            shutil.copyfile(source/'RESULT.json', directory/'RESULT.json')
            shutil.copyfile(actual_tar, directory/actual_tar.name)
            verified = directory/'verified-npm.json'
            with verified.open('wb') as out:
                child = subprocess.run([sys.executable, str(NPM/'check_release.py'), str(directory),
                                        '--commit', actual_build['source_commit']], cwd=ROOT, stdout=out, stderr=subprocess.PIPE)
            output = verified.read_bytes()
            after = subprocess.check_output(['git', 'status', '--porcelain=v1'], cwd=ROOT)
            (receipts/'external-integration.stdout').write_bytes(output)
            (receipts/'external-integration.stderr').write_bytes(child.stderr)
            passed = child.returncode == 0 and before == after == b''
            if passed:
                verified_record = json.loads(output)
                passed = verified_record['source_commit'] == actual_build['source_commit'] and verified_record['tarball'] == str(directory/actual_tar.name)
            integration = {'state': 'EXECUTED', 'native_exit': child.returncode,
                           'receipts_outside_checkout': True, 'redirection_outside_checkout': True,
                           'source_clean_before_and_after': before == after == b'', 'passed': passed}
    result = {
        'scope': 'Validator mutation controls only. The retained real consumer report supplies the positive report fixture. Synthetic artifact-only controls never count as clean source, installed consumers, release CLI success or publication.',
        'real_consumer_report': {'path': str(source/'RESULT.json'), 'sha256': hashlib.sha256(raw_report).hexdigest(),
                                 'tarball_sha256': hashlib.sha256(raw_tar).hexdigest()},
        'consumer_contract_controls': outcomes, 'synthetic_artifact_controls': artifact_outcomes,
        'external_receipt_integration': integration,
        'native_exit': 0 if all(row['passed'] for row in outcomes+artifact_outcomes) and integration.get('passed', True) else 1,
    }
    (receipts/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))
    raise SystemExit(result['native_exit'])


if __name__ == '__main__':
    main()
