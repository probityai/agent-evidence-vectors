#!/usr/bin/env python3
"""Verify the tested tarball and exact source inputs before npm publication."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
from artifact import artifact_population, copied_files, member_path, published_manifest_bytes, source_identity

ROOT = Path(__file__).resolve().parents[1]


def need(condition, message):
    if not condition:
        raise SystemExit(message)


def zero(value):
    return type(value) is int and value == 0


def expected_evidence(root=ROOT):
    """Read the actual case population and pinned qualification tool versions."""
    script = ('import {loadCases} from "./npm/test/cases.mjs"; '
              'const data=await loadCases(); '
              'console.log(JSON.stringify({caseCount:data.cases.length,'
              'retainedCounts:data.retainedCounts,sourceFixtureSha256:data.sourceFiles}));')
    process = subprocess.run(['node', '--input-type=module', '--eval', script],
                             cwd=root, capture_output=True, text=True, timeout=30)
    need(process.returncode == 0, 'Could not read the actual consumer case population.')
    expected = json.loads(process.stdout)
    manifest = json.loads((root/'npm/package.json').read_text())
    workflow = (root/'../../.github/workflows/crate-dsse-npm.yml').read_text()
    versions = re.findall(r'^\s+node-version:\s*(\d+\.\d+\.\d+)\s*$', workflow, re.M)
    minimum = re.fullmatch(r'>=(\d+\.\d+\.\d+)', manifest['engines']['node'])
    need(minimum is not None and len(versions) == 2 and len(set(versions)) == 2
         and minimum[1] in versions, 'Qualification Node pins do not cover the package minimum and current runtime.')
    expected['nodeRuntimes'] = {'v'+version for version in versions}
    expected['typescript'] = manifest['devDependencies']['typescript']
    expected['calls'] = expected['caseCount']
    examples = re.findall(r'```js\n(.*?)```', (root/'docs/NPM.md').read_text(), re.S)
    need(len(examples) == 2 and examples[0].startswith('import assert from "node:assert/strict";'),
         'The documented installed verification example is missing or ambiguous.')
    expected['documentationSha256'] = hashlib.sha256(examples[0].encode()).hexdigest()
    return expected


def validate_consumer_report(report, build, manifest, expected):
    """Check full consumer evidence. Synthetic artifact controls do not satisfy it."""
    need(isinstance(report, dict) and zero(report.get('nativeExit')) and 'error' not in report,
         'Packed consumer qualification did not finish with integer exit zero.')
    need(report.get('synthetic') is not True, 'Synthetic evidence cannot qualify consumers.')
    need(report.get('actualInstalledArtifact') is True and report.get('ownedConsumerRemoved') is True,
         'Actual installed consumer proof or cleanup is missing.')
    need(report.get('rawOperations') == ['verify', 'pae'], 'Consumer operations differ.')
    stages = report.get('steps')
    required = {'native-oracle', 'npm-pack', 'consumer-install', 'node-consumer-0',
                'node-consumer-1', 'typescript-consumer', 'documentation-example'}
    need(isinstance(stages, list) and len(stages) == len(required)
         and all(isinstance(stage, dict) and isinstance(stage.get('label'), str) for stage in stages)
         and {stage.get('label') for stage in stages} == required,
         'Consumer stage population differs.')
    need(all(zero(stage.get('nativeExit')) and 'signal' in stage and stage['signal'] is None
             for stage in stages), 'A consumer stage did not finish with integer exit zero and no signal.')
    calls = report.get('callsPerRuntime')
    need(type(calls) is int and calls == expected['calls'], 'Consumer call population differs.')
    retained = report.get('retainedCounts')
    need(isinstance(retained, dict) and retained.keys() == expected['retainedCounts'].keys()
         and all(type(value) is int and value == expected['retainedCounts'][key]
                 for key, value in retained.items()), 'Retained consumer case counts differ.')
    need(report.get('sourceFixtureSha256') == expected['sourceFixtureSha256'], 'Consumer fixture hashes differ.')

    def counts(value):
        need(isinstance(value, dict) and set(value) == {'accepted', 'refused'}
             and all(type(count) is int and count > 0 for count in value.values())
             and sum(value.values()) == calls, 'Consumer acceptance and refusal totals differ.')
        return value

    nodes = report.get('node')
    need(isinstance(nodes, list) and len(nodes) == 2
         and all(isinstance(node, dict) and isinstance(node.get('runtime'), str) for node in nodes)
         and {node.get('runtime') for node in nodes} == expected['nodeRuntimes'],
         'Consumer Node runtime population differs.')
    common = counts(nodes[0].get('counts'))
    for node in nodes:
        location = node.get('installedPackage')
        need(node.get('synthetic') is not True and node.get('inputContract') is True and node.get('crossRealm') is True
             and isinstance(location, str) and location.startswith('file:///')
             and location.endswith('/node_modules/dsse/lib/node.mjs'),
             'Installed Node byte-input or realm proof is missing.')
        need(counts(node.get('counts')) == common, 'Node consumer results disagree.')
    typescript = report.get('typescript')
    need(isinstance(typescript, dict) and typescript.get('synthetic') is not True and zero(typescript.get('nativeExit'))
         and typescript.get('version') == expected['typescript'], 'TypeScript consumer proof differs.')
    browser = report.get('browser')
    need(isinstance(browser, dict) and browser.get('synthetic') is not True and browser.get('engine') == 'Chromium'
         and isinstance(browser.get('version'), str)
         and re.fullmatch(r'\d+\.\d+\.\d+\.\d+', browser['version']) is not None
         and all(browser.get(key) is True for key in ['inputContract', 'crossRealm', 'actualPackageModule', 'headless']),
         'Installed browser byte-input, realm or module proof is missing.')
    need(counts(browser.get('counts')) == common, 'Browser and Node consumer results disagree.')
    example = report.get('documentationExample')
    need(isinstance(example, dict) and example.get('source') == 'docs/NPM.md'
         and zero(example.get('nativeExit')) and example.get('sha256') == expected['documentationSha256'],
         'The documented example did not run against the installed package or its source differs.')
    package = report.get('package')
    fields = {'name', 'version', 'sourceSha256', 'sourceCommit', 'sourceDirty', 'filesVerified'}
    need(isinstance(package, dict) and set(package) == fields
         and package['name'] == manifest['name'] and package['version'] == manifest['version']
         and package['sourceSha256'] == build['source_sha256']
         and package['sourceCommit'] == build['source_commit']
         and type(package['sourceDirty']) is bool and package['sourceDirty'] is build['source_dirty']
         and type(package['filesVerified']) is int and package['filesVerified'] == len(build['artifact_files']),
         'Consumer package or source identity differs.')


def validate_artifact(receipts, package, commit, root=ROOT):
    """Check artifact/source identity independently of consumer-evidence validation."""
    need(isinstance(package, dict), 'Qualified tarball metadata is missing.')
    name = package['filename']
    if not isinstance(name, str) or Path(name).name != name:
        raise SystemExit('Unexpected packed filename.')
    artifact = receipts/name
    data = artifact.read_bytes()
    integrity = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()
    if type(package['bytes']) is not int or len(data) != package['bytes'] or hashlib.sha256(data).hexdigest() != package['sha256'] or integrity != package['integrity']:
        raise SystemExit('Qualified tarball digest differs.')
    files = {}
    with tarfile.open(artifact) as archive:
        for member in archive:
            if not member.isreg():
                raise SystemExit('Unexpected packed member.')
            try:
                name = member_path(member.name)
            except ValueError as error:
                raise SystemExit(str(error)) from error
            if name in files:
                raise SystemExit('Duplicate packed member.')
            files[name] = archive.extractfile(member).read()
    build = json.loads(files['BUILD.json'])
    if build['source_commit'] != commit or build['source_dirty'] is not False:
        raise SystemExit('Release source identity is not a clean exact commit.')
    population = artifact_population(root)
    if set(files) != population | {'BUILD.json'} or set(build['artifact_files']) != population:
        raise SystemExit('Packed file set differs from the build manifest.')
    for name, expected in build['artifact_files'].items():
        if hashlib.sha256(files[name]).hexdigest() != expected:
            raise SystemExit('Packed file differs: '+name)
    source_files,source_sha256 = source_identity(root)
    if build['source_files'] != source_files or build['source_sha256'] != source_sha256:
        raise SystemExit('Source input population or identity differs.')
    for name,path in copied_files(root).items():
        if files[name] != path.read_bytes():
            raise SystemExit('Copied source file differs: '+name)
    manifest = json.loads(files['package.json'])
    if files['package.json'] != published_manifest_bytes(root) or manifest.get('scripts') or manifest.get('dependencies'):
        raise SystemExit('Release manifest differs from the exact source transform.')
    return files, build, {'tarball':str(artifact),'sha256':package['sha256'],'integrity':integrity,
                         'source_commit':commit,'source_sha256':build['source_sha256'],'native_exit':0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('receipts', type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    clean = subprocess.check_output(['git', 'status', '--porcelain=v1'], cwd=ROOT, text=True).strip() == ''
    need(args.commit == head and clean, 'Release check requires the exact clean source commit.')
    report = json.loads((args.receipts/'RESULT.json').read_text())
    files, build, verified = validate_artifact(args.receipts, report.get('tarball'), args.commit)
    validate_consumer_report(report, build, json.loads(files['package.json']), expected_evidence())
    print(json.dumps(verified))


if __name__ == '__main__':
    main()
