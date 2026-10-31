import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { retainProcess } from './runner.mjs';

// These controls invoke actual entrypoints and actual pinned producers, not parser copies.
const [capsule, review, aps, priorseal, output] = process.argv.slice(2).map(value => path.resolve(value));
assert.equal(process.argv.length, 7,
  'usage: node test-runner.mjs CAPSULE REVIEW APS PRIORSEAL NEW_CONTROL_OUTPUT');
assert.ok(!fs.existsSync(output), 'control output must not exist');
fs.mkdirSync(output);
const publicOutput = path.join(output, 'public-results'); fs.mkdirSync(publicOutput);
const source = path.dirname(fileURLToPath(import.meta.url));
const digest = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const identities = ['https://github.com/probityai/agent-evidence-atlas', 'https://github.com/piiiico/agent-errata'];
const ledger = [];
function publicFiles(directory, names) {
  const relative = path.relative(output, directory);
  assert.ok(!path.isAbsolute(relative) && !relative.split(path.sep).includes('..'));
  assert.ok(fs.lstatSync(directory).isDirectory());
  assert.equal(fs.realpathSync(directory), path.resolve(fs.realpathSync(output), relative),
    'public artifact source directories must not redirect through links');
  const target = path.join(publicOutput, relative);
  fs.mkdirSync(target, { recursive: true });
  for (const name of names) {
    assert.equal(path.basename(name), name, 'public artifact path must be a direct file');
    const original = path.join(directory, name);
    assert.ok(fs.lstatSync(original).isFile(), 'public artifacts must be regular files');
    fs.copyFileSync(original, path.join(target, name), fs.constants.COPYFILE_EXCL);
  }
}
function run(label, entry, argv, cwd, env = process.env) {
  const args = [entry, ...argv];
  const started = new Date().toISOString();
  const actual = spawnSync(process.execPath, args, { cwd, env, encoding: 'utf8', timeout: 120000, maxBuffer: 1024 * 1024 });
  fs.writeFileSync(path.join(output, `${label}.stdout`), actual.stdout ?? '');
  fs.writeFileSync(path.join(output, `${label}.stderr`), actual.stderr ?? '');
  ledger.push({ label, command: [process.execPath, ...args], cwd, started,
    stdout: `${label}.stdout`, stderr: `${label}.stderr`,
    ended: new Date().toISOString(), exit: actual.status, signal: actual.signal,
    error: actual.error ? String(actual.error) : null });
  fs.writeFileSync(path.join(output, 'commands.json'), `${JSON.stringify(ledger, null, 2)}\n`);
  assert.equal(actual.error, undefined, label);
  assert.equal(actual.signal, null, label);
  return actual;
}
function checkRecord(entry, directory, identity, files) {
  const contract = path.basename(entry) === 'check-run-contract.mjs';
  const recordFile = contract ? 'record.json' : 'receipt.json';
  const record = JSON.parse(fs.readFileSync(path.join(directory, recordFile)));
  assert.equal(record.schema, `probity.aps-priorseal-${contract ? 'run-contract' : 'source-replay'}/v2`);
  assert.deepEqual(record.scope.runner, { identity, source: 'caller-declared' });
  assert.deepEqual(record.harness.files, files.map(file => ({ path: path.basename(file), sha256: digest(file) })));
  const observations = [...record.cases.map(item => item.process),
    ...(contract ? [] : [record.selftestProcess])];
  for (const observation of observations) {
    assert.equal(observation.files.length, 3);
    for (const file of observation.files) {
      const actual = path.join(directory, file.path);
      assert.equal(fs.statSync(actual).size, file.bytes);
      assert.equal(digest(actual), file.sha256);
    }
    const metadata = JSON.parse(fs.readFileSync(path.join(directory,
      observation.files.find(file => file.path.endsWith('.command.json')).path)));
    assert.equal(metadata.captureComplete, true);
    assert.equal(metadata.signal, null);
    assert.equal(metadata.error, null);
  }
  if (contract) {
    assert.equal(record.cases.length, 3);
    for (const item of record.cases) {
      assert.equal(item.wrapperExit, 0);
      assert.equal(item.recordedExit, 0);
      assert.equal(item.passPrinted, true);
      assert.equal(item.reportPresentBefore, false);
      assert.equal(item.reportPresent, false);
      assert.equal(item.meetsRunContract, false);
      assert.ok(!Object.hasOwn(item, 'acceptedByProbity'));
    }
  } else {
    assert.deepEqual(record.summary, { established: 14, contradicted: 3, not_established: 5 });
    assert.equal(record.claims.length, 22);
    assert.deepEqual(record.cases.map(item => [item.name, item.exitCode, item.acceptedAsFresh]), [
      ['clean', 0, true], ['substituted-byte', 1, false], ['missing-owner', 1, false],
      ['missing-owner-flag', 2, false], ['stale-output', 1, false],
    ]);
    assert.equal(record.baseline.sha256, digest(path.join(source, 'recorded.json')));
  }
  publicFiles(directory, [recordFile, ...observations.flatMap(item => item.files.map(file => file.path))]);
  return record;
}
const originalBaseline = digest(path.join(source, 'recorded.json'));
const copied = path.join(output, 'standalone'); fs.mkdirSync(copied);
for (const file of ['run.mjs', 'check-run-contract.mjs', 'runner.mjs', 'recorded.json']) {
  fs.copyFileSync(path.join(source, file), path.join(copied, file));
}
const unrelated = path.join(output, 'outside-cwd'); fs.mkdirSync(unrelated);
assert.ok(!fs.existsSync(path.join(copied, '.git')) && !fs.existsSync(path.join(unrelated, '.git')));
const records = [];
for (const entryName of ['run.mjs', 'check-run-contract.mjs']) {
  const roots = [entryName === 'run.mjs' ? capsule : review, aps, priorseal];
  const entry = path.join(source, entryName);
  const helper = path.join(source, 'runner.mjs');
  for (const [index, identity] of identities.entries()) {
    const target = path.join(output, `${entryName}-identity-${index}`);
    assert.equal(run(`${entryName}-identity-${index}`, entry,
      ['--runner', identity, ...roots, target], unrelated).status, 0);
    records.push(checkRecord(entry, target, identity, [entry, helper]));
  }
  const copiedEntry = path.join(copied, entryName);
  const copiedHelper = path.join(copied, 'runner.mjs');
  const standaloneOutput = path.join(output, `${entryName}-standalone`);
  assert.equal(run(`${entryName}-standalone`, copiedEntry,
    ['--runner', identities[1], ...roots, standaloneOutput], unrelated).status, 0);
  const before = checkRecord(copiedEntry, standaloneOutput, identities[1], [copiedEntry, copiedHelper]);
  // A harmless source change changes the actual bound bytes without changing case outcomes.
  fs.appendFileSync(copiedEntry, '\n// external source-byte control\n');
  fs.appendFileSync(copiedHelper, '\n// helper source-byte control\n');
  const changedOutput = path.join(output, `${entryName}-changed-source`);
  assert.equal(run(`${entryName}-changed-source`, copiedEntry,
    ['--runner', identities[1], ...roots, changedOutput], unrelated).status, 0);
  const after = checkRecord(copiedEntry, changedOutput, identities[1], [copiedEntry, copiedHelper]);
  assert.notEqual(before.harness.files[0].sha256, after.harness.files[0].sha256);
  assert.notEqual(before.harness.files[1].sha256, after.harness.files[1].sha256);
  const observedCases = record => record.cases.map(item => {
    const { process: primary, reportSha256, ...outcome } = item;
    return outcome;
  });
  assert.deepEqual(observedCases(before), observedCases(after));
  fs.copyFileSync(helper, copiedHelper);

  const spyBin = path.join(output, `${entryName}-spy`); fs.mkdirSync(spyBin);
  const spyLog = path.join(output, `${entryName}-unexpected-command.log`);
  for (const command of ['git', 'npm']) fs.writeFileSync(path.join(spyBin, command),
    '#!/bin/sh\nprintf "%s\\n" "$0" >> "$CALLER_CONTROL_LOG"\nexit 99\n', { mode: 0o700 });
  const refusalCases = [
    ['omitted', []], ['empty', ['--runner', '']], ['whitespace', ['--runner', '  ']],
    ['outer-whitespace', ['--runner', ' caller']], ['control', ['--runner', 'caller\nidentity']],
    ['format-control', ['--runner', 'caller\u200bidentity']],
    ['line-separator', ['--runner', 'caller\u2028identity']],
    ['paragraph-separator', ['--runner', 'caller\u2029identity']],
    ['oversized', ['--runner', 'é'.repeat(257)]], ['missing-value', ['--runner']],
    ['duplicate', ['--runner', 'caller', '--runner', 'other']],
    ['unknown', ['--other', 'caller']], ['unknown-extra', ['--runner', 'caller', '--other']],
  ];
  for (const [name, options] of refusalCases) {
    const target = path.join(output, `${entryName}-refused-${name}`);
    const result = run(`${entryName}-refused-${name}`, entry,
      [...options, ...roots, target], unrelated,
      { ...process.env, PATH: `${spyBin}${path.delimiter}${process.env.PATH}`, CALLER_CONTROL_LOG: spyLog });
    assert.notEqual(result.status, 0, name);
    assert.match(result.stderr, /usage:|runner identity|expected four paths/);
    assert.ok(!fs.existsSync(target), `${name}: refused command touched its output`);
    assert.ok(!fs.existsSync(spyLog), `${name}: refused command started a checkout process`);
  }
  const maximumOutput = path.join(output, `${entryName}-maximum-identity`);
  const maximum = 'é'.repeat(256);
  assert.equal(run(`${entryName}-maximum-identity`, entry,
    ['--runner', maximum, ...roots, maximumOutput], unrelated).status, 0);
  checkRecord(entry, maximumOutput, maximum, [entry, helper]);
  const producerAlias = path.join(output, `${entryName}-producer-alias`);
  fs.symlinkSync(roots[0], producerAlias, 'dir');
  const insideOutput = path.join(producerAlias, 'refused-caller-output');
  const inside = run(`${entryName}-producer-output-symlink`, entry,
    ['--runner', identities[1], ...roots, insideOutput], unrelated);
  assert.notEqual(inside.status, 0);
  assert.match(inside.stderr, /output directory must be outside/);
  assert.ok(!fs.existsSync(insideOutput));
  const incomplete = path.join(output, `${entryName}-incomplete-copy`); fs.mkdirSync(incomplete);
  fs.copyFileSync(entry, path.join(incomplete, entryName));
  const missingHelperOutput = path.join(output, `${entryName}-missing-helper`);
  const missingHelper = run(`${entryName}-missing-helper`, path.join(incomplete, entryName),
    ['--runner', identities[1], ...roots, missingHelperOutput], unrelated);
  assert.notEqual(missingHelper.status, 0);
  assert.match(missingHelper.stderr, /ERR_MODULE_NOT_FOUND/);
  assert.ok(!fs.existsSync(missingHelperOutput));
  if (entryName === 'run.mjs') {
    fs.copyFileSync(helper, path.join(incomplete, 'runner.mjs'));
    const missingBaselineOutput = path.join(output, 'missing-baseline');
    const missingBaseline = run('missing-baseline', path.join(incomplete, entryName),
      ['--runner', identities[1], ...roots, missingBaselineOutput], unrelated);
    assert.notEqual(missingBaseline.status, 0);
    assert.match(missingBaseline.stderr, /ENOENT/);
    assert.ok(!fs.existsSync(missingBaselineOutput));
    fs.copyFileSync(path.join(source, 'recorded.json'), path.join(incomplete, 'recorded.json'));
    fs.appendFileSync(path.join(incomplete, 'recorded.json'), '\n');
    const changedBaselineOutput = path.join(output, 'changed-baseline');
    const changedBaseline = run('changed-baseline', path.join(incomplete, entryName),
      ['--runner', identities[1], ...roots, changedBaselineOutput], unrelated);
    assert.notEqual(changedBaseline.status, 0);
    assert.match(changedBaseline.stderr, /changed input:/);
    assert.ok(!fs.existsSync(changedBaselineOutput));
  }
}
assert.equal(digest(path.join(source, 'recorded.json')), originalBaseline);
const byteProbe = path.join(output, 'byte-controls'); fs.mkdirSync(byteProbe);
const binaryArgs = ['-e', 'process.stdout.write(Buffer.from([255,0,128])); process.stderr.write(Buffer.from([254,10])); process.exit(7)'];
const binaryStarted = new Date().toISOString();
const binary = spawnSync(process.execPath, binaryArgs, { encoding: null, timeout: 5000 });
const binaryEnded = new Date().toISOString();
assert.equal(binary.status, 7); assert.equal(binary.signal, null); assert.equal(binary.error, undefined);
const binaryFiles = retainProcess(byteProbe, 'binary', process.execPath, binaryArgs, {}, binary,
  binaryStarted, binaryEnded);
assert.deepEqual(fs.readFileSync(path.join(byteProbe, 'binary.stdout')), Buffer.from([255, 0, 128]));
assert.deepEqual(fs.readFileSync(path.join(byteProbe, 'binary.stderr')), Buffer.from([254, 10]));
const cappedArgs = ['-e', 'process.stdout.write(Buffer.alloc(4096, 77))'];
const cappedStarted = new Date().toISOString();
const capped = spawnSync(process.execPath, cappedArgs, { encoding: null, timeout: 5000, maxBuffer: 8 });
const cappedEnded = new Date().toISOString();
assert.ok(capped.error, 'real output cap must be reached');
const cappedFiles = retainProcess(byteProbe, 'capped', process.execPath, cappedArgs, {}, capped,
  cappedStarted, cappedEnded);
assert.equal(JSON.parse(fs.readFileSync(path.join(byteProbe, 'capped.command.json'))).captureComplete, false);
assert.deepEqual(fs.readFileSync(path.join(byteProbe, 'capped.stdout')), capped.stdout);
publicFiles(byteProbe, [...binaryFiles.files, ...cappedFiles.files].map(file => file.path));
ledger.push({ label: 'binary-byte-retention', command: [process.execPath, ...binaryArgs],
  stdout: 'byte-controls/binary.stdout', stderr: 'byte-controls/binary.stderr',
  cwd: process.cwd(), started: binaryStarted, ended: binaryEnded, exit: binary.status,
  signal: binary.signal, error: null, controlledOutcome: 'exit7 with exact binary streams' });
ledger.push({ label: 'real-output-cap', command: [process.execPath, ...cappedArgs],
  stdout: 'byte-controls/capped.stdout', stderr: 'byte-controls/capped.stderr',
  cwd: process.cwd(), started: cappedStarted, ended: cappedEnded, exit: capped.status,
  signal: capped.signal, error: String(capped.error), controlledOutcome: 'explicit incomplete capture' });
fs.writeFileSync(path.join(output, 'commands.json'), `${JSON.stringify(ledger, null, 2)}\n`);
publicFiles(output, ['commands.json', ...ledger.flatMap(item => [item.stdout, item.stderr])
  .filter(file => path.dirname(file) === '.')]);
for (const item of ledger) {
  for (const stream of [item.stdout, item.stderr]) {
    assert.ok(!path.isAbsolute(stream) && !stream.split(path.sep).includes('..'));
    const actual = path.join(output, stream);
    const retained = path.join(publicOutput, stream);
    assert.ok(fs.lstatSync(actual).isFile() && fs.lstatSync(retained).isFile());
    assert.equal(digest(retained), digest(actual), 'ledger streams must bind actual curated bytes');
  }
}
fs.writeFileSync(path.join(output, 'control-results.json'), `${JSON.stringify({
  groups: ['explicit callers', 'standalone dependency route', 'early actual CLI refusals',
    'original pinned outcomes', 'source and helper byte changes', 'historical baseline preservation'],
  actualCommands: ledger.length, callerDeclarations: identities, originalBaseline,
  allGroupsPassed: true, scope: 'Fixture controls; caller declarations are not authenticated identities',
}, null, 2)}\n`);
publicFiles(output, ['control-results.json']);
const publicInventory = [];
function inventory(directory) {
  for (const name of fs.readdirSync(directory)) {
    const actual = path.join(directory, name);
    const metadata = fs.lstatSync(actual);
    if (metadata.isDirectory()) {
      inventory(actual);
    } else {
      assert.ok(metadata.isFile(), 'public artifacts must contain only real directories and regular files');
      assert.ok(!['clean.json', 'stale-output.json', 'recorded.json'].includes(name));
      publicInventory.push({ path: path.relative(publicOutput, actual), bytes: metadata.size, sha256: digest(actual) });
    }
  }
}
inventory(publicOutput);
for (const item of publicInventory) {
  if (!['receipt.json', 'record.json'].includes(path.basename(item.path))) continue;
  const recordPath = path.join(publicOutput, item.path);
  const record = JSON.parse(fs.readFileSync(recordPath));
  const observations = [...record.cases.map(entry => entry.process),
    ...(record.selftestProcess ? [record.selftestProcess] : [])];
  for (const observation of observations) {
    for (const file of observation.files) {
      assert.ok(!path.isAbsolute(file.path) && !file.path.split(path.sep).includes('..'));
      const actual = path.join(path.dirname(recordPath), file.path);
      assert.ok(fs.lstatSync(actual).isFile(), 'curated record references must resolve to regular sibling files');
      assert.equal(fs.statSync(actual).size, file.bytes);
      assert.equal(digest(actual), file.sha256);
    }
  }
}
fs.writeFileSync(path.join(output, 'public-artifact-manifest.json'), `${JSON.stringify({
  schema: 'probity.aps-priorseal-public-artifact/v1',
  base_directory: 'public-results',
  files: publicInventory,
}, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ groups: 6, commands: ledger.length, passed: true })}\n`);
