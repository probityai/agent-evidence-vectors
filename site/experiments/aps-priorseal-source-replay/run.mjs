import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { harness, invocation, retainProcess, validateOutput } from './runner.mjs';

const revisions = {
  capsule: '4162622af24c94efb843f53aa27940ffd1256ad6',
  aps: '948f99b85343bef2c6fa677c8543965caacfc087',
  priorseal: 'd749d2691c3e6be139de4020e7b27cdafca2c428',
};
const digests = {
  adapter: '5f5cc203c921ecd576b81ee5d22063d39efc3ec74cc0b3aa75d1e41916e5cad3',
  lock: '2ca396b3f9b357f5a79e3c6ff7d6dbd9d33ee179c5132792608a8e330e014c7a',
  manifest: '2bf365bc9124ecfc943d5be86c34e8e0cacd51a5929b8d0c906e633a017231f9',
  positive: 'c8dd05f412b3d1dd957f66deaf231a8becb9656e8bd1960ba88638cf9ad4c6da',
  overLimit: 'cb45a8378a5c9f1f7f2695c4d1fb5cbe344d9c840b799cf0ecb786e5ddf3c226',
  producerReport: 'd2c1bea5f0acf0afe06c944376c5a471402ab5d48bf85ca267ed9b5876336ae4',
};
const expectedSummary = { established: 14, contradicted: 3, not_established: 5 };
const recordedSha256 = '4d94934e711610fba6d8156752ed91f55788b3c10aeab697ad166a3825cbf65a';
const expectedErrors = {
  'substituted-byte': /APS copied fixture differs from owner bytes/,
  'missing-owner': /ENOENT.*MANIFEST\.sha256/,
  'missing-owner-flag': /usage: node verify\.mjs --aps-owner/,
  'stale-output': /ENOENT.*MANIFEST\.sha256/,
};

function digest(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function run(command, args, options = {}) {
  const { capture, ...spawnOptions } = options;
  const started = new Date().toISOString();
  const result = spawnSync(command, args, {
    encoding: null,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
    ...spawnOptions,
  });
  if (capture) result.primary = retainProcess(capture.directory, capture.name,
    command, args, spawnOptions, result, started, new Date().toISOString());
  assert.equal(result.error, undefined, `failed to run ${command}: ${result.error}`);
  assert.equal(result.signal, null, `${command} ended on signal ${result.signal}`);
  return { ...result, stdout: result.stdout?.toString('utf8') ?? '',
    stderr: result.stderr?.toString('utf8') ?? '' };
}

function checkout(root, revision) {
  const result = run('git', ['-C', root, 'rev-parse', 'HEAD']);
  assert.equal(result.status, 0, 'source directory is not a Git checkout');
  assert.equal(result.stdout.trim(), revision, `wrong source revision at ${root}`);
  const dirty = run('git', ['-C', root, 'status', '--porcelain']);
  assert.equal(dirty.status, 0, `failed source status at ${root}`);
  assert.equal(dirty.stdout, '', `dirty source checkout at ${root}`);
}

function pinned(file, expected) {
  assert.equal(digest(file), expected, `changed input: ${file}`);
}

function oneCase(name, adapter, args, output, expectedExit, existing = false) {
  const report = path.join(output, `${name}.json`);
  if (existing) fs.copyFileSync(path.join(output, 'clean.json'), report);
  const before = fs.existsSync(report) ? digest(report) : null;
  const result = run(process.execPath, [adapter, ...args, '--out', report],
    { capture: { directory: output, name } });
  assert.equal(result.status, expectedExit, `${name}: unexpected exit: ${result.stderr}`);
  const after = fs.existsSync(report) ? digest(report) : null;
  if (expectedExit === 0) {
    assert.equal(before, null, `${name}: report existed before execution`);
    assert.notEqual(after, null, `${name}: no report on successful execution`);
  } else {
    assert.equal(after, before, `${name}: failed run wrote a report`);
    assert.match(result.stderr, expectedErrors[name], `${name}: wrong refusal`);
  }
  return {
    name,
    exitCode: result.status,
    reportPresentBefore: before !== null,
    reportPresentAfter: after !== null,
    reportSha256: after,
    acceptedAsFresh: result.status === 0 && before === null && after !== null,
    process: result.primary,
  };
}

function main(argv) {
  const parsed = invocation(argv, 'run.mjs');
  const sourceHarness = harness(import.meta.url);
  const baseline = new URL('./recorded.json', import.meta.url);
  pinned(baseline, recordedSha256);
  const recorded = JSON.parse(fs.readFileSync(baseline, 'utf8'));
  const [capsule, aps, priorseal, output] = parsed.paths.map(value => path.resolve(value));
  validateOutput(output, [capsule, aps, priorseal]);
  for (const [name, root] of Object.entries({ capsule, aps, priorseal })) {
    checkout(root, revisions[name]);
  }
  const adapterDir = path.join(capsule, 'capsules/aps-priorseal-v0.1/adapter');
  const adapter = path.join(adapterDir, 'verify.mjs');
  const owner = path.join(aps, 'fixtures/priorseal-decision-binding');
  const copy = path.join(priorseal, 'examples/aps-priorseal-decision-binding-v1/aps-inputs');
  const priorsealCase = path.dirname(copy);
  pinned(adapter, digests.adapter);
  pinned(path.join(adapterDir, 'package-lock.json'), digests.lock);
  pinned(path.join(owner, 'MANIFEST.sha256'), digests.manifest);
  pinned(path.join(copy, 'MANIFEST.sha256'), digests.manifest);
  pinned(path.join(priorsealCase, 'priorseal-inputs/payment-within-limit.json'), digests.positive);
  pinned(path.join(priorsealCase, 'priorseal-inputs/payment-over-limit.json'), digests.overLimit);
  pinned(path.join(priorsealCase, 'PAYMENT-LIMIT-REPORT.json'), digests.producerReport);
  fs.mkdirSync(output, { recursive: false });
  const selftest = run(process.execPath, [adapter, '--selftest'],
    { capture: { directory: output, name: 'selftest' } });
  assert.equal(selftest.status, 0, selftest.stderr);
  assert.deepEqual(JSON.parse(selftest.stdout), { ok: true });

  const common = ['--aps', copy, '--priorseal', priorsealCase];
  const cases = [oneCase('clean', adapter, [...common, '--aps-owner', owner], output, 0)];
  const report = JSON.parse(fs.readFileSync(path.join(output, 'clean.json'), 'utf8'));
  assert.deepEqual(report.summary, expectedSummary);
  assert.deepEqual(report.pins.aps_owner_fixture_binding, {
    owner_commit: revisions.aps,
    manifest_sha256: digests.manifest,
    compared_files: 17,
    byte_identical: true,
  });
  const counts = { ESTABLISHED: 0, CONTRADICTED: 0, NOT_ESTABLISHED: 0 };
  for (const claim of report.claims) {
    assert.ok(Object.hasOwn(counts, claim.result), `unexpected claim result: ${claim.result}`);
    counts[claim.result] += 1;
  }
  assert.equal(report.claims.length, 22);
  assert.deepEqual(Object.values(counts), Object.values(expectedSummary));
  assert.deepEqual(report.claims.map(({ id, result }) => ({ id, result })), recorded.claims);
  const binding = report.claims.find(claim => claim.id === 'composition.aps_owner_fixture_copy.byte_identical');
  assert.equal(binding?.result, 'ESTABLISHED');

  const scratch = fs.mkdtempSync(path.join(output, '.case-'));
  try {
    const changed = path.join(scratch, 'copy');
    fs.cpSync(copy, changed, { recursive: true });
    const changedMember = path.join(changed, 'cases/permit/action-intent-receipt.json');
    const bytes = fs.readFileSync(changedMember);
    bytes[0] ^= 1;
    fs.writeFileSync(changedMember, bytes);
    cases.push(oneCase('substituted-byte', adapter,
      ['--aps', changed, '--priorseal', priorsealCase, '--aps-owner', owner], output, 1));
    const missingOwner = path.join(scratch, 'missing-owner');
    cases.push(oneCase('missing-owner', adapter,
      [...common, '--aps-owner', missingOwner], output, 1));
    cases.push(oneCase('missing-owner-flag', adapter, common, output, 2));
    cases.push(oneCase('stale-output', adapter,
      [...common, '--aps-owner', missingOwner], output, 1, true));
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  assert.deepEqual(
    cases.map(({ name, exitCode, reportPresentBefore, reportPresentAfter, acceptedAsFresh }) =>
      ({ name, exitCode, reportPresentBefore, reportPresentAfter, acceptedAsFresh })),
    recorded.cases.map(({ name, exitCode, reportPresentBefore, reportPresentAfter, acceptedAsFresh }) =>
      ({ name, exitCode, reportPresentBefore, reportPresentAfter, acceptedAsFresh })),
  );
  const receipt = {
    schema: 'probity.aps-priorseal-source-replay/v2',
    harness: sourceHarness,
    baseline: { path: 'recorded.json', sha256: recordedSha256 },
    sourceCommits: revisions,
    sourceSha256: digests,
    node: process.version,
    selftest: 'pass',
    selftestProcess: selftest.primary,
    claims: report.claims.map(({ id, result }) => ({ id, result })),
    summary: report.summary,
    sourceBindingComparedFiles: report.pins.aps_owner_fixture_binding.compared_files,
    cases,
    scope: {
      runner: parsed.runner,
      inputCustody: 'public producer fixtures',
      verifier: 'unmodified pinned Frequency review adapter',
      formalFederationRun: false,
      mutationAdequacyRun: false,
      externalWitness: false,
      productionAdoption: false,
    },
  };
  fs.writeFileSync(path.join(output, 'receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ output, runner: parsed.runner,
    harness: sourceHarness, summary: receipt.summary, cases })}\n`);
}

main(process.argv.slice(2));
