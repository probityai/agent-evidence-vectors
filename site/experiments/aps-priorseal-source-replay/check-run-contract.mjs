import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { harness, invocation, retainProcess, validateOutput } from './runner.mjs';

const revisions = {
  review: 'b12879d5878991d9c3ed260d06ee11716eb99d33',
  aps: '948f99b85343bef2c6fa677c8543965caacfc087',
  priorseal: 'd749d2691c3e6be139de4020e7b27cdafca2c428',
};
const wrapperSha256 = '28594cd2dc584beeb2d62818494282dd73c83190a997a6b29680db2b33201e37';

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
  const head = run('git', ['-C', root, 'rev-parse', 'HEAD']);
  assert.equal(head.status, 0, `missing Git checkout at ${root}`);
  assert.equal(head.stdout.trim(), revision, `unexpected checkout revision at ${root}`);
  const dirty = run('git', ['-C', root, 'status', '--porcelain']);
  assert.equal(dirty.status, 0);
  assert.equal(dirty.stdout, '', `dirty checkout at ${root}`);
}

function oneCase(name, wrapper, roots, output, npmCiExit, nodeExit) {
  const attempt = path.join(output, name);
  const invocationLog = path.join(output, `${name}.commands.txt`);
  const report = path.join(attempt, 'frequency-run-report.json');
  const reportPresentBefore = fs.existsSync(report);
  assert.equal(reportPresentBefore, false, `${name}: report existed before execution`);
  const result = run('bash', [wrapper,
    '--repo', roots.review,
    '--adapter-commit', revisions.review,
    '--aps-repo', roots.aps,
    '--priorseal-repo', roots.priorseal,
    '--attempt-dir', attempt,
  ], {
    capture: { directory: output, name },
    env: {
      ...process.env,
      PATH: `${path.join(output, 'bin')}${path.delimiter}${process.env.PATH}`,
      NPM_CI_EXIT: String(npmCiExit),
      NODE_EXIT: String(nodeExit),
      VECTOR_LOG: invocationLog,
    },
  });
  const invocations = fs.readFileSync(invocationLog, 'utf8').trim().split('\n');
  assert.deepEqual(invocations, ['npm:ci', 'npm:run', 'node:verify.mjs'],
    `${name}: injected commands were not reached`);
  const status = fs.readFileSync(path.join(attempt, 'exit-status.txt'), 'utf8').trim();
  const reportPresent = fs.existsSync(report);
  const passPrinted = result.stdout.includes(`PASS: ${report}`);
  assert.equal(result.status, 0, `${name}: wrapper behavior changed`);
  assert.equal(status, '0', `${name}: recorded status changed`);
  assert.equal(passPrinted, true, `${name}: PASS output changed`);
  assert.equal(reportPresent, false, `${name}: stub unexpectedly produced a report`);
  return {
    name,
    injectedNpmCiExit: npmCiExit,
    injectedNodeExit: nodeExit,
    invocations,
    wrapperExit: result.status,
    recordedExit: Number(status),
    passPrinted,
    reportPresentBefore,
    reportPresent,
    meetsRunContract: result.status === 0 && status === '0' && !reportPresentBefore && reportPresent,
    process: result.primary,
  };
}

function main(argv) {
  const parsed = invocation(argv, 'check-run-contract.mjs');
  const sourceHarness = harness(import.meta.url);
  const [review, aps, priorseal, output] = parsed.paths.map(value => path.resolve(value));
  const roots = { review, aps, priorseal };
  validateOutput(output, Object.values(roots));
  for (const [name, root] of Object.entries(roots)) {
    checkout(root, revisions[name]);
  }
  const wrapper = path.join(review, 'capsules/aps-priorseal-v0.1/run-pinned.sh');
  const actualDigest = createHash('sha256').update(fs.readFileSync(wrapper)).digest('hex');
  assert.equal(actualDigest, wrapperSha256, 'review wrapper bytes changed');

  const bin = path.join(output, 'bin');
  fs.mkdirSync(bin, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(bin, 'npm'), '#!/bin/sh\nprintf "npm:%s\\n" "$1" >> "$VECTOR_LOG"\nif [ "$1" = "ci" ]; then exit "$NPM_CI_EXIT"; fi\nexit 0\n', { mode: 0o700 });
  fs.writeFileSync(path.join(bin, 'node'), '#!/bin/sh\nprintf "node:%s\\n" "$1" >> "$VECTOR_LOG"\nexit "$NODE_EXIT"\n', { mode: 0o700 });
  const cases = [
    oneCase('failed-node', wrapper, roots, output, 0, 17),
    oneCase('failed-install', wrapper, roots, output, 23, 0),
    oneCase('missing-report', wrapper, roots, output, 0, 0),
  ];
  const record = {
    schema: 'probity.aps-priorseal-run-contract/v2',
    harness: sourceHarness,
    sourceCommits: revisions,
    wrapperSha256,
    node: process.version,
    method: 'Pinned review wrapper with stubbed npm and node; no adapter or producer claim evaluated',
    cases,
    scope: {
      runner: parsed.runner,
      finding: 'These three stubbed runs print PASS and record zero without a report',
      actualAdapterResult: 'not-exercised',
      formalPilot: false,
    },
  };
  fs.writeFileSync(path.join(output, 'record.json'), `${JSON.stringify(record, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ runner: parsed.runner, harness: sourceHarness,
    cases: cases.map(({ name, meetsRunContract }) => ({ name, meetsRunContract })) })}\n`);
}

main(process.argv.slice(2));
