import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Parse the complete public interface before resolving paths or starting work. */
export function invocation(argv, entry) {
  const usage = `usage: node ${entry} --runner CALLER_ID SOURCE APS PRIORSEAL NEW_OUTPUT_DIR`;
  assert.equal(argv.length, 6, usage);
  assert.equal(argv[0], '--runner', usage);
  const identity = argv[1];
  assert.ok(typeof identity === 'string' && identity.length > 0,
    'runner identity must be nonempty');
  assert.equal(identity, identity.trim(), 'runner identity must not have outer whitespace');
  assert.ok(!/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(identity),
    'runner identity must not contain control characters or line separators');
  assert.ok(Buffer.byteLength(identity, 'utf8') <= 512, 'runner identity exceeds 512 UTF-8 bytes');
  assert.ok(!identity.startsWith('--'), 'runner identity must not be an option');
  const paths = argv.slice(2);
  assert.ok(paths.every(value => value.length > 0 && !value.startsWith('--')),
    'expected four paths; unknown or repeated options are refused');
  return { runner: { identity, source: 'caller-declared' }, paths };
}

/** Bind the entry and its only imported non-builtin dependency, without inferring a publisher. */
export function harness(entryUrl) {
  const files = [entryUrl, new URL('./runner.mjs', import.meta.url)].map(url => {
    const file = fileURLToPath(url);
    return { path: path.basename(file),
      sha256: createHash('sha256').update(fs.readFileSync(file)).digest('hex') };
  });
  return {
    files,
    binding: 'Local source bytes read at invocation; not publisher or operator authentication',
  };
}

/** Refuse an output under a producer checkout, including through a parent symlink. */
export function validateOutput(output, roots) {
  assert.ok(!fs.existsSync(output), 'output directory must not exist');
  let ancestor = output;
  const tail = [];
  while (!fs.existsSync(ancestor)) {
    tail.unshift(path.basename(ancestor));
    ancestor = path.dirname(ancestor);
  }
  const actualOutput = path.join(fs.realpathSync(ancestor), ...tail);
  for (const root of roots) {
    const relative = path.relative(fs.realpathSync(root), actualOutput);
    assert.ok(relative === '..' || relative.startsWith(`..${path.sep}`),
      'output directory must be outside the source checkouts');
  }
}

/** Preserve delivered child bytes and the actual process result before outcome assertions. */
export function retainProcess(directory, name, command, args, options, result, started, ended) {
  const metadata = {
    argv: [command, ...args], cwd: options.cwd ?? process.cwd(), started, ended,
    exit: result.status, signal: result.signal,
    error: result.error ? { name: result.error.name, code: result.error.code ?? null,
      message: result.error.message } : null,
    captureComplete: result.error === undefined,
    environmentOverrides: options.env ? Object.fromEntries(
      ['PATH', 'NPM_CI_EXIT', 'NODE_EXIT', 'VECTOR_LOG'].filter(key => key in options.env)
        .map(key => [key, options.env[key]])) : {},
  };
  const values = [
    [`${name}.stdout`, result.stdout ?? Buffer.alloc(0)],
    [`${name}.stderr`, result.stderr ?? Buffer.alloc(0)],
    [`${name}.command.json`, Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`)],
  ];
  const files = values.map(([relative, raw]) => {
    fs.writeFileSync(path.join(directory, relative), raw, { flag: 'wx' });
    return { path: relative, bytes: raw.length,
      sha256: createHash('sha256').update(raw).digest('hex') };
  });
  return { files };
}
