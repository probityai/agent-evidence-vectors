import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SIGSTORE_REVISION, loadSigstoreSource } from './native.mjs';

const [destination, ...extra] = process.argv.slice(2);
if (!destination || extra.length) throw new Error('usage: node install.mjs NEW_DIRECTORY');
await loadSigstoreSource();
const target = resolve(destination);
// Refuse an existing directory so installation cannot overwrite retained work.
await mkdir(target);
const files = ['consumer.mjs', 'native.mjs', 'json.mjs', 'cli.mjs', 'source-manifest.json'];
const hashes = [];
for (const name of files) {
  const source = new URL(`./${name}`, import.meta.url);
  const bytes = await readFile(source);
  await writeFile(join(target, name), bytes);
  hashes.push({ path: name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
}
await cp(fileURLToPath(new URL('./vendor', import.meta.url)), join(target, 'vendor'), { recursive: true });
await writeFile(join(target, 'installation.json'), `${JSON.stringify({
  schema: 'probity.sigstore-js-installed-consumer.v1',
  sourceRevision: SIGSTORE_REVISION,
  runtime: process.version,
  installation: 'Standalone copied Node modules with retained, hash-checked Sigstore source; no npm dependencies.',
  files: hashes,
}, null, 2)}\n`);
console.log('installed standalone Sigstore-source threshold consumer');
