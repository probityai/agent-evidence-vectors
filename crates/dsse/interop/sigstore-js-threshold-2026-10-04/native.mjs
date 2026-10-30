import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SIGSTORE_REVISION = '769a53d8713248a8bf49edfc2a5d1955b0dcc24d';
export const SOURCE_HASHES = Object.freeze({
  'packages/core/src/crypto.ts': '4475b75ab49f1f8b899cd9d92acc2b413447fd1d855faff2c2e703b8429ff504',
  'packages/core/src/dsse.ts': 'd79190ca5fe9d776076a4c45dad4939734b2ff212f6152802aa6136f69a62636',
  'packages/verify/src/bundle/dsse.ts': '4c8086ec138c2afba83696ea5466a50978568bbf1ef0c30af8f77d14019daed5',
});
const DEFAULT_VENDOR = fileURLToPath(new URL('./vendor', import.meta.url));

function moduleURL(source) {
  const javascript = stripTypeScriptTypes(source, { mode: 'strip' });
  return `data:text/javascript;base64,${Buffer.from(javascript).toString('base64')}`;
}

async function sourceFile(root, path, expected) {
  const bytes = await readFile(join(root, path));
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) throw new Error(`native source hash differs: ${path}`);
  return bytes.toString('utf8');
}

/**
 * Load the exact retained Sigstore functions after checking their fixed hashes.
 *
 * Only TypeScript syntax and import resolution change at runtime. No signature,
 * digest, PAE or selection logic is replaced. See source-manifest.json for the
 * originals and adaptation list. This is source execution, not an npm install.
 *
 * @param {string} root - Directory containing the retained publisher files.
 * @returns {Promise<object>} Native DSSESignatureContent and PAE functions.
 * @throws {Error} When a retained source hash differs or a module cannot load.
 */
export async function loadSigstoreSource(root = DEFAULT_VENDOR) {
  const sources = Object.fromEntries(await Promise.all(
    Object.entries(SOURCE_HASHES).map(async ([path, hash]) =>
      [path, await sourceFile(root, path, hash)]),
  ));
  const crypto = moduleURL(sources['packages/core/src/crypto.ts'].replace(
    "import crypto, { BinaryLike } from 'crypto';",
    "import crypto from 'node:crypto';",
  ));
  const dsse = moduleURL(sources['packages/core/src/dsse.ts']);
  const content = moduleURL(sources['packages/verify/src/bundle/dsse.ts'].replace(
    "import { crypto, dsse } from '@sigstore/core';",
    `import * as crypto from '${crypto}'; import * as dsse from '${dsse}';`,
  ));
  const [signature, encoding] = await Promise.all([import(content), import(dsse)]);
  return Object.freeze({ ...signature, ...encoding, sourceRevision: SIGSTORE_REVISION });
}
