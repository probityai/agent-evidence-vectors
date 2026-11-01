import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { verifyThreshold } from './consumer.mjs';
import { parseUniqueJSON } from './json.mjs';
import { SIGSTORE_REVISION } from './native.mjs';

const [envelopePath, policyPath, reportPath, ...extra] = process.argv.slice(2);
if (!envelopePath || !policyPath || !reportPath || extra.length) {
  console.error('usage: node cli.mjs ENVELOPE.json POLICY.json REPORT.json');
  process.exit(2);
}
if ([envelopePath, policyPath].some(path => resolve(path) === resolve(reportPath))) {
  console.error('report path must differ from input paths');
  process.exit(2);
}
// Clear a stale report before any input or verification step can fail.
await writeFile(reportPath, '');
try {
  const envelope = parseUniqueJSON(await readFile(envelopePath, 'utf8'));
  const policyBytes = await readFile(policyPath);
  const policy = parseUniqueJSON(policyBytes.toString('utf8'));
  const verified = await verifyThreshold(envelope, policy.keys, policy.threshold);
  const report = {
    schema: 'probity.sigstore-dsse-consumer.v1',
    sourceRevision: SIGSTORE_REVISION,
    decision: 'verified-offline-dsse',
    payloadType: verified.payloadType,
    payload: verified.payload.toString('base64'),
    payloadSHA256: createHash('sha256').update(verified.payload).digest('hex'),
    acceptedKeys: verified.acceptedKeys,
    acceptedIdentities: verified.acceptedIdentities,
    threshold: policy.threshold,
    policySHA256: createHash('sha256').update(policyBytes).digest('hex'),
    scope: 'Ed25519 signature integrity under supplied trusted keys; authority, effects and publication are separate.',
  };
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`verified ${verified.payload.length} bytes using ${verified.acceptedKeys.length} distinct key(s)`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
