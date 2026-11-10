// The six suites this package reads, and the corpus-level run the CLI prints.

import { join } from "node:path";

import * as approvalBindingV2 from "./approval-binding-v2.js";
import * as attenuatedDelegation from "./attenuated-delegation.js";
import { type Json, type Verdict, ReaderError, loadManifest, readRecord } from "./common.js";
import * as decisionClient from "./decision-client.js";
import * as durableHistory from "./durable-history.js";
import * as grantUse from "./grant-use.js";
import * as revocationEpoch from "./revocation-epoch.js";

/** A family's derivation: the parsed record and the exact bytes it came from. */
export type JudgeFn = (record: Json, recordBytes: Uint8Array) => Verdict;

/** Each suite named by a manifest's `suite` member, with its family's judge. */
export const SUITES: ReadonlyMap<string, JudgeFn> = new Map<string, JudgeFn>([
  ["attenuated-delegation/v1", attenuatedDelegation.judge],
  ["grant-use/v1", grantUse.judge],
  ["revocation-epoch/v1", revocationEpoch.judge],
  ["durable-history/v1", durableHistory.judge],
  ["approval-binding/v2", approvalBindingV2.judge],
  ["decision-client-failure-modes/v1", decisionClient.judge],
]);

/**
 * One `<id>\t<decision>\t<reason>` line per manifest vector, in manifest order,
 * derived from each case's record.json alone.
 * Throws ReaderError when the corpus is unreadable or its suite unknown.
 */
export function verdictLines(dir: string): string[] {
  const manifest = loadManifest(dir);
  const judge = SUITES.get(manifest.suite);
  if (judge === undefined) {
    throw new ReaderError(`unknown suite ${JSON.stringify(manifest.suite)}`);
  }
  return manifest.vectors.map((vector) => {
    const { record, bytes } = readRecord(join(dir, vector.path));
    const verdict = judge(record, bytes);
    return `${vector.id}\t${verdict.decision}\t${verdict.reason}`;
  });
}
