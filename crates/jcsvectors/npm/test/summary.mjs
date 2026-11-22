// The summary the cross-language check compares with the Go module's (written
// by its TestWriteSummary). Exported so test/cross.mjs and the tests share it.
import { createHash } from "node:crypto";

import { BYTE_CORPUS, admits, canonical, depthAdmitted, drifts, features, includes, parserDifferential, reject, tooDeep } from "../index.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function summary() {
  const rows = [];
  // integerOnly is what filter decides for a vector, and what admits decides
  // for a drift or a differential, which no reader filters.
  const row = (kind, corpus, id, clause, family, input, canon, feats, error, bounded, integerOnly) =>
    rows.push({
      kind,
      corpus,
      id,
      clause,
      family,
      input_sha256: sha256(input),
      canonical_sha256: canon === null ? null : sha256(canon),
      features: feats,
      error,
      bounded_error: bounded,
      integer_only: integerOnly,
    });
  for (const [kind, read] of [["canonical", canonical], ["reject", reject], ["too-deep", tooDeep], ["depth-admitted", depthAdmitted]]) {
    for (const v of read()) row(kind, v.corpus, v.id, v.clause, "", v.input, v.canonical, v.features, "", "", includes("integer-only", v));
  }
  for (const d of drifts()) {
    const feats = features(d.input, d.canonical);
    row("drift", BYTE_CORPUS, d.id, "", d.family, d.input, d.canonical, feats, "", "", admits("integer-only", feats));
  }
  for (const d of parserDifferential()) {
    row("differential", BYTE_CORPUS, d.id, "", d.family, d.input, d.canonical, d.features, d.error, d.boundedError, admits("integer-only", d.features));
  }
  const key = (r) => [r.kind, r.corpus, r.id];
  rows.sort((a, b) => {
    const [x, y] = [key(a), key(b)];
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
  });
  return rows;
}
