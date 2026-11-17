// The summary the cross-language check compares with the Go module's (written
// by its TestWriteSummary). Exported so test/cross.mjs and the tests share it.
import { createHash } from "node:crypto";

import { BYTE_CORPUS, admits, canonical, depthAdmitted, drifts, features, parserDifferential, reject, tooDeep } from "../index.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function summary() {
  const rows = [];
  const row = (kind, corpus, id, input, canon, feats, error, bounded) =>
    rows.push({
      kind,
      corpus,
      id,
      input_sha256: sha256(input),
      canonical_sha256: canon === null ? null : sha256(canon),
      features: feats,
      error,
      bounded_error: bounded,
      integer_only: admits("integer-only", feats),
    });
  for (const [kind, read] of [["canonical", canonical], ["reject", reject], ["too-deep", tooDeep], ["depth-admitted", depthAdmitted]]) {
    for (const v of read()) row(kind, v.corpus, v.id, v.input, v.canonical, v.features, "", "");
  }
  for (const d of drifts()) row("drift", BYTE_CORPUS, d.id, d.input, d.canonical, features(d.input, d.canonical), "", "");
  for (const d of parserDifferential()) row("differential", BYTE_CORPUS, d.id, d.input, d.canonical, d.features, d.error, d.boundedError);
  const key = (r) => [r.kind, r.corpus, r.id];
  rows.sort((a, b) => {
    const [x, y] = [key(a), key(b)];
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
  });
  return rows;
}
