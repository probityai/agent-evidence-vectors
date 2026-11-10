// Reader for the approval-binding/v2 corpus.
//
// Not ported yet: judge returns the unimplemented verdict for every record.

import { type Json, type Verdict, unimplemented } from "./common.js";

/**
 * Derive the verdict for one record. `record` is the parsed record.json
 * (integers are bigint, other numbers are number) and `recordBytes` the exact
 * bytes it was parsed from.
 */
export function judge(_record: Json, _recordBytes: Uint8Array): Verdict {
  return unimplemented();
}
