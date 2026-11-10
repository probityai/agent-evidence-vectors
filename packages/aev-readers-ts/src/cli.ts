#!/usr/bin/env node
// aev-verdicts <corpus-dir>: print `<id>\t<decision>\t<reason>` for every manifest
// vector, in manifest order, derived from each record.json alone.
// Exit 0 when the run completed, 2 when the corpus is unreadable or its suite
// is unknown.

import { ReaderError } from "./common.js";
import { verdictLines } from "./verdicts.js";

function main(argv: readonly string[]): number {
  const [dir, ...extra] = argv;
  if (dir === undefined || extra.length > 0) {
    process.stderr.write("usage: aev-verdicts <corpus-dir>\n");
    return 2;
  }
  try {
    const lines = verdictLines(dir);
    process.stdout.write(lines.map((line) => `${line}\n`).join(""));
    return 0;
  } catch (error) {
    if (error instanceof ReaderError) {
      process.stderr.write(`aev-verdicts: ${error.message}\n`);
      return 2;
    }
    throw error;
  }
}

process.exitCode = main(process.argv.slice(2));
