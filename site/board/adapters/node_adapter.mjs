// Answer the a2a-jcs-v01 external-verifier contract for one TypeScript or JavaScript function.
//
//   tsx node_adapter.mjs --file PATH --func NAME TARGET INPUT.json
//
// Exit 0 and {"canonical_utf8_hex": ...} on the last stdout line: the function returned a
// string. Exit 1: it threw, a refusal. Exit 2: the adapter could not run (usage, import).
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const argv = process.argv.slice(2);
const opts = {};
const rest = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--file") opts.file = argv[++i];
  else if (argv[i] === "--func") opts.func = argv[++i];
  else rest.push(argv[i]);
}
let fn, text;
try {
  const [target, input] = rest;
  if (target !== "rfc8785" || !opts.file || !opts.func || !input) throw new Error("usage");
  const mod = await import(pathToFileURL(resolve(opts.file)).href);
  fn = mod[opts.func];
  if (typeof fn !== "function") throw new Error(`no function ${opts.func}`);
  text = readFileSync(input, "utf8");
} catch (e) {
  console.error(`adapter-error: ${e && e.message}`);
  process.exit(2);
}
let out;
try {
  out = fn(JSON.parse(text));
  if (typeof out !== "string") throw new TypeError("function returned a non-string");
} catch (e) {
  console.error(`refused: ${e && e.name}: ${e && e.message}`);
  process.exit(1);
}
console.log(JSON.stringify({ canonical_utf8_hex: Buffer.from(out, "utf8").toString("hex") }));
