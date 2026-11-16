import * as api from "jcs-admit";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";
import { checkCase, checkInputContract, same } from "./check.mjs";

const data = JSON.parse(await readFile(new URL("./cases.json", import.meta.url), "utf8"));
const counts = { accepted: 0, refused: 0 };
checkInputContract(api);
const foreign = runInNewContext("new Uint8Array([0,123,125,0]).subarray(1,3)");
if (foreign instanceof Uint8Array) throw new Error("Control did not create another realm");
same([...api.admit(foreign)], [123, 125], "genuine cross-realm Uint8Array view");
same([...api.admit(Buffer.from("{}"))], [123, 125], "Node Buffer is a byte view");
for (let index = 0; index < data.expected.length; index += 1) {
  const expected = data.expected[index];
  const item = data.cases[expected.caseIndex];
  counts[checkCase(api, item, expected)] += 1;
}
console.log(JSON.stringify({ runtime: process.version, counts, inputContract: true, crossRealm: true, installedPackage: installedEntry() }));

// The file the "node" export condition resolves to from this consumer.
// import.meta.resolve is unflagged only from Node 20.6, and the package's
// minimum is 20.0, so the resolution goes through createRequire, which
// applies the same "node" condition to the same exports map.
function installedEntry() {
  return pathToFileURL(createRequire(import.meta.url).resolve("jcs-admit")).href;
}
