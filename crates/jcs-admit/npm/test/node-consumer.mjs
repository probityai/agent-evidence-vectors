import * as api from "jcs-admit";
import { readFile } from "node:fs/promises";
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
console.log(JSON.stringify({ runtime: process.version, counts, inputContract: true, crossRealm: true, installedPackage: import.meta.resolve("jcs-admit") }));
