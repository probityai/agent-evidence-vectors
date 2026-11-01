import * as api from "dsse";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import { assert, checkCase, checkInputContract, checkedPayload, keyInputs, same } from "./check.mjs";

const data = JSON.parse(await readFile(new URL("./cases.json", import.meta.url), "utf8"));
const item = data.cases.find((value) => value.id === "reference/verify/binary_batch_root");
const expected = data.expected.find((value) => value.id === item.id);
const controls = checkInputContract(api, item, expected);
const foreign = runInNewContext(`new Uint8Array(${JSON.stringify([0xff, ...item.envelope, 0xff])}).subarray(1,-1)`);
const foreignKey = runInNewContext(`new Uint8Array(${JSON.stringify(item.trusted_keys[0].public_key)})`);
assert(!(foreign instanceof Uint8Array) && !(foreignKey instanceof Uint8Array), "Control did not create another realm");
same(checkedPayload(api.verify(foreign, [{ public_key: foreignKey, key_id: item.trusted_keys[0].key_id }], 1), "cross realm"), expected.verified, "Cross-realm envelope and key views");
same(checkedPayload(api.verify(Buffer.from(item.envelope), keyInputs(item), 1), "Node Buffer"), expected.verified, "Node Buffer is a byte view");
const foreignPayload = runInNewContext("new Uint8Array([0,255,128,65])");
same([...api.pae("t", foreignPayload)], [...api.pae("t", new Uint8Array([0, 255, 128, 65]))], "Cross-realm PAE payload");
const counts = { accepted: 0, refused: 0 };
for (const answer of data.expected) counts[checkCase(api, data.cases[answer.caseIndex], answer)] += 1;
console.log(JSON.stringify({ runtime: process.version, counts, inputContract: true, crossRealm: true, controls, installedPackage: import.meta.resolve("dsse") }));
