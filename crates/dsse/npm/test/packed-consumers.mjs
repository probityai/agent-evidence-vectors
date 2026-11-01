import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readFile, writeFile, copyFile, readdir, rm, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { loadCases } from "./cases.mjs";
import { assert } from "./check.mjs";

const npmRoot = fileURLToPath(new URL("../", import.meta.url));
const root = path.dirname(npmRoot);
const receipts = path.resolve(process.env.DSSE_TEST_RECEIPTS || path.join(npmRoot, "test-results"));
await mkdir(receipts, { recursive: true });
const steps = [];

async function checked(label, command, args, options = {}) {
  const child = spawnSync(command, args, { cwd: root, maxBuffer: 64 << 20, timeout: 120000, ...options });
  steps.push({ label, nativeExit: child.status, signal: child.signal });
  await writeFile(path.join(receipts, `${label}.stdout`), child.stdout || Buffer.alloc(0));
  await writeFile(path.join(receipts, `${label}.stderr`), child.stderr || Buffer.alloc(0));
  if (child.status !== 0 || child.signal !== null) throw new Error(`${label}: native ${child.status}, signal ${child.signal}: ${child.error?.message || ""}`);
  return child.stdout || Buffer.alloc(0);
}

function nativeRequest(item) {
  return item.operation === "verify"
    ? { id: item.id, operation: item.operation, envelope: item.envelope, trusted_keys: item.trusted_keys, threshold: item.threshold }
    : { id: item.id, operation: item.operation, payload_type: item.payload_type, payload: item.payload };
}

const consumer = await mkdtemp(path.join(os.tmpdir(), "dsse-packed-consumer-"));
let server;
let browser;
const result = { nativeExit: 1, steps, rawOperations: ["verify", "pae"], actualInstalledArtifact: true };
try {
  const loaded = await loadCases();
  const requests = loaded.cases.map(nativeRequest);
  const oracle = process.env.DSSE_NATIVE_ORACLE || path.join(process.env.CARGO_TARGET_DIR || path.join(root, "target"), "debug/examples/wasm_oracle");
  const native = await checked("native-oracle", oracle, [], { input: requests.map((row) => JSON.stringify(row)).join("\n") + "\n" });
  const lines = native.toString().trimEnd().split("\n");
  assert(lines.length === requests.length && lines.length > 40, "Native oracle case population is incomplete");
  const expected = lines.map((line, index) => {
    const value = JSON.parse(line);
    assert(value.id === requests[index].id && typeof value.ok === "boolean", "Native oracle response order/source differs");
    return { ...value, caseIndex: index };
  });
  const packageRows = JSON.parse((await checked("npm-pack", "npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", receipts], { cwd: path.join(npmRoot, "dist") })).toString());
  assert(packageRows.length === 1, "Expected one actual packed npm artifact");
  const packed = path.join(receipts, packageRows[0].filename);
  const rawTarball = await readFile(packed);
  result.tarball = { filename: packageRows[0].filename, bytes: rawTarball.length, sha256: createHash("sha256").update(rawTarball).digest("hex"), integrity: packageRows[0].integrity };
  await writeFile(path.join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  await checked("consumer-install", "npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", packed], { cwd: consumer });
  const installed = path.join(consumer, "node_modules/dsse");
  const manifest = JSON.parse(await readFile(path.join(installed, "package.json"), "utf8"));
  const build = JSON.parse(await readFile(path.join(installed, "BUILD.json"), "utf8"));
  assert(manifest.name === "dsse" && manifest.version === "0.1.0" && !manifest.scripts && !Object.keys(manifest.dependencies || {}).length, "Installed package has an unexpected identity or runtime dependency");
  for (const [relative, digest] of Object.entries(build.artifact_files)) {
    assert(!relative.includes("\\") && !path.posix.isAbsolute(relative) && path.posix.normalize(relative) === relative && !relative.split("/").includes(".."), "Packed source member name is not canonical");
    assert(createHash("sha256").update(await readFile(path.join(installed, relative))).digest("hex") === digest, `Packed artifact differs: ${relative}`);
  }
  const generated = await readdir(path.join(installed, "generated"));
  assert(generated.filter((name) => name.endsWith(".wasm")).length === 1, "Expected one shared WASM artifact");
  result.package = { name: manifest.name, version: manifest.version, sourceSha256: build.source_sha256, sourceCommit: build.source_commit, sourceDirty: build.source_dirty, filesVerified: Object.keys(build.artifact_files).length };
  await writeFile(path.join(consumer, "cases.json"), JSON.stringify({ cases: loaded.cases, expected }));
  for (const name of ["node-consumer.mjs", "check.mjs", "types.ts"]) await copyFile(path.join(npmRoot, "test", name), path.join(consumer, name));
  const nodeExecutables = [...new Set([process.execPath, process.env.DSSE_NODE_MIN].filter(Boolean))];
  assert(nodeExecutables.length === 2, "Two distinct Node executables are required, including DSSE_NODE_MIN");
  result.node = [];
  for (let index = 0; index < nodeExecutables.length; index += 1) {
    result.node.push(JSON.parse((await checked(`node-consumer-${index}`, nodeExecutables[index], [path.join(consumer, "node-consumer.mjs")], { cwd: consumer })).toString()));
  }
  await writeFile(path.join(consumer, "tsconfig.json"), JSON.stringify({ compilerOptions: { target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", strict: true, noEmit: true, types: [], lib: ["ES2022", "DOM"] }, files: ["types.ts"] }));
  const tsManifest = JSON.parse(await readFile(path.join(npmRoot, "node_modules/typescript/package.json"), "utf8"));
  await checked("typescript-consumer", path.resolve(npmRoot, "node_modules/typescript", tsManifest.bin.tsc), ["--project", path.join(consumer, "tsconfig.json")], { cwd: consumer });
  result.typescript = { version: tsManifest.version, nativeExit: 0 };

  const browserEntry = "/node_modules/dsse/" + manifest.exports["./browser"].default.replace(/^\.\//, "");
  await writeFile(path.join(consumer, "index.html"), `<!doctype html><html lang="en"><meta charset="utf-8"><link rel="icon" href="data:,"><title>DSSE packed browser consumer</title><script type="importmap">${JSON.stringify({ imports: { "dsse/browser": browserEntry } })}</script><body>Packed artifact test</body></html>`);
  server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://127.0.0.1");
      const relative = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
      const file = path.resolve(consumer, "." + relative);
      if (!file.startsWith(consumer + path.sep)) { response.writeHead(403).end(); return; }
      const body = await readFile(file);
      const mime = file.endsWith(".wasm") ? "application/wasm" : /\.(?:mjs|js)$/.test(file) ? "text/javascript" : file.endsWith(".json") ? "application/json" : "text/html";
      response.writeHead(200, { "Content-Type": mime, "Cache-Control": "no-store" }).end(body);
    } catch { response.writeHead(404).end(); }
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const browserResult = await page.evaluate(async () => {
    const api = await import("dsse/browser");
    const { assert, checkCase, checkInputContract, checkedPayload, same } = await import("./check.mjs");
    await api.default();
    const data = await (await fetch("./cases.json")).json();
    const item = data.cases.find((value) => value.id === "reference/verify/binary_batch_root");
    const expected = data.expected.find((value) => value.id === item.id);
    const controls = checkInputContract(api, item, expected);
    const frame = document.createElement("iframe");
    document.body.append(frame);
    try {
      const foreign = new frame.contentWindow.Uint8Array([0xff, ...item.envelope, 0xff]).subarray(1, -1);
      const foreignKey = new frame.contentWindow.Uint8Array(item.trusted_keys[0].public_key);
      assert(!(foreign instanceof Uint8Array) && !(foreignKey instanceof Uint8Array), "Browser control did not create another realm");
      same(checkedPayload(api.verify(foreign, [{ public_key: foreignKey, key_id: item.trusted_keys[0].key_id }], 1), "browser cross realm"), expected.verified, "Browser cross-realm envelope/key extent");
      same([...api.pae("t", new frame.contentWindow.Uint8Array([0, 255]))], [...api.pae("t", new Uint8Array([0, 255]))], "Browser cross-realm PAE payload");
    } finally { frame.remove(); }
    const counts = { accepted: 0, refused: 0 };
    for (const answer of data.expected) counts[checkCase(api, data.cases[answer.caseIndex], answer)] += 1;
    return { counts, inputContract: true, crossRealm: true, actualPackageModule: true, controls };
  });
  assert(pageErrors.length === 0, `Browser runtime errors: ${pageErrors.join("; ")}`);
  result.browser = { ...browserResult, engine: "Chromium", version: browser.version(), headless: true };
  await writeFile(path.join(receipts, "browser-consumer.json"), JSON.stringify(result.browser, null, 2) + "\n");

  const guide = await readFile(path.join(root, "docs/NPM.md"), "utf8");
  const fence = guide.match(/```js\n([\s\S]*?)\n```/);
  assert(fence, "Guide has no executable verify-example.mjs fence");
  const example = Buffer.from(fence[1] + "\n");
  await writeFile(path.join(consumer, "verify-example.mjs"), example);
  const documented = await checked("documentation-example", process.execPath, [path.join(consumer, "verify-example.mjs")], { cwd: consumer });
  assert(documented.toString() === "verified empty reference payload\n", "Guide example did not produce its stated result");
  result.documentationExample = { source: "docs/NPM.md", sha256: createHash("sha256").update(example).digest("hex"), nativeExit: 0 };
  result.retainedCounts = loaded.retainedCounts;
  result.sourceFixtureSha256 = loaded.sourceFiles;
  result.scope = loaded.scope;
  result.callsPerRuntime = expected.length;
  result.nativeExit = 0;
} catch (error) {
  result.error = { name: error.name, message: error.message, stack: error.stack };
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
  if (server) await new Promise((resolve) => server.close(resolve));
  await rm(consumer, { recursive: true, force: true });
  result.ownedConsumerRemoved = true;
  await writeFile(path.join(receipts, "RESULT.json"), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify({ nativeExit: result.nativeExit, tarball: result.tarball, node: result.node, browser: result.browser, typescript: result.typescript, documentationExample: result.documentationExample, callsPerRuntime: result.callsPerRuntime, error: result.error?.message }));
}
