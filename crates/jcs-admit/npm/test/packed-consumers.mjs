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
const receipts = path.resolve(process.env.JCS_TEST_RECEIPTS || path.join(npmRoot, "test-results"));
await mkdir(receipts, { recursive: true });
const steps = [];

function run(label, command, args, options = {}) {
  const child = spawnSync(command, args, { cwd: root, maxBuffer: 64 << 20, ...options });
  steps.push({ label, nativeExit: child.status, signal: child.signal });
  return { child, stdout: child.stdout || Buffer.alloc(0), stderr: child.stderr || Buffer.alloc(0) };
}

async function checked(label, command, args, options = {}) {
  const result = run(label, command, args, options);
  await writeFile(path.join(receipts, `${label}.stdout`), result.stdout);
  await writeFile(path.join(receipts, `${label}.stderr`), result.stderr);
  if (result.child.status !== 0) throw new Error(`${label}: native ${result.child.status}, signal ${result.child.signal}`);
  return result.stdout;
}

const consumer = await mkdtemp(path.join(os.tmpdir(), "jcs-packed-consumer-"));
let server;
let browser;
const result = { nativeExit: 1, steps, rawByteProfiles: ["admit", "admit_ijson"], actualInstalledArtifact: true };
try {
  const loaded = await loadCases();
  assert(new Set(loaded.cases.map((item) => item.id)).size === loaded.cases.length, "Case IDs collide");
  const requests = loaded.cases.flatMap((item, caseIndex) => ["admit", "admit_ijson"].map((profile) => ({ id: item.id, profile, bytes: item.bytes, repeat: item.repeat, caseIndex })));
  const oracle = process.env.JCS_NATIVE_ORACLE || path.join(process.env.CARGO_TARGET_DIR || path.join(root, "target"), "debug/examples/wasm_oracle");
  const native = await checked("native-oracle", oracle, [], { input: requests.map((row) => JSON.stringify(row)).join("\n") + "\n" });
  const expected = native.toString().trimEnd().split("\n").map((line, index) => {
    const value = JSON.parse(line);
    assert(value.id === requests[index].id && value.profile === requests[index].profile, "Native oracle response order/source differs");
    return { ...value, caseIndex: requests[index].caseIndex };
  });
  assert(expected.length === requests.length && expected.length > 2000, "Native oracle coverage is incomplete");
  const packageRows = JSON.parse((await checked("npm-pack", "npm", ["pack", "--json", "--pack-destination", receipts], { cwd: path.join(npmRoot, "dist") })).toString());
  assert(packageRows.length === 1, "Expected one packed npm artifact");
  const packed = path.join(receipts, packageRows[0].filename);
  result.tarball = { filename: packageRows[0].filename, bytes: (await readFile(packed)).length, sha256: createHash("sha256").update(await readFile(packed)).digest("hex"), integrity: packageRows[0].integrity };
  await writeFile(path.join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  await checked("consumer-install", "npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", packed], { cwd: consumer });
  const installed = path.join(consumer, "node_modules/jcs-admit");
  const manifest = JSON.parse(await readFile(path.join(installed, "package.json"), "utf8"));
  const build = JSON.parse(await readFile(path.join(installed, "BUILD.json"), "utf8"));
  assert(manifest.name === "jcs-admit" && !manifest.scripts && !Object.keys(manifest.dependencies || {}).length, "Installed package unexpectedly has runtime scripts/dependencies");
  for (const [relative, digest] of Object.entries(build.artifact_files)) {
    const actual = createHash("sha256").update(await readFile(path.join(installed, relative))).digest("hex");
    assert(actual === digest, `Packed artifact differs: ${relative}`);
  }
  const generated = await readdir(path.join(installed, "generated"));
  assert(generated.filter((name) => name.endsWith(".wasm")).length === 1, "Expected one shared WASM artifact");
  result.package = { name: manifest.name, version: manifest.version, sourceSha256: build.source_sha256, sourceCommit: build.source_commit, sourceDirty: build.source_dirty, filesVerified: Object.keys(build.artifact_files).length };
  await writeFile(path.join(consumer, "cases.json"), JSON.stringify({ cases: loaded.cases, expected }));
  for (const name of ["node-consumer.mjs", "check.mjs", "types.ts"]) await copyFile(path.join(npmRoot, "test", name), path.join(consumer, name));
  const nodeExecutables = [...new Set([process.execPath, process.env.JCS_NODE_MIN].filter(Boolean))];
  result.node = [];
  for (let index = 0; index < nodeExecutables.length; index += 1) {
    const output = await checked(`node-consumer-${index}`, nodeExecutables[index], [path.join(consumer, "node-consumer.mjs")], { cwd: consumer });
    result.node.push(JSON.parse(output.toString().trim()));
  }
  await writeFile(path.join(consumer, "tsconfig.json"), JSON.stringify({ compilerOptions: { target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", strict: true, noEmit: true, types: [], lib: ["ES2022", "DOM"] }, files: ["types.ts"] }));
  const tsManifest = JSON.parse(await readFile(path.join(npmRoot, "node_modules/typescript/package.json"), "utf8"));
  await checked("typescript-consumer", path.resolve(npmRoot, "node_modules/typescript", tsManifest.bin.tsc), ["--project", path.join(consumer, "tsconfig.json")], { cwd: consumer });
  result.typescript = { version: tsManifest.version, nativeExit: 0 };
  const browserEntry = "/node_modules/jcs-admit/" + manifest.exports["./browser"].default.replace(/^\.\//, "");
  await writeFile(path.join(consumer, "index.html"), `<!doctype html><html lang="en"><meta charset="utf-8"><title>JCS packed browser consumer</title><script type="importmap">${JSON.stringify({ imports: { "jcs-admit/browser": browserEntry } })}</script><body>Packed artifact test</body></html>`);
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
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const browserResult = await page.evaluate(async () => {
    const api = await import("jcs-admit/browser");
    const { checkCase, checkInputContract, same } = await import("./check.mjs");
    await api.default();
    const data = await (await fetch("./cases.json")).json();
    checkInputContract(api);
    const frame = document.createElement("iframe");
    document.body.append(frame);
    try {
      const foreign = new frame.contentWindow.Uint8Array([0, 123, 125, 0]).subarray(1, 3);
      if (foreign instanceof Uint8Array) throw new Error("Browser control did not create another realm");
      same([...api.admit(foreign)], [123, 125], "browser cross-realm byte view");
    } finally { frame.remove(); }
    const counts = { accepted: 0, refused: 0 };
    for (const expected of data.expected) counts[checkCase(api, data.cases[expected.caseIndex], expected)] += 1;
    return { counts, inputContract: true, crossRealm: true, actualPackageModule: true };
  });
  result.browser = { ...browserResult, engine: "Chromium", version: browser.version(), headless: true };
  await writeFile(path.join(receipts, "browser-consumer.json"), JSON.stringify(result.browser, null, 2) + "\n");
  result.retainedCounts = loaded.retainedCounts;
  result.sourceFixtureSha256 = loaded.sourceFiles;
  result.scope = loaded.scope;
  result.profileCallsPerRuntime = expected.length;
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
  console.log(JSON.stringify({ nativeExit: result.nativeExit, tarball: result.tarball, node: result.node, browser: result.browser, typescript: result.typescript, profileCallsPerRuntime: result.profileCallsPerRuntime, error: result.error?.message }));
}
