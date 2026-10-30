import { readFile } from "node:fs/promises";
import initialize from "../generated/dsse.js";

await initialize({
  module_or_path: await readFile(new URL("../generated/dsse_bg.wasm", import.meta.url)),
});

export { verify, pae, DsseError } from "./api.mjs";
