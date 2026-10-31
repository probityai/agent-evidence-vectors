import { readFile } from "node:fs/promises";
import initialize from "../generated/jcs_admit.js";

await initialize({
  module_or_path: await readFile(new URL("../generated/jcs_admit_bg.wasm", import.meta.url)),
});

export { admit, admit_ijson, JcsError } from "./api.mjs";
