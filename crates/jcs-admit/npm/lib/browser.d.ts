export { admit, admit_ijson, JcsError } from "./index.js";

type ModuleInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

/** Initialize the same WASM core; defaults to the package's adjacent .wasm. */
export default function initialize(
  options?: { module_or_path?: ModuleInput | Promise<ModuleInput> },
): Promise<WebAssembly.Exports>;
