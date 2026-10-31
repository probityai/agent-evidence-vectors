export { verify, pae, DsseError, type TrustedKey, type VerifiedPayload } from "./index.js";

type ModuleInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

/** Initialize the adjacent WASM artifact before a browser call. */
export default function initialize(
  options?: { module_or_path?: ModuleInput | Promise<ModuleInput> },
): Promise<WebAssembly.Exports>;
