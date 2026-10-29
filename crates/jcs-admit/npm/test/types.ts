import { admit, admit_ijson, JcsError } from "jcs-admit";
import initialize, { admit as browserAdmit } from "jcs-admit/browser";

const raw = new Uint8Array([123, 125]);
const canonical: Uint8Array = admit(raw);
const tightened: Uint8Array = admit_ijson(raw);
let error: Error | undefined;
try { admit(raw); } catch (value) {
  if (value instanceof JcsError) error = value;
}
const browser: Uint8Array = browserAdmit(raw);
const initialized: Promise<WebAssembly.Exports> = initialize();
void [canonical, tightened, error, browser, initialized];
// @ts-expect-error Raw bytes are required, even when the string contains JSON.
admit("{}");
// @ts-expect-error A numeric array is not a raw typed byte view.
admit([123, 125]);
