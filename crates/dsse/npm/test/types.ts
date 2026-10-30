import { verify, pae, DsseError, type TrustedKey, type VerifiedPayload } from "dsse";
import initialize, { verify as browserVerify, pae as browserPae } from "dsse/browser";

const envelope = new Uint8Array([123, 125]);
const keys: readonly TrustedKey[] = [{ public_key: new Uint8Array(32), key_id: "key-a" }];
const checked: VerifiedPayload = verify(envelope, keys, 1);
const payload: Uint8Array = checked.payload;
const ids: readonly string[] = checked.accepted_keys;
const framed: Uint8Array = pae("t", payload);
const browser: VerifiedPayload = browserVerify(envelope, keys, 1);
const browserFramed: Uint8Array = browserPae("t", payload);
const initialized: Promise<WebAssembly.Exports> = initialize();
let error: Error | undefined;
try { verify(envelope, keys, 1); } catch (value) {
  if (value instanceof DsseError) error = value;
}
payload.fill(0);
void [ids, framed, browser, browserFramed, initialized, error];
// @ts-expect-error Verification requires original envelope bytes.
verify("{}", keys, 1);
// @ts-expect-error Numeric arrays are not typed byte views.
verify([123, 125], keys, 1);
// @ts-expect-error Trust anchors contain raw typed public-key bytes.
verify(envelope, [{ public_key: "key" }], 1);
// @ts-expect-error Threshold transport is numeric.
verify(envelope, keys, "1");
// @ts-expect-error PAE also requires raw bytes.
pae("t", "payload");
// @ts-expect-error Accepted key membership is immutable.
checked.accepted_keys.push("extra");
// @ts-expect-error The checked payload property cannot be replaced.
checked.payload = new Uint8Array();
