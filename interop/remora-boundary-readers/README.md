# REMORA execution boundaries

Separate readers for REMORA's frozen call-binding, fresh-authority and effect-evidence
packages. The source pin is `fe324dd734734d9227aa894330ac52c2bb916b94`.
The authored manifests name an earlier revision; [source-lock.json](source-lock.json)
keeps both identities and every consumed file digest.

The reader admits raw JSON before parsing, signs fixture authorizations with a public,
test-only HMAC key, checks that signature, and invokes a local callback only after
the call passes its binding and authority checks. This exercises the bounded contract;
it does not call a production tool or authenticate a REMORA-issued authorization.

| Reader | What it checks |
| --- | --- |
| Call binding | Tool, typed arguments, array order, tenant, target, principal and single use. Refused mismatches leave the authorization unspent. |
| Fresh authority | The validity window, visible revocation, observation, policy and tool-definition state at presentation. Grant admission stays separate from dispatch. |
| Effect evidence | Dispatch, the tool's report and the supplied observation of declared fields. Missing observations, mismatches and vacuous postconditions keep their distinct states. |

The frozen effect package names `hash` without defining its preimage or including a
case that uses it. This reader returns `EFFECT_UNSUPPORTED` for that rule until the
contract supplies an exact definition. Frozen cases are unchanged; additional controls
are generated separately in [controls.py](controls.py).

## Run the installed reader

```sh
python -m pip install ./interop/remora-boundary-readers
probity-remora-boundary --profile interop/remora-boundary-readers \
  --output .build/remora-native \
  --implementation-revision "$(git rev-parse HEAD)"
```

The output path must be new. Malformed input exits with no property verdict.
Duplicate keys, escaped duplicate names, invalid UTF-8, non-JSON numbers and
oversized input are refused before evaluation.

The [native workflow](../../.github/workflows/ci.yml) (job `remora_boundary_readers`) installs
the reader and pinned [Probity Verify](https://github.com/probityai/probity-verify),
then retains every fixture decision, additional case, source mutation, malformed-input
control, command, exit status and environment. The source mutations disable signature
verification, principal binding, replay prevention, revocation, stale-policy checks,
strict scalar kinds and effect-state separation in isolated copies. A separate endpoint
control checks the exclusive expiry boundary.

## Verify bridge

The bridge runs Verify's installed `event_absence/v1` adapter on the local callback
log from each executed call-binding fixture. A dispatch event contradicts an absence
claim. An empty log supports it only within the declared finite scope, with matching
consumer pins, field visibility and complete coverage. Missing visibility, unknown
coverage, a different invocation and changed bytes leave the claim unestablished.
Malformed pinned bytes produce no verdict.

Verify's adapter uses UTC seconds. The bridge rounds the start down and the end up,
and retains the original callback timestamps alongside that projection.

These decisions concern the executed fixture callback log. They do not establish
external target effects, the provenance of an independently operated Observer,
causation, production safety or host adoption.

## Source and operator

This is a second implementation maintained by Probity, with an implementation-owned
qualification run. REMORA runtime and reference-verifier bytes are neither imported
nor executed. Reference file digests remain in the producer manifests as package
identity records; the files themselves are absent.

The native result is labeled `L2_SECOND_IMPLEMENTATION`. Outside custody, producer
review and any lifecycle change are separate steps. The existing E7 review and its
publication timing remain separate from these new packages.

Original REMORA fixture text, schemas, manifests and notices in [source](source) retain
the [upstream license](source/LICENSE) and [notice](source/NOTICE). The reader and
qualification code use this repository's Apache license.
