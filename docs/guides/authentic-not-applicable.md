# A genuine record that is not about the thing in hand

A signature says who made a record and that its bytes did not change. It does
not say the record is about the build, release or artifact the receiving party
is looking at. A receiver that stops at the signature accepts a genuine record
for the wrong thing.

This page names three members of this repository as one group. In each, the
signature verifies and a separate check on the claim does not, and each fails
with its own stop reason, so a reader sees which of the two checks fired.

| Case | Member | What changed | Signature | Claim check |
| --- | --- | --- | --- | --- |
| 1. Valid for release A | [`vffe497f243510a8f`](../../corpora/vectors-admission/INDEX.md), admission | nothing: the consumer pins the digest the observer bound | verifies | admitted |
| 2. The same signed object beside release B | [`v7cb1b503b1949a5f`](../../corpora/vectors-admission/INDEX.md), admission | nothing in the statement: the same file, with a consumer that pins the artifact it deploys | verifies | refused, `subject-anchor-mismatch` |
| 3. A mutated artifact, same metadata | [`vb8a8df5360bc6f37`](../../corpora/vectors-artifact-binding/INDEX.md), artifact binding | one byte of a covered artifact; the signed record is untouched | verifies | `failed`, `artifact-digest-mismatch` and `artifact-length-mismatch` |

Cases 1 and 2 share one statement file, `statements/v96d442af53d71bf4.json`. Only
the consumer's policy differs, so the only thing that moves the answer is what
the consumer says it is looking at. Case 3 has a twin that shows the check is
not a blanket refusal: `vd05d2e7059332fd5`, the same contract with every covered
byte intact, is `verified`.

## Run it

From a checkout of this repository, with `cryptography` installed (the
artifact-binding signature check needs it):

```python
import json
import pathlib
import sys

sys.path[:0] = ["packaging", "tools/artifact-binding"]
import verify
from agent_evidence_vectors import admission

adm = pathlib.Path("corpora/vectors-admission")
members = {v["id"]: v for v in json.loads((adm / "MANIFEST.json").read_text())["vectors"]}
for case, ident in (("1 release A", "vffe497f243510a8f"), ("2 release B", "v7cb1b503b1949a5f")):
    entry = members[ident]
    answer = admission.admit(
        (adm / entry["file"]).read_bytes(),
        admission.load_policy((adm / entry["policy"]).read_bytes()),
    )
    print(f"case {case}: statement {entry['file']}  signed and valid={answer['verdict'] == 'valid'}  "
          f"admitted={answer['admitted']}  codes={answer['policyCodes']}")

ab = pathlib.Path("corpora/vectors-artifact-binding")
manifest = json.loads((ab / "MANIFEST.json").read_text())
key = bytes.fromhex(manifest["publicKey"])
for case, ident in (("1 (twin of 3)", "vd05d2e7059332fd5"), ("3 mutated artifact", "vb8a8df5360bc6f37")):
    entry = next(v for v in manifest["vectors"] if v["id"] == ident)
    outcome = verify.verify(
        ab / entry["trial"], ab / entry["manifest"], ab / entry["signature"], key, manifest["profile"]
    )
    print(f"case {case}: record {entry['manifest']}  signature verifies="
          f"{'signature-invalid' not in outcome.codes and 'signer-key-mismatch' not in outcome.codes}  "
          f"verdict={outcome.verdict}  codes={sorted(outcome.codes)}")
```

It prints:

```
case 1 release A: statement statements/v96d442af53d71bf4.json  signed and valid=True  admitted=True  codes=[]
case 2 release B: statement statements/v96d442af53d71bf4.json  signed and valid=True  admitted=False  codes=['subject-anchor-mismatch']
case 1 (twin of 3): record cases/intact-execute/trial/binding/manifest.json  signature verifies=True  verdict=verified  codes=[]
case 3 mutated artifact: record cases/covered-byte-changed/trial/binding/manifest.json  signature verifies=True  verdict=failed  codes=['artifact-digest-mismatch', 'artifact-length-mismatch']
```

Against your own reader, `uv add agent-evidence-vectors` and run each corpus
with the harness's `--verifier` option (`--corpus vectors-admission`). The
admission corpus carries both of the first two cases; the artifact-binding
corpus is judged with `aee-verify` or a named verifier, and its third case is
the one named above.

## What the group does not show

The three cases are about one failure: a valid signature standing in for an
applicability check. They say nothing about whether the signer deserves
trust, which is a separate check with its own members (`wrong-signer` in the
artifact-binding corpus and the `observation-key-published` case in the
admission corpus).
