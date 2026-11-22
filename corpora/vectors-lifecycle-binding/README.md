# vectors-lifecycle-binding

Suite `lifecycle-binding/v1`: 42 record sets asking one question about runtime evidence. Does the authenticated
execution report name the action the authenticated control authorized, for one decision and one instruction?
Each set gets one of five states, `satisfied`, `failure`, `missing`, `not_evaluated` or `indeterminate`, or
`refused` when the set cannot be admitted. Absent evidence is never `satisfied`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-lifecycle-binding
python3 corpora/vectors-lifecycle-binding/check_vectors.py --verifier "<your verifier>"
```

Your verifier is called as `<verifier> <case-dir>/record.json --json`, prints `{"decision", "reason"}` and exits 0
for `satisfied`, 1 for `failure` or `refused`, 2 for `missing`, `not_evaluated` or `indeterminate`.

## Families

| Family | Cases | What it checks |
|---|---|---|
| `lifecycle-shape` | 11 | complete; issuer-only authorization; no execution; no control; no decision; authorized differs from executed; two instructions under one decision; a broken decision, control or execution; a revoked governor |
| `binding-scope` | 13 | V1 cross-instruction substitution, V2 a receiving side that disagrees, V3 and V3b a shared identity in either order, V4 and V7 a revoked executor, V5 an unbound key, V6 a valid self-hash with no signature, V8 two identical records under one id, V9 a receiver-side control alone (`missing`: the executor's side never authorizes), V10 an issuer-side control the executor signed, V11 the executor's key bound a second time under another name and signing the issuer-side control (both `failure`), C0 control |
| `tag-confusion` | 13 | a body hashed under another type's tag, a decision retyped as an execution, a decision signature on a control, an untagged pre-image, an unregistered or case-folded type, CRLF and double-LF separators, another version, a body rewritten after signing, a relabelled wire `alg` (still `satisfied`), a signature over another suite id, and a signature over a DSSE pre-authentication encoding replayed as a record signature |
| `admissibility` | 5 | a member repeated under an escaped spelling, a lone surrogate, `1E400`, `9007199254740993`, and `-0` (admitted: its RFC 8785 form is `0`) |

Every vector carries `expectedClass` (`positive`, `negative` or `absent`) and every record a `does_not_establish`
sentence: the claim is about records, never that the executed bytes were observed. Keys come from seeds under the
neutral label `aev-lifecycle-binding-vectors/`, every record was written for this corpus, and `gen_vectors.py`
regenerates it byte for byte. Revisions are listed in [REVISIONS.md](REVISIONS.md); a published revision is
never restated.

The records follow the `lifecycle_binding` term of agent-evidence-vocabulary: grouping by (decision, instruction),
a closed registry of six tags `agent-evidence/lifecycle-binding/v1/{decision,control,execution}/{hash,signature}`,
the signature suite taken from the producer's key binding, and a required revocation snapshot. The reference
verifier `agent-evidence-verify` reads them as `lifecycle_binding/v1` and agrees with all 42 cases.
