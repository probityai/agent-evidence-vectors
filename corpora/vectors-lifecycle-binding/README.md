# vectors-lifecycle-binding

Suite `lifecycle-binding/v1`: 39 record sets asking one question about runtime evidence. Does the authenticated
execution report name the action the authenticated control authorized, for one decision and one instruction?
Each set gets one of five states, `satisfied`, `failure`, `missing`, `not_evaluated` or `indeterminate`, or
`refused` when the set cannot be admitted. Absent evidence is never `satisfied`.

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
| `binding-scope` | 10 | V1 cross-instruction substitution, V2 a receiving side that disagrees, V3 and V3b a shared identity in either order, V4 and V7 a revoked executor, V5 an unbound key, V6 a valid self-hash with no signature, V8 two identical records under one id, C0 control |
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
verifier `agent-evidence-verify` reads them as `lifecycle_binding/v1` and agrees with all 39 cases.
