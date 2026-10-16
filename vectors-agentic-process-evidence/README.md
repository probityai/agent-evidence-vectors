# Agentic process evidence vectors

Cases for `agentic-process-evidence/v0.1`: signed in-toto Statements carrying
the Agentic Process Evidence predicate, version 0.1, proposed to in-toto in
[in-toto/attestation#609](https://github.com/in-toto/attestation/pull/609) and
specified in [jfrog/agentic-process-evidence](https://github.com/jfrog/agentic-process-evidence).
A record names the provider stacks (harness, agent, language models) that ran
an agentic process, its result, the user accountable for it, when it started
and ended, and the session logs, tools and context artifacts it used.

Replay from the installed package:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-agentic-process-evidence
agent-evidence-vectors --corpus vectors-agentic-process-evidence --verifier "./my-verifier"
```

Or from a workflow:

```yaml
- uses: probityai/agent-evidence-vectors@<tag>
  with:
    corpus: vectors-agentic-process-evidence
    verifier: ./my-verifier
```

## The rules under test

The field rules are the specification's own, read from the pull request at
head `7ac6780cf813377c07a66dafe066b819f08b3f01` and from
`spec/agentic-process-evidence.md` and `spec/agent-identifier.md` at
jfrog/agentic-process-evidence commit `1d2feec9678919178520f1ecaeed185f12657f3f`.
A verifier reads a DSSE v1 envelope signed with Ed25519 and a consumer policy
that pins the payload type, the predicate type and the trusted keys. It names
the first check that fails:

| Step | Check | Refusal |
| --- | --- | --- |
| 1 | the envelope parses as DSSE v1 | no verdict, `malformed_envelope` |
| 2 | the payload type is the pinned one | `unsupported_payload_type` |
| 3 | a signature naming a pinned keyid verifies; signatures naming other keys are ignored | `untrusted_key`, `signature_invalid` |
| 4 | the payload is a JSON object and an in-toto Statement v1 | `payload_not_json_object`, `unsupported_statement_type` |
| 5 | the predicate type is the pinned one | `unsupported_predicate` |
| 6 | each constrained field is well formed, Statement fields first, then the predicate's required fields, then its optional ones | `field_invalid:<field>` |

A record that passes all six is `supported` with `process_evidence_verified`.
A `FAILED` or `MISALIGNED` result is still supported: the record is verified,
and whether its outcome is acceptable is the consumer's policy.

| Field | Rule, from the specification |
| --- | --- |
| `createdAt`, `predicate.startTimestamp`, `predicate.endTimestamp` | required ISO 8601 timestamp, read in its RFC 3339 profile |
| `createdBy`, `predicate.processType`, `predicate.owner` | required, non-empty |
| `subject` | at least one entry, each with a `uri` and a digest set |
| `predicate.providers` | at least one provider stack |
| `predicate.providers[].harness` | required, with a non-empty `name` and `version` |
| `predicate.providers[].agent`, `.languageModels` | optional; every field non-empty when present |
| `predicate.result` | one of `COMPLETED`, `FAILED`, `CANCELLED`, `APPROVED`, `REJECTED`, `ALIGNED`, `MISALIGNED` |
| `predicate.traceId` | non-empty when present |
| `predicate.sessionsLogs` | resource descriptors, each with a `uri` and a digest set |
| `predicate.tools` | each with a non-empty `name`; `version` non-empty when present |
| `predicate.contextArtifacts` | exactly one of `uri` or `data`; a digest set when `digest` is present; `tags` a list of strings |
| `predicate.custom` | an object |
| `predicate.intents`, `predicate.reviewers` | lists of strings |
| `predicate.processSummary` | a string |

A URI is absolute: a scheme and no whitespace. A digest set is the in-toto
Statement v1 type: at least one algorithm, every value non-empty, and `sha256`,
`sha512`, `sha1` and `gitCommit` lowercase hex of their length. Unknown fields
and unknown digest algorithms are ignored, as both documents require.

## What the members show

The first supported member is the specification's own published
development-process example
(`use_cases/autonomous_code_development/objects_examples/agentic-dev-process-evidence.json`),
signed as issued. The others are variations the specification allows: only the
required fields, a session log as the subject, unknown fields, an inline
context artifact, a negative result, an unpinned co-signer, and the
`https://jfrog.com/evidence/agentic-process/v0.1` type the jfrog repository's
examples carry, under a policy that pins it.

Each refused member names its supported twin and differs from it by one
scripted mutation. Three of them reproduce something in the specification's
own text:

- `predicate-type-pr-example-spelling`: the pull request declares the Type URI
  `https://in-toto.io/attestation/agentic-process/v0.1`, while its schema
  block and example use `.../v0.1.0`. A verifier pinning one refuses the other.
- `context-artifact-uri-and-data`: the schema example's first context artifact
  carries both `uri` and `data`, which the field table forbids.
- `subject-git-commit-elided` and `session-log-uri-placeholder`: the schema
  example elides the commit with `...` and uses `session log url` as a URI.

[INDEX.md](INDEX.md) lists every member; `MANIFEST.json` holds the expected
`decision` and `reason` for each.

## Keys

Every envelope is signed with test keys whose seeds are the SHA-256 of public
labels in `gen_vectors.py`. Anyone can re-derive them. They are test keys only.

## Tools

- `gen_vectors.py` writes every case, `MANIFEST.json` and `INDEX.md`
  deterministically.
- `check_vectors.py` runs the packaged reference reader, or a named verifier
  with `--verifier "<cmd>"`. The contract: `<cmd> <case-dir>/case.json --json`
  prints one JSON object with `decision` and `reason` on its last line, and
  exits 0 for `supported`, 1 for `contradicted` or `not_established`, and 2 when
  no verdict was reached. `case.json` names the envelope file and holds the
  policy: `payload_type`, `predicate_type` and `trusted_keys` (keyid to base64
  raw Ed25519 public key).
- `mutation_check.py` switches off each rule in turn and fails unless some
  member changes its answer.
- The Go reader in `corpora/agenticprocess.go` applies the same rules, so
  `aee-verify vectors-agentic-process-evidence` judges the corpus independently.
