# Predicate type: Done Contract

Type URI: https://w3id.org/agent-evidence/predicate/v1/done-contract

Version: 0.1.0

Predicate Name: Done Contract

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer.
> The page at the URI is built from this file by the `probityai/probity` Pages site.
> The URI will not move once a signed statement carries it, and no signed statement
> carries it before that page is live. The conformance corpus in this repository,
> `vectors-done-contract/`, carries it in unsigned statements.

## Purpose

States, before an agent's first turn, what "done" means for one task: which paths the agent
may not change, which commands a separate verifier will run, and how well those commands
tell a fix from a no-op. The contract is sealed by whoever starts the agent. An outside
verifier later checks the agent's claim of completion against this statement, so the
agent's own transcript is never the standard it is held to.

The contract carries no verdict. Verdicts belong to [done-receipt](done-receipt.md),
computed over this statement and the records of the run.

## Use cases

- A harness seals a contract for a repository task and signs it. A verifier that sees the
  agent's final tree can tell whether the protected tests were left alone and whether the
  acceptance commands pass when it runs them, without asking the agent.
- A reviewer reading a receipt can see what the acceptance commands were able to detect. A
  contract whose `adequacy.killed` is zero cannot distinguish a fix from a no-op, and the
  receipt says so instead of claiming success.
- A benchmark publishes contracts beside its tasks, so two harnesses that grade the same
  agent hold it to the same paths and commands.

## Prerequisites

The in-toto Attestation Framework and the record rules in [done-records](done-records.md),
including strict JSON: a duplicate member at any depth makes the statement malformed.

## Model

The producer is whoever seals the contract: a harness or a task author. The contract is
sealed before the agent runs, so nothing the agent does can enter it.

The **subject** is the contract record, by digest. `subject` MUST carry exactly one member,
whose `digest` MUST carry exactly one entry, `sha256`, equal to the SHA-256 of the bytes of
the `probity-done-contract/v1` record the statement accompanies. The **predicate** is that
record as a JSON value. A verifier MUST parse the record bytes and refuse the statement if
the predicate is not equal to the parsed record. The statement and the record say one thing,
and a statement that says another is a statement about a different contract.

`predicateType` MUST equal the Type URI above.

## Schema

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "contract.json", "digest": { "sha256": "<64-hex of the record bytes>" } }
  ],
  "predicateType": "https://w3id.org/agent-evidence/predicate/v1/done-contract",
  "predicate": {
    "schema_version": "probity-done-contract/v1",
    "contract_id": "contract-app-1",
    "task": "make test_app pass",
    "protected_paths": [
      { "path": "tests", "kind": "directory", "exclude": ["__pycache__"],
        "sha256": "<tree digest of the files under tests>" }
    ],
    "acceptance": [ { "id": "unit", "argv": ["python", "-m", "pytest", "-q", "tests"] } ],
    "adequacy": { "mutants": 4, "killed": 3 }
  }
}
```

The members of the predicate, their types and their rules are those of the done contract in
[done-records](done-records.md).

## Rules

A verifier applies these in order and reports the first that fails.

| # | Rule | Code |
| --- | --- | --- |
| 1 | The statement is strict JSON with exactly `_type`, `subject`, `predicateType` and `predicate` | `statement_json_invalid`, `statement_json_duplicate_key`, `statement_json_number`, `statement_fields` |
| 2 | `_type` is `https://in-toto.io/Statement/v1` | `statement_type_wrong` |
| 3 | `predicateType` is this document's Type URI | `statement_predicate_type_wrong` |
| 4 | `subject` has one member with `name` and a `digest` holding only `sha256` | `statement_subject_malformed` |
| 5 | The contract record parses under the rules in done-records | the code of the first rule the record breaks |
| 6 | The subject digest equals the SHA-256 of the record bytes | `statement_subject_unbound` |
| 7 | The predicate equals the parsed record | `statement_predicate_differs` |

## What a contract does not establish

A contract is a promise about how the run will be judged. It does not show that the
acceptance commands test the task: `adequacy` reports how many generated mutants they
killed, and a contract with no kill cannot support a verdict of done. It does not show that
the agent obeyed it. Neither does it show who sealed it: the producer is a consumer pin, and
a statement that is not signed proves nothing about its origin.

## Conformance

`vectors-done-contract/` holds the members, a valid case for every optional member and one
invalid case for every rule above, with the code each is refused under. A reader conforms
when it reaches the declared verdict and code for every member. `aee-verify` and the packaged
Python reader both replay it.
