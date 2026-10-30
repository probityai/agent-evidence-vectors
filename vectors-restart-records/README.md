# Restart-records vectors

A checker and synthetic members for the
[restoration evidence profile](../profiles/restoration-evidence.md): the records
that say who stopped an agent system, which credentials were revoked, and who
decided it may run again, on what cited evidence.

For anyone who writes or reads those records and wants to know that their reader
applies every rule of the profile's predicate documents, in order, with the same first
failure.

```sh
git clone https://github.com/probityai/agent-evidence-vectors
cd agent-evidence-vectors
python3 vectors-restart-records/check_vectors.py
```

The checker uses the standard library only. Pin the commit you cloned in your own
CI. With no argument it replays every member and exits 0 only when each verdict
and reason match `MANIFEST.json`. To check your own records:

```sh
python3 vectors-restart-records/check_vectors.py --record statement.json
python3 vectors-restart-records/check_vectors.py --bundle path/to/bundle/
```

Each prints `{"reason": ..., "verdict": ...}` and exits 0 for accept, 1 for
reject, 2 when the input is not a record or a bundle.

## Synthetic, and labelled so

Every member is synthetic. Identifiers are on `example.com` and `example.org`
hosts, digests are of fixed labelled strings, and no member records a real
system, organisation or incident. The manifest says so in `synthetic` and
`syntheticNote`. Members are unsigned in-toto Statements; the profile carries
them in DSSE envelopes, and signature checking is out of scope here.

## What the members force

For each predicate, an accepting control, a few accepting variants, and one
reject per rule. Each reject changes exactly one value of its control, and the
rule it names is the first rule that fails. `MANIFEST.json` records the path,
the value before and the value after, and the tests revert the change and get
the control's bytes back.

Bundle members are an R3 with the R1 and R2 it names, and one change per bundle
rule. After the change, every predecessor digest that pointed at the changed
record is recomputed, so the bundle rule named is still the first to fail.

Some rules cannot be forced by any member; `unforcedRules` lists each with
its reason: the closed-vocabulary rule of `joint-authority` and of
`revocation-boundary`, which carry no registry-defined value, and the cycle
rule, which needs a sha256 fixed point. The checker implements them all, and
the tests exercise the cycle check directly.

[INDEX.md](INDEX.md) lists every member with the document and rule it forces.

## What it does not test

Whether a decision was right. A conforming record is a complete and internally
consistent statement by its signer, not evidence that the statement is true.
Which evidence slots a relying party requires to carry a digest, and what it does
with a slot declared not addressed, is that party's own admission policy; a
`notAddressed` slot with a reason is accepted at record level here.

## Docs

| Page | What it covers |
| --- | --- |
| [Profile](../profiles/restoration-evidence.md) | common members and the bundle rules |
| [Predicate documents](../spec/predicates/REGISTRY.md) | the type URIs and their rules |
| [JSON Schemas](../scripts/gen_restart_records_schemas.py) | shape and closed values only |
| [INDEX.md](INDEX.md) | every member |

Regenerate the members with `python3 vectors-restart-records/gen_vectors.py`.
