# Settled readings

Each entry closes a place this predicate's text admitted two readings. They were
recorded by an independent second implementation before its first run, which is
why they are worth stating: a reading left open is not a disagreement anyone sees,
it is two conforming rails that accept different bytes and never find out.

The reading stated here is normative. Where an entry names the alternative, the
alternative is refused.

The registry entry itself carries the two that are rules rather than readings: the
definition of the pinned `networkPosture` digest, and canonical base64 on a signed
surface.

## The encoding profile

**The safe-integer rule binds the value a number denotes, however it is
written.** A number whose exact value is integral with magnitude at or above 2^53
is refused whether it is spelled in integer form (`1000000000000000000000`) or in
exponent form (`1e21`, `1.0e21`). RFC 8785 section 3.2.2 serializes a number from
its value and erases the written form: both spellings above canonicalize to the
same bytes, `1e+21`. A rule keyed to the written form would therefore give two
verdicts on one canonical value. The number layout of RFC 8785 governs how an
admitted value is written back, never whether it is admitted; the bound itself is
the interoperability limit RFC 7493 (I-JSON) section 2.2 sets.

Vectors: `vd3ead02f7ed16d0a` (`1e21`, refused on its value), with
`vd5e0b3f3d1fabb05` (`1E2`), `v97c6888cf7e88f42` (`1.0e2`) and
`v13ede3e42645eb1a` (`-0e0`), whose values the bound admits and which are refused
on spelling alone.

**The Unicode rules bind the code point a string denotes, not the bytes that spell
it.** A noncharacter or an unpaired surrogate reached through a `\u` escape,
including one assembled from an escaped surrogate pair, is refused exactly as a
literal one is. The alternative would let any excluded code point through by
escaping it, which would leave the rule with no effect.

Vectors: `v8a1b8a3333981552` (a noncharacter assembled from an escaped surrogate
pair), `va501d76c995de6d3` and `v0e731123ead5b96e` (a noncharacter as a single
escape), and `v5717f72827e39413`, `v198c19b52cf8890e`, `v86f3484735f41acb` and
`vdef377fb4f572b4d` (unpaired and reversed surrogate escapes).

**The profile constrains the bytes a rail accepts, not where the rail checks
them.** A decoder that raises rather than substitutes satisfies the raw-byte
requirement, because the content of that requirement is that no later check reads
a substituted scalar value; a rail that scans the bytes without decoding satisfies
it identically. Neither arrangement is mandated.

Vectors: the ill-formed-string family, `vf5599bb2dbe66e12` and `v5e14357c80f6239b`
(a surrogate encoded in UTF-8), `vbc7012fb2fcbf1f8` (an overlong encoding) and
`vb705b260669aedc7` (a raw control character). Every arrangement that satisfies
the requirement refuses all of them, so the reading needs no vector of its own.

**Canonical base64 is a property of the carried text, checked on the carried
text.** Minimal padding, no line breaks, no alternate alphabet, no non-alphabet
byte, fail-closed. Two rails that agree on the decoded bytes can still disagree on
whether those bytes were carried canonically, and before this rule they did.

**DSSE PAE runs over the canonical bytes the envelope carries base64-encoded,
never over the base64 text.** DSSE is referenced normatively and defines the
pre-authentication encoding over the serialized body; the envelope carries that
body encoded. The sentence in the registry entry admits both readings in
isolation, so it is pinned here.

Vectors: `vf56664ac324b6613`, a record signed over the PAE of the base64 text,
which is valid with its row `unattested` under both key policies; its twin
`v550c91df0d36a218` signs the raw payload with no PAE at all. A signature is never
a validity fault, so the reading is forced through the tier column.

## The recompute

**The `result` recompute is total.** A predicate it cannot read contributes `fail`
rather than raising. The recompute is defined as a total, deterministic,
severity-independent function of the predicate, and a function that raises on some
predicates is not total: it would make the verifier depend on a well-formedness
gate having run first, which the two-stage description does not promise. An absent
`observationVocabulary` therefore yields empty carried sets, which puts every label
outside them.

Vectors: `ve3c7f7a8d918c70c` (zero rows, a declared result the recompute does not
derive) and `v6945133925a03e15` with `v089e746847cd0af2` (no vocabulary, whose
readings invert across the pair).

**An absent `containmentObserved` is outside the carried labels.** It takes the
first condition and contributes `fail`. The condition spells out *missing* for
`basis`, `method` and `attribution` and not for `containmentObserved`; a member
that is not there is not in the carried set, and fail-closed is the direction the
same sentence takes for every other axis.

Vectors: `va8ff24a38152fc31` (the member absent, carried result `fail`, valid) and
`vc6934681b519c0ce` (the same statement carrying `pass`, refused with
`result-recompute-mismatch`).

**A seal's `aeeObservedSet` is a total function of the records carried.** A run
whose substrate emitted no `interception` or `examination` record commits to the
canonicalization of the empty array. Omitting the member instead would be a
different claim -- silence rather than "nothing was emitted" -- and the member is
required on every `sealed` record.

Vectors: `vcc938c6038536dcb`, whose only records are an `arming` and a `sealed`
record and whose seal commits to the digest of `[]`, and `v42c1c063e3ecf305`, the
same statement with `aeeObservedSet` dropped from the seal, refused with
`sealed-covers-nothing`.

## What this file is not

It is not a second normative surface. Every entry above states the reading of a
rule that the registry entry or another companion already carries; none of them
adds a requirement. Where an entry and the rule it reads ever disagree, the rule
governs and this file is the defect.

[settled readings]: settled-readings.md
