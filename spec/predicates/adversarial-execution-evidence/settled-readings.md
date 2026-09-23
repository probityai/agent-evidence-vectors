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

**The safe-integer rule reaches a number written in integer form.** A magnitude at
or above 2^53 is rejected there. A number written in exponent form is governed by
the RFC 8785 number layout instead, which gives `1e+21` a canonical spelling; a
blanket refusal of every integral value above the bound would make that spelling
unreachable.

**The Unicode rules bind the code point a string denotes, not the bytes that spell
it.** A noncharacter or an unpaired surrogate reached through a `\u` escape,
including one assembled from an escaped surrogate pair, is refused exactly as a
literal one is. The alternative would let any excluded code point through by
escaping it, which would leave the rule with no effect.

**The profile constrains the bytes a rail accepts, not where the rail checks
them.** A decoder that raises rather than substitutes satisfies the raw-byte
requirement, because the content of that requirement is that no later check reads
a substituted scalar value; a rail that scans the bytes without decoding satisfies
it identically. Neither arrangement is mandated.

**Canonical base64 is a property of the carried text, checked on the carried
text.** Minimal padding, no line breaks, no alternate alphabet, no non-alphabet
byte, fail-closed. Two rails that agree on the decoded bytes can still disagree on
whether those bytes were carried canonically, and before this rule they did.

**DSSE PAE runs over the canonical bytes the envelope carries base64-encoded,
never over the base64 text.** DSSE is referenced normatively and defines the
pre-authentication encoding over the serialized body; the envelope carries that
body encoded. The sentence in the registry entry admits both readings in
isolation, so it is pinned here.

## The recompute

**The `result` recompute is total.** A predicate it cannot read contributes `fail`
rather than raising. The recompute is defined as a total, deterministic,
severity-independent function of the predicate, and a function that raises on some
predicates is not total: it would make the verifier depend on a well-formedness
gate having run first, which the two-stage description does not promise. An absent
`observationVocabulary` therefore yields empty carried sets, which puts every label
outside them.

**An absent `containmentObserved` is outside the carried labels.** It takes the
first condition and contributes `fail`. The condition spells out *missing* for
`basis`, `method` and `attribution` and not for `containmentObserved`; a member
that is not there is not in the carried set, and fail-closed is the direction the
same sentence takes for every other axis.

**A seal's `aeeObservedSet` is a total function of the records carried.** A run
whose substrate emitted no `interception` or `examination` record commits to the
canonicalization of the empty array. Omitting the member instead would be a
different claim -- silence rather than "nothing was emitted" -- and the member is
required on every `sealed` record.

## What this file is not

It is not a second normative surface. Every entry above states the reading of a
rule that the registry entry or another companion already carries; none of them
adds a requirement. Where an entry and the rule it reads ever disagree, the rule
governs and this file is the defect.

[settled readings]: settled-readings.md
