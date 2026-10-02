# Canonicalization text offered into in-toto/attestation#588

This is specification prose, written to be dropped into
`spec/predicates/ai-agent-action.md` in place of its current `### Canonicalization`
and `### Genesis and chain continuity` sections. It is adapted from the
canonicalization and bounds text in in-toto/attestation#570, which fought the same
question out over several rounds and settled it.

The conformance members that exercise every rule below live in
`vectors-ai-agent-action/`, and `aee-verify` refuses to pass a corpus in which
any rejecting member lacks an accepting twin.

What changed in adapting #570's text to #588:

- #570 canonicalizes a Statement; #588 canonicalizes an underlying gateway record
  that lives outside the Statement, so the identical-bytes requirement had to be
  restated as a relationship between the log line and the recomputed form rather
  than as a property of one document.
- #570 has no hash chain, so the injective-predecessor rule, the single-head rule
  and the checkpoint linkage rule are new here and have no counterpart there.
- #570's depth bound, safe-integer profile, duplicate-member rule and
  well-formed-string rule carry over almost verbatim, because #588 already cites
  #570 for the depth counting rule and the safe-integer bound and the wording
  should not fork.
- #570's BMP-only rule for sorted strings carries over, and its consequence is
  restated. #570 scopes it to the surfaces a Statement signs and the divergence
  costs that Statement its coverage; here the sorted surface is the record whose
  digest is the chain link, so a supplementary-plane member name splits the chain
  hash, and with it every successor's `previousHash` and the subject digest. The
  rule is the same rule; it reaches further because the hash it perturbs is
  carried forward.
- #588's two-form split is kept. The change is that the signing form's field list
  becomes part of the specification rather than part of an implementation, and the
  chain hash stops being a third, unnamed form.

---

## Canonicalization

This predicate uses two canonical forms, and the boundary between them is drawn by
what a party signs rather than by what a party stores. Every byte string any rule
below hashes is named exactly once, so that two implementations reading only this
document derive identical bytes from identical observations.

### The record canonical form

The record canonical form is the RFC 8785 (JCS) canonicalization of the audit
record object, encoded as UTF-8. Object members are sorted by UTF-16 code unit,
numbers take the shortest form that round-trips under IEEE 754, and no
insignificant whitespace appears. A producer MUST write each JSONL line as exactly
these bytes, and a verifier MUST recompute the form from the parsed record and MUST
reject, fail-closed, any line whose bytes differ from the recomputation.

That last obligation is the one that cannot be dropped. Without it the preimage has
two readings, the bytes on disk and the re-serialization of the parsed object, and
they coincide only by accident. Any log shipper that reparses and re-emits JSON
moves a verifier from one reading to the other while every field value stays
identical, so a chain that verified before the shipper ran fails after it.

`JSON.stringify` MUST NOT be used to derive any hashed byte string. It is not a
canonical form and it is not portable. ECMAScript orders canonical numeric property
names ahead of every other name and in ascending numeric order regardless of
insertion order, so an `extensions` object whose members are `10`, `2`, `aa`, `zz`
serializes as `2, 10, zz, aa` in a JavaScript gateway, as `10, 2, zz, aa` in a
Python gateway that preserves insertion order, and as `10, 2, aa, zz` in a Go
gateway, whose `encoding/json` sorts map keys. That is three chain hashes for one
observation, and none of the three implementations has done anything wrong. JCS
fixes the order to `10, 2, aa, zz` for all of them.

String escaping is fixed by the same rule. JCS emits a character rather than an
escape wherever the character is permitted, so a serializer whose default is
ASCII-escaping output, and a serializer that escapes `<`, `>` and `&`, both produce
non-canonical bytes and both are rejected. Neither behaviour is exotic: the first
is Python's default and the second is Go's.

### The content digest form

Content digests bind MCP payloads without inlining them. They use RFC 8785 over the
payload, and the digest is the lowercase 64-hex SHA-256 of those bytes.

`contentDigest.request` is the digest of the JSON-RPC `params` member. For
`contentDigest.response` the preimage depends on which JSON-RPC response arrived. A
success response carries a `result` member and the digest is over that member. An
error response carries no `result` member at all, and the digest is over the `error`
member. A record with `action.success` false is by construction an error response,
so this is not an edge case: it is every failed tool call, which is the half of an
audit trail an investigator reaches for first. A producer MUST NOT digest `null`,
an empty object, or the whole response envelope in place of the named member.

Floats are permitted here and only here. MCP tool payloads are arbitrary JSON and
routinely carry them.

**Adopting this section requires regenerating the worked example's digests.** The
text above names the `params` member and the `result` member, and #588 already
says the same thing: "`payload` is the JSON-RPC `params` object (for requests) or
`result` object (for responses)". Its worked example does not do that. Under
"Content digest preimages" the request block is captioned "JCS of the `params`
object" and then displays the whole JSON-RPC message, `{"method":...,"params":
{...}}`, and the published digest is the digest of the displayed block. The
response block does the same with `{"result":{...}}`. So the caption names the
member, the preimage beside it is the envelope, and the digest matches the
preimage rather than the caption.

Recomputing against the specification text at `639ec56` (vendored beside this
suite at `vectors-ai-agent-action/spec-vendored/ai-agent-action-639ec56.md`,
sha256 `1eaecff711591ea6e56e5798abc110a077c49194900513bab736d137496b84ba`) gives:

| preimage | sha256 |
|---|---|
| the whole request message, as the example displays and publishes it | `167bd5c6ecde61c67bb42cb8607bd17c39aca91729b302247c67833fe7427815` |
| the `params` member alone, as both captions and this text specify | `b47ce84f9c856142547199358dd70203c504fbe3c82f362f46248bb05cf133cc` |
| the whole response message, as the example displays and publishes it | `46943f801d4623b020293ed8f31d3603972dd20d9687949a31f13a5f12acdd24` |
| the `result` member alone, as both captions and this text specify | `12fcbdcf920251bd7596b9e255eca20a314a179d5c33a70505d764706469825a` |

So the example's `contentDigest.request` becomes `b47ce84f` and its
`contentDigest.response` becomes `12fcbdcf` if this section is adopted as
written. The example's subject digest is unaffected and reproduces exactly as
published, `cd26e6c4930f34da6dbbb53988f4920b13eedc7e3354ac51a82efeac9574e664`.
That control is what makes this a finding rather than an extraction error: an
error in reading the document would have missed the subject digest too.

Which way it resolves is a decision for the predicate and not for this text.
Regenerating the two digests keeps the member-scoped rule; rewriting the two
captions and the rule to say the whole message keeps the digests. Both are
cheap. What is not available is leaving them as they are, because a second
implementer builds against whichever half they read first, and the two produce
different bytes for the same tool call.

### The signing canonical form

The signing canonical form is the tuple-array this predicate already defines: an
ordered array of `[field-name, value]` pairs in which objects become
`["M", [[key, value], ...]]` with keys sorted by UTF-16 code unit, arrays become
`["L", [value, ...]]`, and scalars pass through untagged.

The field list and its order are part of this specification. An implementation
MUST build the tuple from exactly the following fields, in exactly this order,
omitting an absent optional field rather than encoding it as null:

    id, type, timestamp, toolName, namespace, durationMs, success,
    errorCode, errorClass, previousHash, contentDigestRequest,
    contentDigestResponse, extensionsDigest, attestorVersion, configHash

A form whose input list lives in an implementation's type definition is not a
specification of anything. A second implementer can reproduce the tagging rules,
the sort order and the tags exactly and still reproduce no signature at all, and no
conformance vector can be written for it, because a vector needs a preimage the
text determines.

Numbers in the signing form MUST be safe integers: magnitude below 2^53, per RFC
7493 section 2.2. This constraint binds the signing form and the record canonical
form. It does not bind content payloads, which is why the content digest form
exists.

### Strict I-JSON, statement-wide

The whole record and the whole Statement are parsed as strict I-JSON.

A duplicate member anywhere, at any depth, makes the record malformed, and a
verifier MUST reject it fail-closed. A lenient parser that keeps the last of a
repeated member lets a record carry `"toolName": "read_file"` and
`"toolName": "delete_repository"` at once: a first-wins reader shows the auditor
the harmless call while the hash commits to the destructive one, and both readers
believe the chain intact.

Every string literal MUST be a well-formed sequence of Unicode scalar values, in
member-name and value position alike. The record MUST be valid UTF-8 with no
overlong form and no surrogate encoded directly in UTF-8; a `\u` escape naming a
high surrogate MUST be immediately followed by one naming a low surrogate, and an
unpaired escape of either half is malformed; a `\u` escape MUST be exactly four
hexadecimal digits with no sign, whitespace or radix prefix; a string MUST NOT
carry a raw unescaped character below U+0020; and the Unicode noncharacters, U+FDD0
through U+FDEF and U+nFFFE and U+nFFFF in every plane, are excluded. A verifier
MUST apply this to the raw bytes before any decoded string is read, because a
lenient decoder does not fail on ill-formed input, it substitutes U+FFFD, and every
check after that point reads a string the producer never wrote.

A valid surrogate pair is one supplementary-plane character and is well formed.
Nothing in the paragraph above rejects it, and a verifier that treats it as
ill-formed alongside the unpaired half is over-rejecting.

Well formed is not the same as admissible, and the two must not be run together.
Well-formedness is a property of a string on its own: the bytes decode, the
escapes pair, no scalar value is excluded. Admissibility is a property of a
string in a position, and the next rule closes one position against a class of
character the paragraph above admits.

### Member names are BMP-only

On every surface JCS sorts -- object member names at any depth in the record
canonical form, and the keys inside every `["M", ...]` of the signing canonical
form -- strings MUST be BMP-only: no code point above U+FFFF, and therefore no
surrogate pair. A verifier MUST reject, fail-closed, a record carrying a member
name outside the BMP, and MUST treat the violation exactly as it treats
non-canonical bytes.

RFC 8785 sorts object members by UTF-16 code unit. A verifier that instead
compares Unicode code points orders a supplementary-plane name differently from
one in U+E000 through U+FFFF, because that character's leading surrogate lies
below U+E000 while its code point lies above U+FFFF. Both readings are reachable
from a correct reading of everything else in this document, and the language
split is the same one the `JSON.stringify` paragraph already describes: a
JavaScript gateway and a Java gateway compare UTF-16 code units and get this
right without deciding to, and a Python gateway and a Go gateway compare code
points and get it wrong without deciding to.

`extensions` is where this bites, because its member names are whatever the
gateway's caller chose and no rule constrains them. A record whose `extensions`
carries the names U+FF3A and U+1F680 canonicalizes with U+1F680 first under
UTF-16 code units and with U+1F680 last under code points. That is two byte
strings, each of which some conforming implementation calls canonical, so two
chain hashes for one observation. The successor record then carries one of two
values of `previousHash`, and since the genesis hash is the subject digest, the
chain has two identities and a policy targeting it resolves to whichever the
presenter's serializer happened to produce.

That is the same failure the JCS rule fixes for integer-like names, arriving
through a door JCS leaves open, and it is worse in one respect: with integer-like
names exactly one order is correct and the other two implementations are wrong,
whereas here the sort key itself is ambiguous unless the character set is bounded.

Restricting the sorted strings to the BMP makes UTF-16 code-unit order and
code-point order coincide, so the divergence is unconstructible rather than
merely forbidden. Values are untouched. A supplementary-plane character in a
`toolName`, in a content payload, or in any other value position stays
admissible, because nothing sorts it.

A verifier MUST reject, fail-closed, a record or a Statement whose JSON nesting
depth exceeds 128. Depth is the number of arrays and objects open at a point,
counting the outermost brace of the whole document as depth 1; scalars do not
increase it. A record carried as a Statement's predicate is therefore measured
inside the Statement, where its own outermost brace is at depth 2. The bound is normative rather than a
resource limit, because with no bound stated two conforming verifiers disagree
about whether identical bytes are evidence at all across the whole range between
their private choices.

## Chain shape

### The chain hash

The chain hash of a record is the lowercase 64-hex SHA-256 of that record's canonical
form as defined above, including its attestation signature member. The next record
carries it as `previousHash`.

`previousHash` is either lowercase 64-hex or the literal lowercase string `genesis`,
and nothing else. Uppercase hex is not canonical. A digest of any other length is
not admissible, and there is no algorithm agility in this field at v0.1; a future
version that needs another algorithm adds an algorithm member rather than widening
what this one accepts. Without this, a verifier that folds hex case treats two
distinct byte strings as one link while the two successors carrying them hash
differently, so the same logical chain has two identities.

### One head, and one predecessor

Exactly one record in a chain MUST carry any given `previousHash` value. A verifier
MUST reject, fail-closed, a log in which two records share one, and MUST reconstruct
the chain as a strict walk from the genesis record rather than by checking that each
record's `previousHash` appears somewhere in the presented set.

This is the rule that makes the chain a chain. Nothing in a hash link forbids a
fork: two records may each chain from record one, and every hash in both branches
verifies. Since the subject digest is the genesis hash, both branches carry the same
subject digest and a policy targeting the chain cannot distinguish them. A presenter
holding a four-record chain can therefore present a two-record branch that omits
whichever calls it prefers an auditor not see, with no hash broken, no second
genesis, and no gap in sequence for a checkpoint to catch. Set-membership
verification accepts it; a strict walk plus the injectivity rule does not.

### Every record type is on the chain

`checkpoint` and `chain_break` records carry `predicate.chain.previousHash` exactly
as `tool_call` records do, and the record following any record of any type carries
that record's chain hash. `predicate.checkpoint.previousHash` restates the chain
head for the consumer that externalizes it and is not the linkage; the linkage is
always `predicate.chain.previousHash`.

Stating this for `chain_break` alone leaves the checkpoint off the chain the fields
table defines. A verifier walking the documented linkage field steps past every
checkpoint, so a checkpoint can be removed without breaking any documented link, and
the checkpoint is the entire mechanism standing between this predicate and silent
tail truncation.

`predicate.chain` is REQUIRED on every record that is part of a chain. A record
emitted with no chain object stands alone, and a verifier MUST NOT treat it as
evidence about any chain, including one whose genesis hash its subject names.

### Genesis and breaks

The literal `genesis` appears as `previousHash` exactly once in a chain's lifetime,
on the first record. After a `chain_break`, the successor carries the break record's
chain hash, never `genesis`, which binds the discontinuity into the successor chain
so that discarding the break record breaks linkage.

A verifier MUST reject, fail-closed, a log in which `genesis` appears more than
once. This is a MUST and not a SHOULD. A detection obligation a conformant verifier
may decline is not a defence against an adversary who is choosing which verifier to
present to.
