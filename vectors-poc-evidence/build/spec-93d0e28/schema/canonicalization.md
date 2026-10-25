# Canonicalization

## Why this document exists

Theorem 1 in the paper says an adversary cannot make a relying party execute an
action other than the one the policy evaluated. The proof turns on one step: the
relying party recomputes a digest over the request it has been asked to perform,
and compares it to the digest the attesting environment committed to. Equal
digests, execute; different digests, refuse.

That argument holds only if *the same action produces the same bytes in every
implementation*. If your serializer emits keys in insertion order and mine emits
them sorted, we produce different digests for identical actions. Every signature
still verifies. Nothing looks broken. But the comparison fails, so either
legitimate work is refused for reasons nobody can diagnose, or — far worse — an
implementer "fixes" it by relaxing the comparison, and Theorem 1 quietly stops
being true.

So canonicalization is not a formatting preference. It is the part of the
specification that decides whether the central security property survives
contact with a second implementation. This document pins it down, and
[`vectors/`](vectors) contains the cases that prove an implementation got it
right.

## The two canonical forms

There are two, and they have different rules because they contain different
things.

**The claim set** is defined entirely by this profile. Every field is a string,
an integer, an enumerated value, or a nested object of those. **Floating-point
numbers are forbidden.** That is a deliberate restriction: number formatting is
the hardest part of any canonicalization scheme, and by excluding floats the
claim set avoids it completely. `iat` is therefore integer seconds, not a
fractional timestamp; if you need finer ordering, `step_index` already provides
a total order per agent.

**The snapshot** contains application data — the parameters of whatever the
agent is trying to do — and the profile cannot restrict its shape. Snapshots are
canonicalized with **RFC 8785 (JSON Canonicalization Scheme)** in full,
including its number rules, which specify ECMAScript `Number::toString`
behaviour.

## Rules for the claim set

1. **UTF-8**, no byte-order mark.
2. **Object keys sorted** by Unicode code point of the key string. (For the
   claim set every key is ASCII, so code-point order, UTF-16 code-unit order,
   and byte order all coincide. This is not true of snapshots — see the
   divergence note below.)
3. **No insignificant whitespace.** Separators are exactly `,` and `:`.
4. **No floating-point.** Integers are serialized with no decimal point, no
   exponent, and no leading `+` or redundant zeros.
5. **Strings escaped minimally**, per RFC 8785 section 3.2.2.2: escape only
   `"`, `\`, and the C0 controls, using the short forms (`\b \f \n \r \t`)
   where they exist and `\u00XX` otherwise. Do not escape non-ASCII characters.
6. **Digests are algorithm-tagged lowercase strings** of the form
   `sha-256:<hex>`. Uppercase hex is a canonicalization error. The tag is
   mandatory; a verifier MUST reject an untagged digest rather than assume
   SHA-256, because assuming the algorithm is exactly how a hash migration goes
   wrong.
7. **Absent is not empty.** An optional claim that does not apply is omitted. It
   is not present with an empty string, an empty object, or `null`. These
   produce different bytes and therefore different digests.
8. **Duplicate keys are rejected**, not last-wins. A parser that silently keeps
   the last value lets an attacker show one claim set to a verifier and another
   to a relying party.

## What is signed

The signature covers the canonical form of the token **with the `signature`
member removed** — not added as an empty string, removed.

```
signature = Sign(sk, canonical(token \ {signature}))
```

A verifier reconstructs the same byte string by deleting the member and
re-canonicalizing. This means a verifier must canonicalize, not merely hash the
bytes it received: a token that arrives pretty-printed is still valid if it
canonicalizes correctly, and a token whose bytes look right but whose canonical
form differs is not.

## The leaf and the tree

The Merkle leaf for step *t* is computed over the canonical form of the
committed material, with RFC 6962 domain separation:

```
leaf_t = SHA-256(0x00 || canonical({"snapshot": <untagged hex>,
                                    "verdict":  <verdict>}))
node   = SHA-256(0x01 || left || right)
```

The `0x00` / `0x01` prefixes are not decoration. Without them a leaf can be
presented as an interior node, which is the standard second-preimage attack on
Merkle trees.

Note that the leaf uses the **untagged** hex digest. The tag exists for
interoperability of the wire format; inside the hash computation the algorithm
is already fixed by the tree's declared parameters, and including the tag would
make the leaf depend on a redundant string.

## A divergence we did not hide

The reference implementation serializes with Python's
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. This is
**not** RFC 8785. It differs in two ways:

- Python sorts keys by Unicode **code point**; RFC 8785 sorts by UTF-16 **code
  unit**. These orders differ only when a key contains a character outside the
  Basic Multilingual Plane, because such characters are represented as surrogate
  pairs in UTF-16 and sort below `U+E000`–`U+FFFF` rather than above.
- Python's float repr is not ECMAScript `Number::toString` in every case.

Neither can affect the claim set: its keys are ASCII and it contains no floats.
Both can affect a snapshot carrying application data with exotic keys or
floating-point parameters.

`vectors/negative/nonbmp-key-ordering.json` exhibits the ordering case
concretely. An implementation that intends to interoperate on arbitrary
application payloads MUST implement RFC 8785 properly;
[`validate.py`](validate.py) does, and reports when the two disagree.

## Checking yourself

```bash
python3 schema/validate.py --vectors        # run every published test vector
python3 schema/validate.py token.json       # validate one token
python3 schema/validate.py --canonical t.json  # print its canonical bytes
```

An implementation conforms when it (a) validates every positive vector, (b)
rejects every negative vector *for the stated reason*, and (c) reproduces the
published canonical bytes and digests exactly.

Rejecting a negative vector for the wrong reason is not a pass. A validator that
throws on `bad-hex-case.json` because it could not parse the file has not
demonstrated that it checks hex case.
