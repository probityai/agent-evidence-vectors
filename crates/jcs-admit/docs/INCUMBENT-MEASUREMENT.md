# What each RFC 8785 implementation on crates.io does

Raw output of the probe run behind every claim in `tests/incumbent_differential.rs` and the
README table.

Run 2026-09-19 on Linux x86-64, rustc 1.98.0-nightly (57d06900f 2026-05-27), against
`serde_json_canonicalizer` 0.3.2 resolving `serde_json` 1.0.151 and `ryu-js` 1.0.3.

Crate source read at `serde_json_canonicalizer-0.3.2.crate`, sha256
`fe52319a927259afbfa5180c5157cd8167edfd3e8c254f9558c7fef44c5649f2`, downloaded from
static.crates.io the same day. Its whole public API is four functions, in that crate's own `src/util.rs`:
`to_vec`, `to_string`, `to_writer` (all `S: Serialize`) and `pipe(&str)`.

One editorial note about the transcript below, so nobody diffs it against a re-run and finds
a difference nobody declared.

The probe printed each section header with a leading `--- `. That prefix is stripped here,
because three hyphens inside a block read to a prose linter as an em-dash, and that linter
does not exempt fenced blocks.

No other byte of the output is altered.

## Every RFC 8785 implementation on crates.io, read 2026-09-19

The README argues that a canonicalizer cannot see a fault that the parse ahead of it
destroyed. That argument is about where an implementation stands, so it needs the whole
field rather than the delegate alone.

Seven were read: the crate source was downloaded from static.crates.io and the public entry
points were read out of it. Download counts are the crates.io totals on 2026-09-19.

| implementation | downloads | what it accepts |
|---|---|---|
| `serde_json_canonicalizer` 0.3.2 | 7,852,211 | `to_vec`, `to_string`, `to_writer` over `S: Serialize`; `pipe(&str)` |
| `serde_jcs` 0.2.0 | 3,825,932 | `to_vec`, `to_string`, `to_writer` over `T: Serialize`, through a `JcsSerializer` wrapping `serde_json::Serializer` |
| `json-canon` 0.1.3 | 582,329 | `to_vec`, `to_string`, `to_writer` over `T: Serialize` |
| `canon-json` 0.2.1 | 318,516 | a `CanonicalFormatter` implementing `serde_json::ser::Formatter`, so a value again |
| `acdp-jcs` 0.13.2 | 11,750 | `canonicalize<T: Serialize>`, `canonicalize_value(&serde_json::Value)` |
| `jcs-canonicalize` 0.2.1 | 1,021 | `canonicalize(input: &str)`, `sha256_jcs_hex<T: Serialize>` |
| a seventh, 857 downloads over its whole history and 265 on its current release | 857 | `canonicalize(&Value)`, plus a separate `parse_with_dup_check(&str)` |

Not one of the seven accepts bytes. Six canonicalize a value that something else already
parsed, and the remaining one takes `&str`.

`&str` is the same wall. A surrogate encoded directly in UTF-8 and an overlong form are
unrepresentable in a Rust string, so neither can be handed to that entry point at all.

The seventh does reject a duplicate object member, which is worth stating plainly because a
duplicate member is this crate's headline refusal.

It does so by parsing a `&str` with a strict deserializer, in a function separate from its
canonicalizer. So it reaches the one byte-level fault that survives being spelled in UTF-8.

The string-scalar, depth, size and number-profile faults stay out of reach on that path. The
crate is left unnamed here under the standing rule on small-project citation, and the counts
above are what a reader needs to re-find it.

Two limits on the set above.

A crates.io keyword search returned only two of these seven. Full-text searches on `rfc8785`,
`RFC 8785` and `JSON Canonicalization` returned 14, 121 and 558 crates. So the field is larger
than seven, and this is a read of implementations rather than a census of them.

A download count also measures reach and never conformance. None of the seven was run against
the vectors in `tests/vectors/`.

## The three crates.io lookups

```
jcs-admit  HTTP 404  crate does not exist
serde_json_canonicalizer  HTTP 200  v0.3.2  7,852,211 total  5,259,528 recent  updated 2026-02-03
serde_jcs                 HTTP 200  v0.2.0  3,825,932 total  2,711,166 recent  updated 2026-03-25
serde_json                HTTP 200  v1.0.151                                    updated 2026-07-20
```

The 404 is a negative, so it carries three positive controls from the same call in the same
session: the identical request shape returned 200 with populated fields for three names known
to exist.

## Probe output

```
A. duplicate member via pipe() (bytes in, string out)
  pipe("{\"a\":1,\"a\":2}") = Ok("{\"a\":2}")
B. duplicate member via to_vec(&Value) (their serde path)
  serde_json::Value = {"a":2}  -> to_vec = Ok("{\"a\":2}")
C. duplicate member emitted straight into their serializer
  to_string(TwiceKeyed) = Ok("{\"a\":1}")
D. nesting: pipe() at 128 / 129 / 256 / 1000
  depth   128: Err: recursion limit exceeded at line 1 column 128
  depth   129: Err: recursion limit exceeded at line 1 column 128
  depth   256: Err: recursion limit exceeded at line 1 column 128
  depth  1000: Err: recursion limit exceeded at line 1 column 128
E. nesting: to_vec(&Value) built WITHOUT their parser, 129 and 10000
  depth   129: ACCEPTED (262 bytes out)

thread 'main' (2794532) has overflowed its stack
fatal runtime error: stack overflow, aborting
timeout: the monitored command dumped core
A. duplicate member via pipe() (bytes in, string out)
  pipe("{\"a\":1,\"a\":2}") = Ok("{\"a\":2}")
B. duplicate member via to_vec(&Value) (their serde path)
  serde_json::Value = {"a":2}  -> to_vec = Ok("{\"a\":2}")
C. duplicate member emitted straight into their serializer
  to_string(TwiceKeyed) = Ok("{\"a\":1}")
D. nesting: pipe() at 128 / 129 / 256 / 1000
  depth   128: Err: recursion limit exceeded at line 1 column 128
  depth   129: Err: recursion limit exceeded at line 1 column 128
  depth   256: Err: recursion limit exceeded at line 1 column 128
  depth  1000: Err: recursion limit exceeded at line 1 column 128
E. nesting: to_vec(&Value) built WITHOUT their parser, 129 and 10000
  depth   129: ACCEPTED (262 bytes out)
  depth   512: ACCEPTED (1028 bytes out)
F. the RFC 8785 reference number, through their pipe()
  pipe("333333333.33333329") = Ok("333333333.3333333")
  str::parse::<f64> bits    = 0x41b3de4355555555
G. non-finite and unsafe integer, through their pipe()
  pipe("1e400") = Err("number out of range at line 1 column 5")
  pipe("9007199254740993") = Ok("9007199254740992")
  pipe("1e21") = Ok("1e+21")
H. unpaired surrogate escape, through their pipe()
  pipe("{\"a\":\"\\ud800\"}") = Err("unexpected end of hex escape at line 1 column 13")
I. exact depth boundary on pipe()
  depth 126: Ok(252)
  depth 127: Ok(254)
  depth 128: Err("recursion limit exceeded at line 1 column 128")
  depth 129: Err("recursion limit exceeded at line 1 column 128")
J. exact depth boundary on to_vec(&Value)
  depth 128: Ok(260)
  depth 129: Ok(262)
  depth 1000: Ok(2004)
K. the string profile through pipe()
  noncharacter U+FFFF escaped        = Ok("{\"k\":\"\u{ffff}\"}")
  noncharacter U+FDD0 escaped        = Ok("{\"k\":\"\u{fdd0}\"}")
  noncharacter U+1FFFE escaped        = Ok("{\"k\":\"\u{1fffe}\"}")
  high surrogate alone               = Err("unexpected end of hex escape at line 1 column 13")
  low surrogate alone                = Err("lone leading surrogate in hex escape at line 1 column 12")
  high then high                     = Err("lone leading surrogate in hex escape at line 1 column 18")
  raw DEL U+007F                     = Ok("{\"k\":\"\u{7f}\"}")
  raw control U+0001                 = Err("control character (\\u0000-\\u001F) found while parsing a string at line 1 column 7")
  surrogate direct in bytes ED A0 80:
    (CESU-8)                         = NOT UTF-8, pipe() takes &str so it is unreachable: invalid utf-8 sequence of 1 bytes from index 6
  overlong NUL C0 80:
    (overlong)                       = NOT UTF-8, pipe() takes &str so it is unreachable: invalid utf-8 sequence of 1 bytes from index 6
L. the unsafe-integer family through pipe()
  9007199254740992       = Ok("9007199254740992")
  9007199254740993       = Ok("9007199254740992")
  99999999999999999999   = Ok("100000000000000000000")
  1.5                    = Ok("1.5")
  -0.1                   = Ok("-0.1")
  1E21                   = Ok("1e+21")
  1.0e21                 = Ok("1e+21")
M. size: is there any cap?  20 MiB + 1 of array
  input 12000003 bytes -> Ok(12000003)
```

## The stack overflow at 10,000 nested arrays

`to_vec` on 10,000 nested arrays printed `thread 'main' has overflowed its stack`, then
`fatal runtime error: stack overflow, aborting`, exit status 134, core dumped.

It is not asserted in the test suite, because an abort would take the test binary with it. The
suite asserts the uncapped acceptance at 1,000 levels instead.
