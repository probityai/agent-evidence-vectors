# Use jcs-admit as a test oracle

A project that writes its own RFC 8785 canonicalizer, or builds a digest input some other
way, can test it against this crate: feed both the same raw bytes and require the same
answer. This crate is an oracle for that test because it decides on the bytes before any
decoder runs, so it refuses what a parse-then-serialize canonicalizer silently repairs, and
because each refusal is a named variant a test can assert.

## The test

For every input in your test set, both sides must agree on one of two outcomes:

- both admit, with identical output bytes; or
- both refuse.

A case where your canonicalizer emits bytes and `admit` refuses is the finding this test
exists for: your code signs or hashes a document that has no canonical form. A case where
yours refuses and `admit` admits is either a stricter profile of yours, which the test should
name, or a false refusal.

Rust, as a dev-dependency pinned exactly:

```toml
[dev-dependencies]
jcs-admit = "=0.1.4"
```

```rust
#[test]
fn my_canonicalizer_agrees_with_jcs_admit() {
    for input in my_cases() {
        match (my_canonicalize(&input), jcs_admit::admit(&input)) {
            (Ok(mine), Ok(oracle)) => assert_eq!(mine, oracle),
            (Err(_), Err(_)) => {}
            (mine, oracle) => panic!("disagree on {input:?}: {mine:?} vs {oracle:?}"),
        }
    }
}
```

Use `admit_ijson` instead of `admit` when your format follows RFC 7493 (integers inside the
range a double holds exactly, no Unicode noncharacters). Python has the same functions in the
[`jcs-admit` wheel](PYTHON.md) and JavaScript in the [`jcs-admit` npm package](NPM.md); both
take bytes and raise the native variant name.

Add a Dependabot or Renovate entry for the pin, so each release opens a pull request your CI
tests before it changes anything.

## Inputs worth including

The parser-differential classes, with what this crate does with each, are pinned in
[`tests/parser_differential_classes.rs`](../tests/parser_differential_classes.rs):

| class | `admit` (RFC 8785 as written) | `admit_ijson` |
| --- | --- | --- |
| member names equal only under case folding, such as `I`, `i`, U+0130, U+0131 | distinct members, sorted by UTF-16 code unit | same |
| a repeated member at any depth, plain or escaped | `DuplicateMember` | `DuplicateMember` |
| an integer past 2^53, such as `9007199254740993` | rewritten to the nearest double | `UnsafeInteger` |
| one integer respelled, such as `1000.0`, `1e3`, `1E3` | `1000`; the respelling is not canonical | same |
| `1e400` | `NonFiniteNumber` | `UnsafeInteger` |
| a 1,000-digit integer | `NonFiniteNumber` | `UnsafeInteger` |
| a 1,000-digit fraction that rounds to zero | `0` | `0` |
| `-0`, `-0.0` | `0`; `-0` is not canonical | same |

Two rows mean your format may need a rule RFC 8785 does not state: a format that matches
member names case-insensitively must refuse names that collide under case folding, and a
format that bounds token length must check it before canonicalizing.

## Sorted compact JSON

A digest input written as sorted compact JSON (Python's `json.dumps` with `sort_keys=True`,
`separators=(",", ":")` and `ensure_ascii=False`) is byte-identical to RFC 8785 for a flat map
of strings whose member names are ASCII, so `admit` checks it. The two part in three places.
Member names sort by code point in one and by UTF-16 code unit in the other, which differ only
where, at the first position two names differ, one has a code point at or above U+10000 and the
other one in U+E000 to U+FFFF; names below that range sort the same. Number values part: a float
such as `1.0` or `1e16`, and an integer that Python writes exactly while RFC 8785 writes the
nearest double, such as `10**21` (`1e+21`) or `2**53 + 1`. And a repeated member name, which
sorted compact JSON never writes and `admit` refuses. [`python/tests/test_sorted_json_oracle.py`](../python/tests/test_sorted_json_oracle.py)
pins each case.
