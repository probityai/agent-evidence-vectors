# Python byte-profile comparison

This comparison runs jcs-admit and Trail of Bits' Python JCS implementation against the same committed byte corpus. The expected bytes come from the independent Go and RFC reference fixtures in [tests/vectors](../../tests/vectors/PROVENANCE.md).

The Python source is pinned at [655cbe02](https://github.com/trailofbits/rfc8785.py/tree/655cbe02b8761208e3f4cc49e879ab1e328a7dca), version 0.1.4. [MANIFEST.json](MANIFEST.json) records the exact source modules and every input, expected output and control file. The checker verifies their lengths and SHA-256 hashes before it runs.

## Cases

Both implementations must produce the exact committed bytes on 6 RFC reference cases, 30 Go corpus cases and 2 positive boundary controls. The native admission tests also require the 9 Go refusals and 9 added raw-input refusals.

The shared controls show where a parsed Python value loses information that raw admission still has:

| Input | Native profile and result | Python parsed-object result |
| --- | --- | --- |
| Two members named `a`, including an escaped name | RFC 8785: `DuplicateMember` | The parser keeps one member; serialization succeeds |
| `9007199254740993` | I-JSON: `UnsafeInteger` | `IntegerDomainError` |
| `9007199254740993.0` | I-JSON: `UnsafeInteger` | The parser rounds it to `9007199254740992`; serialization succeeds |
| Unpaired surrogate | RFC 8785: `StringNotScalar` | `CanonicalizationError` |
| `1e309` | RFC 8785: `NonFiniteNumber` | `FloatDomainError` |
| Unicode noncharacter | I-JSON: `StringNotScalar` | Serialization succeeds |
| `1.5` | I-JSON with integers-only tightening: `NonIntegerNumber` | Serialization succeeds |
| 129 nested arrays | Default depth cap: `TooDeep` | Serialization succeeds |

Each profile is declared per case in [controls.json](controls.json). The two positive controls keep the comparison honest on safe integers and UTF-16 member order.

## Run it

From the repository root, check out the pinned source and run:

```bash
git clone https://github.com/trailofbits/rfc8785.py interop/rfc8785-py/source
git -C interop/rfc8785-py/source checkout 655cbe02b8761208e3f4cc49e879ab1e328a7dca
python3 interop/rfc8785-py/check.py
```

The command runs the native Rust reference, Go differential and shared boundary tests, then writes `report.json`. It exits unsuccessfully on changed source bytes, a changed expected byte or a different outcome. The native suite and this qualification share the same raw control file.

CI runs the comparison on Python 3.10 and 3.14, runs the Python implementation's own tests, and retains the input corpus, source modules and report. Five checker tests cover a changed source byte, changed expected byte, changed error class, duplicate-key collapse and decimal rounding.
