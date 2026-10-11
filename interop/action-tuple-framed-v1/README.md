# Framed action tuple candidate

This optional, dependency-free package closes the raw string-concatenation ambiguity exposed by the [AgentID offline reader](../agentid-offline/README.md). It defines a separately versioned [byte profile](PROFILE.md), a strict reader and fixed accept/refuse vectors. The historical AgentID reader, fixture, signature and result are unchanged. These candidate packets are unsigned; their success is a frame-and-digest result, not AgentID adoption or an authorization decision.

Run from the repository root with Python 3.12 or later:

```sh
python -m unittest discover -s interop/action-tuple-framed-v1 -p 'test_*.py' -v
python interop/action-tuple-framed-v1/reader.py check interop/action-tuple-framed-v1/cases/ATF-001.json
python interop/action-tuple-framed-v1/reader.py check interop/action-tuple-framed-v1/cases/ATF-010.json
```

The first packet is accepted with exit 0. The second has an ambiguous native replacement tuple paired with the first candidate's frame and digest; it is refused as `tuple-mismatch` with exit 2. A refusal is not reported as an authorization verdict.

For a corpus run, select the manifest SHA-256 from your reviewed, immutable checkout before running the reader. The value below is the pin for this candidate revision:

```sh
python interop/action-tuple-framed-v1/reader.py corpus interop/action-tuple-framed-v1/MANIFEST.json \
  --manifest-sha256 ff4810f187bd484405b1a706c91cb6765c4aca1549e3abde8a1a4dda004dcfe5 \
  --output-dir /tmp/action-tuple-first-attempt
```

The output directory must be new, even if an existing directory is empty. The report retains the selected manifest digest, reader digest, every declared outcome and named refusal class. Exit 0 means every pinned case produced its declared outcome, including deliberate refusals; it does not mean every packet was accepted. Exit 1 means a case outcome differed. Exit 2 means malformed input, failed source/corpus pins or output failure. A failed parse does not create a success report, and a stale report is never reused. The manifest pins all packet bytes, this reader, the profile and the source-input record. Tests also invoke actual subprocess commands for accept/refuse, stale output, changed inputs and wrong manifest selection.

The cases include the original ambiguous pair, the analogous agent/action boundary, empty fields, embedded zero bytes, non-ASCII text, composed and decomposed Unicode, signed timestamp extremes, domain/version changes, tuple reorder, byte-count errors, truncated and oversized lengths, invalid UTF-8, timestamp replacement, trailing bytes and alternate JSON/hex representations. Fixed vectors are produced separately from the reader using `struct.pack`; tests check a hand-specified preimage and known SHA-256 answer. Recomputing a packet is always independent of its expected outcome in the manifest.

[SOURCE-INPUTS.json](SOURCE-INPUTS.json) pins the historical native fixture, request, local reader and upstream producer source. Those files establish why a separate candidate is needed; they are not converted to this format or reused as signatures for it. The source code and published results were read before writing this candidate. This is a Probity-authored and operated test package with no outside operator, host acceptance, formal Pack #3 result or commercial commitment.
