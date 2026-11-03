# Observed-effect code digest candidate

This delivers the optional code-identity join promised in
[in-toto/attestation #557](https://github.com/in-toto/attestation/issues/557#issuecomment-5787647186).
An observed-effect record can now carry `predicate.codeDigest.sha256` while
keeping its one subject equal to the interval's after-state root.

The field is optional. When present it must contain exactly one lowercase
64-hex SHA-256 digest. The Go and packaged Python readers accept a separately
selected expected digest through consumer policy. Requiring that join rejects
missing and mismatching fields. A caller that does not request the join gets the
same verdicts for every member in the
[existing observed-effect corpus](../../corpora/vectors-observed-effect/MANIFEST.json).

The field is a signed producer declaration. Matching it to a capability subject
does not measure executed code, authenticate the capability, prove that its
digest was committed before execution, or join two records to the same interval
and authority. Consumers must authenticate and select their capability inputs
separately. The prior-commitment preimage and existing corpus bytes are unchanged.
Older readers may ignore the extension; a required join needs a 0.5-aware reader.

## Run

```sh
python -m pip install -r interop/observed-code-digest-candidate/requirements-test.txt
python -m pytest interop/observed-code-digest-candidate/test_code_digest.py -q
GOWORK=off go test ./observedeffect -count=1
python corpora/vectors-observed-effect/check_vectors.py
python corpora/vectors-observed-effect/mutation_check.py
```

[The candidate manifest](MANIFEST.json) pins the signed synthetic cases and the
source baseline's bytes.
They cover optional omission, exact matching, required absence/mismatch,
malformed/extra algorithms, uppercase/short/nonhex/numeric/null digests, a trailing
newline, invalid consumer policy, second-subject insertion, after-root
substitution and an unsigned code-digest change. The original reader, packaged
Python reader and Go reader all judge the same cases. Pytest also exercises
arbitrary 32-byte digests, changed consumer pins and duplicate-member input.

`generate.py` deterministically signs candidate files with the released corpus's
published test key. It never writes into the released corpus. `synthetic-code.txt`
is the synthetic artifact whose bytes define the matching digest; it was not
executed to produce these statements. This is same-author conformance work, not
a native capability producer's acceptance or independent code measurement.

The JSON Schema overlay under `spec/schemas/` checks only the optional field's
shape. It deliberately sets both length bounds as well as a pattern so a
validator whose `$` permits a trailing newline cannot accept a longer digest.
The full readers still enforce signatures, interval/subject coherence and
consumer policy. Their two new rules participate in the mutation sweeps together
with this separate candidate profile; the released manifest stays untouched.

## API

The consumer's expected value is supplied out of band. These examples show the
new configuration fields, not a procedure for trusting an arbitrary capability:

```python
policy = observedeffect.Policy(
    predicate_type=consumer_predicate_type,
    observer_public_key=consumer_observer_key,
    expected_code_digest=authenticated_capability_subject_sha256,
)
report = observedeffect.verify(envelope_bytes, policy)
```

```go
policy := observedeffect.Policy{
    PredicateType: consumerPredicateType,
    ObserverPublicKeyHex: consumerObserverKey,
    ExpectedCodeDigest: authenticatedCapabilitySubjectSHA256,
}
report := observedeffect.Verify(envelopeBytes, policy)
```

An empty expected digest means no code join was requested. It never means that
a join succeeded. No record field can set the consumer's expected value.

## Source and license

Base: `probityai/agent-evidence-vectors` at
`beb47f330793c6be19e75d78098abb3ec2f12a1d`. The parent fixture and public signing
seed are from its `vectors-observed-effect` corpus. This extension and its
fixtures use the repository's Apache-2.0 license. The predicate document moves
from 0.4.0 to 0.5.0; the stable predicate URI and released corpus identities do
not change. Previously ignored malformed values of this newly defined field
are rejected by the new reader, so compatibility is claimed for records without
the field, not for every possible preexisting extension.
