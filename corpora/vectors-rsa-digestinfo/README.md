# vectors-rsa-digestinfo

Suite `rsa-digestinfo/v1`: 8 RSASSA-PKCS1-v1_5 SHA-256 signatures judged by the whole recovered block. A verifier
that strips the padding and compares only the trailing 32 bytes with the digest accepts four blocks that end in
the right digest and are not a valid encoding. This slice refuses all four.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-rsa-digestinfo
python3 corpora/vectors-rsa-digestinfo/check_vectors.py --verifier "<your verifier>"
```

Your verifier is called as `<verifier> <case-dir>/record.json --json`, prints `{"decision", "reason"}` and exits 0
for `valid`, 1 for `invalid`, 2 for `profile-dependent`.

| Case | Decision | The block |
|---|---|---|
| `rfc8017-null-parameters` | `valid` | the RFC 8017 encoding, SHA-256 DigestInfo with NULL parameters |
| `absent-null-parameters-exact` | `profile-dependent` | the same DigestInfo with the NULL omitted, exactly; accepting it is the consumer's profile |
| `garbage-prefix` | `invalid` | arbitrary bytes between the padding and the digest |
| `garbage-after-legacy-prefix` | `invalid` | bytes after a DigestInfo prefix, before the digest |
| `sha512-oid` | `invalid` | a SHA-512 OID carrying a 32-byte value |
| `short-padding` | `invalid` | a padding string shorter than the modulus requires, filler before the digest |
| `wrong-message` | `invalid` | control: the right encoding over another message |
| `signature-one-byte-short` | `invalid` | control: a signature shorter than the modulus |

Each record carries the public key as a JWK (`n`, `e`), the message and the signature. The 2048-bit key is derived
deterministically from the seed label `agent-evidence-vectors/rsa-digestinfo/v1/`, so `gen_vectors.py` regenerates
the slice byte for byte. The reference verifier `agent-evidence-verify` applies the same whole-block rule in
`aep_package/v1` and agrees with all 8 cases.
