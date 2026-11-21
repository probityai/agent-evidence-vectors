# vectors-rsa-digestinfo

Suite `rsa-digestinfo/v1`: 8 RSASSA-PKCS1-v1_5 SHA-256 signatures judged by the whole recovered block. A verifier
that strips the padding and compares only the trailing 32 bytes with the digest accepts four blocks that end in
the right digest and are not a valid encoding. This slice refuses all four.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

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
