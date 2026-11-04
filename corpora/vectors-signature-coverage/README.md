# Signature-coverage vectors

Cases for `signature-coverage/v1`: one signature, and what a reader of the record goes on to read. A signature binds bytes. It does not bind the structure the bytes came from, and that structure is often what a consumer reads. The expected decision and reason for every case are in `MANIFEST.json`.

The rule is one sentence: **the signature input must determine everything a reader can read. If two records read differently, they may not share a signature input.**

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-4c6278?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

## The failure this corpus makes testable

A list of key-value entries can hold one key twice. One reader takes the first entry, another the last. A signer that flattens the list into a map keeps one and signs that:

```text
entries:  decision=allow, decision=deny
first-entry reader:  allow
last-entry reader:   deny
signed bytes:        {"decision":"deny"}
```

The signature verifies. The signed bytes are clean canonical JSON, so admission on those bytes passes. Change the shadowed entry and the bytes do not move, so the signature never covered it. `reject-repeat-kept-last`, `reject-repeat-kept-first` and `allow-one-entry-for-the-key` carry one signed payload and one signature; the `sharedSignature` field of a manifest row names the rows that do.

The same gap opens when a flatten folds two keys into one, drops a member, or changes a value's type, and when the signed bytes themselves repeat a member or hold an integer two parsers read differently.

## What a case holds

`record.json` carries `source`, the structure as readers see it (a map is `{"entries": [[key, value], ...]}`, in order, repeats kept); `envelope`, the base64 `payload` with its Ed25519 `signature` and `publicKey`, and the `excluded` top-level keys the signer declares outside the signature; and `consumerReads`, the paths a consumer relies on.

| Check, in order | Refuses |
| --- | --- |
| `contract_id_missing`, `contract_id_unknown` | a record naming no contract, or another one |
| `signature_invalid` | a signature that does not verify over the payload bytes |
| `payload_repeated_member` | signed bytes repeating a member at any depth, on decoded names |
| `number_not_interoperable` | an integer in the payload or source past the range every JSON parser reads exactly |
| `source_repeated_key` | a source repeating a key at any depth, whatever the values |
| `reading_differs_from_signed` | outside the declared keys, a source and payload that differ |
| `consumer_reads_unsigned` | a consumer relying on a key declared outside the signature |

A record passing every check is `allow` with reason `signature_covers_reading`. The `allow-` cases are controls: one key name in sibling maps, keys differing in case or normal form when both are signed, an exclusion nobody reads, and `1.0` against `1`, which a byte comparison gets wrong.

## Run it

```sh
agent-evidence-vectors --corpus vectors-signature-coverage
python3 corpora/vectors-signature-coverage/check_vectors.py --verifier "<verifier>"
```

The external-verifier contract is `<verifier> <case-dir>/record.json --json`, printing `decision` and `reason`, exit 0 for allow and 1 for deny.

## Test a signer

`signer-pairs.json` holds pairs of sources a reader tells apart. A signer passes a pair when it refuses at least one source, or gives the two different signature inputs. Load the pairs in your own test, or run:

```sh
python3 -m agent_evidence_vectors.signaturecoverage --signer "<signer>"
```

The external-signer contract is `<signer> <source.json> --json`, printing `{"refused": true}` or `{"signatureInput": "<base64>"}`. Keeping the first entry does not pass: it matches one reader and leaves the mirror pair open. Refuse the repeat.

## What a pass means

The corpus tests measure naive verifiers and flatteners. A verifier that checks only the signature, one that adds strict admission on the signed bytes, and one that compares the payload with a single reading each pass every control and miss denied cases; every naive flattener fails a pair. All members are synthetic, and the keys are test keys published on purpose.
