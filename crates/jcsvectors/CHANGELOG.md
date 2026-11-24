# Changelog

## Unreleased

- `reject()` also carries the 15 `invalidInputCases` (invalid UTF-8, a byte order mark, malformed JSON, duplicate members, unpaired surrogate escapes), and the family-coverage test lists the family.

## 0.1.0

- First release: the `vectors-a2a-jcs-v01` RFC 8785 vectors and `jcs-byte-vectors` (canonical, reject, refusal, drift and depth cases) embedded with a SHA-256 check of every embedded file, the same files the Go module `jcsvectors` carries.
- `reject()` carries the 23 `refusalCases` (escaped and nested duplicate names, invalid UTF-8, non-finite numbers, trailing content, malformed JSON); a test fails when `cases.json` gains a family the crate does not read.
