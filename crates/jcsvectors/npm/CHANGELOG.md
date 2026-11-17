# Changelog

## 0.2.0

- First release, at the version of the Go module it mirrors: `canonical()`, `reject()`, `parserDifferential()`, `drifts()`, `tooDeep()`, `depthAdmitted()` and `files()` over the `vectors-a2a-jcs-v01` and `jcs-byte-vectors` files, each file checked against its SHA-256 before any case is returned.
- `features` on every case and a `profile` option (`rfc8785`, `integer-only`), with `filter()` to report out-of-profile cases apart.
