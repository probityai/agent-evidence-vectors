# JavaScript and WebAssembly distribution

The npm package exposes the public Rust admission primitive to Node and browsers.
It builds one WebAssembly artifact from the Rust parser and canonicalizer. The
JavaScript layer loads that artifact and represents native refusals as errors.
It does not parse JSON, canonicalize values or translate refusal reasons.

The npm package is `jcs-admit` version `0.1.0`. Its release tag is `jcs-admit-npm-v0.1.0`,
separate from the native crate's version `0.1.3`. The existing Rust `v0.1.1`
release and its pinned consumer examples remain unchanged. Registry metadata,
artifact hashes and provenance identify a published package; a source tag alone
does not establish registry availability.

## Consumer contract

Both `admit(input)` and `admit_ijson(input)` accept a `Uint8Array` and return a new
`Uint8Array`. Node `Buffer` is accepted as a `Uint8Array`. A subarray retains its
byte offset and length. Strings, arrays, parsed objects and other typed arrays
raise `TypeError`. Genuine cross-realm byte views are accepted through captured
typed-array intrinsics. The wrapper creates a local view of the same buffer
without copying, preserves its offset and length, and ignores spoofed tags or
shadowed properties. The Rust size check runs before copying bytes into WASM.
The bindings do not decode and re-encode the input first.

`admit` uses `Options::rfc8785()`, including its existing treatment of numbers as
binary64 values. For example, `9007199254740993` canonicalizes to
`9007199254740992`. `admit_ijson` explicitly selects the native I-JSON tightening,
which refuses that integer and Unicode noncharacters. The default depth and
input-size caps remain 128 and 20 MiB. This API adds no profile or reason alias.

Refused raw input raises `JcsError`, which extends `Error`:

- `variant` is the exact native `Error` discriminant.
- `fields` is a frozen object containing the unchanged native field names and
  values, including byte offsets where that variant supplies one.
- `message` is the native bounded display text. The full native fields are kept
  separately; they can contain attacker-controlled input.

The representation is derived from the Rust enum. There is no second JavaScript
reason enum. A duplicate member called `name`, for example, is available as
`error.fields.name` and does not replace `Error.name`. New native variants remain
possible because the Rust error is non-exhaustive.

Node 22.14 or newer loads the WASM bytes internally through the package's ESM
entry point. Browsers import `jcs-admit/browser` and await its default initializer.
A bundler or static server must retain the adjacent generated modules and `.wasm`
file. Both routes use the same bytes, without an install script or runtime npm
dependency. See [the package README](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/npm/README.md) for complete consumer
examples.

## Build and verify a tarball

The default Rust crate retains its native Rust 1.74 and dependency-floor contract.
The separate `npm/wasm` binding crate has its own manifest and lockfile. It uses
current `wasm-bindgen` 0.2.129 and needs Rust 1.81 or newer. The
qualification workflow pins Rust 1.99.0, Node 22.14.0 and Node 24.19.0. Use the
same wasm-bindgen CLI version as the locked Rust dependency.

From a clean source checkout:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
cargo build --locked --features serde --example wasm_oracle
npm ci --prefix npm --ignore-scripts
python3 npm/build.py --require-clean
npm exec --prefix npm -- playwright install chromium --only-shell
npm test --prefix npm
python3 npm/test/release-guard.py
```

The test packs `npm/dist`, installs the actual tarball into an empty consumer
directory, checks its TypeScript interface, and runs Node and Chromium consumers.
It compares canonical bytes and the complete refusal payload with a native Rust
oracle under both public profiles. It reads the existing independent RFC 8785,
cross-rail, hostile-string and number-tie fixtures without regenerating them.
Additional binding controls cover malformed bytes, reserved-looking duplicate
names, wrong JavaScript types, subarrays and the size cap. These are binding
checks, not new independent corpus evidence or a universal verifier claim.

`npm/dist/BUILD.json` records the source commit, clean state, input file hashes,
tool versions and artifact hashes. The packed test report records the tarball's
SHA-256 and npm integrity string. A release must pass those checks on the actual
installed artifact, with the source files still matching the recorded inputs.
The release gate checks the complete stage and runtime population, native exit
and signal values, fixture hashes, byte-profile counts, and package/source
identity. Synthetic artifact mutation controls cannot satisfy consumer evidence.

## Release authority and provenance

The repository's `release.yml` publishes from a GitHub release whose tag is
`jcs-admit-npm-v<package-version>` and whose commit belongs to `main`. Its build job has read-only repository permissions. A separate
publish job downloads the qualified artifact and verifies its hashes and source
identity before requesting npm publication through OIDC. Only that job receives
`id-token: write`, behind the `npm` environment. It does not rebuild the
tarball or use a long-lived npm token.

The npm trusted-publisher configuration binds the package identity to
`probityai/agent-evidence`, the exact `release.yml` workflow and the `npm`
environment. Establish the package identity and configure that binding through
npm's supported account flow before the OIDC publish job runs. Registry account
access alone does not establish namespace ownership, direct publication authority
or any required OTP approval. Credentials stay outside the repository.

Use npm CLI 11.5.1 or newer on a GitHub-hosted runner. The public repository and
package metadata permit npm's provenance attestation. After publication, check
the registry tarball and provenance against the qualified artifact. A published
package can be pinned by its npm version and integrity; a source tag alone is not
that registry readback.
