# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**
(https://github.com/probityai/agent-evidence/security/advisories/new). Please do not open a
public issue for it.

The most useful report is an envelope and a key: an envelope this crate verifies
that it should reject, or a threshold it counts as met when it is not. Say which
version you ran.

You get an acknowledgement within three working days. A confirmed issue gets a
fix, a patch release and a GitHub security advisory, and the advisory credits the
reporter unless they ask not to be named.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x, latest release | Yes |
| 0.1.0 | No, yanked |

Fixes land on the newest release only. Until 1.0, a security fix that needs an
API change ships as a new minor version.

## Release checks

Every push and pull request runs the test suite on the declared minimum Rust
version (1.88), `cargo semver-checks` against the newest release on crates.io,
and `cargo vet` over every dependency in `Cargo.lock`. The workflows are in the
repository root's `.github/workflows/` (`crate-dsse.yml`, `crate-dsse-npm.yml`
and `release.yml`).
