# Dependency selection instructions (v1)
1. Prefer a package already in the lockfile over a new one.
2. A new package must have a verifiable build provenance attestation.
3. A new package must have no known vulnerability at the pinned version.
4. Pin the exact version and its hash. Never add a range.
5. A human approves the lockfile diff before it merges.
