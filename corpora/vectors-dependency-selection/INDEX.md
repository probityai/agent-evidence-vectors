# Dependency-selection corpus index

Emitted by `gen_vectors.py`. One row per member; what each member is for
is in `MANIFEST.json` under `cites`.

| id | verdict | codes | case |
|---|---|---|---|
| `v041ef6b03dade091` | not-established | required-role-absent | `cases/approval-absent` |
| `v6ab1d5a5b703b65f` | verified | (none) | `cases/intact-selection` |
| `va281d192c2f57e92` | failed | artifact-digest-mismatch | `cases/lockfile-after-changed` |
| `v60618b6bb07a9894` | failed | role-not-in-force | `cases/skill-not-in-force` |
| `v31c08bd68611a0e3` | not-established | required-role-absent | `cases/vulnerability-scan-absent` |
| `v47607cb6a6545f2e` | failed | signer-key-mismatch | `cases/wrong-signer` |
