# Artifact-binding corpus index

Emitted by `gen_vectors.py`. One row per member; what each member is for
is in `MANIFEST.json` under `cites`.

| id | verdict | codes | case |
|---|---|---|---|
| `v21fa0d3af33d010d` | failed | atif-document-digest-mismatch | `cases/atif-pointer-mismatch` |
| `vb8a8df5360bc6f37` | failed | artifact-digest-mismatch, artifact-length-mismatch | `cases/covered-byte-changed` |
| `vfa81facc1464c1d6` | not-established | dependencies-incomplete | `cases/dependency-incomplete` |
| `vd05d2e7059332fd5` | verified | (none) | `cases/intact-execute` |
| `v7020b1fccb496c3b` | failed | manifest-encoding-not-canonical | `cases/non-canonical-encoding` |
| `va8f79964b68a610f` | verified | (none) | `cases/regrade-changed-verifier` |
| `v63555b6f69adb453` | not-established | artifact-absent | `cases/required-role-absent` |
| `vee1d041fe793404e` | failed | signer-key-mismatch | `cases/wrong-signer` |
