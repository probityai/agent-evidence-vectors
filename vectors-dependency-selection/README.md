# Dependency-selection conformance corpus

A worked, signed record of one AI-assisted dependency change, and a twin per
way a reviewer must refuse it. The record is an
[artifact-binding v1](../spec/artifact-binding/v1.md) manifest judged under the
consumer-held profile `dependency-selection/v1` (section 6.2), so the verifier,
the signature scheme and the three verdicts are the ones
[`vectors-artifact-binding`](../vectors-artifact-binding/) already pins.

Run it:

```bash
aee-verify vectors-dependency-selection/                       # behaviour
python3 vectors-artifact-binding/check_vectors.py vectors-dependency-selection
python3 vectors-dependency-selection/gen_vectors.py            # regenerate, byte-identically
```

## The accepting record

`cases/intact-selection/trial/binding/manifest.json` covers, by SHA-256 and
length:

| Role | File |
|---|---|
| `lockfile_before` | `lock/before/requirements.lock` |
| `lockfile_after` | `lock/after/requirements.lock` |
| `skill_instructions` | `agent/skills/dependency-selection.md`, the instructions in force |
| `provenance_check_output` | `checks/provenance-check.log` |
| `vulnerability_scan_output` | `checks/vulnerability-scan.log` |
| `approval` | `approval/approval.json`, naming the approver and the approved lockfile digest |
| `verifier_files` | `binding/grading-inputs/checks.txt`, the checks that ran |

It is signed with the published test key in `public.key`. `MANIFEST.json`
carries the consumer's side: `profile` and `inForce`, the instruction-file
digest the consumer accepts.

## The refusing twins

Each differs from the accepting record in one thing:

| Case | What changed | Verdict |
|---|---|---|
| `lockfile-after-changed` | the lockfile on disk is not the one covered and approved | `failed` |
| `skill-not-in-force` | the record honestly covers a different instruction file | `failed` |
| `vulnerability-scan-absent` | no vulnerability-scan output is covered | `not-established` |
| `approval-absent` | no approval is covered | `not-established` |
| `wrong-signer` | signed by a key the consumer did not pin | `failed` |

`INDEX.md` lists the member identifiers and codes. It is emitted by the
generator, never edited by hand.

## Verify one record with the reference tool

```bash
python3 tools/artifact-binding/aee_bind.py verify \
  vectors-dependency-selection/cases/intact-selection/trial \
  --pubkey vectors-dependency-selection/public.key \
  --profile dependency-selection/v1 \
  --in-force skill_instructions=<inForce.skill_instructions from MANIFEST.json>
```

Exit code 0 is `verified`, 2 is `failed`, 3 is `not-established`.

The lockfile hashes, package versions and check logs are synthetic and fixed so
the corpus regenerates byte-identically; the shape is the point.
