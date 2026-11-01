# ANCHORS stream verifier

Standalone checker for [`ANCHORS.jsonl`](ANCHORS.jsonl) and [`ANCHORS.jsonl.digests.json`](ANCHORS.jsonl.digests.json). **Standard library only.** Takes **public HTTPS URLs** as input — no local checkout required.

## Distribution (canonical)

The canonical distribution is a **single file** fetched and executed directly. **Zero dependencies.**

```bash
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.4/anchors_verify.py
python3 anchors_verify.py --self-test
```

To pin a release, reference tag **`anchors-verify-v0.4`** in the URL (not `main`). Older tags (`anchors-verify-v0.2`, `anchors-verify-v0.1`) remain available for history.

**`anchors-verify-v0.3` was published pointing at the wrong commit and does not implement the `VERIFY PARTIAL` / `VERIFY UNPINNED` outcomes documented here. It is superseded by `v0.4` and left in place rather than re-pointed, because re-pointing a published tag would break the reproducibility this verifier exists to check.**

This verifier is **not distributed as a PyPI package.** Requiring `pip install` would ask auditors to trust the supply chain; a single file can be read in full before execution.

**Run (copy-paste — tag-fixed, reproducible):**

```bash
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.4/anchors_verify.py
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.4/ANCHORS.jsonl
curl -sLO https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.4/ANCHORS.jsonl.digests.json
python3 anchors_verify.py \
  --anchors-url file://$(pwd)/ANCHORS.jsonl \
  --digests-url file://$(pwd)/ANCHORS.jsonl.digests.json \
  --expect-witness-repo aos-standard/catalog
```

The bundled files come from the **same tag** as the verifier. You can reproduce without referencing `main`.

**Self-test (adversarial vectors, no network):**

```bash
python3 anchors_verify.py --self-test
```

**Optional — verify live `main` tip (not tag-fixed):**

Use this only when you intentionally want the moving witness stream on `main`. Results depend on how many lines exist on `main` at fetch time.

```bash
python3 anchors_verify.py \
  --anchors-url https://raw.githubusercontent.com/aos-standard/catalog/main/ANCHORS.jsonl \
  --digests-url https://raw.githubusercontent.com/aos-standard/catalog/main/ANCHORS.jsonl.digests.json \
  --expect-witness-repo aos-standard/catalog
```

## Verification outcomes (do not conflate)

**Contract change (v0.4):** Prior releases through `v0.2` (and the mis-pointed `v0.3` tag) treated partial attestation like full success (`VERIFY OK` with `attested_prefix_lines < lines`). **`v0.4` adds distinct outcomes and exit codes.**

| Outcome | Exit code | Meaning |
|---------|-----------|---------|
| **VERIFY OK** | 0 | **`attested_prefix_lines == lines`** — every line in the presented stream is covered by a verified position-binding prefix, and each attested prefix **byte-matches** the witness platform. |
| **VERIFY PARTIAL** | 3 | **`0 < attested_prefix_lines < lines`** — some prefix is attested and verified, but the stream tip remains unattested. **Not full verification.** |
| **VERIFY UNATTESTED** | 2 | Digest and boundary checks passed, but **`attested_prefix_lines=0`** — no position binding. Not a successful verification. |
| **VERIFY UNPINNED** | 4 | Digest/binding checks may have run, but **`--expect-witness-repo` was omitted** — trust anchor taken from the stream itself. **Not citable as anchored verification.** |
| **VERIFY FAILED** | 1 | Digest mismatch, boundary violation, prefix mismatch, or trust-anchor mismatch. |

**Do not treat PARTIAL, UNATTESTED, or UNPINNED as OK.**

## What it checks

- Each JSONL line SHA-256 matches the sidecar entry for that line index. Hashes cover the **full stored line including the trailing newline byte**.
- Boundary rules for `witness_ref_introduced`, `signature_suite_introduced`, and `position_binding_introduced` (field presence before/after each event).
- **Truncation vector 1:** fewer anchor lines than digest entries → fail closed.
- **Truncation vector 2 (unattested tip only):** anchor lines and sidecar both shortened but internally consistent → fail closed **when compared to witness platform snapshots** on lines **after** the last `position_binding_introduced` attestation.
- **Position binding (attested prefix):** for each `position_binding_introduced` event, the verifier fetches `ANCHORS.jsonl` at the named witness commit and checks that the attested **prefix length, byte length, and SHA-256** match **byte-for-byte** on the witness platform and in the presented stream. Inserted fake boundaries inside an attested prefix are detected.

## Trust anchor (`--expect-witness-repo`)

**Required for VERIFY OK or VERIFY PARTIAL.** Supply the witness repository as `owner/repo` (e.g. `aos-standard/catalog`). The verifier uses this as the trust anchor for platform queries instead of accepting whatever repository the stream under verification names.

- If `--expect-witness-repo` is set and the stream names a different repository → **fail closed** (`VERIFY FAILED`).
- If omitted → **warning** plus **`VERIFY UNPINNED`** (exit 4): a forged stream can point queries at an attacker-controlled repository.

## Rolling attestation discipline

Each sync that changes `ANCHORS.jsonl` should append a `position_binding_introduced` event naming the **witness commit that contains the previous sync** (the commit one step behind the append), plus the **prefix line count, byte length, and digest** of the material being attested. The latest append remains unattested until the next event arrives.

## Limits (read before citing results)

Do **not** claim unconditional fork blocking. The following remain out of scope:

| Limit | Reason |
|-------|--------|
| **Unattested stream tip** | The latest append is not bound until the next `position_binding_introduced` arrives. **Forks at the tip are not detectable.** |
| **Equivocation** | No signature suite is implemented. Conflicting continuations signed by the same key cannot be attributed. |
| **Force-push** | If witness repository history is rewritten, history-dependent checks break. |

What this tool **does** buy: **detection of fake boundaries inserted after the fact within an attested prefix** — not discrimination between two equivalent continuations shown to different auditors.

- **Signature verification is not implemented.** The stream may declare `signature_suite`; this tool does not validate signatures or keys.
- **Truncation vector 2 on the unattested tip** depends on witness platform history not being rewritten. Do **not** claim unconditional truncation detection.

Detection strength inherits the availability and honesty of the witness platform whose history you compare against, and whether you supply `--expect-witness-repo`.
