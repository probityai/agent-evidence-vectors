# Rows for the vector suite

Work that is owed, sized, and not blocking a release. One row per item, each
carrying the number that makes it real and the command that starts it.

## Re-vendor the AEE specification onto the registry-and-companions shape

- [ ] **Move the vendored specification to the shape upstream now publishes, and
  convert every citation into it.** Upstream split the predicate document: the
  page at `spec/predicates/adversarial-execution-evidence.md` is 2,322 lines here
  and 278 lines at the pinned target, because the registry entry was resized to
  the registry and the body moved into companions. Our copy is still the whole
  old document, and the corpus cites into it by line number.

  **The measurement, taken 2026-09-20:** `456` anchors land on different prose if
  the remap is run as-is, out of `484` remapped. Fifteen more address prose that
  was edited rather than moved, which is a smaller and separate class: those need
  a human to read them, because no gate can decide whether a reworded requirement
  still settles the claim that cites it.

  **Run the pre-flight first.** It is the whole point of the check and it now
  answers the same way twice:

  ```sh
  python3 scripts/vendor-remap-test.py
  ```

  It compares the vendored page against `remapTarget.commit` in
  `spec/VENDOR-PIN.json`, pinned at
  `5ab5dd8897de56ddd2bd9683afca5df578a368e2`, read out of the object store rather
  than any working tree. Exit 1 lists every anchor that would be stranded; exit 2
  means the question could not be asked and names what was missing.

  **Then the move itself**, on its own branch, in this order:

  1. `docs/predicate-long-form` supplies the companions and the anchor machinery:
     `scripts/gen_spec_anchors.py`, `scripts/spec_anchors.py`, the
     `spec/CITATION-ANCHORS.json` manifest, and the half of
     `scripts/spec-drift-gate.py` that resolves an anchor. It has to be in before
     this row can be done, not after.
  2. `scripts/vendor-spec.py` copies the new bytes and rewrites
     `spec/VENDOR-PIN.json`; the drift gate then holds the bytes to the digest it
     records, so `commit` and `specDigest` move together with the page and
     `remapTarget` retires or advances to whatever comes next.
  3. Regenerate the anchor manifest and convert the citations to
     `spec:<anchor-id>@<16-hex>`. A citation that survives a reflow and fails on a
     reword is the property being bought; line numbers had neither.
  4. `scripts/spec-drift-gate.py` and `scripts/spec-anchor-gate.py` decide
     whether it worked. Any surviving `spec:<digits>` is a defect by then —
     `spec_anchors.py` exposes `LEGACY_CITATION_RE` so a gate can say so.

  **Why it is not urgent.** It blocks nothing: the workflow step runs the
  `--synthetic` arm, which is self-contained, so a stale vendored page no longer
  reds a push. What it costs while undone is that the corpus cites a document
  upstream has replaced, and every one of those citations is line-addressed, so
  the next upstream edit moves them silently. That is a correctness debt with no
  deadline attached, which is exactly the kind that needs a row rather than a
  memory.

## Move the audit record corpus wholly onto draft-gilda-audit-agent-audit-record-00

- [ ] **Publish the rest of the successor draft's Appendix B and retarget the
  manifest.** The corpus now holds Section 5.4 to the successor draft (entries,
  freshness, `EV13`, `FR1` to `FR16`), but its manifest still names
  `draft-gilda-wimse-agent-audit-record-02`, because the successor's other new
  rows are not published here: `A18` to `A20` (policy-source unavailable and the
  fallback's `decision.policyDigest`), `EV11` (a status outside the closed set),
  `EV12` (an evaluation member the draft does not define, which neither reader
  refuses yet), `R1` to `R9` (the Section 4.7 retention entry and the dating
  check), and `N1`, which the successor gives a single conforming verdict. When
  those land, set `DRAFT` in `gen_vectors.py` to the successor, drop
  `draftDocument`, and rerun:

  ```sh
  uv run --extra generators python vectors-agent-audit-record/gen_vectors.py
  uv run --extra generators python vectors-agent-audit-record/check_vectors.py
  heavy-queue heavy-run --name go-test --timeout 3600 -- go test ./corpora/ -run AuditRecord
  ```
