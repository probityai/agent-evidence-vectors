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

- [x] **Publish the rest of the successor draft's Appendix B and retarget the
  manifest.** Done for v0.26.0: `A18` to `A20`, `EV11`, `EV12` (both readers now
  refuse an undefined evaluation member), `R1` to `R9` with the dating check in
  both readers, `N1` settled as `valid`, `DRAFT` set to
  `draft-gilda-audit-agent-audit-record-00`, `draftDocument` dropped. The
  members are the 99 Appendix B rows and 7 Section 5.4 members. The id map across
  v0.18.1, v0.25.0 and v0.26.0 is `vectors-agent-audit-record/ID-MAP.json`.
  Reported by Lars Kersten Kroehl (MolTrust) on the AUDIT list,
  <https://mailarchive.ietf.org/arch/msg/audit/Wdv-fOIodjvF3z9OUFNfXLGP0ts>.

## Audit record members waiting on revision 01 of the draft

Each needs normative text that revision 01 of
draft-gilda-audit-agent-audit-record is adding. Do not author a member before
-01 defines its rule; when -01 is posted, add each to `gen_vectors.py`, give it
the row identifier -01 prints, and rerun the three commands of the row above.

- [ ] **Root key in `validationData`, two members.** -00 Section 4.7 carries the
  certification path of the record's own signing key and of each anchor, and
  nothing for the root of the delegation the record was decided under. -01 adds
  a `validationData` element for that root. Two retained members: one entry
  that carries the delegation root's path, and one that omits it, which a
  verifier must report as not established for the delegation, never as a pass.
  Source: the -00 text, Section 4.7
  (<https://www.ietf.org/archive/id/draft-gilda-audit-agent-audit-record-00.txt>),
  and the WIMSE thread on the trust anchor the delegation chain rests on.
- [x] **Two individually fresh values of one input (Mikhail Sergeev).** Done for
  v0.26.0 as `FR14` (valid) and `FR15` (malformed), the identifiers -01 prints.
  `FR14` is `A2` judging two delegation paths, both values of `standing-source`
  fresh at `reportedAt` (age 30 under `maxAge` 60, age 3600 under 7200); the
  entry carries the first value's pair, the one that expires first. A verifier
  holding only the record cannot recover the two values, so the manifest entry
  carries them under `aggregation` and the judge requires `aggregate_values` in
  `packaging/agent_evidence_vectors/auditrecord.py` to yield the entry the
  record carries. `FR15` is the pair -00 wrote, refused. The section sweep shows
  -00's rule fails exactly `FR14`. The corpus-only proposals that held `FR14` to
  `FR16` on main are now `FR16`, `FR17a` to `FR17c` and `FR18`, mapped in
  `ID-MAP.json`. Source: Mikhail Sergeev, technical comments on -00, 20 October
  2026, point 1; issue #249. Quoted -01 sentences are pinned by hash in
  `vectors-agent-audit-record/REVISION-01-PIN.json`.
- [x] **Coverage clause: `scopeComplete` of true beside a gap inside `pathScope`
  (Mikhail Sergeev).** Done for v0.26.0 as `TI6` (authoritative, `false`, gaps
  only outside the scope: malformed under -01, accepted by -00), `V4` and `V5`
  (`true` beside a gap inside the scope, authoritative and voluntary: malformed
  at any tier), with a `coverage` rule in the Python and Go readers. The section
  sweep shows -00's clause fails exactly `TI6`, `V4` and `V5`. Source: the same
  message, point 4; issue #250.
- [ ] **A denied decision followed by a write (Mikhail Sergeev).** -01 moves the
  equal-roots condition from the decision to the observed interval: a denied
  request whose own write was observed keeps the write and derives
  `agreement` of `disagree`. `A3` already carries deny beside occurred; the new
  member pins the -01 sentence on a record shaped from `A2` (deny, empty write
  set) gaining its own attributed write, roots and chain moved to match. Source:
  the same message, point 2. Residual of the two rows above: author this member
  from the -01 Section 4.2 sentence, add its `gen_vectors.py` entry with the
  row identifier -01 prints, then rerun `gen_vectors.py`, `check_vectors.py` and
  `go test ./corpora -run AuditRecord`.
- [ ] **OpenTimestamps anchors (Toshikatsu Oga).** No member carries an
  `opentimestamps` anchor, and neither reader dates from one. -01 defines the
  anchor's time as the Bitcoin header time with a 7200-second tolerance in place
  of the 300-second skew, says `anchorWithin` for an OpenTimestamps-only
  retainer covers confirmation latency, and appends an upgraded proof beside
  the pending one. Members: `R1` and `R2` shapes over real OpenTimestamps
  proofs from his #51 pilot (he offered the bytes), an honest retainer whose
  header time is ten minutes before `receivedAt` (refused as `R3` under -00,
  well formed under -01), and a pending proof beside its upgrade, where the
  pending one dates nothing. Both readers then need an offline OpenTimestamps
  path from the proof to a block header the verifier holds. Source: Toshikatsu
  Oga, comments on -00 Section 4.7, 20 October 2026.

## Make the count gate and its test fast enough to run locally

- [ ] **Cut one `scripts/count-gate.py` run from 110 s, and its test from about 30 minutes.**
  Measured 2026-10-30 on 14,300 tracked files: one run takes 110 s, and 73 s of it is
  `re.Pattern.sub` in `countcensus.mask` (56 mask patterns over 1,171 files, about 5 s each,
  no single outlier). `scripts/count-gate-test.py` runs the gate once per case, 66 times on at
  most 4 workers, so it passes only in remote CI; a local run hit a 600 s timeout.
  Fix: combine the masks into one compiled alternation, or mask each file once and cache the
  result across cases. Start with `python3 -m cProfile -s cumtime scripts/count-gate.py --root .`.
