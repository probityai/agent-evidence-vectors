# Conformance appendix for v0.1 of the reporting format

This is the conformance set for v0.1 of the per-check reporting format of the W3C public-agent-conformance community group, written so that an editor can reference it by row and an implementer can run it without reading the thread. Every row of the rejection table is backed by two members of the corpus `vectors-w3c-report/` in the `agent-evidence-vectors` repository: one report that a conforming validator must reject under that row and no other, and one report, as close to it as one change allows, that the validator must accept. The corpus judges itself with two independent readers, one in Go and one in Python, and a test holds their output identical over the committed members and over deliberately broken copies. An implementation conforms to v0.1 when it rejects every reject member under the row the member names and accepts every accept member; that is the whole test, and it is runnable with nothing installed.

The rows are the group's, as the editor fixed the scope on 18 September from the handover of the same day. Rows 1 to 12 are the consolidated table of 15 September and keep their numbers. Rows 13 and 14 are carried under the numbering the handover proposes and are marked proposed, because nobody on the list has numbered them. The two late additions the editor took into sections 3 and 4, the rules the completed freeze list and the editor's restatement carry, the rules the thread settled beside the table, and the two record-definition rules of the handover (arity recomputed, domain declared once) are carried under their own identifiers with no row number, so that a later numbering costs nothing here. A row's identifier is minted by the corpus and bound to a sentence of the vendored message by digest, because the messages carry no identifiers and a message number names a position rather than a sentence. A reword of the sentence stops the corpus from building, which is the property that makes the identifier citable.

A member of the corpus is a whole report rather than one record, because two of the rules are properties of the report and not of any record in it: whether the roll-up says its checks were capable of a negative verdict, and whether the digest over the check set binds the leaf count and names the tree shape. Every report member also carries `resolves`, the store its reader resolves referenced observations against, so that the reading table's three lines are all members of the corpus rather than prose. The corpus carries the two gaps the editor recorded about the reference emitter on 18 September, that `void` had no slot and that `not-exercised` carried no cause, as members that show both closed, and it carries the 42 delta-related pairs Rocchia counted in his own corpus, each once as it was emitted before the freeze and once re-cut against v0.1. A mutation sweep, regenerated with the vectors and published beside them, relaxes each row in turn and records that only the members naming it flip.

## How to read a row

The reject member's `subject` is the report; its `expected.rejects` names the one row; the accept member differs from it by the smallest change that satisfies the row. Both cite the requirement in `requirements`, so a specification change that reworded the sentence would fail the pair by name. The class column is the handover's sort: a consistency row reads declared slots against each other and catches a contradiction; an evidence row reads a declared slot against a recomputed or resolved one and catches a falsehood; a form row is decidable from the object alone. The status column says whether the list agreed the row or this corpus proposes it. The sentence column quotes the vendored text with its line break where the sentence spans one; the digest column is the first sixteen hex digits of the SHA-256 over those bytes, and the full digest is in the manifest.

## The twelve rejection rows

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-001` (1) | consistency | agreed | `vb11134a37e7c0c2b` | `ve5d916a50130739e`, `ve70386fdb6f071d3`, `vfbd7379026575f04` | a non-verdict state with no cause | `87893835a3e13451` |
| `W3C-R-002` (2) | consistency | agreed | `vf374114fe7f28e7d` | `v804ca6858fa22efe`, `vfbd7379026575f04` | void with not_applicable, out_of_scope or withheld | `05fb9274ff0859d9` |
| `W3C-R-003` (3) | consistency | agreed | `v98252c989e84999d` | `v822b02c01fe9ddd2` | not-exercised with integrity-failure | `587e9bc351daaed2` |
| `W3C-R-004` (4) | consistency | proposed | `vec36e393a92b69eb` | `vf82e507d268fed9d` | a confinement control that failed while the check ran | `32dd6b74795b02bd` |
| `W3C-R-005` (5) | consistency | agreed | `v7cac3bda7403c268` | `v320406e03fff4faa`, `ve5d916a50130739e` | a declared exclusion with any state but not-exercised | `ed9007c6e8a11eb2` |
| `W3C-R-006` (6) | consistency | agreed | `v8981e0830c69b869` | `vaad2cb64c5b0646b` | a non-verdict state carrying either qualifier | `4ef6f3c9383ae454` |
| `W3C-R-007` (7) | consistency | agreed | `vdcbd067d047bfbd0` | `v8a7442b19984a1ff` | a verdict state carrying a cause | `831dc816ea23fa26` |
| `W3C-R-008` (8) | consistency | agreed | `v0e286b53de78162a` | `v1a0f984d88bb9fe2` | other-verdict foreclosed with discrimination demonstrated | `2c6f812fc2752889` |
| `W3C-R-009` (9) | consistency | agreed | `v5a2ff35648828621` | `vf9b5623144960dda` | discrimination demonstrated with other-verdict unknown | `111e3eb11cdcc313` |
| `W3C-R-010` (10) | consistency | proposed | `vbe6937292f4f1614` | `v0090b52048ca1f51` | foreclosed without a constraint set and a domain | `139eba59f4dc4345` |
| `W3C-R-011` (11) | consistency | proposed | `vee997c119f09258b` | `vfa79ad0a7bd957b9` | an asserted value without its evidence reference | `f68cd56a997a5773` |
| `W3C-R-012` (12) | consistency | proposed | `vd1eb6a3fb13eb97d` | `v56b6337b612b1ee3` | whose changed slot is the checker | `d2268e7db1d50fe5` |

## Rows 13 and 14, under the numbering the handover proposes

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-025` (13 (proposed)) | evidence | proposed | `v3fef7c8cc4ed5e4b` | `v56f37afaff2a6ca8`, `v76c0022fb2a7f21e` | other-verdict demonstrated citing an evidence object whose moved does not contain the verdict | `01119b86460f6112` |
| `W3C-R-026` (14 (proposed)) | form | proposed | `vcf1cbb85d729dcd1` | `v9b7c8cf7d1b9f679` | 14 moved asserted on an evidence object that neither carries both observations nor references them with digests | `021af13381601bcf` |

## The two late additions of 18 September

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-013` ((a) roll-up) | evidence | agreed | `v1660acd2e4efb7c7`, `v4e4face5dd4ff492`, `vaeb76896b202e837`, `vc58647a590befbb7` | `va213bada85cc9abe`, `vb195f23e8436fd19`, `vd8d93fd735111aa5` | a roll-up states whether the checks it aggregates were capable of a negative verdict | `f73fd10347201018` |
| `W3C-R-014` ((a) prior run) | consistency | agreed | `v66fd68ad7d106fac` | `v04934d23180f6d9c` | a prior discriminating run only counts where check identity survives across runs | `2da5682dbbb4be1f` |
| `W3C-R-015` ((b) set binding) | evidence | agreed | `v28820b464a335617`, `v4a06b866afca0d49`, `v7c22f1451e51aeb5`, `v88935f0b29397a80`, `vfbc5db1c2a012359` | `v1032eb59a7cdb30f`, `v148fc59046a8548a`, `v86e1560a0d27b432` | digest match establishes a set only when the count of leaves is bound too, and a report says which tree shape it uses | `c6fe2b8552666e81` |

## The rules the freeze list and the editor's restatement carry

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-016` (declared slots) | consistency | agreed | `v04b7811e691bd2c9`, `v086f61b528d28efd`, `v10aaaebb49b0bcd3`, `v1a5c0a7b37f5d2c4`, `v1bb2e51524055d00`, `v1bc07a427d07bb7f`, `v239dc2ee7b28a2bb`, `v25ba541b9d311416`, `v2a90adc95b2fbdaf`, `v32c6afab9eb5888a`, `v36999d5568e9aacf`, `v3a14f94887e53e0d`, `v48d22035dc3a5f54`, `v5390d3d7133f3963`, `v54dea8bab0674755`, `v67727ceb5f2f7932`, `v6cfd1d72b49d8853`, `v77f27a301818a512`, `v7aca350e00458527`, `v7ead0086cb766b10`, `v7ec5cc451c0c1564`, `v8b06a7e78dc8d039`, `v96087777a4afe26f`, `vab06fd8893fe7da9`, `vac685ed4f2b7b142`, `vb6be26b7111909cb`, `vb7ec64962345ec63`, `vb8c546609d4103b0`, `vbbeed17aecbe9848`, `vbdcffc81f99b2078`, `vbdf5d0dc993f1310`, `vbec908a03edd1250`, `vcc4002f4776bac10`, `vd4eb88d206b3abdd`, `vd841f2eea4d0651e`, `vd85d62c0213a9749`, `ve14d385f9bcbd83b`, `ve2460634487d8a8f`, `ve784e75da615e795`, `ve9ebdb7db94e0b9d`, `vf0793a8c5fc26e52`, `vf2fde28af69a1348`, `vfbf04f56b585e3fa` | `v050e5667630b8bf7`, `v183b37dea5ad4159`, `v20f99b9d22c842a3`, `v22f803622ac75918`, `v254933bf314c82fc`, `v265c2e6f0a3d31f6`, `v2ddb14c9194e0341`, `v3aef8ba9ac745dbf`, `v44f7a4acc7f66fa4`, `v494ac13464d685ee`, `v4c778d3ee20deb35`, `v518aa8d55ab5460b`, `v568e8a1311ecb396`, `v5a678e8560a4f0f1`, `v7351d22d2343dfb5`, `v737955ac1c0d9c2e`, `v8224d0f41c80f492`, `v828ec4d8309aa2e3`, `v84f8c68bc5fc2810`, `v8c15455bb3d933cb`, `va18bfa567e0405b7`, `va19ba1b3f9f382bb`, `va4fc9fc8f711bd58`, `va91d537fa714f2d3`, `vaca8620fefade22f`, `vb4de5d37845a1546`, `vb684dfb39487fcb1`, `vbb1688d0226174aa`, `vbca0a5030104e2f3`, `vc2cab6dea09f0a3b`, `vc39c75a8c00ab957`, `vc653bb099d9c5839`, `vd27e483fe63e78c0`, `vd64679c8b7f9e736`, `vd7d23c0d86701fc6`, `vdcb0849fc754aaea`, `vdec1361509de89d4`, `ve4744745405812b9`, `ve53f0521c7e3a30c`, `ve7520b18160365d2`, `ve9cefed56bbc8359`, `vea3ee7919ceb2e10`, `vea80ece35200e349` | an object whose moved is not contained in its declared set is rejected | `303d488c14eed0d2` |
| `W3C-R-017` (roll-up denominator) | evidence | agreed | `v1c020dd1ed49874c` | `v735efb00ce85d044` | never emitted without its complete denominator | `526d7694de57f6c5` |
| `W3C-R-018` (roll-up counter) | evidence | agreed | `v48877f27bbd03b55` | `vdf05d359490e7833` | the counter over carried against referenced | `31c3dfd19fc59147` |
| `W3C-R-019` (closed vocabulary) | form | agreed | `v27a01b14321f6ae5` | `v2a251ae413920da5` | because free text does not aggregate | `1b376a60d7520ff7` |
| `W3C-R-020` (reference mismatch) | evidence | agreed | `v499412698a1dd50e`, `v6cd84ff1aea45153`, `vab508347e605c0af` | `v472759709d82c585`, `v4f343e8bd3d6af08`, `vfa24e4f45c2e826e` | resolves with a mismatch (an integrity failure) | `af507f1056e619da` |

## The rules the thread settled beside the table

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-021` (recomputed delta) | evidence | agreed | `v9c68a108ed63da63` | `vecd8b7bb20fed3a3` | they read moved as recomputed from the two observations the object names | `bc4afdb28cee9c30` |
| `W3C-R-022` (coverage block) | form | agreed | `v1158315f2ce233a8`, `v67e996a3fa03e959` | `v0f620037c42bbfc3`, `v42d2d180b1c0b5b3` | a sampled / full_coverage flag with the count of scannable files recorded before the per-repo cap | `50c6f490bcf092b2` |
| `W3C-R-023` (population denominator) | evidence | agreed | `v5c26b11179a2277a`, `vd2e50306dcd6c470` | `v9f618dfd3e44b84a`, `va1e910d25ebbb2c4` | a claim over an empty population is reported as not claimable, not as satisfied | `04fa2499c017be72` |
| `W3C-R-024` (delta-related pair) | consistency | agreed | `va3c277aa6743807a` | `vd3e84d6a85cb6a0f` | Unrelated pass and fail records in one corpus must not qualify | `d75ca465cf824295` |

## Arity and domain, from the handover's record definitions

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-027` (arity recomputed) | form | agreed | `v20a798b25fc2ec0b` | `vc938b2ab36cae34a` | so arity is recomputed from the delta | `8d4a3be209be152c` |
| `W3C-R-028` (domain once) | form | agreed | `vd2ae28ba9140bc89` | `va0620b488f2ff2f5` | The domain is declared once at run level | `fc883a4e2664fb33` |

## Proposed in the v0.1 comment window

| row | class | status | reject | accept | sentence | digest |
|---|---|---|---|---|---|---|
| `W3C-R-029` ((a) control binding) | consistency | proposed | `va86e962a5024f152`, `ve9c436f93e42e394` | `v49afe44cc51bc376`, `v796a6048345b8f58` | say that the control uses the same checker revision and relevant configuration and constraints as the checks whose negative capability is being reported | `c3507c44c022f601` |

## Proposed classification of rows 4, 10, 11, 12 and 13

The handover sorts rows 1, 2, 3, 5, 6, 7, 8 and 9 into the consistency class and row 14 into the form class, and leaves five rows unclassified: 4, 10, 11, 12 and 13. Each of the five is classified here from the record definitions in the handover's own terms, with the vector pair that demonstrates the class under it. The part of the class a validator can measure is measured: every reject member of the corpus is re-judged by a reader that resolves nothing, and a row whose members stop firing reads a resolved slot (`resolvedRead` in the manifest). Rows 4, 10, 11 and 12 fire under that reader; row 13 does not.

### Row 4, `W3C-R-004`: a confinement control that failed while the check ran

**Consistency.** The row reads the record's own `cause` cell against its `state`, the same construction as row 3, which reads the cause value `integrity-failure` against `not-exercised`. The fact that a confinement control failed while the check ran is written as the cause value `confinement-failed-during-check`, admitted only under `void`, so the four-field record of section 1 carries no extra cell for it. That answers the question Schuurkes put on the list of how the antecedent is represented for a reader (`0076`), with the construction Rocchia proposed in reply (`0077`). Nothing is recomputed and nothing is resolved; a reader with no suite and no checker fires the row from the record alone, and the reject member below fires under a reader that resolves nothing (`resolvedRead` false in the manifest). The reject member is `inconclusive` rather than `fail`, because a verdict state carrying any cause is also row 7 and a member is rejected under one row only. What a row over declarations cannot establish, as Schuurkes noted, is that a producer disclosed every confinement control that failed. The value's name is proposed, pending the editor's v0.1 text.

- reject `vec36e393a92b69eb`: a confinement failure during the check recorded as its cause while the state is inconclusive
- accept `vf82e507d268fed9d`: the same record reported void, the only state that cause is admitted under

### Row 10, `W3C-R-010`: foreclosed without a constraint set and a domain

**Consistency.** The row reads a declared value, `foreclosed`, against the presence of the two parameters that value must carry, the constraint set and the domain identifier. The handover's own sort settles what a presence check within one record is: rows 1 and 7 are presence checks (a non-verdict state with no cause; a verdict state with a cause) and both sit in the consistency class. Row 10 is the same reading applied to the other-verdict cell, so it takes the same class. It is not a form row, because the object's shape is fine; what contradicts is the value and its own arguments.

- reject `vbe6937292f4f1614`: foreclosed with neither a constraint set nor a domain
- accept `v0090b52048ca1f51`: foreclosed naming both, by identifier

### Row 11, `W3C-R-011`: an asserted value without its evidence reference

**Consistency.** An asserted qualifier value is read against the presence of its evidence reference, and the reference is read against the report's own evidence list: both are declared by the emitter in the same report. Whether the referenced observations then resolve is the reading table's business (rows 20, 21 and 13 read the resolved slot), not row 11's, which fires before any reader resolves anything. It is row 1 applied to a qualifier: a value asserted with the cell that should justify it left empty.

- reject `vee997c119f09258b`: demonstrated asserted with no evidence reference
- accept `vfa79ad0a7bd957b9`: demonstrated with the reference that carries it

### Row 12, `W3C-R-012`: whose changed slot is the checker

**Consistency.** The handover guessed evidence for this row because it reads a slot of a referenced object. The class is decided by what is read, not by where it lives: the slot read is `changed`, which the per-slot sort lists as declared, written by the emitter, and the object cited sits in the same report. The row catches a contradiction between two declared cells, a discrimination cell witnessed by an object that declares it changed the checker rather than the input, and needs no recomputation; the reject member below fires under a reader that resolves nothing. An evidence-class version of this row would read `changed` against a recomputed diff of the two observations' checkers, which no v0.1 slot carries.

- reject `vd1eb6a3fb13eb97d`: discrimination cites an object whose changed slot is the checker: attribution in a discrimination cell
- accept `v56b6337b612b1ee3`: the same cell citing an object whose changed slot is the input artifact

### Row 13 (proposed), `W3C-R-025`: other-verdict demonstrated citing an evidence object whose moved does not contain the verdict

**Evidence.** The row reads `moved`, and v0.1 fixes `moved` as recomputed over what the referenced observations actually contain, never as declared. So the row reads a declared cell, other-verdict `demonstrated`, against a recomputed slot, which is the definition of the evidence class. The corpus shows the consequence the reading table requires: the reject member fires when both references resolve with matching digests and the recomputed delta holds the fired-rule list and not the verdict; the second accept member is the identical report read by a reader that can resolve neither reference, and the row degrades rather than fires (`resolvedRead` true in the manifest).

- reject `v3fef7c8cc4ed5e4b`: the other verdict asserted demonstrated by an object whose two observations both fail: moved, recomputed, holds the fired-rule list and not the verdict
- accept `v56f37afaff2a6ca8`: the rejected report read by a reader that cannot resolve either reference: unchecked, so the row reading moved degrades and does not fire
- accept `v76c0022fb2a7f21e`: the same assertion citing an object whose observations pass and fail, so the verdict is in moved

## The value for void

The fixed vocabulary is CAP-1's eight dispositions, a value for void, `integrity-failure` kept apart from `availability-failure`, and `precondition-unsatisfiable`, and this corpus adds one more under void, proposed with row 4: `confinement-failed-during-check`, the cause row 4 reads against the state. The list named the void slot and never its value. This corpus proposes `evidence-does-not-hold`, in the words of the message that found the gap: void is a unit that was examined and whose evidence does not hold up. The reference emitter writes it for a harness that could not establish a verdict, and family `w3c-f-gaps` carries the member. The name is proposed, not agreed; any closed identifier the list prefers replaces it in one constant on each rail.

## The reading table, as members

Carry-or-reference is fixed as: the format permits both and requires one, the form is decidable from the object alone (row 14), and reading a well-formed object is a table rather than a row. The three lines of the table are each a member. Resolves with matching digests: the accept members of families `w3c-f-20`, `w3c-f-21` and `w3c-f-25`, where the reader's store carries the observation the reference names and `moved` recomputes from it. Resolves with a mismatch: the `w3c-f-20` reject member whose store resolves the reference to bytes with another digest, an integrity failure, beside the check-set member whose RFC 6962 root was computed with domain separation over a duplicated last leaf, which is the same failure over the set. Does not resolve: the second accept member of `w3c-f-25`, the report that a reader with the suite rejects, read by a reader without it, unchecked, with the rows that read `moved` degrading rather than firing. The Merkle line the editor took from the narrowing on the list, that binding the count is necessary and is not a general membership proof and that domain separation added while duplicate-last padding is retained does not remove the ambiguity, is the `w3c-f-15` reject member that binds its count and asserts domain separation with no tree shape declared, rejected because the producer declares the shape.

## The tree shapes, as a closed set

Section 3.1 of the v0.1 draft requires a report to declare which tree shape its digest over a collection uses and leaves the vocabulary open (Q7). This corpus holds it closed, for the reason the cause vocabulary is closed: free text does not aggregate. The set is `flat`, `rfc6962`, `RFC9162_SHA256`. `RFC9162_SHA256` is the identifier RFC 9942 section 5.1 registers for the Merkle tree of RFC 9162 section 2.1.1 over SHA-256, whose tree hash is the RFC 6962 one, so the two names denote one construction and a report may use either. Its admission is proposed, following the closed, versioned set of construction identifiers Schuurkes asked for on the list, and it enters with its members: in `w3c-f-15` an accept member bound under `RFC9162_SHA256` and a reject member naming the same tree in free text, and in `w3c-f-20` a reject member whose `RFC9162_SHA256` root was computed over a duplicated last leaf with its accepting twin. Each reader maps every name in the set to its own root function and refuses any other name, so a shape outside the set can never be hashed as one inside it.

## The counts on open row B, labelled as the editor labels them

Row B, whether a stated delta is bounded to one field, stays open, and the editor carries the figures with the standing each has. The 42 one-field pairs in the disensor corpus are reproducible: `tools/emitir-42.py` in `NicolasRocchia/disensor` runs the pinned checker over every vector, and this corpus's own derivation (`origin/derive_pairs.py`) and a re-run of that script on 18 September both give 42 (v0.2 4, v0.3 16, v0.4 22), 0 carried against 84 referenced, 69 errors serialised as strings, 0 vectors disagreeing with their declared expectation. The 0 (MUST-FAIL pairs with different fired-rule lists at one field) and the 132 (at two fields) come from a script that is not published, and the editor attributes those two to their author rather than presenting them as reproducible. Sankalp's 252 at v0.11.1 sits beside them with the same labelling, and it is reproducible: of the 315 reject entries across the eight manifests of `agent-evidence-vectors` at tag `v0.11.1`, 269 carry an `expected.codes` list and 252 of those hold exactly one code. Re-derive it from a clone with the tag fetched:

```
python3 - <<'EOF'
import json, subprocess
files = subprocess.run(["git", "ls-tree", "-r", "--name-only", "v0.11.1"], capture_output=True, text=True, check=True).stdout.split()
one = rejects = 0
for path in [f for f in files if f.startswith("vectors") and f.endswith("MANIFEST.json")]:
    manifest = json.loads(subprocess.run(["git", "show", f"v0.11.1:{path}"], capture_output=True, text=True, check=True).stdout)
    for entry in manifest.get("vectors", []):
        if entry.get("kind") == "reject":
            rejects += 1
            codes = (entry.get("expected") or {}).get("codes")
            one += isinstance(codes, list) and len(codes) == 1
print(rejects, one)
EOF
```

The figure is pinned to `v0.11.1` and does not track the live suite, because row B is an argument about what a corpus at a stated revision already asserts. The measurements do not contradict each other: one field is a property of how a corpus was built, not one the format can assume, and arity is therefore recomputed from the delta (`W3C-R-027`) and read by no row while the question is open.

## Section 9.1: the reference emitter's run, published

The v0.1 draft records as a known gap (section 9.1) the report the reference emitter writes over the adversarial-execution corpus, and asks for a check by a second reader. That report is published beside this corpus, pinned in the manifest's `referenceEmitterRuns` and re-judged by both readers on every run, which refuse the corpus if the file is gone, its bytes have changed, or the validator would reject it. It is kept apart from `observedRuns`, which is reserved for runs by an implementation this repository did not write.

- `vectors-w3c-report/observed/aee-v0.12.0/report.json`, sha256 `37288d8dfc01f56cb5ef553232258dc596928bc962e2309e0c7dc09ae588baf2`, written by `uvx agent-evidence-vectors==0.12.0 --emit-w3c-report report.json` (agent-evidence-vectors 0.12.0, tag `v0.12.0`, commit `2f3aee40a454df6de0f571d119f057d7dbb8dd67`) from the harness report `vectors-w3c-report/observed/aee-v0.12.0/conformance-report.json`, with the record of the run at `vectors-w3c-report/observed/aee-v0.12.0/RUN.json`. It holds one record per member of the AEE corpus at tag `v0.12.0` (239 fail, 31 pass, 2 inconclusive), with no shape error and no row firing, and runs made at `2026-09-24T13:11:34Z` and `2026-09-25T15:46:07Z` wrote the same bytes.

## The crosswalk from the harness's report, and the known gaps

The reference emitter in `packaging/agent_evidence_vectors/w3creport.py` writes a v0.1 report from the report the AEE harness writes, one per-check record per replayed vector, with the domain declared once at run level. The two altitudes are kept apart: the harness's `result` stays four-valued and recomputable, and the per-check record says what a consumer may conclude about the statement the vector carries. `pass` is a valid verdict with result `pass` or `pass_indirect`, the result carried as the qualifier; `fail` is a valid verdict with result `fail` or `degraded`, or an invalid verdict, with the codes carried; `not-exercised` is a manifest entry declaring `expected.unmeasurableBecause`, reported with cause `precondition-unsatisfiable` and that text, or a report member the manifest expects and the rail left absent, with cause `unavailable`; `void` is a harness that could not establish a verdict, with cause `evidence-does-not-hold` and the rail's errors or exit as detail. The report the emitter writes from the AEE corpus conforms: no row fires on it.

Two things the emitter says out loud rather than quietly fixing. The indeterminate kind, a vector whose specification admits more than one reading, is reported `inconclusive` with cause `unsupported_input`, the nearest closed disposition, and the reading the rail committed to or the readings declared as detail; the fixed vocabulary has no value for an input the specification leaves undetermined, and free text in place of a disposition is refused, so the gap is recorded here and not papered over with a value the list did not agree. And the emitted report carries no evidence objects: the harness replays each vector alone, so no record asserts a demonstrated other verdict or a demonstrated discrimination, and the roll-up's negative-capable field is answered from the run's own non-pass counts.

## Two further subjects in the same corpus

The same manifest carries members of two other subject types, judged by their own sentences in their own modules: the Run object of `draft-arsentev-agent-run-metrics-00`, twenty-two rows over the members and invariants a validator can read off one Report, and the discovery snapshot of `draft-arsentev-llm-context-discovery-00`, eleven rows over what an origin advertises and what a consumer resolves. Their tables follow the same shape and are listed after the report rows.

## Run object rows

| row | reject | accept | sentence | digest |
|---|---|---|---|---|
| `ARM-R-001` (5.1) | `va934761de6c65857` | `vc7c310827b9dbd10` | Reporter MUST emit "1" while conforming to this specification | `f313511759b2f6ce` |
| `ARM-R-002` (3.1) | `v696c5dd5918c854b` | `v3d5079f23e498451` | The "end" member MUST be present when "status" is "completed",    "failed" or "aborted", and MUST NOT be present when "status" is    "running" | `a82c8c4e90b439d6` |
| `ARM-R-003` (3.1) | `v9815e1f08a7e0664` | `v668c618f2a50e26e` | When present, "end" MUST NOT be earlier than "start" | `1651e4aa28aef3c5` |
| `ARM-R-004` (3.1) | `vecddffbd8678e5ef` | `vf7334aa7dcf00826` | a Reporter MUST NOT emit    a value other than the four listed | `532a0c7a01289d79` |
| `ARM-R-005` (3.1) | `ve3fcd2bc70913ea2` | `v068436e239f3711a` | When the "steps" array is present, "step_count" MUST be    greater than or equal to the length of that array | `b0245f78d559c0cf` |
| `ARM-R-006` (3.2) | `vccc374459c05dd52` | `va32bdaeb5f8aed8f` | Within one Run, "index" values MUST be unique and MUST be assigned in    the order in which Steps began | `de2c45f5dcc4d136` |
| `ARM-R-007` (3.2) | `ve2c7ff41cba0be5d` | `v838fe3be3393696c` | When "kind" is "model_invocation", the "usage" and "model" members    MUST be present | `bb47f3459eea16f1` |
| `ARM-R-008` (3.2) | `v3add8861d36c2543` | `vbf88ec51ebd083b6` | When "kind" is "tool_call", the "tool" member MUST    be present and the "usage" member MUST NOT be present | `cbf735970617d21d` |
| `ARM-R-009` (3.4) | `vc17bb5b854981008` | `v2b052236457b678c` | All members of a Usage object MUST be non-negative integers | `0748102d1586a9c5` |
| `ARM-R-010` (3.4) | `v0120d95db38b892b` | `vb1c8d4729c06472c` | "cache_read_tokens" is a subset of "input_tokens" and therefore        MUST be less than or equal to it | `912e608876053400` |
| `ARM-R-011` (3.4) | `vd02cc7abe1dbc2bf` | `vea598711b897286e` | "cache_read_tokens" and "cache_write_tokens"        denote disjoint subsets of "input_tokens" and their sum MUST be        less than or equal to "input_tokens" | `ab264faa892721d2` |
| `ARM-R-012` (3.4) | `ve4b9c82536808f52` | `v827901388ec40c23` | "totals" object MUST be, member by member, the sum of the    corresponding members of every Step's Usage object | `e6b6a4c51dfe30f7` |
| `ARM-R-013` (3.5) | `v28824a66a84f4b8c` | `vff5545c0760d7544` | One    "lifetime" value MUST NOT appear in more than one element of the same    array | `89119163b621c774` |
| `ARM-R-014` (3.5) | `vf1e99cf0310cc1c6` | `vd53bcd623743858d` | The sum of the "tokens" members of "cache_writes" MUST equal the    "cache_write_tokens" member of the same Usage object | `17816ade45921f0d` |
| `ARM-R-015` (3.3) | `vf414a4c9065ad7b8` | `v0f648c5f3080e1b1` | A Reporter MUST NOT    emit two Steps of one Run with the same "invocation_id" | `0883bbd19a653019` |
| `ARM-R-016` (3.6) | `v32c1e0be1a7bf104` | `v9dc96e6ca225e6e2` | A Run that emits "root_run_id" and has no       parent MUST set it equal to its own "run_id" | `546781f078f7e248` |
| `ARM-R-017` (3.7) | `vaac3a24b2552738b` | `vbba71aa9e6a41e1c` | The "amount" member MUST be a JSON string matching the ABNF [RFC5234]    rule | `f15b1c8c7a0cfe45` |
| `ARM-R-018` (3.12) | `vd302fdc2d7a97e6e` | `v21fe5a5de5f50124` | Its value MUST be a JSON object whose members all    have string values | `4d1f574a3f6c8983` |
| `ARM-R-019` (5) | `v8d4e61737e9ee6a6` | `v81c7f6fc68ea35a7` | Timestamps MUST be strings conforming to the "date-time" production    of [RFC3339].  They MUST use the "Z" time offset | `af8a371a7c03ddaa` |
| `ARM-R-020` (5) | `v2652b0b04c946504` | `v7257ad4efb1d0638` | MUST be non-empty strings of at most 128    characters | `f45b4290574244a8` |
| `ARM-R-021` (5.1) | `vf3af943ff1bf7375` | `vcdb9ae63a12852a8` | A Reporter MUST NOT use an unprefixed member    name for a purpose other than the one specified here | `a9283399f2f72c8c` |
| `ARM-R-022` (3.4) | `vef09761654b57a92` | `vb6e8cb7973f1fab5` | "reasoning_tokens" is a subset of "output_tokens" and        therefore MUST be less than or equal to it | `77239d6671db6001` |

## Discovery snapshot rows

| row | reject | accept | sentence | digest |
|---|---|---|---|---|
| `LCD-R-001` (3.1) | `vff8f75223d6658ef` | `v85c0428fc7fdabc7` | A context file MUST NOT be served with a "Content-Type" of "text/    html" | `dea0684290a3e21a` |
| `LCD-R-002` (3.2) | `vf86d92beb5a12905` | `v1910c8190bcd1b5c` | A discovery mechanism defined in Section 4 MUST point at an index       resource, never directly at a detail resource | `993eae7ed8a98e13` |
| `LCD-R-003` (4.1) | `v7bc7c1460093e973` | `ve5819dc9edb1f47b` | A publisher advertising a context file through this mechanism MUST    arrange that a GET request for "/.well-known/llm-context" on the    origin returns either | `b75a01b97d999548` |
| `LCD-R-004` (4.3) | `vb608f4ddfcc00a20` | `vb7065104515600ba` | Its value MUST be an absolute    URI | `cbf9300432d96463` |
| `LCD-R-005` (4.3) | `v388dee224f53c2c1` | `v9cfb2c8197757948` | A publisher MUST NOT use this record to advertise a context file    whose retrieval the same robots.txt disallows | `6c62b556add0487c` |
| `LCD-R-006` (4.4) | `v12f1e7e27b3f59c5` | `vcd6021208e8e8a6e` | a consumer MUST    apply the following precedence, highest first | `bc76905fa3c30441` |
| `LCD-R-007` (4.4) | `v85db98532abea6d9` | `v191fc069115f8706` | A consumer MUST NOT retrieve more than one index resource per origin    per retrieval cycle | `9303b76c717a46a4` |
| `LCD-R-008` (7.2) | `ve2b3a699bc06e53d` | `vf753bb908231e0a1` | A consumer MUST NOT attribute the content of a cross-origin index    resource to the advertising origin | `de7f08a1b2a8a663` |
| `LCD-R-009` (7.4) | `v70533f1029ed78e6` | `vd88fd757419269aa` | A consumer MUST impose its own ceiling on the size of any retrieved    context file | `6bf3ffe5624cb4d3` |
| `LCD-R-010` (3.3) | `vcbd0eaef95bc9181` | `vfeb5d1872929ab35` | the response MUST carry an appropriate "Content-Language" | `1f8ceb1482c75131` |
| `LCD-R-011` (4.4) | `v79266aba771310af` | `vb450f39bace98641` | a consumer MUST evaluate the exclusion    rules of [RFC9309] against the index resource's URI before retrieving    it | `1cb26bd4e4ca5526` |

## The vendored text

| key | author | sha256 | source |
|---|---|---|---|
| `0001` | Kenne Ives | `62bafb6e88629bda0dc09c1d19982aaf831be7b8845bf80a2fb31deda676b143` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0001.html |
| `0025` | Nicolas Rocchia | `2ee9306408474a6966d8294d4e641c39aa253a2ab2bb377d01abcee5c3b94e95` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0025.html |
| `0036` | Evgenii Arsentev | `7a034174eb5f27f8f8865f49ab6999de20157dd3906b9d158366b62cc83b7738` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0036.html |
| `0043` | Nicolas Rocchia | `76f5af49f11108fccf5d01c3710771acdb4539c8761b655b8e06bda993bb03f1` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0043.html |
| `0050` | Kenne Ives | `1399c56136e7aa7630000f723a92169c12313ef6012eab130b3511ed2c7a5e35` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0050.html |
| `0060` | Nicolas Rocchia | `47f96e10c2ac5dc023a0dde77582331f58431cf4e8fabbb53a068a6d6a8f12bd` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0060.html |
| `0062` | Evgenii Arsentev | `b92f4a6ca926eaa8514c313054cf1736524d187ce36c9b6ef6c1f5d2b19ed977` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0062.html |
| `0069` | Evgenii Arsentev | `40153b17403b0e6594dfe00a9e9a5c01e5b978b6ce47b12a4ef0bbe31817514b` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0069.html |
| `0072` | Nicolas Rocchia | `27cea4f3ffd48ed4fd0cab47ae08df3542f3cdded2aded7163a489e2edf8b831` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0072.html |
| `0073` | Evgenii Arsentev | `42fa833367e0e1d5b484f988da520c96936f009bbe2578fa7d0f22691830a134` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0073.html |
| `0076` | Roel Schuurkes | `7622d0dc1cf7fc1d8b136739e042e3cc648a9291367301716e21c7b8dd05e751` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0076.html |
| `0077` | Nicolas Rocchia | `88531111f9d8c4243532011b983b9885a67b88c06560da36746dbbdb70769a7a` | https://lists.w3.org/Archives/Public/public-agent-conformance/2026Sep/0077.html |
| `draft-arsentev-agent-run-metrics-00` | Evgenii Arsentev | `0ef9e7fbc39d04bf2e245ed12b6a15eb4988d56abf3b07a65aab7861ad14d7f0` | https://datatracker.ietf.org/doc/draft-arsentev-agent-run-metrics/ |
| `draft-arsentev-llm-context-discovery-00` | Evgenii Arsentev | `13081268c70a19e9b3f74a6f772b657c56403ce6c45623da39a188394eefd411` | https://datatracker.ietf.org/doc/draft-arsentev-llm-context-discovery/ |
