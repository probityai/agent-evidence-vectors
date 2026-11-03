---
target: https://github.com/harbor-framework/harbor/issues/2343 ("Discussion: optional provenance-aware decision events for ATIF", an ISSUE, opened 2026-07-15T12:30:02Z by ktwu01, state open, 4 comments, last activity 2026-07-17T12:08:22Z)
channel: GitHub issue comment into the live discussion
deadline: none. The thread has been quiet since 2026-07-17 and there is no window to miss.
audience: ktwu01, who opened it, plus HarperZ9 and clementineCU, who between them converged on a specific invariant in the last 3 comments
status: DRAFT. Not posted. The operator sends.
identity: private individual. No company, product or repository name from the stealth list appears in this text.
writing_pass: edelman register applied; humanizer run end to end including the jury stage; mechanical gates run. See the report for the per-gate results.
evidence_status:
  - "the issue's subject is candidate actions and rejection provenance, not artifact binding": verified_fact, gh api capture held privately (harbor thread 2343, JSON). An earlier internal reading had this thread wrong
  - "the quoted lines from the issue body and from the 4 comments": verified_fact, same capture plus 2343-comments.json, sha256 in _raw/INDEX.md
  - "ATIF v1.7 provides root extra, root trajectory_id, root session_id, subagent_trajectories, trajectory_path, continued_trajectory_ref, per-step and per-observation extra": verified_fact, rfcs/0001-trajectory-format.md:30-99 and :356-376 at harbor-framework/harbor 1f84b4c
  - "trajectory_id is required on embedded subagents, optional on standalone trajectories": verified_fact, rfcs/0001-trajectory-format.md:92
  - "session_id is run-scoped, may collide across siblings, informational only on a ref": verified_fact, rfcs/0001-trajectory-format.md:91 and :362
  - "the 4 arms reach the outcomes the contract states": verified_fact, demo/four-arms.sh exits 0
  - "8 corpus cases with expected verdicts": verified_fact, `go build -o aee-verify ./cmd/aee-verify && ./aee-verify corpora/vectors-artifact-binding/` reports 8 members, 2 verified, 4 failed, 2 not-established; exit 1 names a member whose bytes moved
push_plan:
  - the operator posts it as an issue comment, from his own account, as a private individual
  - re-read the thread first. It has 3 substantive human comments and a 4th would land on a converged invariant, so a comment that ignores that convergence reads as inattention
  - it goes out within a day of the harbor#3123 comment and each links the other
  - if ktwu01 or the maintainers want text, the follow-up is a pull request against rfcs/0001-trajectory-format.md adding the convention section only, with no core field change
  - follow-up cadence: one nudge after 2 weeks, then leave it
---

# Draft comment for harbor#2343

clementineCU's last comment states the invariant this convention turns on: "the link between them is causal, not mutating: reopened_from=<refusal_decision_id>", so that "review can still replay why the first run refused even after the second run becomes valid." I have that running, in a different vocabulary.

What I built is a record over a finished evaluation run's persisted bytes: a role, a relative path, a byte length and a SHA-256 for each covered file, canonicalized with RFC 8785, signed with a detached ed25519 signature. A second grading of the same saved bytes writes a second record. It never overwrites the first.

The second record names the first by digest, names the archive both of them graded by the same digest, and verifies independently of it. My demonstration runs 4 arms. An intact archive verifies and regrades.

One changed byte fails before any grading runs. A required artifact that is absent returns a third outcome, not-established, with its own exit code. And the same archive graded by a changed verifier yields 2 records, 2 rewards, 1 archive.

Arm 4 is clementineCU's assertion list, item for item. A refusal keeps its own hash. The later event has a new one.

The link points back without rewriting.

One piece is missing. It is the piece that gives an observation hash its meaning. clementineCU's sketch has a refusal event keeping "its original observation hash, checked fields, missing/stale field, and reopen condition." A hash the producer writes into its own document, inside a document nothing binds, is a self-report.

The number is whatever the writer chose to write. It cannot establish that the document in a reader's hands is the one the run produced. It cannot establish that the files the observation covered are still the files on disk.

Bind the whole document from the outside, and the hash inside it becomes checkable. Leave it unbound, and `reopened_from` links 2 assertions. It does not link 2 records.

ktwu01's Important limitation section is the strongest part of that issue, and it is the same distinction one level up: "An inferred option must not be presented as evidence that the agent actually considered it." That is a third state, and formats lose third states.

My implementation returns 3 verdicts for that reason: verified, failed, and not-established for a record that cannot be checked to a conclusion because something required was never captured. A verifier that collapses not-established into failed accuses whoever ran the job of tampering. The file it names was never written.

One that collapses it into verified admits an incomplete record instead.

The agent_emitted and posthoc_inferred values fail the same way if a consumer may read a missing provenance field as either. So I would make the absent case an explicit third value in the schema and refuse a decision event that omits it. Leaving that default to consumers is where the distinction gets lost.

On mechanism, the instinct in the issue body is right and no core ATIF field is needed for any of this. The body proposes "an ATIF extra field" over "changing the core schema". I followed that.

v1.7 already carries an extra object at the root, on every step and on every observation, and it already defines root `trajectory_id` as the canonical per-document identifier, required on embedded subagents. Setting it on root costs nothing and gives a binding a stable name for the document. The whole ask against the format is one conventional key, with a decision-trace key beside it at the same level.

One caution about identity, since the thread reaches for hashes. Do not key anything on `session_id`. v1.7 is explicit that it is run-scoped, that siblings may legitimately share it, and that on a reference it is "informational only".

A decision event wants a document-level name, which is `trajectory_id`, and a run-level name, which for a Harbor run is the trial id in its result file. Those are 2 facts. v1.7 spent a breaking change on separating them, and folding them back into 1 field undoes that work.

For a first version I would also keep the binding at the whole-document level. That is a real disagreement with the direction a decision-event chain invites. One hash over the finalized document cannot disagree with itself and needs no chaining rule.

A per-step commitment earns its cost when somebody needs partial disclosure, streaming verification, or independently authenticated intermediate events. None of those has a consumer in this thread yet. Decision events that live under extra are already covered by the whole-document hash, at no extra cost.

That argues for their current shape.

HarperZ9's offer of an independent producer fixture with "an expected classification matrix showing that `agent_emitted` and `posthoc_inferred` remain distinct" is the right instrument. I would add one case a matrix alone will probably not catch.

My corpus has 8 cases: the 4 arms, a wrong signer, a non-canonical encoding carrying a valid signature over its own non-canonical bytes, a dependency the record names and does not cover, and a pointer that disagrees with the document it claims to hash. The non-canonical case is the one that earns its place. A signature-only consumer accepts it.

A second implementation rejects it. That disagreement stays invisible until 2 implementations exist.

The limit of what any of this establishes, so a bound record is not read as more than it is: it binds a result to the saved artifacts and grading inputs it names, it supports integrity checking and auditable regrading, and it does not, by itself, attest that the original agent execution was genuine or completely observed.

It cannot tell you a trajectory is a true account of what an agent did, and it cannot tell you a candidate set was complete. It can tell you the trajectory you are reading is the one that was graded. It can tell you a later decision event points at a refusal record that still verifies.

The record side belongs on harbor#3123, and I have put it there. If the convention section for this thread is wanted as text, I will write it against the trajectory-format RFC as extra keys only, with the 3-state provenance value and the reopened-from link as clementineCU specified them, and no core schema change.
