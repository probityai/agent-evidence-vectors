// Package aee implements the verification core for the in-toto
// Adversarial Execution Evidence predicate, version 0.7
// (predicateType https://in-toto.io/attestation/adversarial-execution-evidence/v0.7).
//
// The category of attestation this predicate defines is a recomputable
// execution attestation: the consumer recomputes the outcome from carried
// bytes (execute-and-attest), rather than matching a producer-asserted
// verdict (match-and-assert).
//
// The verification pipeline is a strict two-gate design plus a recompute
// equality check and a trust-relative tier:
//
//	GATE 0  statement well-formedness   (statement.go) — spec "Parsing Rules" + field shapes
//	GATE 1  coverage validity           (validity.go)  — spec "Coverage validity"; a
//	        consumption precondition: on failure the attestation is INVALID and its
//	        result MUST NOT be consumed
//	        recompute equality          (recompute.go) — carried result must equal the
//	        pure recompute over carried bytes
//	GATE 2  evidence tier               (tier.go)      — {declared|unattested|attested},
//	        trust-relative, derived per consumer key policy; never alters result
//
// Spec line references in this package are to the vendored predicate
// specification at spec/predicates/adversarial-execution-evidence.md. Which
// upstream commit that is, is recorded in spec/VENDOR-PIN.json and derived by
// scripts/vendor-spec.py from git at vendor time. It is deliberately not
// restated here: this line carried a hand-typed commit that was four normative
// revisions stale, which is the same defect the vendor pin exists to end, and
// every citation below is remapped and re-pinned on every re-vendor.
package aee

// Code is a stable, machine-readable failure code. The registry of codes and
// their precedence pins is documented in the conformance suite README; the
// codes here are the implementation's closed set. Message text is never part
// of the conformance contract; codes are.
type Code string

// GATE 0 — statement well-formedness codes.
const (
	CodeStatementMalformed        Code = "statement-malformed" // catch-all: unparseable JSON / wrong member type
	CodeStatementTypeUnsupported  Code = "statement-type-unsupported"
	CodePredicateTypeUnsupported  Code = "predicate-type-unsupported"
	CodeMemberSpelling            Code = "member-spelling"
	CodeResultVocabulary          Code = "result-vocabulary"
	CodeEnvironmentIncomplete     Code = "environment-incomplete"
	CodePostureVocabulary         Code = "posture-vocabulary"
	CodeVocabularyMissing         Code = "vocabulary-missing"
	CodeVocabularyNotCanonical    Code = "vocabulary-not-canonical"
	CodeVocabularyCaughtNotSubset Code = "vocabulary-caught-not-subset"
	CodeVocabularyDigestMismatch  Code = "vocabulary-digest-mismatch"
	CodeCorpusDigestMismatch      Code = "corpus-digest-mismatch"
	CodeManifestDuplicateAttack   Code = "manifest-duplicate-attack"
	CodeCorpusManifestNoAttacks   Code = "corpus-manifest-no-attacks" // counts attack IDENTIFIERS, not classes; rationale at gate0Corpus
	// CodeManifestExpectedPayloadsMalformed reports a corpus manifest whose
	// optional expectedPayloads map violates any of its shape rules: a key
	// naming an attack the same manifest's classes do not declare, an empty,
	// unsorted or duplicate-carrying array, or an entry that is not lowercase
	// 64-hex. The map is a manifest member, so its violation is a malformed
	// statement at GATE 0 and never a row-level fault: nothing on a row can
	// repair a manifest whose pre-image is already inside the run binding.
	CodeManifestExpectedPayloadsMalformed Code = "manifest-expected-payloads-malformed"
	CodeCoverageMissing                   Code = "coverage-missing"
	CodeCoverageIncomplete                Code = "coverage-incomplete"
	CodeRowAttackUnknown                  Code = "row-attack-unknown"
	CodeMissingActualLayer                Code = "malformed-missing-actual-layer"
	CodeCleanRowLayerNotNone              Code = "clean-row-layer-not-none"
	CodeSubjectCardinality                Code = "subject-cardinality"
	CodeSubjectSha256Missing              Code = "subject-sha256-missing"
	CodeDigestNotCanonical                Code = "digest-not-canonical"
	CodeRunEntropyMissing                 Code = "run-entropy-missing"
	CodeIssuedAtMissing                   Code = "issued-at-missing"
	CodeIssuedAtMalformed                 Code = "issued-at-malformed"
)

// GATE 1 — statement-level observation-record codes (evaluated whenever
// observationRecords is non-empty, BEFORE any per-row logic).
const (
	CodeBatchRootMissing  Code = "batch-root-missing"
	CodeBatchRootMismatch Code = "batch-root-mismatch"
	CodeBatchRootOrphaned Code = "batch-root-orphaned"
	CodeDuplicateRecord   Code = "duplicate-record"
	CodeRecordsAbsent     Code = "records-absent"
	CodeRecordUndecodable Code = "record-undecodable" // registry extension: a record whose payload is not valid base64 (v4ff6cb70764bf703)
	// CodeRecordSignaturesEmpty is a registry extension for a record whose
	// signatures array is absent or carries zero entries, which the spec
	// forbids ("signatures, which MUST carry at least one entry"). The name
	// says what is detected — an empty array — and deliberately not
	// "unsigned", because counting entries is all this code stands for.
	CodeRecordSignaturesEmpty Code = "record-signatures-empty"
)

// GATE 1 — per-row coverage-validity codes.
const (
	CodeRefsEmpty                      Code = "refs-empty"
	CodeRefMalformed                   Code = "ref-malformed"
	CodeRefOutOfRange                  Code = "ref-out-of-range"
	CodeFailClosedSubstrateRow         Code = "fail-closed-substrate-row"
	CodePayloadNotIJSON                Code = "payload-not-ijson"
	CodePayloadNotCanonical            Code = "payload-not-canonical"
	CodePayloadMediaType               Code = "payload-media-type"
	CodePayloadMissingReserved         Code = "payload-missing-reserved"
	CodeRunBindingMismatch             Code = "run-binding-mismatch"
	CodeMethodCapExceeded              Code = "method-cap-exceeded"
	CodeCaughtRowUncovered             Code = "caught-row-uncovered"
	CodeReconstructedRowUncovered      Code = "reconstructed-row-uncovered"
	CodeCleanRowUncovered              Code = "clean-row-uncovered"
	CodeArmingCoversNothing            Code = "arming-covers-nothing"
	CodeSealedCoversNothing            Code = "sealed-covers-nothing"
	CodeExaminationCoversNothing       Code = "examination-covers-nothing"
	CodeRecordKindUnknownCoversNothing Code = "record-kind-unknown-covers-nothing"
	// The two registered non-covering kinds report under their own names
	// (spec:req-fields-record-violating-constraint-declared-aeekind@4d3303cb6087db63). The specification asks a verifier to distinguish them
	// from an unrecognized kind because the two are different producer errors
	// with different fixes: one cites a record that can never cover anything,
	// the other cites a record this verifier is too old to read. Reporting both
	// as unknown tells the first producer to upgrade its verifier, which will
	// not help.
	CodeMoatDropCoversNothing               Code = "moat-drop-covers-nothing"
	CodeUncommittedObservationCoversNothing Code = "uncommitted-observation-covers-nothing"
	// CodePayloadCommitmentMalformed reports an interception record whose
	// aeePayloadCommitment is present but violates its shape rules (empty,
	// unsorted, duplicate-carrying, or an entry that is not lowercase 64-hex).
	// The ABSENCE of the member keeps reporting payload-missing-reserved,
	// which is the code every other missing reserved member already takes; a
	// present-but-malformed value is a different fault and says so, because a
	// producer reading "missing" for a value it plainly carries has been told
	// the wrong thing about its own record.
	CodePayloadCommitmentMalformed Code = "payload-commitment-malformed"
)

// GATE 1 — statement-level coverage validity requirements added at 0.7. Each
// is a function of carried bytes on the same terms as the per-row list above,
// and each violation makes the attestation invalid.
const (
	// CodeCleanRowContradicted reports a clean row that resolves an
	// observationRefs index to an interception record. The row states nothing
	// was caught while pointing at a record in which the substrate signed that
	// it intercepted traffic. Stated over EVERY row, not only a substrate row,
	// because the contradiction does not depend on the vantage the row declares.
	CodeCleanRowContradicted Code = "clean-row-contradicted"
	// CodeInterceptionRecordOrphaned reports a carried interception record that
	// no caught row resolves. One record MAY be resolved by several rows, so
	// this costs none of the sharing the predicate permits; what it refuses is
	// the escalation of dropping the reference instead of the record.
	CodeInterceptionRecordOrphaned Code = "interception-record-orphaned"
	// CodeSealedRecordAbsent reports a statement carrying at least one
	// basis: substrate row and no sealed record that satisfies every constraint
	// of its kind and whose aeeRunBinding equals the derived binding. The
	// requirement is unconditional at 0.7: a rule conditioned on the presence
	// of the record it constrains is a rule a producer switches off by omission.
	CodeSealedRecordAbsent Code = "sealed-record-absent"
	// CodeObservedSetMismatch reports a sealed record whose aeeObservedSet does
	// not equal the value recomputed over the carried interception and
	// examination records.
	CodeObservedSetMismatch Code = "observed-set-mismatch"
	// CodeObservedAttackUncaught reports an attack identifier the seal names in
	// aeeObservedAttacks for which the statement carries no row whose
	// containmentObserved is in the carried caught set. The rule reads in ONE
	// direction: a seal omitting an attack licenses nothing.
	CodeObservedAttackUncaught Code = "observed-attack-uncaught"
	// CodeAssessedSetExceedsDeclaration reports a statement whose union of
	// manifest identifiers for the carried coverage.assessedClasses is not a
	// subset of the arming record's aeeAssessedAttacks. A subset and not an
	// equality, so a run that loses coverage part-way can still disclose it.
	CodeAssessedSetExceedsDeclaration Code = "assessed-set-exceeds-declaration"
)

// GATE 1 — attribution binding codes. A row declaring the stronger value
// carries the binding it claims, in three parts, because a rail implementing
// one of the three and not the others would pass a corpus that named the rule
// once.
const (
	// CodeAttributionPinnedRecordless reports a pinned row resolving no
	// interception record at all. Not redundant beside the other two: a
	// requirement universally quantified over an empty set is vacuously true,
	// so without it a producer deletes the interception records, relabels the
	// row, resolves only run-level records, and keeps the stronger value.
	CodeAttributionPinnedRecordless Code = "attribution-pinned-recordless"
	// CodeAttributionUnpinnable reports a pinned row whose attackId carries no
	// entry in corpus.manifest.expectedPayloads. Such a row MUST declare paired.
	CodeAttributionUnpinnable Code = "attribution-unpinnable"
	// CodeAttributionPinUnmatched reports a pinned row resolving an interception
	// record that carries none of the values the manifest declared for the row's
	// attack.
	CodeAttributionPinUnmatched Code = "attribution-pin-unmatched"
)

// Recompute-equality gate.
const (
	CodeResultRecomputeMismatch Code = "result-recompute-mismatch"
)

// Consumer-policy stage codes. These are consumer-relative admission facts,
// recorded on the report's consumer surface (Report.PolicyCodes) and folded
// into Admitted; they are NEVER validity codes: the byte-pure verdict and
// its code list are unchanged by any anchor comparison.
const (
	CodeCorpusAnchorMismatch    Code = "corpus-anchor-mismatch"
	CodeSubstrateAnchorMismatch Code = "substrate-anchor-mismatch"
)

// appendCode appends c to codes unless it is already present, preserving
// detection order (the first code is the deterministic primary code).
func appendCode(codes []Code, c Code) []Code {
	for _, existing := range codes {
		if existing == c {
			return codes
		}
	}
	return append(codes, c)
}
