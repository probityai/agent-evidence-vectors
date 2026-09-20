// Package aeetest builds deterministic, fully synthetic AEE v0.7 statements
// for tests and demos. Every value is either a string the public predicate
// specification itself publishes (posture names, observation labels) or an
// obviously synthetic example value; every digest is DERIVED from a
// committed one-line synthetic pre-image, never typed in.
//
// TEST KEYS — derived, never stored. seed(role) = SHA-256 of the published
// constant "in-toto-aee-test-key/<role>/v1". Anyone can re-derive the
// private side; these keys authenticate NOTHING and must never be trusted
// outside test fixtures.
package aeetest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// Published test-key roles.
const (
	RoleSubstrateObservation = "substrate-observation-test"
	RoleWrongSigner          = "wrong-signer-test"
	RoleStatement            = "statement-test"
)

// TestKey derives the deterministic test key for a role.
func TestKey(role string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("in-toto-aee-test-key/" + role + "/v1"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// KeyID returns the lookup-hint keyid for a key: the SHA-256 of the raw
// public key bytes. A keyid is never the check itself.
func KeyID(pub ed25519.PublicKey) string {
	return aee.SHA256Hex(pub)
}

// Fixed timestamps used by every built statement.
const (
	IssuedAt = "2026-01-01T00:00:00Z"
	ArmedAt  = "2025-12-31T23:59:00Z"
)

// PayloadType is the neutral example media type for observation records.
const PayloadType = "application/vnd.example.aee-observation.v1+json"

// Options selects the built statement's shape and optional single faults.
// The zero value builds a VALID caught-row statement (substrate basis,
// method intercepted, one interception record).
type Options struct {
	// Clean builds a clean-row statement (label no_egress, arming + sealed
	// records) instead of a caught-row one.
	Clean bool

	// RowMethod overrides the row's method member ("" = intercepted;
	// "ABSENT" drops the member entirely).
	RowMethod string

	// RecordMethod overrides the aeeMethod signed inside the interception
	// record ("" = intercepted). Setting it to reconstructed while the row
	// stays intercepted is the method-inflation fault.
	RecordMethod string

	// Result overrides the carried result ("" = the honest recompute).
	Result string

	// SignerRole selects the record-signing key role ("" =
	// RoleSubstrateObservation).
	SignerRole string

	// ArmedAt overrides the arming record's armedAt ("" = ArmedAt).
	ArmedAtOverride string

	// SealedStillArmedFalse signs the sealed record with aeeStillArmed false.
	SealedStillArmedFalse bool

	// TamperBatchRoot flips the last hex digit of the committed batchRoot.
	TamperBatchRoot bool

	// TamperVocabularyDigest carries a stale observationVocabulary digest.
	TamperVocabularyDigest bool

	// DropRunEntropy removes observationEnvironment.runEntropy.
	DropRunEntropy bool

	// ExtraManifestAttack adds a second attack id to the manifest with no
	// matching row (coverage-incomplete at attack granularity).
	ExtraManifestAttack bool

	// PredicateType overrides the statement predicateType ("" = v0.7 URI).
	PredicateType string

	// ExtraVocabularyLabels appends labels to observationVocabulary.labels,
	// re-deriving the vocabulary digest, the run binding and every record
	// signature over it. A caller that wants a label no Go string can carry
	// through a decode builds with the DECODED form here and substitutes the
	// raw source into the returned bytes afterwards: everything the substitution
	// would otherwise leave inconsistent has already been derived over the
	// decoded value, which is the value a rail reads. Each label must sort
	// after every existing one, or the statement is unsorted rather than
	// whatever the caller meant to test.
	ExtraVocabularyLabels []string
}

// canonMust canonicalizes or panics; builder inputs are all synthetic
// literals, so a failure is a programming error in the builder itself.
func canonMust(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		panic(err)
	}
	return canon
}

func digestOf(v any) string { return aee.SHA256Hex(canonMust(v)) }

// Pinned synthetic pre-images (each a committed one-liner).
var (
	catchPolicyDigest = digestOf(map[string]any{"examplePolicy": "enforcing"})
	postureDigest     = digestOf(map[string]any{"examplePosture": "sinkhole"})
	substrateDigest   = digestOf(map[string]any{"exampleSubstrate": "image"})
	subjectDigest     = digestOf(map[string]any{"exampleSubject": "bundle"})
	runEntropyDigest  = aee.SHA256Hex([]byte("example-run-start-checkpoint/1"))
	commitmentDigest  = aee.SHA256Hex([]byte("example-intercepted-bytes/1"))
)

// Build returns the canonical bytes of one complete in-toto statement.
func Build(o Options) []byte {
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	labels = append(labels, o.ExtraVocabularyLabels...)
	vocabDigest := aee.SHA256Hex(canonMust(map[string]any{"caught": caught, "labels": labels}))
	if o.TamperVocabularyDigest {
		vocabDigest = aee.SHA256Hex([]byte("stale"))
	}

	attackIDs := []string{"XA-EXAMPLE-1"}
	if o.ExtraManifestAttack {
		attackIDs = append(attackIDs, "XA-EXAMPLE-2")
	}
	manifest := map[string]any{"classes": map[string]any{"XA": attackIDs}}
	corpusDigest := aee.SHA256Hex(canonMust(manifest))

	posture := map[string]any{"digest": map[string]any{"sha256": postureDigest}, "posture": "sinkhole"}

	// The version-2 networkPosture input is the canonical digest of the whole
	// carried object, so it is built from the same literal the environment
	// below carries rather than from postureDigest, which is that object's own
	// pinned digest member.
	posturePreimage := aee.SHA256Hex(canonMust(posture))
	binding := aee.DeriveRunBinding(catchPolicyDigest, corpusDigest, posturePreimage, vocabDigest, runEntropyDigest, subjectDigest, substrateDigest)

	signerRole := o.SignerRole
	if signerRole == "" {
		signerRole = RoleSubstrateObservation
	}
	signer := TestKey(signerRole)

	var records []map[string]any
	var refs []int
	if o.Clean {
		armedAt := o.ArmedAtOverride
		if armedAt == "" {
			armedAt = ArmedAt
		}
		arming := map[string]any{
			"aeeAssessedAttacks": toAny(attackIDs),
			"aeeKind":            "arming",
			"aeeMethod":          "intercepted",
			"aeePostureDigest":   postureDigest,
			"aeeRunBinding":      binding,
			"armedAt":            armedAt,
			"producerNote":       "example arming record",
		}
		// A clean run emits no interception and no examination, so the set the
		// seal commits to is empty and its digest is the digest of the empty
		// array. That is a value, not an absence: the member is required.
		sealed := sealedRecord(binding, nil, !o.SealedStillArmedFalse)
		records = append(records, signRecord(arming, signer), signRecord(sealed, signer))
		refs = []int{0, 1}
	} else {
		recordMethod := o.RecordMethod
		if recordMethod == "" {
			recordMethod = "intercepted"
		}
		interception := map[string]any{
			"aeeKind":              "interception",
			"aeeMethod":            recordMethod,
			"aeePayloadCommitment": []any{commitmentDigest},
			"aeeRunBinding":        binding,
			"producerNote":         "example interception commitment",
		}
		signed := signRecord(interception, signer)
		// From 0.7 a statement carrying a basis: substrate row carries a sealed
		// record whether or not a row resolves an index to it, so the caught
		// shape carries one too. It is unreferenced, which is the whole of what
		// "unconditional" buys: a rule conditioned on the presence of the record
		// it constrains is a rule a producer switches off by omission.
		sealed := sealedRecord(binding, []map[string]any{signed}, !o.SealedStillArmedFalse)
		records = append(records, signed, signRecord(sealed, signer))
		refs = []int{0}
	}

	batchRoot := computeBatchRoot(records)
	if o.TamperBatchRoot {
		batchRoot = flipLastHex(batchRoot)
	}

	rowMethod := o.RowMethod
	if rowMethod == "" {
		rowMethod = "intercepted"
	}
	row := map[string]any{
		"attackId":        "XA-EXAMPLE-1",
		"basis":           "substrate",
		"observationRefs": refs,
	}
	if rowMethod != "ABSENT" {
		row["method"] = rowMethod
	}
	// paired is the floor a producer may always truthfully declare, and the
	// only value a synthetic statement can carry without a corpus expectation.
	row["attribution"] = "paired"
	if o.Clean {
		row["containmentObserved"] = "no_egress"
		row["actualLayer"] = "none"
	} else {
		row["containmentObserved"] = "egress_captured"
		row["actualLayer"] = "policy.egress_sinkhole"
	}

	result := o.Result
	if result == "" {
		if o.Clean && (rowMethod == "intercepted" || rowMethod == "reconstructed") {
			result = "pass"
		} else {
			result = "fail"
		}
	}

	env := map[string]any{
		"catchPolicy":    map[string]any{"digest": map[string]any{"sha256": catchPolicyDigest}},
		"corpus":         map[string]any{"digest": map[string]any{"sha256": corpusDigest}, "manifest": manifest, "name": "example-corpus", "uri": "pkg:example/corpus@1"},
		"networkPosture": posture,
		"observationVocabulary": map[string]any{
			"caught": caught,
			"digest": map[string]any{"sha256": vocabDigest},
			"labels": labels,
		},
		"substrate": map[string]any{"digest": map[string]any{"sha256": substrateDigest}, "name": "example-substrate"},
	}
	if !o.DropRunEntropy {
		env["runEntropy"] = map[string]any{"digest": map[string]any{"sha256": runEntropyDigest}}
	}

	predicateType := o.PredicateType
	if predicateType == "" {
		predicateType = aee.PredicateType
	}

	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": predicateType,
		"subject": []any{
			map[string]any{"digest": map[string]any{"sha256": subjectDigest}, "name": "example-agent-bundle"},
		},
		"predicate": map[string]any{
			"attackResults":          []any{row},
			"batchRoot":              batchRoot,
			"coverage":               map[string]any{"assessedClasses": []any{"XA"}, "outOfScope": map[string]any{}, "routedElsewhere": map[string]any{}},
			"issuedAt":               IssuedAt,
			"observationEnvironment": env,
			"observationRecords":     records,
			"result":                 result,
		},
	}
	return canonMust(statement)
}

// BuildArtifactOnly returns a minimal VALID artifact-only statement: one
// artifact-basis caught row, no records, no batchRoot, no runEntropy.
func BuildArtifactOnly() []byte {
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	vocabDigest := aee.SHA256Hex(canonMust(map[string]any{"caught": caught, "labels": labels}))
	manifest := map[string]any{"classes": map[string]any{"XA": []any{"XA-EXAMPLE-1"}}}
	corpusDigest := aee.SHA256Hex(canonMust(manifest))
	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": aee.PredicateType,
		"subject": []any{
			map[string]any{"digest": map[string]any{"sha256": subjectDigest}, "name": "example-agent-bundle"},
		},
		"predicate": map[string]any{
			"attackResults": []any{map[string]any{
				"actualLayer":         "none",
				"attackId":            "XA-EXAMPLE-1",
				"attribution":         "paired",
				"basis":               "artifact",
				"containmentObserved": "egress_captured",
				"method":              "reconstructed",
			}},
			"coverage": map[string]any{"assessedClasses": []any{"XA"}, "outOfScope": map[string]any{}, "routedElsewhere": map[string]any{}},
			"issuedAt": IssuedAt,
			"observationEnvironment": map[string]any{
				"catchPolicy":    map[string]any{"digest": map[string]any{"sha256": catchPolicyDigest}},
				"corpus":         map[string]any{"digest": map[string]any{"sha256": corpusDigest}, "manifest": manifest, "name": "example-corpus", "uri": "pkg:example/corpus@1"},
				"networkPosture": map[string]any{"digest": map[string]any{"sha256": postureDigest}, "posture": "sinkhole"},
				"observationVocabulary": map[string]any{
					"caught": caught,
					"digest": map[string]any{"sha256": vocabDigest},
					"labels": labels,
				},
				"substrate": map[string]any{"digest": map[string]any{"sha256": substrateDigest}, "name": "example-substrate"},
			},
			"result": "fail",
		},
	}
	return canonMust(statement)
}

// toAny widens a []string for the canonicalizer, which walks any.
func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// sealedRecord builds a seal committing to the interception and examination
// records passed to it. The commitment is over the leaf hashes those records
// contribute, sorted ascending and duplicate-free -- lowercase hex is ASCII,
// so a byte sort is the UTF-16 code-unit sort the specification names.
func sealedRecord(binding string, observed []map[string]any, stillArmed bool) map[string]any {
	seen := map[string]bool{}
	leaves := []string{}
	for _, rec := range observed {
		payload, err := base64.StdEncoding.DecodeString(rec["payload"].(string))
		if err != nil {
			panic(err)
		}
		leaf := aee.LeafHash(aee.PAE(rec["payloadType"].(string), payload))
		hexLeaf := fmt.Sprintf("%x", leaf[:])
		if !seen[hexLeaf] {
			seen[hexLeaf] = true
			leaves = append(leaves, hexLeaf)
		}
	}
	sort.Strings(leaves)
	return map[string]any{
		"aeeDropCount":       0,
		"aeeKind":            "sealed",
		"aeeMethod":          "intercepted",
		"aeeObservedAttacks": []any{},
		"aeeObservedSet":     aee.SHA256Hex(canonMust(leaves)),
		"aeePostureDigest":   postureDigest,
		"aeeRunBinding":      binding,
		"aeeStillArmed":      stillArmed,
	}
}

func signRecord(payload map[string]any, signer ed25519.PrivateKey) map[string]any {
	canon := canonMust(payload)
	pae := aee.PAE(PayloadType, canon)
	sig := ed25519.Sign(signer, pae)
	return map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(canon),
		"payloadType": PayloadType,
		"signatures": []any{map[string]any{
			"keyid": KeyID(signer.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
}

func computeBatchRoot(records []map[string]any) string {
	leaves := make([][32]byte, len(records))
	for i, rec := range records {
		payload, err := base64.StdEncoding.DecodeString(rec["payload"].(string))
		if err != nil {
			panic(err)
		}
		leaves[i] = aee.LeafHash(aee.PAE(rec["payloadType"].(string), payload))
	}
	root := aee.MerkleRoot(leaves)
	return fmt.Sprintf("%x", root[:])
}

func flipLastHex(s string) string {
	last := s[len(s)-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	return s[:len(s)-1] + string(replacement)
}
