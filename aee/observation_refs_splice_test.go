package aee_test

// Cross-row observationRefs splice: exchanging the record ASSIGNMENT between
// two rows while leaving the record SET untouched.
//
// This file was written to record an expected NULL, and the null was real: no
// gate read the assignment, so the permutation left the rail's whole report
// byte-identical. It said so in the way a measurement should be said -- pinned
// rather than assumed, with a positive control beside it -- and it named the
// exact claim a future revision would falsify, so that a rail which started
// authenticating the assignment would turn this file red and bring whoever
// wrote that rule here to say so instead of leaving the record stale.
//
// A revision falsified it, in one direction and not the other, and the file now
// measures both directions rather than one.
//
// Where the corpus declares nothing, the null STANDS. On a row declaring
// `paired` the obligation is still exactly what it was, a producer obligation
// outside every gate ("a conforming verifier neither can nor may invent an
// evidencing heuristic in its place"), and no record names its attack, because
// a substrate signs an interception at observation time and before attribution.
// TestCrossRowObservationRefsSpliceIsInvisible is that measurement, unchanged
// in what it asserts.
//
// Where the corpus declares an expectation, the null FALLS.
// `corpus.manifest.expectedPayloads` names, per attack, the commitment its
// interception is expected to carry; `aeePayloadCommitment` carries what the
// record committed to; and a row declaring `attribution: pinned` obliges the
// two to meet. Exchanging the assignment then points each row at a record
// carrying the other attack's value, and the rail kills it.
// TestPinnedAttributionKillsTheSplice is that measurement.
//
// That kill was proven HERE first and only here, which was a gap and not a
// choice: every pinned vector in the corpus carried a single row, and permuting
// one row is the identity, so the corpus could not reach the arm and none of the
// three vendored consumer copies was ever measured against it. A control the
// corpus cannot exercise is a control no consumer is held to.
// `vd1aa74416099f3f0` and `v6ed1e2626b2af5ad` are the same
// operator on the same shape, in the corpus, so the kill now travels with the
// vectors. What stays here is what the corpus cannot carry: the null and its
// two controls side by side, built by one operator over three bases, which is
// what makes the boundary between them a measurement rather than three
// unrelated results.
//
// The boundary the three cases locate together is therefore no longer "class,
// never assignment". It is: the rail authenticates a row's coverage CLASS
// always, and the ASSIGNMENT within a class exactly where the corpus was
// willing to predict what the substrate would commit to. A consumer policy
// that discriminates between attacks -- by severity, class, regulatory mapping
// or attack identifier -- is reading a mapping the producer may still permute
// at will on every attack the pinned corpus declares no expectation for, and
// the statement says which rows those are, in the `attribution` member, on the
// wire.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
	"github.com/probityai/agent-evidence-vectors/aeetest"
)

// Synthetic pre-images, each a committed one-liner, mirroring aeetest's
// discipline: every digest is DERIVED here, never typed in.
func spliceDigest(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return aee.SHA256Hex(canon)
}

// spliceEnv is everything a statement carries that both bases share.
type spliceEnv struct {
	env      map[string]any
	binding  string
	manifest map[string]any
}

func newSpliceEnv(t *testing.T, manifest map[string]any) spliceEnv {
	t.Helper()
	labels := []string{"egress_captured", "no_egress"}
	caught := []string{"egress_captured"}
	vocabDigest := spliceDigest(t, map[string]any{"caught": caught, "labels": labels})
	corpusDigest := spliceDigest(t, manifest)

	catchPolicyDigest := spliceDigest(t, map[string]any{"examplePolicy": "enforcing"})
	postureDigest := spliceDigest(t, map[string]any{"examplePosture": "sinkhole"})
	substrateDigest := spliceDigest(t, map[string]any{"exampleSubstrate": "image"})
	subjectDigest := spliceDigest(t, map[string]any{"exampleSubject": "bundle"})
	runEntropyDigest := aee.SHA256Hex([]byte("example-run-start-checkpoint/1"))

	posture := map[string]any{
		"digest":  map[string]any{"sha256": postureDigest},
		"posture": "sinkhole",
	}
	binding := aee.DeriveRunBinding(
		catchPolicyDigest, corpusDigest, spliceDigest(t, posture),
		vocabDigest, runEntropyDigest, subjectDigest, substrateDigest,
	)

	env := map[string]any{
		"catchPolicy": map[string]any{"digest": map[string]any{"sha256": catchPolicyDigest}},
		"corpus": map[string]any{
			"digest":   map[string]any{"sha256": corpusDigest},
			"manifest": manifest,
			"name":     "example-corpus",
			"uri":      "pkg:example/corpus@1",
		},
		"networkPosture": posture,
		"observationVocabulary": map[string]any{
			"caught": caught,
			"digest": map[string]any{"sha256": vocabDigest},
			"labels": labels,
		},
		"runEntropy": map[string]any{"digest": map[string]any{"sha256": runEntropyDigest}},
		"substrate": map[string]any{
			"digest": map[string]any{"sha256": substrateDigest},
			"name":   "example-substrate",
		},
	}
	return spliceEnv{env: env, binding: binding, manifest: manifest}
}

func (e spliceEnv) subjectDigest(t *testing.T) string {
	t.Helper()
	return spliceDigest(t, map[string]any{"exampleSubject": "bundle"})
}

func (e spliceEnv) postureDigest(t *testing.T) string {
	t.Helper()
	return spliceDigest(t, map[string]any{"examplePosture": "sinkhole"})
}

// signSpliceRecord signs one record payload under the pinned substrate key.
func signSpliceRecord(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize record: %v", err)
	}
	signer := aeetest.TestKey(aeetest.RoleSubstrateObservation)
	sig := ed25519.Sign(signer, aee.PAE(aeetest.PayloadType, canon))
	return map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(canon),
		"payloadType": aeetest.PayloadType,
		"signatures": []any{map[string]any{
			"keyid": aeetest.KeyID(signer.Public().(ed25519.PublicKey)),
			"sig":   base64.StdEncoding.EncodeToString(sig),
		}},
	}
}

func spliceBatchRoot(t *testing.T, records []map[string]any) string {
	t.Helper()
	leaves := make([][32]byte, len(records))
	for i, rec := range records {
		payload, err := base64.StdEncoding.DecodeString(rec["payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = aee.LeafHash(aee.PAE(rec["payloadType"].(string), payload))
	}
	root := aee.MerkleRoot(leaves)
	return fmt.Sprintf("%x", root[:])
}

// assemble canonicalizes a whole statement around the supplied rows and records.
func (e spliceEnv) assemble(t *testing.T, rows []any, records []map[string]any, assessed []any) []byte {
	t.Helper()
	recs := make([]any, len(records))
	for i, r := range records {
		recs[i] = r
	}
	statement := map[string]any{
		"_type":         aee.StatementType,
		"predicateType": aee.PredicateType,
		"subject": []any{map[string]any{
			"digest": map[string]any{"sha256": e.subjectDigest(t)},
			"name":   "example-agent-bundle",
		}},
		"predicate": map[string]any{
			"attackResults": rows,
			"batchRoot":     spliceBatchRoot(t, records),
			"coverage": map[string]any{
				"assessedClasses": assessed,
				"outOfScope":      map[string]any{},
				"routedElsewhere": map[string]any{},
			},
			"issuedAt":               aeetest.IssuedAt,
			"observationEnvironment": e.env,
			"observationRecords":     recs,
			"result":                 "fail",
		},
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize statement: %v", err)
	}
	return canon
}

func caughtRow(attackID string, refs []any) map[string]any {
	return caughtRowAttributed(attackID, refs, aee.AttributionPaired)
}

func caughtRowAttributed(attackID string, refs []any, attribution string) map[string]any {
	return map[string]any{
		"actualLayer":         "policy.egress_sinkhole",
		"attackId":            attackID,
		"attribution":         attribution,
		"basis":               "substrate",
		"containmentObserved": "egress_captured",
		"method":              "intercepted",
		"observationRefs":     refs,
	}
}

func cleanRow(attackID string, refs []any) map[string]any {
	return map[string]any{
		"actualLayer":         "none",
		"attackId":            attackID,
		"attribution":         aee.AttributionPaired,
		"basis":               "substrate",
		"containmentObserved": "no_egress",
		"method":              "intercepted",
		"observationRefs":     refs,
	}
}

// spliceSealed builds the run-end seal 0.7 requires on any statement carrying a
// basis: substrate row, committing to the interception and examination records
// passed to it.
func spliceSealed(t *testing.T, e spliceEnv, observed []map[string]any) map[string]any {
	t.Helper()
	seen := map[string]bool{}
	leaves := []string{}
	for _, rec := range observed {
		payload, err := base64.StdEncoding.DecodeString(rec["payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		leaf := aee.LeafHash(aee.PAE(rec["payloadType"].(string), payload))
		hexLeaf := fmt.Sprintf("%x", leaf[:])
		if !seen[hexLeaf] {
			seen[hexLeaf] = true
			leaves = append(leaves, hexLeaf)
		}
	}
	sort.Strings(leaves)
	return signSpliceRecord(t, map[string]any{
		"aeeDropCount":       0,
		"aeeKind":            "sealed",
		"aeeMethod":          "intercepted",
		"aeeObservedAttacks": []any{},
		"aeeObservedSet":     spliceDigest(t, leaves),
		"aeePostureDigest":   e.postureDigest(t),
		"aeeRunBinding":      e.binding,
		"aeeStillArmed":      true,
	})
}

// twoCaughtRows builds a statement whose two rows are IDENTICAL in every member
// a gate reads except attackId and observationRefs, each resolving its own
// interception record, and whose attacks sit in different corpus classes. The
// class split is deliberate: a consumer policy keyed on attack class is the
// cheapest example of one that reads the assignment.
func twoCaughtRows(t *testing.T) ([]byte, spliceEnv) {
	t.Helper()
	e := newSpliceEnv(t, map[string]any{"classes": map[string]any{
		"XA": []any{"XA-EXAMPLE-1"},
		"XB": []any{"XB-EXAMPLE-1"},
	}})
	records := []map[string]any{
		spliceInterception(t, e, "A"),
		spliceInterception(t, e, "B"),
	}
	records = append(records, spliceSealed(t, e, records))
	rows := []any{
		caughtRow("XA-EXAMPLE-1", []any{0}),
		caughtRow("XB-EXAMPLE-1", []any{1}),
	}
	return e.assemble(t, rows, records, []any{"XA", "XB"}), e
}

// spliceCommitment is the value the substrate commits to for one observation,
// derived from a committed one-liner exactly as every other digest here is.
func spliceCommitment(t *testing.T, which string) string {
	t.Helper()
	return aee.SHA256Hex([]byte("example-intercepted-bytes/" + which))
}

func spliceInterception(t *testing.T, e spliceEnv, which string) map[string]any {
	t.Helper()
	return signSpliceRecord(t, map[string]any{
		"aeeKind":              "interception",
		"aeeMethod":            "intercepted",
		"aeePayloadCommitment": []any{spliceCommitment(t, which)},
		"aeeRunBinding":        e.binding,
		"producerNote":         "example interception commitment " + which,
	})
}

// twoPinnedCaughtRows is the same two-row shape with the ONE difference 0.7
// adds: the corpus declares, per attack, the commitment its interception is
// expected to carry, each record carries its own attack's value, and each row
// declares the stronger attribution rather than the floor.
func twoPinnedCaughtRows(t *testing.T) []byte {
	t.Helper()
	e := newSpliceEnv(t, map[string]any{
		"classes": map[string]any{
			"XA": []any{"XA-EXAMPLE-1"},
			"XB": []any{"XB-EXAMPLE-1"},
		},
		"expectedPayloads": map[string]any{
			"XA-EXAMPLE-1": []any{spliceCommitment(t, "A")},
			"XB-EXAMPLE-1": []any{spliceCommitment(t, "B")},
		},
	})
	records := []map[string]any{
		spliceInterception(t, e, "A"),
		spliceInterception(t, e, "B"),
	}
	records = append(records, spliceSealed(t, e, records))
	rows := []any{
		caughtRowAttributed("XA-EXAMPLE-1", []any{0}, aee.AttributionPinned),
		caughtRowAttributed("XB-EXAMPLE-1", []any{1}, aee.AttributionPinned),
	}
	return e.assemble(t, rows, records, []any{"XA", "XB"})
}

// caughtAndCleanRows builds the control base: one caught row resolving an
// interception, one clean row resolving the arming and sealed pair. The two
// rows sit in DIFFERENT coverage classes, which is the only thing that
// separates this base from the one above.
func caughtAndCleanRows(t *testing.T) []byte {
	t.Helper()
	e := newSpliceEnv(t, map[string]any{"classes": map[string]any{
		"XA": []any{"XA-EXAMPLE-1", "XA-EXAMPLE-2"},
	}})
	interception := spliceInterception(t, e, "A")
	records := []map[string]any{
		interception,
		signSpliceRecord(t, map[string]any{
			"aeeAssessedAttacks": []any{"XA-EXAMPLE-1", "XA-EXAMPLE-2"},
			"aeeKind":            "arming",
			"aeeMethod":          "intercepted",
			"aeePostureDigest":   e.postureDigest(t),
			"aeeRunBinding":      e.binding,
			"armedAt":            aeetest.ArmedAt,
			"producerNote":       "example arming record",
		}),
		spliceSealed(t, e, []map[string]any{interception}),
	}
	rows := []any{
		caughtRow("XA-EXAMPLE-1", []any{0}),
		cleanRow("XA-EXAMPLE-2", []any{1, 2}),
	}
	return e.assemble(t, rows, records, []any{"XA"})
}

// splice exchanges observationRefs between two rows and canonicalizes the
// result. Nothing else in the statement is touched, so the record set, every
// signature, every digest and the batch root are the producer's own bytes.
func splice(t *testing.T, body []byte, i, j int) []byte {
	t.Helper()
	var stmt map[string]any
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	rows := stmt["predicate"].(map[string]any)["attackResults"].([]any)
	ri := rows[i].(map[string]any)
	rj := rows[j].(map[string]any)
	ri["observationRefs"], rj["observationRefs"] = rj["observationRefs"], ri["observationRefs"]
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := aee.Canonicalize(raw)
	if err != nil {
		t.Fatalf("canonicalize spliced statement: %v", err)
	}
	return canon
}

// refsOf reports each row's observationRefs, rendered, in row order.
func refsOf(t *testing.T, body []byte) []string {
	t.Helper()
	var stmt map[string]any
	if err := json.Unmarshal(body, &stmt); err != nil {
		t.Fatal(err)
	}
	rows := stmt["predicate"].(map[string]any)["attackResults"].([]any)
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = fmt.Sprint(r.(map[string]any)["observationRefs"])
	}
	return out
}

// fingerprint renders a whole report, so the comparison below cannot pass by
// omitting a field that a later revision adds.
func fingerprint(t *testing.T, r *aee.Report) string {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// requireSpliceMoved asserts the mutation altered the bytes it claims to and
// only those: the statement differs, the per-row refs differ, and the MULTISET
// of refs across all rows is unchanged, which is what makes it an assignment
// permutation rather than an edit to the reference set.
func requireSpliceMoved(t *testing.T, base, mutated []byte, i, j int) {
	t.Helper()
	if string(base) == string(mutated) {
		t.Fatal("splice changed no bytes; the mutation asserts nothing")
	}
	before, after := refsOf(t, base), refsOf(t, mutated)
	if before[i] == after[i] || before[j] == after[j] {
		t.Fatalf("rows %d/%d refs did not move: %v -> %v", i, j, before, after)
	}
	if before[i] != after[j] || before[j] != after[i] {
		t.Fatalf("refs were not exchanged: %v -> %v", before, after)
	}
	for k := range before {
		if k != i && k != j && before[k] != after[k] {
			t.Fatalf("row %d refs changed and should not have: %v -> %v", k, before, after)
		}
	}
}

// TestCrossRowObservationRefsSpliceIsInvisible is the measurement. Exchanging
// the record assignment between two rows of the same coverage class leaves the
// rail's whole report byte-identical, under a pinned key policy and under none.
//
// This is not a rule passing. It is the absence of a rule, recorded where it
// can be re-measured: the corpus cell U7 in vectors/coverage-unforced.json
// carries the same finding in the published matrix.
func TestCrossRowObservationRefsSpliceIsInvisible(t *testing.T) {
	base, _ := twoCaughtRows(t)
	mutated := splice(t, base, 0, 1)
	requireSpliceMoved(t, base, mutated, 0, 1)

	policies := map[string]*aee.ConsumerPolicy{
		"pinned key": pinnedPolicy(),
		"no key":     nil,
	}
	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			before := aee.Verify(base, policy)
			requireValid(t, before)
			after := aee.Verify(mutated, policy)
			got, want := fingerprint(t, after), fingerprint(t, before)
			if got != want {
				t.Fatalf("the rail distinguishes the splice:\n before %s\n after  %s", want, got)
			}
			if before.Result != "fail" {
				t.Fatalf("base result %q, want fail", before.Result)
			}
		})
	}
}

// TestCaughtToCleanSpliceIsRejected is the positive control for the test above.
// Same operator, same statement shape, rows drawn from DIFFERENT coverage
// classes: the rail kills it. Without this case, a splice the rail cannot see
// and a harness that cannot see any splice produce the same green run.
func TestCaughtToCleanSpliceIsRejected(t *testing.T) {
	base := caughtAndCleanRows(t)
	requireValid(t, aee.Verify(base, pinnedPolicy()))

	mutated := splice(t, base, 0, 1)
	requireSpliceMoved(t, base, mutated, 0, 1)

	r := aee.Verify(mutated, pinnedPolicy())
	requireInvalid(t, r, aee.CodeCaughtRowUncovered)
}

// TestPinnedAttributionKillsTheSplice is what the version above this one
// bought, measured with the SAME operator on the SAME two-caught-row shape that
// the null case uses. The only difference is that the corpus declares, per
// attack, the commitment that attack's interception is expected to carry, and
// each row declares the stronger attribution rather than the floor.
//
// The corpus now carries the same operator as a vector pair, so this case is no
// longer the only place the kill is measured, and it is kept for what the pair
// cannot say: that the kill and the null differ in exactly one input. A vector
// pair states an outcome about bytes on disk; three cases sharing one builder
// and one splice function state a boundary.
//
// The unspliced statement is valid: every row resolves an interception whose
// committed value the corpus predicted for that row's attack. Exchange the
// assignment and each row resolves the other attack's record, whose commitment
// the corpus predicted for a different attack, so the check the row's own
// declaration invited now fails.
//
// It is worth being exact about what this does and does not close, because the
// member is a declaration and not a detector. A producer that declares `paired`
// on both rows emits a statement this rail cannot distinguish from the null
// case, and violates nothing: `paired` is a claim an honest producer with a
// weaker binding makes truthfully. What the format does is put the weakness on
// the wire where a policy can read it, which is why the closure against that
// producer is a consumer obligation and not a rule here.
func TestPinnedAttributionKillsTheSplice(t *testing.T) {
	base := twoPinnedCaughtRows(t)
	requireValid(t, aee.Verify(base, pinnedPolicy()))

	mutated := splice(t, base, 0, 1)
	requireSpliceMoved(t, base, mutated, 0, 1)

	for name, policy := range map[string]*aee.ConsumerPolicy{
		"pinned key": pinnedPolicy(),
		"no key":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			// Byte-pure: the assignment check reads the corpus and the record
			// payloads and no key at all, so it kills the splice with a pinned
			// consumer policy and without one alike.
			requireInvalid(t, aee.Verify(mutated, policy), aee.CodeAttributionPinUnmatched)
		})
	}
}
