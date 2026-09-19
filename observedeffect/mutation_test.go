package observedeffect

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The corpus this rail is measured against. Relative because the module is the
// unit that ships; an absolute path would be one machine's answer.
const (
	corpusDir = "../vectors-observed-effect"
	specPath  = "../spec/predicates/observed-effect.md"
)

type manifestVector struct {
	ID         string   `json:"id"`
	Slug       string   `json:"slug"`
	Kind       string   `json:"kind"`
	File       string   `json:"file"`
	Conditions []string `json:"conditions"`
	Expected   struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
	Readings []struct {
		Verdict string `json:"verdict"`
	} `json:"readings"`
}

type manifest struct {
	PredicateType string            `json:"predicateType"`
	EmptyTree     map[string]string `json:"emptyTree"`
	Counts        map[string]int    `json:"counts"`
	Keys          map[string]struct {
		KeyID     string `json:"keyid"`
		PublicKey string `json:"publicKey"`
	} `json:"keys"`
	Vectors []manifestVector `json:"vectors"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusDir, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("the corpus manifest is unreadable, so nothing below measured anything: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("the corpus manifest does not parse: %v", err)
	}
	if len(m.Vectors) == 0 {
		t.Fatal("the corpus manifest carries no vectors, so every assertion below is vacuous")
	}
	return m
}

func testPolicy(t *testing.T, m manifest) Policy {
	t.Helper()
	predicateType, err := PredicateTypeFromSpec(specPath)
	if err != nil {
		t.Fatalf("the predicate document states no Type URI: %v", err)
	}
	blob := []byte(strings.Repeat("port: 8080\nmode: strict\n", 8))
	sum := sha256.Sum256(blob)
	return Policy{
		PredicateType:        predicateType,
		ObserverPublicKeyHex: m.Keys["observer"].PublicKey,
		Blobs:                map[string][]byte{hex.EncodeToString(sum[:]): blob},
	}
}

func readVector(t *testing.T, v manifestVector) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusDir, v.File))
	if err != nil {
		t.Fatalf("%s: %v", v.ID, err)
	}
	return body
}

// outcome is what a replay produced, as one comparable string.
func outcome(r *Report) string {
	return r.Verdict + ":" + strings.Join(r.Codes, ",")
}

// TestCorpusBehavesAsDeclared is the GREEN column: with every rule in place, each
// member reaches the verdict its manifest entry declares and a reject member
// reaches it with the code the entry names.
func TestCorpusBehavesAsDeclared(t *testing.T) {
	m := loadManifest(t)
	policy := testPolicy(t, m)
	counted := map[string]int{}
	for _, v := range m.Vectors {
		report := Verify(readVector(t, v), policy)
		counted[v.Kind]++
		if v.Kind == "indeterminate" {
			allowed := false
			for _, reading := range v.Readings {
				if reading.Verdict == report.Verdict {
					allowed = true
				}
			}
			if !allowed {
				t.Errorf("%s (%s): reading %q is outside the declared set", v.ID, v.Slug, report.Verdict)
			}
			continue
		}
		if report.Verdict != v.Expected.Verdict {
			t.Errorf("%s (%s): want %s, got %s %v", v.ID, v.Slug, v.Expected.Verdict, report.Verdict, report.Codes)
			continue
		}
		if len(v.Expected.Codes) > 0 && outcome(report) != v.Expected.Verdict+":"+strings.Join(v.Expected.Codes, ",") {
			t.Errorf("%s (%s): want codes %v, got %v", v.ID, v.Slug, v.Expected.Codes, report.Codes)
		}
	}
	for kind, want := range m.Counts {
		if counted[kind] != want {
			t.Errorf("replayed %d %s members and the manifest declares %d", counted[kind], kind, want)
		}
	}
}

// TestEveryRuleIsLoadBearing is the RED and MUTATED columns in one measurement.
//
// For each rule it replays the whole corpus with that rule and nothing else
// disabled, which is the state the corpus was in before the rule existed. A rule
// that is load-bearing changes at least one member's outcome; a rule whose removal
// changes nothing is not a gate, and the test fails naming it, because a check that
// cannot be made to fail measures nothing.
//
// This is the seam that makes the red-green-mutate claim checkable rather than
// narrated: the same run produces the before state and the after state from one
// tree, so neither can be a stale build of the other.
func TestEveryRuleIsLoadBearing(t *testing.T) {
	m := loadManifest(t)
	policy := testPolicy(t, m)
	baseline := map[string]string{}
	bodies := map[string][]byte{}
	for _, v := range m.Vectors {
		bodies[v.ID] = readVector(t, v)
		baseline[v.ID] = outcome(Verify(bodies[v.ID], policy))
	}
	for _, name := range RuleNames() {
		var flipped []string
		for _, v := range m.Vectors {
			got := outcome(verify(bodies[v.ID], policy, name))
			if got != baseline[v.ID] {
				flipped = append(flipped, v.ID+" "+v.Slug+" -> "+got)
			}
		}
		sort.Strings(flipped)
		if len(flipped) == 0 {
			t.Errorf("rule %s: disabling it changes no member's outcome, so nothing in the "+
				"corpus forces it and it cannot be shown to do anything", name)
			continue
		}
		t.Logf("rule %-28s forced by %d member(s): %s", name, len(flipped), strings.Join(flipped, "; "))
	}
}

// TestEmptyTreeConstantsMatchTheCorpus checks the one value this rail states as a
// literal against the value the reference verifier computes from the preimage.
func TestEmptyTreeConstantsMatchTheCorpus(t *testing.T) {
	m := loadManifest(t)
	if len(m.EmptyTree) == 0 {
		t.Fatal("the manifest publishes no empty-tree constants, so this comparison is vacuous")
	}
	for algorithm, declared := range m.EmptyTree {
		held, known := EmptyTree(algorithm)
		if !known {
			t.Errorf("the corpus declares an empty-tree constant for %s and this rail holds none", algorithm)
			continue
		}
		if held != declared {
			t.Errorf("%s empty tree: this rail holds %s, the corpus computes %s", algorithm, held, declared)
		}
	}
}

// TestVoluntaryIsNeverReadAsIndependentlyObserved is the vocabulary's prohibition
// as an assertion over every member that verifies: a verifier must not read a
// voluntary attestation as evidence that the attested content corresponds to any
// independently observed fact.
func TestVoluntaryIsNeverReadAsIndependentlyObserved(t *testing.T) {
	m := loadManifest(t)
	policy := testPolicy(t, m)
	seenVoluntary := false
	for _, v := range m.Vectors {
		report := Verify(readVector(t, v), policy)
		if report.Verdict != verdictValid {
			continue
		}
		if report.DerivedTier == "voluntary" {
			seenVoluntary = true
			if report.IndependentlyObserved {
				t.Errorf("%s (%s): voluntary and reported as independently observed", v.ID, v.Slug)
			}
		}
	}
	if !seenVoluntary {
		t.Error("no member recomputed to a voluntary tier, so the prohibition was not exercised " +
			"by anything and this test would pass against a rail that ignores it")
	}
}

// TestPayloadDuplicateMemberIsRefused proves the decoder's own refusal rather than
// assuming encoding/json does it, which it does not: json.Unmarshal into a map
// keeps the last spelling of a repeated key and reports a clean parse.
func TestPayloadDuplicateMemberIsRefused(t *testing.T) {
	duplicate := []byte(`{"a":1,"a":2}`)
	if _, f := decodeIJSON(duplicate); f == nil || f.code != "duplicate-member" {
		t.Fatalf("a duplicate member was not refused: %v", f)
	}
	// The control: the same shape without the repeat has to decode, or the test
	// above passes for the wrong reason.
	if _, f := decodeIJSON([]byte(`{"a":1,"b":2}`)); f != nil {
		t.Fatalf("a clean object was refused: %v", f.code)
	}
}

// TestEnvelopeSignatureIsChecked proves the last gate runs, by breaking one byte of
// a member that otherwise verifies.
func TestEnvelopeSignatureIsChecked(t *testing.T) {
	m := loadManifest(t)
	policy := testPolicy(t, m)
	var accepted manifestVector
	for _, v := range m.Vectors {
		if v.Kind == "accept" {
			accepted = v
			break
		}
	}
	if accepted.ID == "" {
		t.Fatal("no accept member in the corpus, so there is nothing to break")
	}
	body := readVector(t, accepted)
	if report := Verify(body, policy); report.Verdict != verdictValid {
		t.Fatalf("control failed: %s does not verify as it stands (%v)", accepted.ID, report.Codes)
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("%s does not parse: %v", accepted.ID, err)
	}
	signatures, _ := envelope["signatures"].([]any)
	first, _ := signatures[0].(map[string]any)
	raw, err := base64.StdEncoding.DecodeString(first["sig"].(string))
	if err != nil {
		t.Fatalf("the member's signature is not base64: %v", err)
	}
	raw[0] ^= 0xff
	first["sig"] = base64.StdEncoding.EncodeToString(raw)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("re-encoding failed: %v", err)
	}
	report := Verify(tampered, policy)
	if report.Verdict != verdictInvalid || len(report.Codes) == 0 || report.Codes[0] != "envelope-signature-invalid" {
		t.Fatalf("a flipped signature byte produced %s %v", report.Verdict, report.Codes)
	}
}
