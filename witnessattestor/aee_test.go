package witnessattestor

// Tests for the emit seam and the served schema. These compile against the
// go-witness module (see BUILD-NOTES.md for wiring); the vector-driven
// refusal subtests additionally load reject-vector bodies from the sibling
// vector suite when it is present, and skip cleanly when it is not.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/probityai/agent-evidence-vectors/aee"
	"github.com/probityai/agent-evidence-vectors/aeetest"
)

// Emit-refusal (the widened attestor-refuses behavior assertion): the seam
// must error, never sign, on gate-1 faults AND gate-0 faults AND recompute
// faults. Synthetic bodies exercise it without the vector suite.
func TestEmitSeamRefusesSyntheticFaults(t *testing.T) {
	cases := map[string][]byte{
		"gate1-method-inflation":  aeetest.Build(aeetest.Options{RecordMethod: "reconstructed"}),
		"gate1-batch-root":        aeetest.Build(aeetest.Options{TamperBatchRoot: true}),
		"gate0-vocabulary-digest": aeetest.Build(aeetest.Options{TamperVocabularyDigest: true}),
		"gate0-coverage":          aeetest.Build(aeetest.Options{ExtraManifestAttack: true}),
		"recompute-mismatch":      aeetest.Build(aeetest.Options{Result: "pass"}),
	}
	for name, body := range cases {
		if _, err := aee.VerifyForEmit(body); err == nil {
			t.Errorf("%s: emit seam would sign a statement the suite rejects", name)
		}
	}
	if _, err := aee.VerifyForEmit(aeetest.Build(aeetest.Options{})); err != nil {
		t.Errorf("emit seam refused a valid statement: %v", err)
	}
}

// Vector-driven refusal bodies (gate-1 faults bad-302/bad-407 plus GATE-0
// faults bad-605/bad-806, per the widened behavior assertion).
func TestEmitSeamRefusesVectorBodies(t *testing.T) {
	dir := os.Getenv("AEE_VECTORS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "vectors")
	}
	rejectDir := ""
	for _, sub := range []string{"reject", "invalid"} {
		if info, err := os.Stat(filepath.Join(dir, sub)); err == nil && info.IsDir() {
			rejectDir = filepath.Join(dir, sub)
			break
		}
	}
	if rejectDir == "" {
		if os.Getenv("AEE_SKIP_VECTORS") == "1" {
			t.Skipf("vector suite not present at %s and AEE_SKIP_VECTORS=1 set; skipping vector-driven emit-refusal", dir)
		}
		t.Fatalf("vector suite not present at %s (set AEE_VECTORS_DIR, or AEE_SKIP_VECTORS=1 to skip): the emit-refusal gate must not silently no-op", dir)
	}
	entries, err := os.ReadDir(rejectDir)
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"bad-302", "bad-407", "bad-605", "bad-806"}
	ran := 0
	for _, e := range entries {
		for _, p := range prefixes {
			if len(e.Name()) >= len(p) && e.Name()[:len(p)] == p {
				body, err := os.ReadFile(filepath.Join(rejectDir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := aee.VerifyForEmit(body); err == nil {
					t.Errorf("%s: emit seam would sign a reject vector", e.Name())
				}
				ran++
			}
		}
	}
	if ran == 0 {
		t.Skip("named emit-refusal vectors not found in the suite")
	}
}

// MarshalJSON must be exactly the validated predicate bytes, and must
// refuse to serialize before validation.
func TestMarshalIsValidatedPredicateBytes(t *testing.T) {
	a := New()
	if _, err := json.Marshal(a); err == nil {
		t.Fatal("unvalidated attestor serialized an empty predicate")
	}
	body := aeetest.Build(aeetest.Options{})
	statement, err := aee.ParseStatement(body)
	if err != nil {
		t.Fatal(err)
	}
	a.predicateRaw = statement.PredicateRaw
	out, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(statement.PredicateRaw) {
		t.Fatal("marshaled predicate drifted from validated bytes")
	}
}

// Schema round-trip losslessness: the served schema must round-trip through
// the invopop type without dropping top-level structure; drift here would
// mean Schema() serves less than the published schema.
func TestSchemaRoundTripLossless(t *testing.T) {
	var want map[string]any
	if err := json.Unmarshal(embeddedSchema, &want); err != nil {
		t.Fatalf("embedded schema does not parse: %v", err)
	}
	served := New().Schema()
	out, err := json.Marshal(served)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"$schema", "$id", "type", "required", "properties", "$defs"} {
		if _, ok := want[key]; !ok {
			continue
		}
		if _, ok := got[key]; !ok {
			t.Errorf("schema round-trip dropped top-level %q", key)
		}
	}
	wantProps := want["properties"].(map[string]any)
	gotProps, ok := got["properties"].(map[string]any)
	if !ok {
		t.Fatal("round-tripped schema lost the properties object")
	}
	wantKeys := make([]string, 0, len(wantProps))
	for k := range wantProps {
		wantKeys = append(wantKeys, k)
	}
	for _, k := range wantKeys {
		if _, ok := gotProps[k]; !ok {
			t.Errorf("schema round-trip dropped property %q", k)
		}
	}
	if !reflect.DeepEqual(want["required"], got["required"]) {
		t.Errorf("schema round-trip changed required: %v vs %v", want["required"], got["required"])
	}
}
