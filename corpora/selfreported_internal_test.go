package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// srrAcceptedStatement reads the first accepted member of the vendored corpus
// as a decoded statement.
func srrAcceptedStatement(t *testing.T) map[string]any {
	t.Helper()
	dir := filepath.Join("..", "vectors-self-reported-record")
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest srrManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, v := range manifest.Vectors {
		if v.Kind != "accept" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := srrDecode(body)
		if err != nil {
			t.Fatal(err)
		}
		return objectAt(decoded)
	}
	t.Fatal("no accepted member")
	return nil
}

// Each wrong-typed or oddly spelled member is a malformed record, not an
// absent one.
func TestSelfReportedWellformedRefusesMalformedMembers(t *testing.T) {
	if !srrWellformed(srrAcceptedStatement(t)) {
		t.Fatal("the accepted member must be well formed before it is mutated")
	}
	mutations := map[string]func(map[string]any){
		"statement type": func(s map[string]any) { s["_type"] = "x" },
		"predicate type": func(s map[string]any) { s["predicateType"] = "x" },
		"subject":        func(s map[string]any) { s["subject"] = "x" },
		"predicate":      func(s map[string]any) { s["predicate"] = "x" },
		"required member": func(s map[string]any) {
			delete(s["predicate"].(map[string]any), srrRequired[0])
		},
		"container": func(s map[string]any) {
			s["predicate"].(map[string]any)[srrContainers[0]] = "x"
		},
		"hash algorithm": func(s map[string]any) {
			s["predicate"].(map[string]any)["hashAlgorithm"] = "md5"
		},
		"attesting key": func(s map[string]any) {
			s["predicate"].(map[string]any)["attestingKey"] = map[string]any{"keyid": "zz", "publicKey": "zz"}
		},
		"self signer": func(s map[string]any) {
			s["predicate"].(map[string]any)["selfSigners"] = []any{"zz"}
		},
		"ledgers": func(s map[string]any) {
			s["predicate"].(map[string]any)["ledgers"] = []any{}
		},
		"issued at": func(s map[string]any) {
			s["predicate"].(map[string]any)["issuedAt"] = "yesterday"
		},
	}
	for name, mutate := range mutations {
		statement := srrAcceptedStatement(t)
		mutate(statement)
		if srrWellformed(statement) {
			t.Errorf("%s: a malformed record was judged well formed", name)
		}
	}
}
