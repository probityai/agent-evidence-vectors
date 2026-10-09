package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Disabling one rule must free exactly that requirement's reject member. A
// rule that frees nothing was never the reason its reject member failed, and a
// rule that frees another member is judging a requirement it does not own.
func TestMCPOWASPEachRuleOwnsItsReject(t *testing.T) {
	dir := filepath.Join("..", "vectors-mcp-owasp")
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m moManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	rejectOf := map[string]string{}
	for _, e := range m.Vectors {
		if e.Kind == "reject" {
			rejectOf[e.Conditions[0]] = e.ID
		}
	}
	if len(rejectOf) != len(moRules) {
		t.Fatalf("%d reject members for %d rules", len(rejectOf), len(moRules))
	}
	for requirement, rule := range moRules {
		moRules[requirement] = func(map[string]any) string { return "" }
		res, err := mcpOWASP{}.Judge(dir, raw)
		moRules[requirement] = rule
		if err != nil {
			t.Fatal(err)
		}
		var freed []string
		for _, member := range res.Members {
			if !member.OK() {
				freed = append(freed, member.ID)
			}
		}
		if len(freed) != 1 || freed[0] != rejectOf[requirement] {
			t.Errorf("disabling %s freed %v, not exactly %s", requirement, freed, rejectOf[requirement])
		}
	}
}
