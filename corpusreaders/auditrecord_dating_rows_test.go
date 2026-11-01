package corpora

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// arRetainedMembers loads the manifest, its anchor trust and every retained
// member's raw file by draft identifier.
func arRetainedMembers(t *testing.T) (arManifest, []arTreeHead, map[string][]byte, map[string]arDating) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(arCorpusDir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest arManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	bodies, expected := map[string][]byte{}, map[string]arDating{}
	for _, v := range manifest.Vectors {
		if v.Expected.Dating == nil {
			continue
		}
		body, err := os.ReadFile(filepath.Join(arCorpusDir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		bodies[v.DraftID], expected[v.DraftID] = body, *v.Expected.Dating
	}
	return manifest, arHeads(&manifest), bodies, expected
}

// TestAuditRecordRevisionOneDatingRows pins each R10 to R16 rule to its own
// member: the unweakened reader reaches the declared result, and disabling the
// rule the row tests moves that member off it.
func TestAuditRecordRevisionOneDatingRows(t *testing.T) {
	manifest, heads, bodies, expected := arRetainedMembers(t)
	key := manifest.Keys.Observer.PublicKey
	cases := []struct{ row, rule string }{
		{"R10", "opentimestamps-tolerance"},
		{"R11", "entry-received-after-anchor"},
		{"R12", "anchor-validation"},
		{"R13", "entry-delegation-root"},
		{"R15", "entry-delegation-root"},
		{"R16", "anchor-validation"},
	}
	for _, c := range cases {
		body, ok := bodies[c.row]
		if !ok {
			t.Fatalf("the corpus carries no %s", c.row)
		}
		report, dated := arVerifyRetained(body, manifest.PredicateType, key, heads, "")
		if report.verdict != "valid" || !dated.equal(expected[c.row]) {
			t.Errorf("%s: got %s and %+v, want valid and %+v", c.row, report.verdict, dated, expected[c.row])
		}
		if _, weakened := arVerifyRetained(body, manifest.PredicateType, key, heads, c.rule); weakened.equal(expected[c.row]) {
			t.Errorf("%s: disabling %s leaves its dating result unmoved", c.row, c.rule)
		}
	}
	if expected["R14"].DelegationRoot.Result != "not-established" {
		t.Errorf("R14 must report the root not established, never a pass")
	}
}

// TestAuditRecordRevisionOneRejectsFailForOneReason restores the one mutation
// of each malformed entry and requires the parent's result back.
func TestAuditRecordRevisionOneRejectsFailForOneReason(t *testing.T) {
	manifest, heads, bodies, expected := arRetainedMembers(t)
	key := manifest.Keys.Observer.PublicKey
	restore := func(row, parent string, change func(child, from map[string]any)) {
		var child, from map[string]any
		if json.Unmarshal(bodies[row], &child) != nil || json.Unmarshal(bodies[parent], &from) != nil {
			t.Fatalf("%s or %s unreadable", row, parent)
		}
		change(child["retention"].(map[string]any), from["retention"].(map[string]any))
		body, _ := json.Marshal(child)
		if _, dated := arVerifyRetained(body, manifest.PredicateType, key, heads, ""); !dated.equal(expected[parent]) {
			t.Errorf("%s with its mutation restored dates %+v, want %s's %+v", row, dated, parent, expected[parent])
		}
	}
	restore("R11", "R10", func(child, from map[string]any) {
		child["anchors"].([]any)[1] = from["anchors"].([]any)[1]
	})
	restore("R15", "R13", func(child, from map[string]any) {
		child["validationData"] = from["validationData"]
	})
}
