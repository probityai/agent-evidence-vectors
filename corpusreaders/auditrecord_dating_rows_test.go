package corpusreaders

import (
	"crypto/sha256"
	"encoding/base64"
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

// TestAuditRecordKeySetBindsNoParty holds R13 and R25 to what a key set shows: the
// key the chain verifier held, its algorithm family and its RFC 7638 thumbprint,
// and never the binding of that key to a party. A reader that reports the binding
// established for a key set disagrees with the corpus.
func TestAuditRecordKeySetBindsNoParty(t *testing.T) {
	manifest, heads, bodies, expected := arRetainedMembers(t)
	key := manifest.Keys.Observer.PublicKey
	for row, family := range map[string]string{"R13": "Ed25519", "R25": "P-256"} {
		body, ok := bodies[row]
		if !ok {
			t.Fatalf("the corpus carries no %s", row)
		}
		want := expected[row].DelegationRoot
		if want.Result != "established" || want.Algorithm != family || want.Binding != "not-established" {
			t.Errorf("%s: want the root established under %s and the binding not established, got %+v", row, family, want)
		}
		var member struct {
			Retention struct {
				ValidationData []struct {
					For, MediaType, Value string
				} `json:"validationData"`
			} `json:"retention"`
		}
		if err := json.Unmarshal(body, &member); err != nil {
			t.Fatal(err)
		}
		var keys []map[string]any
		for _, element := range member.Retention.ValidationData {
			if element.For != "delegation-root" {
				continue
			}
			material, err := base64.StdEncoding.DecodeString(element.Value)
			var set struct {
				Keys []map[string]any `json:"keys"`
			}
			if err != nil || element.MediaType != "application/jwk-set+json" || json.Unmarshal(material, &set) != nil {
				t.Fatalf("%s: the root element is not a readable key set", row)
			}
			keys = set.Keys
		}
		if len(keys) != 1 || keys[0]["x5c"] != nil || keys[0]["x5u"] != nil {
			t.Fatalf("%s: want one key with no certificate, got %v", row, keys)
		}
		required := []string{"crv", "kty", "x"}
		if keys[0]["kty"] == "EC" {
			required = append(required, "y")
		}
		members := map[string]any{}
		for _, name := range required {
			members[name] = keys[0][name]
		}
		text, _ := json.Marshal(members)
		sum := sha256.Sum256(text)
		if want.KeyThumbprint != base64.RawURLEncoding.EncodeToString(sum[:]) {
			t.Errorf("%s: keyThumbprint %q is not the RFC 7638 thumbprint of the held key", row, want.KeyThumbprint)
		}
		report, dated := arVerifyRetained(body, manifest.PredicateType, key, heads, "")
		if report.verdict != "valid" || !dated.equal(expected[row]) {
			t.Errorf("%s: got %s and %+v, want valid and %+v", row, report.verdict, dated, expected[row])
		}
		dated.DelegationRoot.Binding = "established"
		if dated.equal(expected[row]) {
			t.Errorf("%s: a reader reporting the binding established agrees with the corpus", row)
		}
	}
}
