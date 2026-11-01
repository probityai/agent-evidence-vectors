package corpora

// Every rule the delegation lifecycle reader applies is load-bearing: switching
// any one off must change the answer of at least one committed member. A rule
// whose removal changes nothing measures nothing, and a green corpus cannot say
// that about itself.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDelegationLifecycleEveryRuleIsLoadBearing(t *testing.T) {
	dir := filepath.Join("..", "vectors-delegation-lifecycle")
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName)) // #nosec G304 -- the committed manifest
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []dlVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, rule := range dlRules {
		t.Run(rule, func(t *testing.T) {
			moved := 0
			for _, v := range manifest.Vectors {
				got, err := dlDecideDir(filepath.Join(dir, v.Path), map[string]bool{rule: true})
				if err != nil {
					t.Fatalf("%s: %v", v.ID, err)
				}
				if got != v.Expected {
					moved++
				}
			}
			if moved == 0 {
				t.Fatalf("switching %s off changes no member", rule)
			}
		})
	}
}

func TestDelegationLifecycleUnreadableCaseIsAnError(t *testing.T) {
	if _, err := dlDecideDir(t.TempDir(), nil); err == nil {
		t.Fatal("a case directory with no case.json was decided")
	}
}

func TestDelegationLifecycleRecordRefusals(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &dlState{policy: dlPolicy{PayloadType: "application/x"}}
	// payload "{}" (e30=) has no type; payload `{"type":"grant"}` lacks its fields;
	// payload `{"type":"presentation","presenter":"p","observed_at":"noon"}` has a
	// time that does not parse.
	for name, body := range map[string]string{
		"absent.json":   "",
		"other.json":    `{"payload":"e30=","payloadType":"application/y","signatures":[{"keyid":"k","sig":""}]}`,
		"array.json":    `{"payload":"W10=","payloadType":"application/x","signatures":[{"keyid":"k","sig":""}]}`,
		"untyped.json":  `{"payload":"e30=","payloadType":"application/x","signatures":[{"keyid":"k","sig":""}]}`,
		"unfilled.json": `{"payload":"eyJ0eXBlIjoiZ3JhbnQifQ==","payloadType":"application/x","signatures":[{"keyid":"k","sig":""}]}`,
		"badtime.json":  `{"payload":"eyJ0eXBlIjoicHJlc2VudGF0aW9uIiwicHJlc2VudGVyIjoicCIsIm9ic2VydmVkX2F0Ijoibm9vbiJ9","payloadType":"application/x","signatures":[{"keyid":"k","sig":""}]}`,
	} {
		if name != "absent.json" {
			write(name, body)
		}
		if _, ok := s.parse(dir, name); ok {
			t.Errorf("%s parsed as a record", name)
		}
	}
	if _, ok := dlPublicKey(dlKey{KeyID: "x", PublicKey: "%%"}); ok {
		t.Error("a key that is not base64 was accepted")
	}
	if s.verify(&dlRecord{kind: "unknown"}) {
		t.Error("a record of no known type verified")
	}
	if s.registryKeys() != nil {
		t.Error("a policy with no registry key yielded one")
	}
	if _, reason := s.chain(&dlRecord{fields: map[string]any{}}); reason != "chain_broken" {
		t.Errorf("a presentation with no chain gave %q", reason)
	}
}
