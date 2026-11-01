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

func moObs(t *testing.T, raw string) map[string]any {
	t.Helper()
	v, err := decodeJSONNumbers([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// Every rule refuses an observation that did not run its test, and every
// refusal path names its reason. Each case is one observation and the
// requirement whose rule must reject it.
func TestMCPOWASPRulesRefuseMalformedObservations(t *testing.T) {
	cases := []struct{ rule, obs string }{
		{"MCPVS-1", `{}`},
		{"MCPVS-1", `{"approvedDigest":"a","servedDigest":"b","clientDecision":"refused","reportedDigests":["a"]}`},
		{"MCPVS-2", `{}`},
		{"MCPVS-2", `{"approvedDigest":"a","servedDigest":"b"}`},
		{"MCPVS-2", `{"approvedDigest":"a","servedDigest":"b","connections":[{"afterRestart":false,"decision":"refused"}]}`},
		{"MCPVS-2", `{"approvedDigest":"a","servedDigest":"b","connections":["x",{"afterRestart":true}]}`},
		{"MCPVS-3", `{}`},
		{"MCPVS-3", `{"tokens":{"A":"ta","B":"tb"},"calledServer":"B","receivedArguments":{"k":["ta"]}}`},
		{"MCPVS-4", `{}`},
		{"MCPVS-4", `{"sessionScopes":["S1"],"callRequires":"S2","grantedAcrossSessions":["S1"]}`},
		{"MCPVS-5", `{"payloads":["; id"]}`},
		{"MCPVS-5", `{"payloads":["; id","$(id)","` + "`id`" + `"],"spawnedProcesses":[]}`},
		{"MCPVS-6", `{}`},
		{"MCPVS-6", `{"before":{},"after":{},"unapprovedCallsAfter":1}`},
		{"MCPVS-6", `{"before":{},"after":{},"unapprovedCallsAfter":0,"contentRecordedAs":"instruction"}`},
		{"MCPVS-7", `{}`},
		{"MCPVS-7", `{"configuredDigests":["a"],"launchedDigest":"b","decision":"refused","namedExpected":"c"}`},
		{"MCPVS-8", `{}`},
		{"MCPVS-8", `{"records":["x",{}]}`},
		{"MCPVS-8", `{"records":[{"server":"s"},{}]}`},
		{"MCPVS-9", `{}`},
		{"MCPVS-9", `{"stream":[{"seq":1,"prev":""}]}`},
		{"MCPVS-9", `{"stream":["x"],"headHolder":"client"}`},
		{"MCPVS-9", `{"stream":[{"seq":1,"prev":"bad"}],"headHolder":"log","verification":{"result":"pass"}}`},
		{"MCPVS-9", `{"stream":[{"seq":1,"prev":"bad"}],"headHolder":"log","verification":{"result":"fail","breakAt":2}}`},
		{"MCPVS-9", `{"stream":[{"seq":"one","prev":"bad"}],"headHolder":"log","verification":{"result":"fail","breakAt":-1}}`},
		{"MCPVS-10", `{}`},
		{"MCPVS-10", `{"untrustedConfigServers":["w"],"started":[],"refusalReported":false}`},
		{"MCPVS-10", `{"untrustedConfigServers":["w"],"started":["a"],"refusalReported":true,"reportedStarted":[]}`},
		{"MCPVS-11", `{}`},
		{"MCPVS-11", `{"calls":["x",{"userBound":false}]}`},
		{"MCPVS-11", `{"calls":[{"userBound":true,"decision":"refused"},{"userBound":false}]}`},
		{"MCPVS-11", `{"calls":[{"userBound":false,"decision":"refused"}]}`},
		{"MCPVS-12", `{}`},
	}
	for _, c := range cases {
		if reason := moRules[c.rule](moObs(t, c.obs)); reason == "" {
			t.Errorf("%s accepted %s", c.rule, c.obs)
		}
	}
	if got, _ := moVerdict(map[string]any{"requirement": "MCPVS-99"}); got != "reject" {
		t.Error("an unknown requirement was not rejected")
	}
	if got, _ := moVerdict(map[string]any{"requirement": "MCPVS-1"}); got != "reject" {
		t.Error("a record with no observation was not rejected")
	}
	for _, v := range []any{nil, "", "x", true, false, json.Number("0"), json.Number("2"), []any{}, map[string]any{}, 1.5} {
		_ = moTruthy(v)
	}
}

// A broken registry and a broken manifest are named, never passed.
func TestMCPOWASPRefusesBrokenCorpus(t *testing.T) {
	src := filepath.Join("..", "vectors-mcp-owasp")
	dir := t.TempDir()
	for _, sub := range []string{"", "records", "drafts"} {
		entries, err := os.ReadDir(filepath.Join(src, sub))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(src, sub, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, sub, e.Name()), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	regPath := filepath.Join(dir, "REGISTRY.json")
	raw, _ := os.ReadFile(regPath)
	var reg map[string]any
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	threats := reg["threats"].([]any)
	threats[0].(map[string]any)["testedBy"] = []any{}
	threats[1].(map[string]any)["testedBy"] = []any{"MCPVS-99"}
	threats[2].(map[string]any)["id"] = "MCPTM-77"
	out, _ := json.Marshal(reg)
	if err := os.WriteFile(regPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	manPath := filepath.Join(dir, ManifestName)
	mraw, _ := os.ReadFile(manPath)
	var man map[string]any
	if err := json.Unmarshal(mraw, &man); err != nil {
		t.Fatal(err)
	}
	vecs := man["vectors"].([]any)
	vecs[0].(map[string]any)["record"] = "records/missing.json"
	for _, v := range vecs {
		if m := v.(map[string]any); m["kind"] == "reject" {
			m["twin"] = "nobody"
			break
		}
	}
	man["counts"] = map[string]any{"accept": 1}
	if err := os.WriteFile(filepath.Join(dir, "records", "garbage.json"), []byte("[1]"), 0o600); err != nil {
		t.Fatal(err)
	}
	vecs = append(vecs, map[string]any{"id": "vgarbage", "kind": "accept", "record": "records/garbage.json", "conditions": []any{"MCPVS-1"}})
	man["vectors"] = vecs
	mout, _ := json.Marshal(man)
	res, err := mcpOWASP{}.Judge(dir, mout)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || len(res.Findings) < 4 {
		t.Fatalf("a broken corpus judged clean or under-reported: %v", res.Findings)
	}
	if _, err := (mcpOWASP{}).Judge(dir, []byte("{")); err == nil {
		t.Error("an unparseable manifest was not an error")
	}
	if _, err := (mcpOWASP{}).Judge(dir, []byte(`{"registry":"nope.json"}`)); err == nil {
		t.Error("a missing registry was not an error")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (mcpOWASP{}).Judge(dir, []byte(`{"registry":"bad.json"}`)); err == nil {
		t.Error("an unparseable registry was not an error")
	}
}
