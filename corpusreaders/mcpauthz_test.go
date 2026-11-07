package corpusreaders_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

const maDir = "vectors-mcp-authz"

func maJudge(t *testing.T, dir string) *corpusreaders.Result {
	t.Helper()
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	return result
}

func maStage(t *testing.T) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), maDir)
	copyTree(t, corpusPath(maDir), copied)
	return copied
}

func maFirstFile(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "observations", "*.json"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no observation to alter: %v", err)
	}
	return matches[0]
}

func maRequire(t *testing.T, result *corpusreaders.Result, want string) {
	t.Helper()
	if result.OK() {
		t.Fatalf("an altered corpus was judged intact, expected a finding about %q", want)
	}
	all := strings.Join(result.Findings, " ")
	for _, m := range result.Members {
		all += " " + strings.Join(m.Findings, " ")
	}
	if !strings.Contains(all, want) {
		t.Fatalf("no finding mentions %q: %s", want, all)
	}
}

func TestMCPAuthzCommittedCorpusIsIntact(t *testing.T) {
	result := maJudge(t, corpusPath(maDir))
	if !result.OK() {
		t.Fatalf("corpus findings: %v %v", result.Findings, result.Members)
	}
	if len(result.Members) == 0 {
		t.Fatal("no member was judged")
	}
}

func TestMCPAuthzRefusesAnEditedObservation(t *testing.T) {
	dir := maStage(t)
	path := maFirstFile(t, dir)
	body, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	maRequire(t, maJudge(t, dir), "sha256")
}

func TestMCPAuthzRefusesAnObservationNotMarkedSynthetic(t *testing.T) {
	dir := maStage(t)
	path := maFirstFile(t, dir)
	body, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc["fixture"] = map[string]any{"synthetic": false}
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	maRequire(t, maJudge(t, dir), "synthetic")
}

func TestMCPAuthzRefusesAnAnswerThatDoesNotFitItsKind(t *testing.T) {
	dir := maStage(t)
	manifestPath := filepath.Join(dir, "MANIFEST.json")
	body, err := os.ReadFile(manifestPath) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(body), `"verdict": "invalid"`, `"verdict": "valid"`, 1)
	if edited == string(body) {
		t.Fatal("the manifest carries no reject member to alter")
	}
	if err := os.WriteFile(manifestPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	maRequire(t, maJudge(t, dir), "does not fit the kind")
}

func TestMCPAuthzRefusesAMissingObservation(t *testing.T) {
	dir := maStage(t)
	if err := os.Remove(maFirstFile(t, dir)); err != nil {
		t.Fatal(err)
	}
	maRequire(t, maJudge(t, dir), "missing")
}
