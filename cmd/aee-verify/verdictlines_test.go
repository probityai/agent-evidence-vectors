package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vlExpected struct {
	Verdict  string `json:"verdict"`
	Result   string `json:"result"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type vlTestManifest struct {
	Suite        string `json:"suite"`
	CorpusDigest string `json:"corpusDigest"`
	Vectors      []struct {
		ID       string     `json:"id"`
		Expected vlExpected `json:"expected"`
	} `json:"vectors"`
}

var vlKeys = map[string]bool{"schema": true, "suite": true, "corpusDigest": true, "vector": true,
	"verdict": true, "reason": true, "result": true, "verifier": true}

// TestVerdictLinesMatchEveryManifest runs the corpus mode over the AEE corpus
// and the two record-family corpora and holds every line to the manifest: one
// line per member, the manifest's digest, and the verdict, result token and
// (for a decision corpus) reason the manifest expects.
func TestVerdictLinesMatchEveryManifest(t *testing.T) {
	dirs := []string{"../../vectors", "../../corpora/vectors-approval-binding",
		"../../corpora/vectors-uncertain-effect"}
	var out, errOut bytes.Buffer
	if code := run(append([]string{"-verdict-lines"}, dirs...), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	seen := map[string]map[string]any{}
	for _, raw := range lines {
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("not one JSON object per line: %q", raw)
		}
		for key := range line {
			if !vlKeys[key] {
				t.Fatalf("unknown member %q in %s", key, raw)
			}
		}
		seen[line["suite"].(string)+" "+line["vector"].(string)] = line
	}
	total := 0
	for _, dir := range dirs {
		body, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m vlTestManifest
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		for _, v := range m.Vectors {
			total++
			line, ok := seen[m.Suite+" "+v.ID]
			if !ok {
				t.Fatalf("%s %s: no line", m.Suite, v.ID)
			}
			if line["corpusDigest"] != m.CorpusDigest {
				t.Errorf("%s: digest %v", v.ID, line["corpusDigest"])
			}
			want := map[string]string{"valid": "accept", "invalid": "reject", "allow": "accept",
				"deny": "reject"}[v.Expected.Verdict+v.Expected.Decision]
			if line["verdict"] != want {
				t.Errorf("%s %s: verdict %v, manifest expects %s", m.Suite, v.ID, line["verdict"], want)
			}
			if v.Expected.Result != "" && line["result"] != v.Expected.Result {
				t.Errorf("%s: result %v, want %s", v.ID, line["result"], v.Expected.Result)
			}
			if v.Expected.Decision != "" && line["reason"] != v.Expected.Reason {
				t.Errorf("%s: reason %v, want %s", v.ID, line["reason"], v.Expected.Reason)
			}
		}
	}
	if len(lines) != total || total != 288+37+40 {
		t.Fatalf("%d lines for %d members", len(lines), total)
	}
}

// TestVerdictLinesSuiteNotImplemented answers a corpus with no per-member
// reader here with one not-applicable line per member, never a pass and never
// silence.
func TestVerdictLinesSuiteNotImplemented(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-verdict-lines", "../../corpora/vectors-dispatch-fence"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, raw := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.Contains(raw, `"verdict":"not-applicable","reason":"suite-not-implemented"`) {
			t.Fatalf("expected not-applicable, got %s", raw)
		}
	}
}

// TestVerdictLinesRefusesUnreadableCorpus exits 2 with NOT RUN rather than an
// empty, clean-looking output.
func TestVerdictLinesRefusesUnreadableCorpus(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-verdict-lines", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "NOT RUN") || out.Len() != 0 {
		t.Fatalf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if code := run([]string{"-verdict-lines"}, &out, &errOut); code != 2 {
		t.Fatalf("no directory: exit %d, want 2", code)
	}
}
