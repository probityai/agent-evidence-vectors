package corpora

// The refund-connected Judge is held to the corpus it reads: intact, it is clean; with a
// file of a run changed, the manifest edited, or a run it cannot read, it names the
// problem. The verdict rules themselves are held to the Python reader in
// refundconnected_internal_test.go.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rcCorpusDir = "../vectors-refund-connected"

// rcCopyCorpus copies the corpus into a temporary directory and returns it.
func rcCopyCorpus(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(rcCorpusDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(rcCorpusDir, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		body, err := os.ReadFile(path) // #nosec G304,G122 -- the corpus under test
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// rcManifestEdit rewrites the manifest of a corpus copy through edit and judges it.
func rcManifestEdit(t *testing.T, dir string, edit func(manifest map[string]any)) *Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json")) // #nosec G304 -- the copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	edit(manifest)
	edited, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	result, err := refundConnected{}.Judge(dir, edited)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func rcAnyFinding(result *Result, want string) bool {
	all := append([]string{}, result.Findings...)
	for _, m := range result.Members {
		all = append(all, m.Findings...)
	}
	for _, f := range all {
		if strings.Contains(f, want) {
			return true
		}
	}
	return false
}

func TestRefundConnectedJudgeIntact(t *testing.T) {
	dir := rcCopyCorpus(t)
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json")) // #nosec G304 -- the copy
	if err != nil {
		t.Fatal(err)
	}
	result, err := refundConnected{}.Judge(dir, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings on the intact corpus: %v", result.Findings)
	}
	kinds := map[string]int{}
	for _, m := range result.Members {
		if len(m.Findings) != 0 {
			t.Errorf("%s: %v", m.ID, m.Findings)
		}
		kinds[m.Kind]++
	}
	for _, kind := range []string{"established", "rejected", "not-reached", "not-established"} {
		if kinds[kind] == 0 {
			t.Errorf("no member ends as %q: %v", kind, kinds)
		}
	}
}

func TestRefundConnectedJudgeNamesWhatChanged(t *testing.T) {
	r2 := "source/j01-connected-20261028-r2"
	cases := []struct {
		name string
		want string
		edit func(t *testing.T, dir string, manifest map[string]any)
	}{
		{"a byte of a run file flipped", "effects.jsonl", func(t *testing.T, dir string, _ map[string]any) {
			path := filepath.Join(dir, r2, "executor", "effects.jsonl")
			body, err := os.ReadFile(path) // #nosec G304 -- the copy
			if err != nil {
				t.Fatal(err)
			}
			body[10] ^= 1
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a run file removed", "1 missing", func(t *testing.T, dir string, _ map[string]any) {
			if err := os.Remove(filepath.Join(dir, r2, "executor", "outcomes.jsonl")); err != nil {
				t.Fatal(err)
			}
		}},
		{"a run file added", "1 extra", func(t *testing.T, dir string, _ map[string]any) {
			if err := os.WriteFile(filepath.Join(dir, r2, "extra.txt"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a run tree gone", "cannot be read", func(t *testing.T, dir string, _ map[string]any) {
			if err := os.RemoveAll(filepath.Join(dir, r2)); err != nil {
				t.Fatal(err)
			}
		}},
		{"no run declared", "declares no run", func(_ *testing.T, _ string, m map[string]any) { m["runs"] = map[string]any{} }},
		{"a member names an undeclared run", "does not declare", func(_ *testing.T, _ string, m map[string]any) {
			m["vectors"].([]any)[0].(map[string]any)["run"] = "zz"
		}},
		{"a member names a case that is not there", "not a case directory", func(_ *testing.T, _ string, m map[string]any) {
			m["vectors"].([]any)[0].(map[string]any)["case"] = "nope"
		}},
		{"a recorded verdict differs", "the manifest records", func(_ *testing.T, _ string, m map[string]any) {
			steps := m["vectors"].([]any)[0].(map[string]any)["expected"].(map[string]any)["steps"].(map[string]any)
			steps["execution"] = "ESTABLISHED"
		}},
		{"a recorded step is missing", "records none", func(_ *testing.T, _ string, m map[string]any) {
			delete(m["vectors"].([]any)[0].(map[string]any)["expected"].(map[string]any)["steps"].(map[string]any), "input_pic")
		}},
		{"a recorded step the reader does not have", "has no such step", func(_ *testing.T, _ string, m map[string]any) {
			m["vectors"].([]any)[0].(map[string]any)["expected"].(map[string]any)["steps"].(map[string]any)["extra"] = "ESTABLISHED"
		}},
		{"a row is not an object", "does not parse", func(_ *testing.T, _ string, m map[string]any) {
			m["vectors"] = append(m["vectors"].([]any), "x")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := rcCopyCorpus(t)
			result := rcManifestEdit(t, dir, func(m map[string]any) { c.edit(t, dir, m) })
			if !rcAnyFinding(result, c.want) {
				t.Errorf("no finding mentions %q: %v", c.want, result.Findings)
			}
		})
	}
}

func TestRefundConnectedJudgeChecksTheCorpusDigest(t *testing.T) {
	dir := rcCopyCorpus(t)
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json")) // #nosec G304 -- the copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		CorpusDigest string `json:"corpusDigest"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Replace(raw, []byte(manifest.CorpusDigest), []byte(strings.Repeat("0", 64)), 1)
	result, err := refundConnected{}.Judge(dir, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || !strings.Contains(result.Findings[0], "corpusDigest") {
		t.Errorf("findings: %v", result.Findings)
	}
	if _, err := (refundConnected{}).Judge(dir, []byte("{")); err == nil {
		t.Error("a manifest that does not parse was judged")
	}
}

func TestRefundConnectedJudgeNamesAStoppedReader(t *testing.T) {
	fx := loadRCDiff(t)
	for _, m := range fx.Mutations {
		if m.Want != nil || m.Trusting || m.Run != "r2" {
			continue
		}
		dir := rcCopyCorpus(t)
		root := filepath.Join(dir, "source", "j01-connected-20261028-r2")
		h := &rcDiffHarness{dirs: map[string]string{m.Run: root}, base: map[string]map[string][]byte{m.Run: {}}}
		h.apply(t, m)
		result := rcManifestEdit(t, dir, func(map[string]any) {})
		if !rcAnyFinding(result, "the reader stopped judging the run") {
			t.Errorf("%s: %v", m.ID, result.Findings)
		}
		return
	}
	t.Fatal("the golden holds no stop of the reader on a run")
}

func TestRefundConnectedMemberKind(t *testing.T) {
	steps := func(first string) rcVector {
		var v rcVector
		v.Expected.Steps = map[string]string{"input_pic": first}
		for _, step := range rcSteps[1:] {
			v.Expected.Steps[step] = rcEstablished
		}
		return v
	}
	for verdict, want := range map[string]string{
		rcEstablished:             "established",
		rcRefused + ":x":          "rejected",
		rcContra + ":x":           "contradicted",
		rcAbsent + ":x":           "not-established",
		rcNotReached:              "not-reached",
		"SOMETHING_ELSE":          "unrecognized",
		rcRefused + "-not-a-code": "unrecognized",
	} {
		if got := rcMemberKind(steps(verdict)); got != want {
			t.Errorf("%q: got %q, want %q", verdict, got, want)
		}
	}
}
