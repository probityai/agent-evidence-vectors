package main

// The CLI's corpus mode: the exit codes a consumer branches on, and the lines
// they read.
//
// The three codes are not interchangeable. 0 means every member behaved. 1
// means a named member did not. 2 means the corpus could not be judged at all,
// which a caller must never be able to confuse with 0 -- a corpus nothing read
// and a corpus that came back clean would otherwise print the same nothing.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// theAEECorpus is the corpus this repository publishes, judged through the
// same argv a third party is told to run.
const theAEECorpus = "../../vectors"

func TestCorpusModeClearsThePublishedCorpus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{theAEECorpus}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d on the published corpus; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"suite: adversarial-execution-evidence-conformance",
		"members: ",
		"accept: ",
		"reject: ",
		"every member behaves as MANIFEST.json declares",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the human report does not carry %q:\n%s", want, out)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("a clean run wrote to stderr: %s", stderr.String())
	}
}

func TestCorpusModeJSONIsOneLine(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-json", theAEECorpus}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d; stderr: %s", code, stderr.String())
	}
	body := strings.TrimRight(stdout.String(), "\n")
	if strings.Contains(body, "\n") {
		t.Error("the JSON report spans more than one line; a caller reading the last line " +
			"of stdout would parse a fragment")
	}
	var report struct {
		Suite   string `json:"suite"`
		Members []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"members"`
	}
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		t.Fatalf("the report does not parse: %v", err)
	}
	if report.Suite == "" || len(report.Members) == 0 {
		t.Fatalf("the report carries no suite or no members: %s", body)
	}
}

func TestCorpusModeNamesTheMemberAndExitsOne(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "vectors-anchor-stream")
	copyForCLI(t, "../../corpora/vectors-anchor-stream", corpus)

	raw, err := os.ReadFile(filepath.Join(corpus, "MANIFEST.json")) // #nosec G304 -- the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []struct {
			ID     string `json:"id"`
			Stream string `json:"stream"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	member := manifest.Vectors[0]
	stream := filepath.Join(corpus, member.Stream)
	body, err := os.ReadFile(stream) // #nosec G304 -- the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0x01
	if err := os.WriteFile(stream, body, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{corpus}, &stdout, &stderr); code != 1 {
		t.Fatalf("a corpus with a flipped byte exited %d, not 1", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "FAIL "+member.ID) {
		t.Errorf("the report does not name %s:\n%s", member.ID, out)
	}
	if !strings.Contains(out, "do not hold") {
		t.Errorf("the report has no closing verdict:\n%s", out)
	}
}

func TestCorpusModeRefusesADirectoryItCannotJudge(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		want     string
	}{
		{"an unknown suite", `{"suite":"nothing-here-judges-this"}`, "nothing-here-judges-this"},
		{"no suite at all", `{"vectors":[]}`, "declares no \"suite\""},
		{"a manifest that does not parse", `{`, "does not parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "MANIFEST.json"), []byte(tc.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{dir}, &stdout, &stderr); code != 2 {
				t.Fatalf("exit %d, want 2; a corpus that could not be judged must not "+
					"share an exit code with one that came back clean", code)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("the refusal does not carry %q: %s", tc.want, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("a refusal wrote a report to stdout: %s", stdout.String())
			}
		})
	}
}

func TestCorpusModeRefusesADirectoryWithNoManifest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{t.TempDir()}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "no MANIFEST.json") {
		t.Errorf("the refusal does not say what is missing: %s", stderr.String())
	}
}

func copyForCLI(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(source string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, source)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		// #nosec G304,G122 -- a test copying the repository's own committed
		// fixture tree, which carries no symlink.
		body, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
