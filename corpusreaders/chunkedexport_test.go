package corpora_test

// The chunked-export reader derives every decision from the record and the
// chunk payloads. Swapping one member's record for another's must move the
// derived decision, and the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const ceDir = "vectors-chunked-export"

func ceStage(t *testing.T, member, name string, body []byte) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), ceDir)
	copyTree(t, corpusPath(ceDir), copied)
	if err := os.WriteFile(filepath.Join(copied, "cases", member, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func ceRead(t *testing.T, member, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(corpusPath(ceDir), "cases", member, name)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestChunkedExportCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(ceDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestChunkedExportEachCheckMovesTheVerdict(t *testing.T) {
	// Each of these records exports chunks 0 and 1 only, so the payload files
	// of variant-a-below-threshold still cover them.
	for _, from := range []string{"contract-id-missing", "contract-id-unknown",
		"threshold-committed-after-first-chunk"} {
		t.Run("below-threshold with the record of "+from, func(t *testing.T) {
			dir := ceStage(t, "variant-a-below-threshold", "record.json", ceRead(t, from, "record.json"))
			if got := scDerived(t, dir, "variant-a-below-threshold"); !strings.Contains(got, "derived deny/") {
				t.Fatalf("want a derived deny, got %q", got)
			}
		})
	}
	t.Run("crossing sealed reversible", func(t *testing.T) {
		dir := ceStage(t, "variant-a-at-crossing", "record.json", ceRead(t, "variant-a-max-of-labels-seal", "record.json"))
		got := scDerived(t, dir, "variant-a-at-crossing")
		if !strings.Contains(got, "derived deny/seal_understates_composition") {
			t.Fatalf("want seal_understates_composition, got %q", got)
		}
	})
	t.Run("a denied record with the permitted record", func(t *testing.T) {
		dir := ceStage(t, "variant-a-at-crossing", "record.json", ceRead(t, "variant-a-below-threshold", "record.json"))
		got := scDerived(t, dir, "variant-a-at-crossing")
		for _, want := range []string{"derived allow/reversible_so_far", "composed class reversible"} {
			if !strings.Contains(got, want) {
				t.Fatalf("want %q in %q", want, got)
			}
		}
	})
}

func TestChunkedExportUnreadableInputsAreFindings(t *testing.T) {
	contract := `"contractId":"https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1",`
	cases := []struct{ body, want string }{
		{"{", "record.json does not parse"},
		{`{"chunks":[{"index":0,"payloadFile":"absent.bin"}],"exported":[0]}`, "absent.bin cannot be read"},
		{`{"chunks":[],"exported":[7]}`, "exported chunk 7 is not in chunks"},
		{`{"chunks":[],"exported":[]}`, "the record exports no chunk"},
		{`{` + contract + `"chunks":[],"exported":[],"reconstruction":{"kind":"count","k":1}}`, "exports no chunk"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			dir := ceStage(t, "variant-a-below-threshold", "record.json", []byte(tc.body))
			if got := scDerived(t, dir, "variant-a-below-threshold"); !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in %q", tc.want, got)
			}
		})
	}
	t.Run("unknown rule kind", func(t *testing.T) {
		body := strings.Replace(string(ceRead(t, "variant-a-below-threshold", "record.json")),
			`"kind": "count"`, `"kind": "entropy"`, 1)
		dir := ceStage(t, "variant-a-below-threshold", "record.json", []byte(body))
		if got := scDerived(t, dir, "variant-a-below-threshold"); !strings.Contains(got, `unknown reconstruction rule kind "entropy"`) {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("unparseable commitment time", func(t *testing.T) {
		body := strings.Replace(string(ceRead(t, "variant-a-below-threshold", "record.json")),
			`"committedAt": "2026-10-10T10:59:00Z"`, `"committedAt": "soon"`, 1)
		dir := ceStage(t, "variant-a-below-threshold", "record.json", []byte(body))
		if got := scDerived(t, dir, "variant-a-below-threshold"); !strings.Contains(got, `"soon" does not parse`) {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("changed payload", func(t *testing.T) {
		dir := ceStage(t, "variant-a-below-threshold", "chunk-0.bin", []byte("other\n"))
		if got := scDerived(t, dir, "variant-a-below-threshold"); !strings.Contains(got, "chunk-0.bin does not match its stated digest") {
			t.Fatalf("got %q", got)
		}
	})
}

func TestChunkedExportDamagedManifestIsAFinding(t *testing.T) {
	copied := filepath.Join(t.TempDir(), ceDir)
	copyTree(t, corpusPath(ceDir), copied)
	path := filepath.Join(copied, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	damaged := strings.Replace(string(raw), `"reversible_so_far"`, `"reversible_so_far "`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(copied)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("want a corpusDigest finding")
	}
	if err := os.WriteFile(path, []byte(`{"suite":"chunked-export/v1","vectors":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := corpora.Judge(copied); err == nil {
		t.Fatal("a manifest whose rows are not a list must be an error")
	}
}
