package corpora_test

// One harness, every corpus. Two assertions per reader, and the second is the
// one that matters:
//
//  1. the corpus as committed is judged clean, and
//  2. a corpus with ONE byte flipped in ONE member is judged dirty, and the
//     reader NAMES that member.
//
// The second is what a green first assertion cannot establish. A reader that
// looked at nothing would pass the intact corpus exactly as a correct one does,
// which is the whole reason the Python runners these readers replace carried
// their own mutation checks. Each case below therefore copies the corpus into a
// temporary directory, mutates one named file, and requires the finding to
// carry the mutated member's identifier.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

// corpusCase is one registered reader, the directory it judges, and the member
// whose bytes the red half of the test flips.
type corpusCase struct {
	dir string
	// memberFileKey is the manifest field naming the file each member's bytes
	// live in: "file" for a statement, "stream" for an anchor stream, "record"
	// for a run record, "manifest" for a binding record.
	memberFileKey string
}

var corpusCases = []corpusCase{
	{dir: "vectors", memberFileKey: "file"},
	{dir: "vectors-ai-agent-action", memberFileKey: "file"},
	{dir: "vectors-acs-core", memberFileKey: "file"},
	{dir: "vectors-anchor-stream", memberFileKey: "stream"},
	{dir: "vectors-mcp-record-contract", memberFileKey: "record"},
	{dir: "vectors-mcp-response-phase", memberFileKey: "file"},
	{dir: "vectors-artifact-binding", memberFileKey: "manifest"},
	// One ACI member is a whole deployment serialised into one file, so the
	// key is "file" as for a statement and the bytes flipped are a manifest the
	// deployment publishes.
	{dir: "vectors-aci", memberFileKey: "file"},
	// A member of the W3C report corpus is one whole v0.1 report in one file.
	{dir: "vectors-w3c-report", memberFileKey: "file"},
	// A member of the Observed Effect corpus is one DSSE envelope in one file.
	{dir: "vectors-observed-effect", memberFileKey: "file"},
}

func corpusPath(dir string) string { return filepath.Join("..", dir) }

// stageSiblingSpec copies the repository's spec tree next to a staged corpus.
//
// A corpus directory is not always enough to judge a corpus. One reader reads the
// predicate's Type URI out of the document that DEFINES it rather than trusting
// the copy in the manifest, and resolves that document through dir/.. -- which is
// the right way round, because a manifest asserting its own predicate type is a
// corpus grading its own homework. Staged on its own, that corpus cannot be
// judged at all: Judge returns an unreadable-corpus error, and the red half of
// this test then fails for a reason that has nothing to do with the byte it
// flipped. Staging the document keeps the assertion about the member bytes.
func stageSiblingSpec(t *testing.T, root string) {
	t.Helper()
	source := filepath.Join("..", "spec")
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("the repository has no spec tree to stage (%v), so a reader that reads a "+
			"vendored document cannot run here and this case would report an unreadable "+
			"corpus instead of the finding it exists to assert", err)
	}
	copyTree(t, source, filepath.Join(root, "spec"))
}

// TestEveryCommittedCorpusIsClean is the green half: one binary, every corpus.
func TestEveryCommittedCorpusIsClean(t *testing.T) {
	for _, tc := range corpusCases {
		t.Run(tc.dir, func(t *testing.T) {
			if _, err := os.Stat(corpusPath(tc.dir)); err != nil {
				t.Fatalf("%s is not in this worktree: %v. A corpus that cannot be read is "+
					"never a corpus that passed", tc.dir, err)
			}
			result, err := corpora.Judge(corpusPath(tc.dir))
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			if !result.OK() {
				for _, m := range result.Members {
					for _, f := range m.Findings {
						t.Errorf("%s: %s", m.ID, f)
					}
				}
				for _, f := range result.Findings {
					t.Errorf("corpus: %s", f)
				}
			}
			if len(result.Members) == 0 {
				t.Fatal("the reader returned no members, so a clean verdict here means nothing")
			}
			// The counts are what an intact run prints, so a reader that returned
			// members under no verdict at all would still have to be caught.
			total := 0
			for _, n := range result.CountsByVerdict() {
				total += n
			}
			if total != len(result.Members) {
				t.Errorf("counts by verdict sum to %d over %d members", total, len(result.Members))
			}
		})
	}
}

// TestAFlippedByteNamesItsMember is the red half.
func TestAFlippedByteNamesItsMember(t *testing.T) {
	for _, tc := range corpusCases {
		t.Run(tc.dir, func(t *testing.T) {
			root := t.TempDir()
			copied := filepath.Join(root, tc.dir)
			copyTree(t, corpusPath(tc.dir), copied)
			stageSiblingSpec(t, root)
			id, rel := firstMember(t, copied, tc.memberFileKey)
			flipOneByte(t, filepath.Join(copied, rel))

			result, err := corpora.Judge(copied)
			if err != nil {
				t.Fatalf("judge: %v", err)
			}
			if result.OK() {
				t.Fatalf("%s was mutated in %s and the reader still calls the corpus clean, "+
					"so the reader is not reading the bytes", id, rel)
			}
			named := false
			for _, m := range result.Members {
				if m.ID == id && !m.OK() {
					named = true
				}
			}
			if !named {
				t.Errorf("the corpus is dirty and no finding is attached to %s, the member "+
					"whose bytes changed; corpus-level findings alone do not tell an "+
					"implementer where to look", id)
			}
		})
	}
}

// TestUnknownSuiteIsRefusedByName: a directory whose suite names no reader is
// refused with the suite in the message, never skipped and never clean.
func TestUnknownSuiteIsRefusedByName(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"suite":"a-suite-nobody-here-judges","vectors":[]}`
	if err := os.WriteFile(filepath.Join(dir, corpora.ManifestName), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(dir)
	if result != nil {
		t.Fatal("an unjudgeable corpus returned a result, which a caller would read as a pass")
	}
	var unknown *corpora.UnknownSuiteError
	if !errors.As(err, &unknown) {
		t.Fatalf("want an UnknownSuiteError, got %v", err)
	}
	if !strings.Contains(err.Error(), "a-suite-nobody-here-judges") {
		t.Errorf("the refusal does not name the suite: %v", err)
	}
	if len(unknown.Known) == 0 {
		t.Error("the refusal lists no known suite, so a reader who mistyped one sees no set")
	}
}

// TestRegisteredButUnimplementedSuiteRefuses: the SCITT/COSE corpus is a real
// corpus this binary cannot yet judge. It must refuse by name rather than pass.
func TestRegisteredButUnimplementedSuiteRefuses(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"suite":"scitt-cose-carriage-conformance","vectors":[]}`
	if err := os.WriteFile(filepath.Join(dir, corpora.ManifestName), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := corpora.Judge(dir)
	if result != nil || err == nil {
		t.Fatal("a suite with no reader behind it returned a result")
	}
	for _, want := range []string{"scitt-cose-carriage-conformance", "CBOR", "not a pass"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestEverySuiteInTheTreeHasAReader: no corpus directory in this repository may
// sit unregistered. Without this, adding a corpus and forgetting the reader
// would be invisible: nothing runs it, so nothing reports it.
func TestEverySuiteInTheTreeHasAReader(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, suite := range corpora.Suites() {
		known[suite] = true
	}
	found := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "vectors") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", entry.Name(), corpora.ManifestName))
		if err != nil {
			continue
		}
		var head struct {
			Suite string `json:"suite"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Suite == "" {
			t.Errorf("%s/MANIFEST.json declares no suite, so no reader can be selected for it",
				entry.Name())
			continue
		}
		found++
		if !known[head.Suite] {
			t.Errorf("%s declares suite %q and no reader is registered for it; "+
				"one binary judges every corpus in this repository", entry.Name(), head.Suite)
		}
	}
	if found == 0 {
		t.Fatal("no corpus directory was found, so this test asserted nothing")
	}
}

func copyTree(t *testing.T, from, to string) {
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
		body, err := os.ReadFile(source) // #nosec G304,G122 -- a test copying the repository's own committed fixture tree, which contains no symlink
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// firstMember returns the identifier and member-file path of the first manifest
// row, which is the row the red test mutates.
func firstMember(t *testing.T, dir, fileKey string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, corpora.ManifestName)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []map[string]json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Vectors) == 0 {
		t.Fatal("the manifest carries no vectors, so there is nothing to mutate")
	}
	var id, rel string
	if err := json.Unmarshal(manifest.Vectors[0]["id"], &id); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifest.Vectors[0][fileKey], &rel); err != nil {
		t.Fatalf("the first row carries no %q: %v", fileKey, err)
	}
	return id, rel
}

// flipOneByte changes exactly one byte, in the middle of the file, so the file
// stays the same length and the mutation is nothing but a changed byte.
func flipOneByte(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- a test mutating its own copy
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 2 {
		t.Fatalf("%s is %d bytes, which is too small to mutate meaningfully", path, len(body))
	}
	body[len(body)/2] ^= 0x01
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
