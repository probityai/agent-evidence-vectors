package corpora

// The Go done checks are held to the Python reader's verdicts on runs the corpora do not
// hold. testdata/done-members.json.gz names corpus members and, for each, one change to one
// record and the verdicts the Python reader derives once the consumer's pins move to the
// changed bytes (written by vectors-done-receipt/tests/test_done_member_cases.py, which
// also checks it). This test makes the same change, moves the pins the same way and
// requires the same verdicts.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type doneMemberCase struct {
	Member string `json:"member"`
	Role   string `json:"role"`
	Path   []any  `json:"path"`
	Op     string `json:"op"`
	Value  any    `json:"value"`
	Want   int    `json:"want"`
}

var doneMemberSuites = map[string]string{
	"vectors-done-receipt": doneReceiptSuite, "vectors-spoofed-tool-output": doneSpoofedSuite,
	"vectors-test-tampering": doneTamperSuite, "vectors-grader-isolation": doneGraderSuite,
}

func doneDecodeNumbers(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(out)
}

// donePinned rewrites every case and policy so they bind the role's new bytes.
func donePinned(t *testing.T, files map[string][]byte, role string) {
	t.Helper()
	data := files[role+".json"]
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	for name, raw := range files {
		var document map[string]any
		switch {
		case strings.HasSuffix(name, ".case.json"):
			if err := doneDecodeNumbers(raw, &document); err != nil {
				t.Fatal(err)
			}
			if artifact, ok := doneObj(document["artifacts"])[role].(map[string]any); ok {
				artifact["length"] = len(data)
				artifact["sha256"] = digest
			}
		case strings.HasSuffix(name, ".policy.json"):
			if err := doneDecodeNumbers(raw, &document); err != nil {
				t.Fatal(err)
			}
			if witness, ok := doneObj(document["witnesses"])[role].(map[string]any); ok {
				witness["sha256"] = digest
			}
		default:
			continue
		}
		encoded, err := doneEncoded(document)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = encoded
	}
}

func TestDoneMembersAgreeWithPython(t *testing.T) {
	packed, err := os.ReadFile("testdata/done-members.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []doneMemberCase `json:"cases"`
		Wants []map[string]any `json:"wants"`
	}
	if err := doneDecodeNumbers(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 1000 || len(fixture.Wants) == 0 {
		t.Fatalf("done-members.json.gz holds %d cases and %d answers", len(fixture.Cases), len(fixture.Wants))
	}
	base := t.TempDir()
	for index, item := range fixture.Cases {
		corpus := strings.SplitN(item.Member, "/", 2)[0]
		suite, known := doneMemberSuites[corpus]
		if !known {
			t.Fatalf("case %d names %s", index, item.Member)
		}
		source := filepath.Join("..", item.Member)
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(source, entry.Name())) // #nosec G304 -- a test reading its own corpus
			if err != nil {
				t.Fatal(err)
			}
			files[entry.Name()] = data
		}
		var record any
		if err := doneDecodeNumbers(files[item.Role+".json"], &record); err != nil {
			t.Fatal(err)
		}
		edited, err := doneEdited(record, doneRecordCase{Path: item.Path, Op: item.Op, Value: item.Value})
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		if files[item.Role+".json"], err = doneEncoded(edited); err != nil {
			t.Fatal(err)
		}
		donePinned(t, files, item.Role)
		directory := filepath.Join(base, "m")
		if err := os.RemoveAll(directory); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		declared := doneDeclared(t, item.Member)
		if item.Want < 0 || item.Want >= len(fixture.Wants) {
			t.Fatalf("case %d names answer %d", index, item.Want)
		}
		want := fixture.Wants[item.Want]
		got := doneJudgeMember(suite, directory, declared)
		if !doneEqual(normalize(got), normalize(want)) {
			gotText, _ := json.Marshal(got)
			wantText, _ := json.Marshal(want)
			t.Errorf("case %d: %s %s.json %v %s %v:\n Go     %s\n Python %s", index, item.Member,
				item.Role, item.Path, item.Op, item.Value, gotText, wantText)
		}
	}
}

var doneDeclaredCache = map[string][]string{}

// doneDeclared is the checks the member's manifest row declares.
func doneDeclared(t *testing.T, member string) []string {
	t.Helper()
	if found, ok := doneDeclaredCache[member]; ok {
		return found
	}
	parts := strings.SplitN(member, "/", 2)
	raw, err := os.ReadFile(filepath.Join("..", parts[0], ManifestName)) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Vectors []doneVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, vector := range manifest.Vectors {
		doneDeclaredCache[parts[0]+"/"+vector.Path] = vector.Checks
	}
	found, ok := doneDeclaredCache[member]
	if !ok {
		t.Fatalf("%s is in no manifest row", member)
	}
	return found
}
