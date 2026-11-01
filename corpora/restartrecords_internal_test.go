package corpora

// The Go restart-records reader is held to the Python checker's answers.
// testdata/restart-records.json.gz holds every accepting record of the corpus with
// tens of thousands of edits of it, byte-level variants, and edits of the accepting
// bundles, each with the verdict and reason the Python checker gives (written by
// vectors-restart-records/tests/test_go_parity.py, which also checks it). This test
// replays every one and requires the same answer, then switches each rule off in
// turn and requires some case or member to notice.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const rrCorpus = "../vectors-restart-records"

type rrRecordCase struct {
	Base  int      `json:"base"`
	Path  []any    `json:"path"`
	Op    string   `json:"op"`
	Value any      `json:"value"`
	Want  []string `json:"want"`
}

type rrBundleCase struct {
	Bundle  int                `json:"bundle"`
	Files   map[string]*string `json:"files"`
	Digests map[string]string  `json:"digests"`
	Want    []string           `json:"want"`
}

type rrFixture struct {
	Records struct {
		Bases []any          `json:"bases"`
		Cases []rrRecordCase `json:"cases"`
	} `json:"records"`
	Raw []struct {
		Bytes string   `json:"bytes"`
		Want  []string `json:"want"`
	} `json:"raw"`
	Bundles struct {
		Bases []map[string]*string `json:"bases"`
		Cases []rrBundleCase       `json:"cases"`
	} `json:"bundles"`
}

func loadRRFixture(t *testing.T) *rrFixture {
	t.Helper()
	packed, err := os.ReadFile("testdata/restart-records.json.gz")
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
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var fx rrFixture
	if err := decoder.Decode(&fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Records.Cases) == 0 || len(fx.Raw) == 0 || len(fx.Bundles.Cases) == 0 {
		t.Fatal("the fixture holds no cases, so agreement here would mean nothing")
	}
	return &fx
}

func rrDecode64(t *testing.T, text string) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// rrCase is one replayable input with the Python answer.
type rrCase struct {
	label string
	want  [2]string
	judge func() [2]string
}

func rrWant(t *testing.T, want []string) [2]string {
	t.Helper()
	if len(want) != 2 {
		t.Fatalf("an answer of %d fields", len(want))
	}
	return [2]string{want[0], want[1]}
}

func rrBundleAnswer(files map[string][]byte) [2]string {
	verdict, reason, err := rrCheckBundle(files)
	if errors.Is(err, errRRUnreadable) {
		return [2]string{"unreadable", ""}
	}
	return [2]string{verdict, reason}
}

func rrCases(t *testing.T, fx *rrFixture) []rrCase {
	t.Helper()
	var out []rrCase
	for i, item := range fx.Records.Cases {
		edited, err := doneEdited(fx.Records.Bases[item.Base], doneRecordCase{
			Path: item.Path, Op: item.Op, Value: item.Value})
		if err != nil {
			t.Fatalf("record case %d: %v", i, err)
		}
		data, err := doneEncoded(edited)
		if err != nil {
			t.Fatalf("record case %d: %v", i, err)
		}
		out = append(out, rrCase{
			label: fmt.Sprintf("record case %d (base %d, %v %s %v)", i, item.Base, item.Path, item.Op, item.Value),
			want:  rrWant(t, item.Want),
			judge: func() [2]string { v, r := rrCheckRecord(data); return [2]string{v, r} },
		})
	}
	for i, item := range fx.Raw {
		data := rrDecode64(t, item.Bytes)
		out = append(out, rrCase{label: fmt.Sprintf("raw case %d", i), want: rrWant(t, item.Want),
			judge: func() [2]string { v, r := rrCheckRecord(data); return [2]string{v, r} }})
	}
	for i, item := range fx.Bundles.Cases {
		files := map[string][]byte{}
		for name, body := range fx.Bundles.Bases[item.Bundle] {
			files[name] = rrDecode64(t, *body)
		}
		for name, body := range item.Files {
			if body == nil {
				delete(files, name)
			} else {
				files[name] = rrDecode64(t, *body)
			}
		}
		assigned := map[string]string{}
		for name, digest := range item.Digests {
			if body, ok := files[name]; ok {
				assigned[string(body)] = digest
			}
		}
		out = append(out, rrCase{label: fmt.Sprintf("bundle case %d", i), want: rrWant(t, item.Want),
			judge: func() [2]string {
				if len(assigned) > 0 {
					realDigest := rrDigest
					rrDigest = func(b []byte) string {
						if d, ok := assigned[string(b)]; ok {
							return d
						}
						return realDigest(b)
					}
					defer func() { rrDigest = realDigest }()
				}
				return rrBundleAnswer(files)
			}})
	}
	return append(out, rrMemberCases(t)...)
}

// rrMemberCases are the corpus members themselves, with their manifest answers.
func rrMemberCases(t *testing.T) []rrCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(rrCorpus, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest rrManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	var out []rrCase
	for _, v := range manifest.Vectors {
		caseDir := filepath.Join(rrCorpus, v.Path)
		want := [2]string{v.Expected.Verdict, v.Expected.Reason}
		if v.Shape == "bundle" {
			files, err := rrBundleDir(caseDir)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, rrCase{label: v.ID, want: want, judge: func() [2]string { return rrBundleAnswer(files) }})
			continue
		}
		data, err := os.ReadFile(filepath.Join(caseDir, "statement.json")) // #nosec G304 -- the committed corpus
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rrCase{label: v.ID, want: want,
			judge: func() [2]string { a, b := rrCheckRecord(data); return [2]string{a, b} }})
	}
	return out
}

// rrRun is a case's answer, and a panic is an answer too: a rule switched off can
// let a later rule meet a value it was never meant to see.
func rrRun(c rrCase) (got [2]string, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return c.judge(), false
}

// rrSkipExempt lists rules no input can show missing, each with its reason.
var rrSkipExempt = map[string]string{
	rrR4 + "/closed-vocabulary-violation": "no member of this predicate takes a registry-defined value; the rule always holds (unforcedRules)",
	rrRB + "/closed-vocabulary-violation": "no member of this predicate takes a registry-defined value; the rule always holds (unforcedRules)",
}

func rrAllRuleKeys() []string {
	keys := []string{"statement/statement-malformed", "bundle/B1"}
	for _, name := range rrNames {
		for _, rule := range rrRules[name] {
			keys = append(keys, name+"/"+rule.code)
		}
	}
	for _, rule := range rrBundleRules {
		keys = append(keys, "bundle/"+rule.code)
	}
	return keys
}

func TestRestartRecordsAgreesWithPython(t *testing.T) {
	cases := rrCases(t, loadRRFixture(t))
	answers := map[[2]string]int{}
	for _, c := range cases {
		got, panicked := rrRun(c)
		if panicked {
			t.Fatalf("%s: the reader panics", c.label)
		}
		answers[got]++
		if got != c.want {
			t.Errorf("%s: Go says %v, Python says %v", c.label, got, c.want)
		}
	}
	t.Logf("%d cases agree over %d distinct answers", len(cases), len(answers))
	t.Run("a skipped rule is noticed", func(t *testing.T) {
		for _, key := range rrAllRuleKeys() {
			if reason, exempt := rrSkipExempt[key]; exempt {
				t.Logf("%s: exempt, %s", key, reason)
				continue
			}
			rrSkipped[key] = true
			noticed := false
			// The cases Python refuses under this rule are tried first: they are the
			// ones that must change, so the search ends after a handful of them.
			code := key[strings.Index(key, "/")+1:]
			ordered := make([]rrCase, 0, len(cases))
			var rest []rrCase
			for _, c := range cases {
				if c.want[1] == code || (code == "B1" && c.want[0] == "reject") {
					ordered = append(ordered, c)
				} else {
					rest = append(rest, c)
				}
			}
			for _, c := range append(ordered, rest...) {
				if got, panicked := rrRun(c); panicked || got != c.want {
					noticed = true
					break
				}
			}
			delete(rrSkipped, key)
			if !noticed {
				t.Errorf("switching %s off changes no answer on any of %d cases", key, len(cases))
			}
		}
	})
}

func TestRestartRecordsCorpusIsClean(t *testing.T) {
	result, err := Judge(rrCorpus)
	if err != nil {
		t.Fatal(err)
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
	counts := result.CountsByVerdict()
	if len(result.Members) != 57 || counts["accept"] != 15 || counts["reject"] != 42 {
		t.Errorf("judged %d members, %v", len(result.Members), counts)
	}
}

// rrStage copies the corpus and the documents it pins into a temporary tree.
func rrStage(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"vectors-restart-records", "profiles", "spec/predicates"} {
		rrCopyTree(t, filepath.Join("..", dir), filepath.Join(root, dir))
	}
	return filepath.Join(root, "vectors-restart-records")
}

func rrCopyTree(t *testing.T, from, to string) {
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
		body, err := os.ReadFile(source) // #nosec G304,G122 -- the repository's own committed tree
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func rrFindings(result *Result, id string) []string {
	if id == "" {
		return result.Findings
	}
	for _, m := range result.Members {
		if m.ID == id {
			return m.Findings
		}
	}
	return nil
}

func TestRestartRecordsJudgeNamesWhatChanged(t *testing.T) {
	staged := rrStage(t)
	if result, err := Judge(staged); err != nil || !result.OK() {
		t.Fatalf("the staged copy is not clean: %v %v", err, result)
	}
	edits := []struct {
		name, id, want string
		edit           func(dir string)
	}{
		{"a flipped byte in a record", "revocation-sweep-control", "does not match its manifest digest", func(dir string) {
			rrFlip(t, filepath.Join(dir, "cases/revocation-sweep-control/statement.json"))
		}},
		{"a flipped byte in a bundle", "bundle-consistent", "does not match its manifest digest", func(dir string) {
			rrFlip(t, filepath.Join(dir, "cases/bundle-consistent/r2.json"))
		}},
		{"an unlisted file", "joint-authority-control", "not in its manifest row", func(dir string) {
			rrWrite(t, filepath.Join(dir, "cases/joint-authority-control/extra.txt"), []byte("x"))
		}},
		{"a changed expected reason", "joint-authority-control", "derived accept/assignment-recorded", func(dir string) {
			rrEditManifest(t, dir, `"reason": "assignment-recorded"`, `"reason": "assignment-changed"`)
		}},
		{"a changed count", "", "accept", func(dir string) {
			rrEditManifest(t, dir, `"accept": 15`, `"accept": 14`)
		}},
		{"a changed corpus digest", "", "corpusDigest is", func(dir string) {
			rrEditManifest(t, dir, `"corpusDigest": "5`, `"corpusDigest": "6`)
		}},
		{"a changed document", "", "does not match its pinned digest", func(dir string) {
			path := filepath.Join(dir, "..", rrProfile)
			body, err := os.ReadFile(path) // #nosec G304 -- the staged copy
			if err != nil {
				t.Fatal(err)
			}
			rrWrite(t, path, append(body, '\n'))
		}},
	}
	for _, e := range edits {
		t.Run(e.name, func(t *testing.T) {
			dir := rrStage(t)
			e.edit(dir)
			result, err := Judge(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(rrFindings(result, e.id), "\n"), e.want) {
				t.Errorf("no finding on %q mentions %q: member %v, corpus %v", e.id, e.want,
					rrFindings(result, e.id), result.Findings)
			}
		})
	}
}

func rrFlip(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- the staged copy
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0x01
	rrWrite(t, path, body)
}

func rrWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func rrEditManifest(t *testing.T, dir, from, to string) {
	t.Helper()
	path := filepath.Join(dir, ManifestName)
	body, err := os.ReadFile(path) // #nosec G304 -- the staged copy
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(from)) {
		t.Fatalf("MANIFEST.json has no %q", from)
	}
	rrWrite(t, path, bytes.Replace(body, []byte(from), []byte(to), 1))
}

// The rule tables here are the tables in the documents, read from the documents.
func TestRestartRecordsRulesAreTheDocumentsRules(t *testing.T) {
	row := regexp.MustCompile("(?m)^\\| (B?\\d+) \\| .* \\| `?([a-z' -]+?)`? \\|$")
	read := func(rel string) [][]string {
		body, err := os.ReadFile(filepath.Join("..", rel)) // #nosec G304 -- the repository's own document
		if err != nil {
			t.Fatal(err)
		}
		return row.FindAllStringSubmatch(string(body), -1)
	}
	for _, name := range rrNames {
		rows := read("spec/predicates/" + name + ".md")
		want := []string{"statement-malformed"}
		for _, rule := range rrRules[name] {
			want = append(want, rule.code)
		}
		if len(rows) != len(want) {
			t.Fatalf("%s: the document has %d rules, the reader %d", name, len(rows), len(want))
		}
		for i, r := range rows {
			if r[1] != fmt.Sprint(i+1) || r[2] != want[i] {
				t.Errorf("%s rule %s is %q in the document, %q here", name, r[1], r[2], want[i])
			}
		}
	}
	rows := read(rrProfile)
	if len(rows) != len(rrBundleRules)+1 || rows[0][1] != "B1" {
		t.Fatalf("the profile has %d bundle rules, the reader %d", len(rows), len(rrBundleRules)+1)
	}
	for i, rule := range rrBundleRules {
		if rows[i+1][1] != fmt.Sprintf("B%d", i+2) || rows[i+1][2] != rule.code {
			t.Errorf("bundle rule %s is %q in the profile, %q here", rows[i+1][1], rows[i+1][2], rule.code)
		}
	}
}

func TestRestartRecordsFindCycle(t *testing.T) {
	if !rrFindCycle(map[string][]string{"a": {"b"}, "b": {"a"}}) || !rrFindCycle(map[string][]string{"a": {"a"}}) {
		t.Error("a cycle is not found")
	}
	if rrFindCycle(map[string][]string{"r3": {"r1", "r2"}, "r2": {"r1"}, "r1": {}}) {
		t.Error("an acyclic graph is reported as a cycle")
	}
}

func TestRestartRecordsBundleDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := rrBundleDir(dir); !errors.Is(err, errRRUnreadable) {
		t.Errorf("an empty directory: %v", err)
	}
	for _, name := range []string{"r1.json", "r2.json", "r3.json"} {
		body, err := os.ReadFile(filepath.Join(rrCorpus, "cases/bundle-consistent", name)) // #nosec G304 -- the committed corpus
		if err != nil {
			t.Fatal(err)
		}
		rrWrite(t, filepath.Join(dir, name), body)
	}
	rrWrite(t, filepath.Join(dir, ".hidden.json"), []byte("not json"))
	rrWrite(t, filepath.Join(dir, "notes.txt"), []byte("not json"))
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	files, err := rrBundleDir(dir)
	if err != nil || len(files) != 3 {
		t.Fatalf("read %d files: %v", len(files), err)
	}
	if verdict, reason, err := rrCheckBundle(files); err != nil || verdict != "accept" || reason != rrBundleOK {
		t.Errorf("got %s %s %v", verdict, reason, err)
	}
}
