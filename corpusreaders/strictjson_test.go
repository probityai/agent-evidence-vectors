package corpusreaders_test

// No reader accepts a record that repeats a member.
//
// encoding/json keeps the last of two members with one name. A record written
// {"k": null, <the original members>} therefore decodes to exactly the original
// record, and a reader that keeps the last judges it as it judged the original.
// A reader in another language may keep the first, and the Python readers refuse
// the record outright, so a reader that accepts it disagrees with its own Python
// rail about the same bytes. The test takes the accepted members of every corpus,
// repeats the first member of each JSON object file of one member ahead of the
// original, re-pins the file's digest wherever the corpus pins it, and requires
// the reader to stop agreeing that the member is accepted.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

var acceptingKinds = map[string]bool{
	"accept": true, "accepted": true, "allow": true, "verified": true, "supported": true,
	"valid": true, "pass": true, "conformant": true, "anchored": true, "exempt": true,
	"admit": true, "admitted": true, "holds": true, "established": true, "ok": true,
}

var leadingMember = regexp.MustCompile(`^\s*\{\s*("(?:[^"\\]|\\.)*")\s*:`)

// repeated is body with its first member repeated, as null, ahead of the original.
func repeated(body []byte) ([]byte, bool) {
	m := leadingMember.FindSubmatchIndex(body)
	if m == nil {
		return nil, false
	}
	brace := strings.IndexByte(string(body), '{') + 1
	out := append([]byte{}, body[:brace]...)
	out = append(out, body[m[2]:m[3]]...)
	out = append(out, []byte(": null, ")...)
	return append(out, body[brace:]...), true
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// memberFiles are the JSON object files that belong to one member: those under a
// directory named for it, or named for it.
func memberFiles(t *testing.T, corpus, id string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(corpus, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		rel, _ := filepath.Rel(corpus, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for i, part := range parts {
			if part == id || (i == len(parts)-1 && strings.TrimSuffix(part, ".json") == id) {
				out = append(out, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// repin replaces every mention of an old digest in the corpus's text files.
func repin(t *testing.T, corpus string, old, new string) {
	t.Helper()
	err := filepath.Walk(corpus, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 8<<20 {
			return err
		}
		body, err := os.ReadFile(path) // #nosec G304,G122 -- a staged copy of a committed corpus
		if err != nil || !strings.Contains(string(body), old) {
			return err
		}
		return os.WriteFile(path, []byte(strings.ReplaceAll(string(body), old, new)), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func corporaWithManifests(t *testing.T) []string {
	t.Helper()
	dirs := []string{"vectors"}
	matches, err := filepath.Glob(filepath.Join("..", "corpora", "*", "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		dirs = append(dirs, filepath.Base(filepath.Dir(m)))
	}
	return dirs
}

func TestNoReaderAcceptsARepeatedMember(t *testing.T) {
	for _, dir := range corporaWithManifests(t) {
		t.Run(dir, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(corpusPath(dir), "MANIFEST.json")) // #nosec G304 -- committed corpus
			if err != nil {
				t.Fatal(err)
			}
			var head struct {
				Suite string `json:"suite"`
			}
			if json.Unmarshal(raw, &head) != nil || head.Suite == "" {
				t.Skip("no suite field, so no reader is selected for this directory")
			}
			if !contains(corpusreaders.Suites(), head.Suite) {
				t.Skip("no Go reader for suite " + head.Suite)
			}
			root := t.TempDir()
			staged := filepath.Join(root, "corpora", dir)
			copyTree(t, corpusPath(dir), staged)
			stageSiblingSpec(t, root)
			pristine, err := corpusreaders.Judge(staged)
			if err != nil {
				t.Skipf("the staged copy cannot be judged (%v); the committed-corpus test owns that", err)
			}
			tried := 0
			for _, member := range pristine.Members {
				if !member.OK() || !acceptingKinds[member.Kind] || tried == 3 {
					continue
				}
				files := memberFiles(t, staged, member.ID)
				if len(files) == 0 {
					continue
				}
				tried++
				for _, file := range files {
					body, err := os.ReadFile(file) // #nosec G304 -- staged copy
					if err != nil {
						t.Fatal(err)
					}
					hostile, ok := repeated(body)
					if !ok {
						continue
					}
					if err := os.WriteFile(file, hostile, 0o600); err != nil {
						t.Fatal(err)
					}
					repin(t, staged, hexSum(body), hexSum(hostile))
					judged, err := corpusreaders.Judge(staged)
					if err == nil {
						for _, m := range judged.Members {
							if m.ID == member.ID && m.OK() {
								rel, _ := filepath.Rel(staged, file)
								t.Errorf("%s accepted member %s with a repeated member in %s",
									head.Suite, member.ID, rel)
							}
						}
					}
					if err := os.WriteFile(file, body, 0o600); err != nil {
						t.Fatal(err)
					}
					repin(t, staged, hexSum(hostile), hexSum(body))
				}
			}
			if tried == 0 {
				t.Logf("%s: no accepted member with its own JSON object file", head.Suite)
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
