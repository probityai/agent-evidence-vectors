// Package corpora judges every conformance corpus in this repository with one
// binary.
//
// A corpus used to ship with its own Python runner beside it, so the command a
// third party was told to run was a different command per corpus. A reader who
// has to install one harness per corpus is a reader who runs none of them, and
// a runner that lives next to the vectors it judges is a corpus grading its own
// homework in a language nobody else in the tree speaks.
//
// This package inverts that. Every corpus directory carries a MANIFEST.json
// with a "suite" field; the field selects a reader here; the reader judges the
// members and returns one Result. A directory whose suite names no reader is
// REFUSED BY NAME. It is never skipped, because a skipped corpus and a passing
// corpus print the same zero.
package corpora

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ManifestName is the file every corpus directory publishes its suite in.
const ManifestName = "MANIFEST.json"

// Member is one corpus member as judged. Kind is the corpus's own verdict
// vocabulary for that member (accept, reject, indeterminate, verified, failed,
// not-established): the counts printed by verdict are counts over this field.
// Findings is empty when the member behaves as the corpus declares.
type Member struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Findings []string `json:"findings,omitempty"`
}

// OK reports whether this member behaved as its manifest entry declares.
func (m Member) OK() bool { return len(m.Findings) == 0 }

// Result is one corpus, judged. Findings at this level are the ones that belong
// to no single member: a count that disagrees with the tree, a reject condition
// with no accepting twin, a vendored specification that no longer matches its
// pinned digest.
type Result struct {
	Suite    string   `json:"suite"`
	Dir      string   `json:"dir"`
	Members  []Member `json:"members"`
	Findings []string `json:"findings,omitempty"`
}

// OK reports whether every member behaved and no corpus-level finding stands.
func (r *Result) OK() bool {
	if len(r.Findings) > 0 {
		return false
	}
	for _, m := range r.Members {
		if !m.OK() {
			return false
		}
	}
	return true
}

// CountsByVerdict is the member count per Kind, which is what an intact corpus
// prints instead of a bare "ok".
func (r *Result) CountsByVerdict() map[string]int {
	counts := map[string]int{}
	for _, m := range r.Members {
		counts[m.Kind]++
	}
	return counts
}

// Reader judges one suite. Judge is handed the corpus directory and the raw
// manifest bytes, so a reader needing a field this package does not model reads
// it itself rather than growing a union type here.
type Reader interface {
	// Suite is the exact MANIFEST.json "suite" value this reader answers for.
	Suite() string
	// Judge returns the members and the corpus-level findings. It returns an
	// error only where the corpus could not be READ at all: an unreadable
	// manifest, a directory that is not one. A member that misbehaves is a
	// finding and never an error, because a finding names the member.
	Judge(dir string, manifest []byte) (*Result, error)
}

// registry is keyed by suite. A second reader for a suite already registered is
// a programming error and panics at init: two readers for one suite means one
// of them never runs, and which one is decided by map iteration order.
var registry = map[string]Reader{}

func register(r Reader) {
	if _, seen := registry[r.Suite()]; seen {
		panic("corpora: two readers registered for suite " + r.Suite())
	}
	registry[r.Suite()] = r
}

// Suites lists every suite this binary can judge, sorted. It is printed in the
// refusal for an unknown suite, so a reader who names one wrong sees the set.
func Suites() []string {
	out := make([]string, 0, len(registry))
	for suite := range registry {
		out = append(out, suite)
	}
	sort.Strings(out)
	return out
}

// ErrNoManifest is returned for a directory carrying no MANIFEST.json, which is
// how a caller tells a corpus directory from any other directory.
var ErrNoManifest = errors.New("no " + ManifestName + " in this directory")

// UnknownSuiteError refuses a corpus by the name it published. A corpus this
// binary cannot judge fails loudly with the suite in the message: silence here
// is how a corpus stops being checked without anybody noticing.
type UnknownSuiteError struct {
	Suite string
	Dir   string
	Known []string
}

func (e *UnknownSuiteError) Error() string {
	return fmt.Sprintf(
		"%s declares suite %q and no reader in this binary judges it. "+
			"Known suites: %v. A corpus is refused by name rather than skipped, "+
			"because a skipped corpus and a clean one print the same zero.",
		filepath.Join(e.Dir, ManifestName), e.Suite, e.Known)
}

// Judge reads dir's manifest, selects the reader its suite names, and runs it.
func Judge(dir string) (*Result, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName)) // #nosec G304 -- the caller names the corpus by design
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s: %w", dir, ErrNoManifest)
		}
		return nil, err
	}
	var head struct {
		Suite string `json:"suite"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", filepath.Join(dir, ManifestName), err)
	}
	if head.Suite == "" {
		return nil, fmt.Errorf("%s declares no \"suite\", so no reader can be selected for it",
			filepath.Join(dir, ManifestName))
	}
	reader, ok := registry[head.Suite]
	if !ok {
		return nil, &UnknownSuiteError{Suite: head.Suite, Dir: dir, Known: Suites()}
	}
	result, err := reader.Judge(dir, raw)
	if err != nil {
		return nil, err
	}
	result.Suite, result.Dir = head.Suite, dir
	return result, nil
}
