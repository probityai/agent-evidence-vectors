package corpora

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sha is the hex SHA-256 the corpora publish their digests in.
func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// corpusParent is the directory a corpus sits in, which is where its vendored
// contract or criterion lives. It resolves the argument to an absolute path
// first: filepath.Dir("corpus/") is "corpus" and filepath.Dir(".") is ".", so
// naming the corpus with a trailing slash, or from inside it, looked for the
// contract in the wrong directory and reported it missing.
func corpusParent(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Dir(filepath.Clean(dir))
	}
	return filepath.Dir(abs)
}

// readIn reads a corpus-relative path. Every path in a manifest is relative to
// the corpus directory, so nothing here takes an absolute one.
// #nosec G304,G703 -- the corpus directory is a path the operator named on the
// command line and the relative part comes from that corpus's own manifest. No
// privilege boundary is crossed by reading a file a corpus lists as its own
// member, there is no allow-list a member path could be validated against, and
// the one path shape that WOULD be a finding -- a member escaping its trial
// directory -- is checked where it means something, in the artifact-binding
// reader's artifact-path-unsafe code.
func readIn(dir, rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, rel)) // #nosec G304,G703 -- see the comment above
}

// #nosec G304,G703 -- as readIn above.
func existsIn(dir, rel string) bool {
	info, err := os.Stat(filepath.Join(dir, rel)) // #nosec G304,G703 -- see the comment above
	return err == nil && !info.IsDir()
}

// orderedCorpusDigest is the digest every corpus in this repository publishes:
// SHA-256 over the concatenated bytes of one named file per member, with the
// members ordered by identifier. The identifiers are sorted here rather than
// taken in manifest order, because manifest order is editable and the digest
// must not be.
func orderedCorpusDigest(dir string, ids, files []string) (string, error) {
	if len(ids) != len(files) {
		return "", fmt.Errorf("corpora: %d ids and %d files", len(ids), len(files))
	}
	order := make([]int, len(ids))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return ids[order[a]] < ids[order[b]] })
	h := sha256.New()
	for _, i := range order {
		body, err := readIn(dir, files[i])
		if err != nil {
			// A member file that is not there is a MEMBER finding, made where the
			// member is judged, and not a failure to read the corpus. Returning an
			// error here instead would replace every per-member finding with one
			// I/O message and leave a reader no way to tell which member is gone.
			// The digest simply cannot match, which is the true thing to report.
			continue
		}
		h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// orphanTwins is the check that makes a corpus of refusals scoreable: every
// label a reject member carries must also be carried by a member that has to be
// accepted. Without it a verifier that refuses everything scores full marks.
func orphanTwins(accepted, rejected map[string]bool) []string {
	var orphan []string
	for label := range rejected {
		if !accepted[label] {
			orphan = append(orphan, label)
		}
	}
	sort.Strings(orphan)
	return orphan
}

// sortedKeys of a set, for a finding that has to be stable to be diffable.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// declaredMinusUsed names the labels a manifest declares that no member carries.
// A condition nobody forces is a condition that was named, which is a different
// property from its being tested.
func declaredMinusUsed[V any](declared map[string]V, used map[string]bool) []string {
	var idle []string
	for label := range declared {
		if !used[label] {
			idle = append(idle, label)
		}
	}
	sort.Strings(idle)
	return idle
}

// countsDisagree compares a manifest counts block against the members measured.
// Returns the empty string when they agree.
func countsDisagree(declared map[string]int, measured map[string]int) string {
	if len(declared) != len(measured) {
		return fmt.Sprintf("counts disagree: manifest %s, measured %s",
			renderCounts(declared), renderCounts(measured))
	}
	for kind, n := range measured {
		if declared[kind] != n {
			return fmt.Sprintf("counts disagree: manifest %s, measured %s",
				renderCounts(declared), renderCounts(measured))
		}
	}
	return ""
}

func renderCounts(counts map[string]int) string {
	keys := sortedKeys(counts)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// checkVendored asserts one vendored file still hashes to the digest the corpus
// pinned it at. A corpus whose vendored copy drifted certifies against text
// nobody published.
func checkVendored(dir, rel, pinned, what string) string {
	if !existsIn(dir, rel) {
		return fmt.Sprintf("the vendored %s %s is missing, so nothing records what this corpus certifies against", what, rel)
	}
	body, err := readIn(dir, rel)
	if err != nil {
		return fmt.Sprintf("the vendored %s %s is unreadable: %v", what, rel, err)
	}
	if got := sha(body); got != pinned {
		return fmt.Sprintf(
			"the vendored %s %s does not match its pinned digest (pinned %s, on disk %s). "+
				"Re-vendor from upstream instead of editing the copy.",
			what, rel, short(pinned), short(got))
	}
	return ""
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// sortedStrings returns a sorted copy, so a finding listing values is stable
// between runs and therefore diffable.
func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

// idFromBytes is the name every corpus in this repository gives a member: "v"
// followed by the first 16 hex digits of SHA-256 over the member's own bytes.
// An edit to those bytes without regenerating leaves a name describing bytes
// that are no longer there, and checking it is what lets a corpus-wide digest
// failure NAME the member rather than only report that one exists.
func idFromBytes(payload []byte) string {
	return "v" + sha(payload)[:16]
}

// idPayloadFromFields is the other spelling of the same name: the digest is
// taken over the CPython-compact JSON of a few fields of the member rather than
// over a file. The field set differs per corpus and is passed in.
func idPayloadFromFields(document map[string]any, fields []string) ([]byte, error) {
	subset := map[string]any{}
	for _, field := range fields {
		subset[field] = document[field]
	}
	return pythonCompactJSON(subset)
}
