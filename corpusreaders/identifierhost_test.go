package corpusreaders_test

// Both spellings of our host name one identifier (internal/identifiers). Every
// reader below compares an identifier a record carries, or one its manifest
// names, with one of ours, so each is held to two facts:
//
//  1. the corpus with every https://probityai.github.io/ rewritten to
//     https://probityai.org/ is judged exactly as the committed corpus is, member
//     by member, verdict and reason, and
//  2. the corpus rewritten to http://probityai.org/ is judged exactly as the
//     corpus rewritten to http://probityai.github.io/, a spelling no release has
//     ever read as ours: the scheme is part of the match, and a near spelling
//     keeps today's unknown-identifier verdict.
//
// The second assertion also requires the near spelling to change at least one
// member's judgement, so a reader that never looked at the identifier, or a
// rewrite that never reached it, cannot pass by judging the same bytes twice.
//
// A rewritten file no longer has the digest its manifest pins, so every digest
// of a rewritten file is replaced by the digest of the new bytes wherever it is
// written in the tree, until nothing changes. A member named by its own bytes
// ("v" and the first 16 hex digits of their SHA-256) is renamed the same way,
// in every file that names it and in its own file name. Bytes inside a base64 envelope are
// not text and are not rewritten: there the rewrite reaches the expected type the
// manifest or the specification names, which is the other side of the same
// comparison.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpusreaders"
)

var identifierHostCorpora = []string{
	"vectors-acs-decision-record",
	"vectors-agent-audit-record",
	"vectors-aggregate-accounting",
	"vectors-approval-binding",
	"vectors-authority-at-dispatch",
	"vectors-badge-vc-verify",
	"vectors-budget-lineage",
	"vectors-capability-requirement",
	"vectors-chunked-export",
	"vectors-completion-confirmation",
	"vectors-containment-journal",
	"vectors-converted-argument-binding",
	"vectors-decision-client-failure-modes",
	"vectors-delegator-right",
	"vectors-dispatch-fence",
	"vectors-evidence-state",
	"vectors-execution-billing-finality",
	"vectors-incident-evidence-cell",
	"vectors-monitor-coverage",
	"vectors-observed-effect",
	"vectors-propagation-step",
	"vectors-refusal-reason-priority",
	"vectors-responsibility-escalation",
	"vectors-restart-records",
	"vectors-self-reported-record",
	"vectors-signature-coverage",
	"vectors-uncertain-effect",
}

const committedSpelling = "https://probityai.github.io/"

// stageRewritten copies the corpus and the specification tree it may resolve
// through into a temporary root, rewrites every committedSpelling to to, and
// re-pins the digests of what it rewrote. It returns the corpus directory and the
// number of files whose bytes the rewrite changed.
func stageRewritten(t *testing.T, dir, to string) (string, int) {
	t.Helper()
	root := t.TempDir()
	copied := filepath.Join(root, "corpora", dir)
	copyTree(t, corpusPath(dir), copied)
	copyTree(t, filepath.Join("..", "spec"), filepath.Join(root, "spec"))
	files := map[string][]byte{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		body, err := os.ReadFile(path) // #nosec G304,G122 -- a test reading its own temporary copy, which copyTree wrote as regular files, so it holds no symlink
		files[path] = body
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := func(body []byte) []byte {
		sum := sha256.Sum256(body)
		return []byte(hex.EncodeToString(sum[:]))
	}
	memberID := func(body []byte) string { return "v" + string(digest(body)[:16]) }
	repin := func(pending map[string][]byte, body, next []byte) {
		pending[string(digest(body))] = digest(next)
		pending[memberID(body)] = []byte(memberID(next))
	}
	original := map[string][]byte{}
	rewritten := map[string]bool{}
	pending := map[string][]byte{}
	for path, body := range files {
		original[path] = body
		next := bytes.ReplaceAll(body, []byte(committedSpelling), []byte(to))
		if !bytes.Equal(next, body) {
			rewritten[path] = true
			repin(pending, body, next)
			files[path] = next
		}
	}
	for round := 0; len(pending) > 0; round++ {
		if round > 32 {
			t.Fatalf("%s: re-pinning digests did not settle", dir)
		}
		moved := map[string][]byte{}
		for path, body := range files {
			next := body
			for old, replacement := range pending {
				next = bytes.ReplaceAll(next, []byte(old), replacement)
			}
			if !bytes.Equal(next, body) {
				rewritten[path] = true
				repin(moved, body, next)
				files[path] = next
			}
		}
		pending = moved
	}
	for path := range rewritten {
		target := path
		stem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if stem == memberID(original[path]) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target = filepath.Join(filepath.Dir(path), memberID(files[path])+filepath.Ext(path))
		}
		if err := os.WriteFile(target, files[path], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return copied, len(rewritten)
}

// judgeMembers returns each member's verdict and findings in manifest order.
// The member id is left out: a member named by its own bytes is renamed by the
// rewrite, so its id is the one thing that is meant to change.
func judgeMembers(t *testing.T, dir string) []corpusreaders.Member {
	t.Helper()
	result, err := corpusreaders.Judge(dir)
	if err != nil {
		t.Fatalf("judge %s: %v", dir, err)
	}
	if len(result.Members) == 0 {
		t.Fatalf("%s judged no members, so nothing was compared", dir)
	}
	out := make([]corpusreaders.Member, len(result.Members))
	for i, m := range result.Members {
		out[i] = corpusreaders.Member{Kind: m.Kind, Findings: m.Findings}
	}
	return out
}

func TestEachReaderJudgesTheNewHostSpellingAsTheCommittedOne(t *testing.T) {
	for _, dir := range identifierHostCorpora {
		t.Run(dir, func(t *testing.T) {
			committed := judgeMembers(t, corpusPath(dir))
			staged, changed := stageRewritten(t, dir, "https://probityai.org/")
			if changed == 0 {
				t.Fatalf("no file in %s names %s, so the rewrite tested nothing", dir, committedSpelling)
			}
			if got := judgeMembers(t, staged); !reflect.DeepEqual(got, committed) {
				for i := range committed {
					if i < len(got) && !reflect.DeepEqual(got[i], committed[i]) {
						t.Errorf("member %d judged %+v, the committed corpus %+v", i, got[i], committed[i])
					}
				}
				if len(got) != len(committed) {
					t.Errorf("%d members judged, the committed corpus has %d", len(got), len(committed))
				}
			}
		})
	}
}

func TestEachReaderKeepsANearHostSpellingUnknown(t *testing.T) {
	for _, dir := range identifierHostCorpora {
		t.Run(dir, func(t *testing.T) {
			committed := judgeMembers(t, corpusPath(dir))
			nearNew, _ := stageRewritten(t, dir, "http://probityai.org/")
			nearOld, _ := stageRewritten(t, dir, "http://probityai.github.io/")
			gotNew, gotOld := judgeMembers(t, nearNew), judgeMembers(t, nearOld)
			if !reflect.DeepEqual(gotNew, gotOld) {
				t.Errorf("http://probityai.org/ is judged differently from http://probityai.github.io/:\n%+v\n%+v",
					gotNew, gotOld)
			}
			if reflect.DeepEqual(gotNew, committed) {
				t.Errorf("a near spelling of the host changed no member's judgement in %s, "+
					"so this reader is not shown to compare the identifier", dir)
			}
		})
	}
}
