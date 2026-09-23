package corpora_test

// Every finding a reader can report, provoked.
//
// The clean-corpus test proves the readers agree with the corpora as they
// stand, and the flipped-byte test proves they read the bytes at all. Neither
// establishes that a given refusal is reachable, and an unreachable refusal is
// the shape of defect this repository has spent its history removing: a check
// that cannot fail reports a corpus as clean in exactly the same words as a
// check that passed.
//
// Each case below copies a corpus, makes ONE change, and requires the reader to
// say a specific thing about it. The wanted text is a fragment of the finding
// rather than the whole line, so a reworded message does not fail the test while
// a deleted check does.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

// findingCase is one mutation and the sentence the reader owes for it.
type findingCase struct {
	name   string
	dir    string
	mutate func(t *testing.T, dir string)
	want   string
}

// stage copies a corpus into a temporary directory so a mutation never touches
// the committed tree.
func stage(t *testing.T, dir string) string {
	t.Helper()
	root := t.TempDir()
	copied := filepath.Join(root, dir)
	copyTree(t, corpusPath(dir), copied)
	// One reader reads the predicate's Type URI out of the document that defines
	// it, resolved through dir/.., so a corpus staged alone cannot be judged at
	// all and every case against it would report an unreadable corpus instead of
	// the finding it exists to assert.
	stageSiblingSpec(t, root)
	return copied
}

// allFindings returns every finding the reader reported, member and corpus
// level alike, as one slice a case can search.
func allFindings(t *testing.T, dir string) []string {
	t.Helper()
	result, err := corpora.Judge(dir)
	if err != nil {
		return []string{"JUDGE ERROR: " + err.Error()}
	}
	var out []string
	for _, m := range result.Members {
		for _, f := range m.Findings {
			out = append(out, m.ID+": "+f)
		}
	}
	out = append(out, result.Findings...)
	return out
}

// editManifest rewrites a corpus manifest through a function. Re-marshalling
// reorders members and reformats whitespace, which no reader depends on: every
// digest in these corpora is over the MEMBER files, never over the manifest's
// own bytes.
func editManifest(t *testing.T, dir string, edit func(m map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, corpora.ManifestName)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	edit(manifest)
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// vectorsOf returns the manifest's vector rows as editable maps.
func vectorsOf(m map[string]any) []any {
	rows, _ := m["vectors"].([]any)
	return rows
}

// firstRowWhere returns the first vector row satisfying pick.
func firstRowWhere(t *testing.T, m map[string]any, pick func(row map[string]any) bool) map[string]any {
	t.Helper()
	for _, item := range vectorsOf(m) {
		row, ok := item.(map[string]any)
		if ok && pick(row) {
			return row
		}
	}
	t.Fatal("no vector row matched, so this case would have asserted nothing")
	return nil
}

// declares picks a row by the expectation it carries rather than by how its
// identifier is spelled. Every corpus here names its members after their own
// bytes, so a selector built on a name matches nothing the day the bytes move,
// and a test whose selector matches nothing asserts nothing.
func declares(field string) func(map[string]any) bool {
	return func(row map[string]any) bool {
		expected, _ := row["expected"].(map[string]any)
		_, has := expected[field]
		return has
	}
}

func kindIs(kind string) func(map[string]any) bool {
	return func(row map[string]any) bool { return row["kind"] == kind }
}

// setDeep sets a nested manifest value, creating nothing: a path that does not
// resolve fails the test rather than inventing structure the corpus never had.
func setDeep(t *testing.T, row map[string]any, value any, keys ...string) {
	t.Helper()
	node := row
	for _, key := range keys[:len(keys)-1] {
		next, ok := node[key].(map[string]any)
		if !ok {
			t.Fatalf("the row carries no %q to edit", key)
		}
		node = next
	}
	node[keys[len(keys)-1]] = value
}

func removeFile(t *testing.T, dir, rel string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, rel)); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEveryFindingIsReachable(t *testing.T) {
	cases := append(anchorFindings(), acsFindings()...)
	cases = append(cases, w3cFindings()...)
	cases = append(cases, mcpFindings()...)
	cases = append(cases, bindingFindings()...)
	cases = append(cases, agentActionFindings()...)
	cases = append(cases, aeeFindings()...)
	cases = append(cases, aciFindings()...)
	cases = append(cases, observedEffectFindings()...)
	cases = append(cases, mcpResponsePhaseFindings()...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := stage(t, tc.dir)
			tc.mutate(t, dir)
			findings := allFindings(t, dir)
			for _, f := range findings {
				if strings.Contains(f, tc.want) {
					return
				}
			}
			t.Errorf("no finding contains %q; the reader said:\n  %s",
				tc.want, strings.Join(findings, "\n  "))
		})
	}
}

func anchorFindings() []findingCase {
	const dir = "vectors-anchor-stream"
	return []findingCase{
		{"anchor/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"anchor/spec-authority", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specAuthority"] = "targetTag" })
		}, "specAuthority names something other than specDigest"},
		{"anchor/spec-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specDigest"] = strings.Repeat("0", 64) })
		}, "does not match its pinned digest"},
		{"anchor/spec-name", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["targetCommit"] = strings.Repeat("f", 40) })
		}, "the file name and the pin disagree"},
		{"anchor/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the streams on disk"},
		{"anchor/missing-stream", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				removeFile(t, d, row["stream"].(string))
			})
		}, "manifest names a stream file that does not exist"},
		{"anchor/stream-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["streamSha256"] = strings.Repeat("0", 64)
			})
		}, "declared streamSha256 does not recompute"},
		{"anchor/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "unknown kind maybe"},
		{"anchor/undefined-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["conditions"] = []any{"ans-c-nope"}
			})
		}, "cites condition ans-c-nope the manifest does not define"},
		{"anchor/basis-disagrees", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["contractBasis"] = "invented"
			})
		}, "declares contractBasis"},
		{"anchor/undefined-outcome", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "VERIFY MAYBE", "expected", "outcome")
			})
		}, "the contract does not define"},
		{"anchor/wrong-exit", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), 9.0, "expected", "exit")
			})
		}, "and the contract pairs it with"},
		{"anchor/reject-not-failing", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "VERIFY OK", "expected", "outcome")
			})
		}, "reject member that does not expect the failing outcome"},
		{"anchor/stop-reason-vocabulary", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "invented", "expected", "stopReason")
			})
		}, "not in the corpus vocabulary"},
		{"anchor/accept-with-stop-reason", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), "truncation", "expected", "stopReason")
			})
		}, "accept member carrying a stop reason"},
		{"anchor/idle-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				conditions, _ := m["conditions"].(map[string]any)
				conditions["ans-c-unused"] = map[string]any{"basis": "as-vendored", "requires": "nothing"}
			})
		}, "conditions declared and carried by no member"},
		{"anchor/orphan-twin", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				for _, item := range vectorsOf(m) {
					row := item.(map[string]any)
					if row["kind"] == "accept" {
						row["conditions"] = []any{}
					}
				}
			})
		}, "reject conditions with no accepting twin"},
		{"anchor/separator-not-carried", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["insertedCodepoint"]
					return has && r["kind"] == "reject"
				})
				setDeep(t, row, "U+0041", "properties", "insertedCodepoint")
			})
		}, "and does not carry it there"},
		{"anchor/terminator-declaration", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["endsWithNewline"]
					return has
				})
				properties := row["properties"].(map[string]any)
				properties["endsWithNewline"] = !properties["endsWithNewline"].(bool)
			})
		}, "declares endsWithNewline"},
		{"anchor/sidecar-entries", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["sidecarEntries"]
					return has
				})
				setDeep(t, row, 999.0, "properties", "sidecarEntries")
			})
		}, "sidecar entries and carries"},
		{"anchor/witness-commit-unserved", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["witnessCommit"]
					return has
				})
				setDeep(t, row, strings.Repeat("a", 40), "properties", "witnessCommit")
			})
		}, "the platform file serves no such commit"},
		{"anchor/record-field-collision", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["carriesRecordFields"]
					return has
				})
				properties := row["properties"].(map[string]any)
				properties["carriesRecordFields"] = !properties["carriesRecordFields"].(bool)
			})
		}, "declares carriesRecordFields"},
		{"anchor/rule-version", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["ruleVersion"]
					return has && r["kind"] == "reject"
				})
				setDeep(t, row, "witness-ref-v1", "properties", "ruleVersion")
			})
		}, "unrecognised and it is one of the three"},
		{"anchor/binding-repo", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["bindingRepo"]
					return has
				})
				setDeep(t, row, "nobody/nothing", "properties", "bindingRepo")
			})
		}, "declares a binding repo of"},
		{"anchor/default-branch-lines", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["defaultBranchLines"]
					return has
				})
				setDeep(t, row, 4242.0, "properties", "defaultBranchLines")
			})
		}, "declares a default branch of"},
		{"anchor/boolean-field", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					properties, _ := r["properties"].(map[string]any)
					_, has := properties["jsonType"]
					return has && r["kind"] == "reject"
				})
				setDeep(t, row, "nosuchfield", "properties", "field")
			})
		}, "and no row in the stream carries one"},
	}
}

func acsFindings() []findingCase {
	const dir = "vectors-acs-core"
	return []findingCase{
		{"acs/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0, "indeterminate": 1.0}
			})
		}, "counts disagree"},
		{"acs/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the vector files on disk"},
		{"acs/observed-run", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["observedRuns"] = []any{map[string]any{"who": "us"}} })
		}, "the manifest records an observed run"},
		{"acs/vendored-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vendored := m["specVendored"].(map[string]any)
				for _, entry := range vendored {
					entry.(map[string]any)["sha256"] = strings.Repeat("0", 64)
				}
			})
		}, "does not match its pinned digest"},
		{"acs/requirement-sentence-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := m["requirements"].([]any)
				rows[0].(map[string]any)["sentence"] = "a sentence no vendored copy carries"
			})
		}, "quotes a sentence the vendored copy no longer carries"},
		{"acs/requirement-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := m["requirements"].([]any)
				rows[0].(map[string]any)["sentenceDigest"] = strings.Repeat("0", 64)
			})
		}, "the pinned sentence digest does not recompute"},
		{"acs/requirement-line", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := m["requirements"].([]any)
				rows[0].(map[string]any)["line"] = 999999.0
			})
		}, "and the sentence sits on line"},
		{"acs/requirement-file-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := m["requirements"].([]any)
				rows[0].(map[string]any)["vendored"] = "spec-vendored/nothing-here.md"
			})
		}, "names a vendored file"},
		{"acs/idle-requirement", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := m["requirements"].([]any)
				clone := map[string]any{}
				for k, v := range rows[0].(map[string]any) {
					clone[k] = v
				}
				clone["id"] = "ACS-R-UNUSED"
				m["requirements"] = append(rows, clone)
			})
		}, "requirements minted and cited by no member"},
		{"acs/unknown-vocabulary", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["witnessScope"] = "ELSEWHERE"
			})
		}, "declares witness scope"},
		{"acs/undefined-family", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["family"] = "acs-f-nope"
			})
		}, "the manifest does not define"},
		{"acs/no-requirement", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["requirements"] = []any{}
			})
		}, "cites no requirement"},
		{"acs/spec-version", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["specVersion"] = "9.9.9"
			})
		}, "declares a specification version the manifest does not pin"},
		{"acs/unknown-code", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					expected, _ := r["expected"].(map[string]any)
					return expected["code"] != nil
				})
				setDeep(t, row, "NO_SUCH_CODE", "expected", "code")
			})
		}, "which the specification's own registry does not define"},
		{"acs/code-value", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					expected, _ := r["expected"].(map[string]any)
					return expected["code"] != nil
				})
				setDeep(t, row, -1.0, "expected", "codeValue")
			})
		}, "carries a code value the registry does not pair with that name"},
		{"acs/accept-not-allow", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), "deny", "expected", "verdict")
			})
		}, "accept member that does not expect an allow"},
		{"acs/indeterminate-scorable", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("indeterminate")), "deny", "expected", "verdict")
			})
		}, "sits in the indeterminate bucket and expects a scorable verdict"},
		{"acs/unmeasurable-outside-bucket", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "unmeasurable", "expected", "verdict")
			})
		}, "expects an unmeasurable verdict and is not in the indeterminate bucket"},
		{"acs/file-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["file"].(string))
			})
		}, "the manifest names a vector file that does not exist"},
		{"acs/file-disagrees", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "accept"
			})
		}, "the vector file and the manifest disagree about kind"},
	}
}

func w3cFindings() []findingCase {
	const dir = "vectors-w3c-report"
	return []findingCase{
		{"w3c/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"w3c/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the vector files on disk"},
		{"w3c/vendored-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vendored := m["specVendored"].(map[string]any)
				for _, entry := range vendored {
					entry.(map[string]any)["sha256"] = strings.Repeat("0", 64)
				}
			})
		}, "does not match its pinned digest"},
		{"w3c/requirement-sentence-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := m["requirements"].([]any)
				rows[0].(map[string]any)["sentence"] = "a sentence no vendored copy carries"
			})
		}, "quotes a sentence the vendored copy no longer carries"},
		{"w3c/wrong-row", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				row["requirements"] = []any{"W3C-R-012"}
				setDeep(t, row, []any{"W3C-R-012"}, "expected", "rejects")
			})
		}, "the validator rejects under"},
		{"w3c/two-rows", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				setDeep(t, row, []any{"W3C-R-001", "W3C-R-002"}, "expected", "rejects")
			})
		}, "does not name exactly one row"},
		{"w3c/subject-type", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["subjectType"] = "poem"
			})
		}, "declares subject type"},
		{"w3c/file-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["file"].(string))
			})
		}, "the manifest names a vector file that does not exist"},
	}
}

func mcpResponsePhaseFindings() []findingCase {
	const dir = "vectors-mcp-response-phase"
	return []findingCase{
		{"mrp/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"mrp/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the operation files on disk"},
		{"mrp/criterion-missing", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["criterion"] = "docs/NO-SUCH-CRITERION.md" })
		}, "corpus measures a rule nobody can read"},
		{"mrp/spec-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specDigest"] = strings.Repeat("0", 64) })
		}, "does not match its pinned digest"},
		{"mrp/undefined-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["conditions"] = []any{"mrp-c-nope"}
			})
		}, "the manifest does not define"},
		{"mrp/no-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["conditions"] = []any{}
			})
		}, "cites no condition"},
		{"mrp/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "declares kind \"maybe\""},
		{"mrp/file-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["file"].(string))
			})
		}, "the manifest names an operation file that does not exist"},
		{"mrp/no-invoked-axis", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				expected := firstRowWhere(t, m, kindIs("reject"))["expected"].(map[string]any)
				delete(expected, "policyInvoked")
			})
		}, "declares no expectation on policyInvoked"},
		{"mrp/no-receives-axis", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				expected := firstRowWhere(t, m, kindIs("accept"))["expected"].(map[string]any)
				delete(expected, "callerReceives")
			})
		}, "declares no expectation on callerReceives"},
		{"mrp/accept-not-invoked", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), false, "expected", "policyInvoked")
			})
		}, "accept member declaring policyInvoked=false"},
		{"mrp/accept-wrong-receives", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), map[string]any{"kind": "error"}, "expected", "callerReceives")
			})
		}, "callerReceives is not what the policy applied"},
		{"mrp/reject-no-defect", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				// The mrp-c-2 reject differs from its twin only on policyInvoked;
				// setting it true makes the member agree on both axes.
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					if r["kind"] != "reject" {
						return false
					}
					return r["expected"].(map[string]any)["policyInvoked"] == false
				})
				setDeep(t, row, true, "expected", "policyInvoked")
			})
		}, "encodes no defect"},
		{"mrp/reject-both-axes", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				// A reject whose callerReceives already differs from the conformant
				// outcome: flipping policyInvoked to false fails both axes at once.
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					if r["kind"] != "reject" {
						return false
					}
					return r["expected"].(map[string]any)["policyInvoked"] == true
				})
				setDeep(t, row, false, "expected", "policyInvoked")
			})
		}, "failing both axes at once"},
	}
}

func mcpFindings() []findingCase {
	const dir = "vectors-mcp-record-contract"
	return []findingCase{
		{"mcp/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"mcp/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the record files on disk"},
		{"mcp/criterion-missing", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["criterion"] = "docs/NO-SUCH-CRITERION.md" })
		}, "corpus measures a rule nobody can read"},
		{"mcp/undefined-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["conditions"] = []any{"mrc-c-nope"}
			})
		}, "the manifest does not define"},
		{"mcp/no-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["conditions"] = []any{}
			})
		}, "cites no condition"},
		{"mcp/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "declares kind \"maybe\""},
		{"mcp/record-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["record"].(string))
			})
		}, "the manifest names a record file that does not exist"},
		{"mcp/no-axis", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				expected := row["expected"].(map[string]any)
				delete(expected, "independence")
			})
		}, "declares no expectation on independence"},
		{"mcp/accept-declares-failure", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), false, "expected", "recheckable")
			})
		}, "accept member declaring a failure"},
		{"mcp/two-axes", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				setDeep(t, row, false, "expected", "recheckable")
				setDeep(t, row, false, "expected", "figureMeansWhatItSays")
			})
		}, "reject member declaring failures on"},
		{"mcp/criterion-disagrees", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("accept"))
				setDeep(t, row, "self-report", "expected", "independence")
			})
		}, "and the checker answers"},
		{"mcp/idle-condition", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				conditions := m["conditions"].(map[string]any)
				conditions["mrc-c-unused"] = map[string]any{"requires": "nothing"}
			})
		}, "conditions declared and carried by no member"},
	}
}

func bindingFindings() []findingCase {
	const dir = "vectors-artifact-binding"
	return []findingCase{
		{"binding/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"verified": 1.0, "failed": 1.0, "notEstablished": 1.0}
			})
		}, "declares counts that the entries do not carry"},
		{"binding/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the vectors it names"},
		{"binding/published-key", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["publicKey"] = strings.Repeat("ab", 32)
			})
		}, "publishes a key whose id is"},
		{"binding/record-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["manifest"].(string))
			})
		}, "is missing"},
		{"binding/wrong-verdict", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), "failed", "expected", "verdict")
			})
		}, "the reference verifier answered"},
		{"binding/code-not-emitted", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				setDeep(t, row, []any{"a-code-nothing-emits"}, "expected", "codes")
			})
		}, "were not emitted"},
		{"binding/no-verified-member", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				for _, item := range vectorsOf(m) {
					expected := item.(map[string]any)["expected"].(map[string]any)
					if expected["verdict"] == "verified" {
						expected["verdict"] = "failed"
					}
				}
			})
		}, "no verified member"},
		{"binding/no-not-established-member", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				for _, item := range vectorsOf(m) {
					expected := item.(map[string]any)["expected"].(map[string]any)
					if expected["verdict"] == "not-established" {
						expected["verdict"] = "failed"
					}
				}
			})
		}, "the third outcome is untested"},
		{"binding/signature-broken", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("accept"))
				writeFile(t, d, row["signature"].(string), strings.Repeat("00", 64))
			})
		}, "the reference verifier answered"},
	}
}

func agentActionFindings() []findingCase {
	const dir = "vectors-ai-agent-action"
	return []findingCase{
		{"agent-action/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"agent-action/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the files on disk"},
		{"agent-action/spec-authority", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specAuthority"] = "specUpstreamCommit" })
		}, "specAuthority names something other than specDigest"},
		{"agent-action/provenance-field", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specUpstreamRepo"] = "" })
		}, "the manifest carries no specUpstreamRepo"},
		{"agent-action/spec-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specDigest"] = strings.Repeat("0", 64) })
		}, "does not match its pinned digest"},
		{"agent-action/spec-name", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["specUpstreamCommit"] = strings.Repeat("f", 40) })
		}, "the file name and the pin disagree"},
		{"agent-action/predicate-type", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["predicateType"] = "https://example.invalid/other" })
		}, "predicateType does not match the suite"},
		{"agent-action/file-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["file"].(string))
			})
		}, "manifest names a file that does not exist"},
		{"agent-action/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "unknown kind maybe"},
		{"agent-action/records-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					_, has := r["records"]
					return has
				})
				removeFile(t, d, row["records"].(string))
			})
		}, "manifest names a records sidecar that does not exist"},
		{"agent-action/orphan-twin", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				for _, item := range vectorsOf(m) {
					row := item.(map[string]any)
					if row["kind"] == "accept" {
						row["conditions"] = []any{}
					}
				}
			})
		}, "reject conditions with no accepting twin"},
		{"agent-action/appendix-b-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, declares("requestDigest"))
				setDeep(t, row, strings.Repeat("0", 64), "expected", "requestDigest")
			})
		}, "requestDigest is not the digest of"},
		{"agent-action/appendix-b-ieee754", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					expected, _ := r["expected"].(map[string]any)
					pattern, _ := expected["ieee754"].(string)
					return pattern != "" && pattern != "0000000000000000" &&
						pattern != "8000000000000000"
				})
				setDeep(t, row, "1111111111111111", "expected", "ieee754")
			})
		}, "not the declared"},
		{"agent-action/ordering-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, declares("chainHashUtf16"))
				setDeep(t, row, strings.Repeat("0", 64), "expected", "chainHashUtf16")
			})
		}, "chainHashUtf16 does not recompute from the sidecar record"},
	}
}

func aeeFindings() []findingCase {
	const dir = "vectors"
	return []findingCase{
		{"aee/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"aee/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "which this reader does not replay"},
		{"aee/file-gone", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				removeFile(t, d, firstRowWhere(t, m, kindIs("reject"))["file"].(string))
			})
		}, "vector body missing"},
		{"aee/no-file", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				delete(firstRowWhere(t, m, kindIs("reject")), "file")
			})
		}, "MANIFEST row declares no file"},
		{"aee/accept-is-reject", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("accept"))["kind"] = "reject"
			})
		}, "got valid"},
		{"aee/reject-is-accept", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "accept"
			})
		}, "expected valid, got invalid"},
		{"aee/wrong-code", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), []any{"no-such-code"}, "expected", "codes")
			})
		}, "not in expected set"},
		{"aee/wrong-result", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("accept")), "not-a-result", "expected", "result")
			})
		}, "want \"not-a-result\""},
		{"aee/one-reading", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("indeterminate"))
				expected := row["expected"].(map[string]any)
				readings := expected["readings"].(map[string]any)
				kept := ""
				for name := range readings {
					kept = name
					break
				}
				expected["readings"] = map[string]any{kept: readings[kept]}
			})
		}, "reading(s); a family with fewer than two"},
		{"aee/undeclared-reading", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				for _, item := range vectorsOf(m) {
					row := item.(map[string]any)
					if row["kind"] != "indeterminate" {
						continue
					}
					expected := row["expected"].(map[string]any)
					readings := expected["readings"].(map[string]any)
					for name := range readings {
						readings[name] = "a-code-no-rail-emits"
					}
				}
			})
		}, "predicted by no declared reading"},
	}
}

// aciFindings: one case per sentence the ACI reader can report. Writing these
// is what found the split severity of ACI-DIS-002, where publishing the
// discovery file is a SHOULD and the three fields it must then carry are a
// MUST, so the same code is a warning in one member and a refusal in another.
func aciFindings() []findingCase {
	const dir = "vectors-aci"
	return []findingCase{
		{"aci/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"aci/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not match the members on disk"},
		{"aci/spec-version", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { delete(m, "specVersion") })
		}, "declares no specVersion"},
		{"aci/spec-commit", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { delete(m, "specCommit") })
		}, "declares no specCommit"},
		{"aci/check-missing-from-manifest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				checks, _ := m["checks"].(map[string]any)
				delete(checks, "ACI-SER-001")
			})
		}, "the reader carries check ACI-SER-001 and the manifest does not declare it"},
		{"aci/check-section-disagrees", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				checks, _ := m["checks"].(map[string]any)
				checks["ACI-SER-001"] = "99.9"
			})
		}, "cites section"},
		{"aci/check-unknown-to-reader", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				checks, _ := m["checks"].(map[string]any)
				checks["ACI-NOPE-001"] = "1.1"
			})
		}, "and no reader here carries it"},
		{"aci/check-never-forced", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				aciDropCode(m, "ACI-IDF-003")
			})
		}, "so that check is named and never forced"},
		{"aci/duplicate-identifier", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vectors, _ := m["vectors"].([]any)
				first, _ := vectors[0].(map[string]any)
				second, _ := vectors[1].(map[string]any)
				second["id"] = first["id"]
			})
		}, "duplicate identifier"},
		{"aci/identifier-does-not-recompute", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vectors, _ := m["vectors"].([]any)
				first, _ := vectors[0].(map[string]any)
				first["id"] = "v" + strings.Repeat("0", 16)
			})
		}, "identifier does not recompute from the member's own bytes"},
		{"aci/unreadable-member", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vectors, _ := m["vectors"].([]any)
				first, _ := vectors[0].(map[string]any)
				first["file"] = "deployment-members/gone.json"
			})
		}, "is unreadable"},
		{"aci/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vectors, _ := m["vectors"].([]any)
				first, _ := vectors[0].(map[string]any)
				first["kind"] = "maybe"
			})
		}, "is not one this corpus judges"},
		{"aci/level-out-of-range", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vectors, _ := m["vectors"].([]any)
				first, _ := vectors[0].(map[string]any)
				first["level"] = 9.0
			})
		}, "is outside the three the specification defines"},
		{"aci/expects-unknown-code", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				vectors, _ := m["vectors"].([]any)
				first, _ := vectors[0].(map[string]any)
				expected, _ := first["expected"].(map[string]any)
				expected["codes"] = []any{"ACI-NOPE-002"}
			})
		}, "which is not one of the nineteen checks"},
		{"aci/declared-code-does-not-fire", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				aciAddCodeTo(m, "ACI-IDF-003")
			})
		}, "and the checks do not emit it at level"},
		{"aci/fired-code-undeclared", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				aciDropCode(m, "ACI-SER-001")
			})
		}, "and the member does not declare it"},
		{"aci/member-not-a-deployment", dir, func(t *testing.T, d string) {
			body, err := os.ReadFile(filepath.Join(d, corpora.ManifestName))
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			vectors, _ := m["vectors"].([]any)
			first, _ := vectors[0].(map[string]any)
			rel, _ := first["file"].(string)
			if err := os.WriteFile(filepath.Join(d, rel), []byte("[]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "does not parse as a deployment"},
	}
}

// aciDropCode removes one code from whichever member declares it, so the
// corpus-level "named and never forced" check and the per-member "the checks
// emit it and the member does not declare it" check are both reachable.
func aciDropCode(m map[string]any, code string) {
	vectors, _ := m["vectors"].([]any)
	for _, raw := range vectors {
		vector, _ := raw.(map[string]any)
		expected, _ := vector["expected"].(map[string]any)
		codes, _ := expected["codes"].([]any)
		kept := make([]any, 0, len(codes))
		for _, value := range codes {
			if text, ok := value.(string); ok && text == code {
				continue
			}
			kept = append(kept, value)
		}
		expected["codes"] = kept
	}
}

// aciAddCodeTo declares a code on the accept member, which by construction
// fires nothing, so the declared-but-not-emitted sentence is reachable.
func aciAddCodeTo(m map[string]any, code string) {
	vectors, _ := m["vectors"].([]any)
	for _, raw := range vectors {
		vector, _ := raw.(map[string]any)
		if kind, _ := vector["kind"].(string); kind != "accept" {
			continue
		}
		expected, _ := vector["expected"].(map[string]any)
		codes, _ := expected["codes"].([]any)
		expected["codes"] = append(codes, code)
		return
	}
}

// observedEffectFindings provokes every finding the Observed Effect reader can
// report.
//
// The reader arrived with no case of its own: the clean run judged its corpus and
// nothing established that any of its refusals could fire, which left its file at
// 72.1% of statements under an 80% floor. The floor is the symptom. The defect is
// that a refusal nothing provokes is indistinguishable from a refusal that works,
// and one of them turned out to be exactly that -- see
// TestTheObservedBitIsTheRecomputedTier for the guard that could not fail.
//
// Every case below mutates a staged copy and requires the reader to say a
// specific thing about it. The wanted text is a fragment, so rewording a message
// does not fail the case while deleting the check does.
func observedEffectFindings() []findingCase {
	const dir = "vectors-observed-effect"
	return []findingCase{
		{"oe/no-file", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["file"] = ""
			})
		}, "MANIFEST row declares no file"},
		{"oe/missing-body", dir, func(t *testing.T, d string) {
			removeFile(t, d, oeMemberFile(t, d, kindIs("reject")))
		}, "vector body missing"},
		{"oe/id-does-not-hash", dir, func(t *testing.T, d string) {
			writeFile(t, d, oeMemberFile(t, d, kindIs("accept")), "{}\n")
		}, "file bytes hash to"},
		{"oe/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "which this reader does not replay"},
		{"oe/wrong-verdict", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "valid", "expected", "verdict")
			})
		}, "expected valid, got"},
		{"oe/wrong-codes", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")),
					[]any{"a-code-no-rule-emits"}, "expected", "codes")
			})
		}, "expected codes [a-code-no-rule-emits], got"},
		{"oe/indeterminate-no-readings", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("indeterminate"))["readings"] = []any{}
			})
		}, "names no readings, so no answer can be wrong"},
		{"oe/indeterminate-outside-the-set", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("indeterminate"))["readings"] = []any{
					map[string]any{"verdict": "a-verdict-no-rail-emits"},
					map[string]any{"verdict": "another-one"},
				}
			})
		}, "which is outside the declared set"},
		{"oe/predicate-type", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["predicateType"] = "https://example.invalid/predicate/v1/not-this-one"
			})
		}, "is not the Type URI"},
		{"oe/empty-tree-unknown-algorithm", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				constants, _ := m["emptyTree"].(map[string]any)
				constants["sha3-512"] = strings.Repeat("0", 128)
			})
		}, "this rail knows none"},
		{"oe/empty-tree-wrong", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				constants, _ := m["emptyTree"].(map[string]any)
				constants["sha256"] = strings.Repeat("0", 64)
			})
		}, "empty-tree constant is not the one this rail holds"},
		{"oe/blob-named-by-nobody", dir, oeUnnameTheBlob,
			"named by no read row"},
		{"oe/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"oe/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["corpusDigest"] = strings.Repeat("0", 64)
			})
		}, "does not recompute"},
		{"oe/condition-only-rejected", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				oeStripConditionFromAccepts(t, m)
			})
		}, "is exercised only by reject members"},
		{"oe/condition-unexercised", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				conditions, _ := m["conditions"].(map[string]any)
				conditions["oe-nobody-forces-this"] = "declared and exercised by nothing"
			})
		}, "is declared and no member exercises it"},
		{"oe/condition-undeclared", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("reject"))
				carried, _ := row["conditions"].([]any)
				row["conditions"] = append(carried, "oe-never-declared")
			})
		}, "is used by a member and not declared"},
		{"oe/condition-has-no-reject", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				conditions, _ := m["conditions"].(map[string]any)
				conditions["oe-accepted-only"] = "carried by an accept member and by no reject one"
				row := firstRowWhere(t, m, kindIs("accept"))
				carried, _ := row["conditions"].([]any)
				row["conditions"] = append(carried, "oe-accepted-only")
			})
		}, "has no reject member"},
		{"oe/reject-without-parent", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				delete(firstRowWhere(t, m, kindIs("reject")), "parent")
			})
		}, "a reject member names no parent"},
		{"oe/parent-is-not-a-member", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["parent"] = "vnotamemberatall"
			})
		}, "is not a member"},
		{"oe/manifest-shape", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["counts"] = "not an object" })
		}, "does not parse"},
		{"oe/no-vectors", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["vectors"] = []any{} })
		}, "carries no vectors"},
		{"oe/no-predicate-spec", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { delete(m, "predicateSpec") })
		}, "names no predicateSpec"},
	}
}

// oeMemberFile is the file of the first member the picker chooses.
func oeMemberFile(t *testing.T, dir string, pick func(map[string]any) bool) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, corpora.ManifestName)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	rel, _ := firstRowWhere(t, manifest, pick)["file"].(string)
	if rel == "" {
		t.Fatal("the chosen member names no file, so this case would mutate nothing")
	}
	return rel
}

// oeStripConditionFromAccepts removes one condition from every accept member
// while leaving it on a reject member, which is the state that gives a
// refuse-everything verifier full marks on it. The condition is chosen from the
// corpus rather than named here: a literal goes stale the day the corpus is
// regenerated, and a case whose selector matches nothing asserts nothing.
func oeStripConditionFromAccepts(t *testing.T, m map[string]any) {
	t.Helper()
	accepted, rejected := map[string]bool{}, map[string]bool{}
	for _, item := range vectorsOf(m) {
		row, _ := item.(map[string]any)
		kind, _ := row["kind"].(string)
		carried, _ := row["conditions"].([]any)
		for _, value := range carried {
			if text, ok := value.(string); ok {
				switch kind {
				case "accept":
					accepted[text] = true
				case "reject":
					rejected[text] = true
				}
			}
		}
	}
	shared := make([]string, 0, len(accepted))
	for condition := range accepted {
		if rejected[condition] {
			shared = append(shared, condition)
		}
	}
	if len(shared) == 0 {
		t.Fatal("no condition is carried by both an accept and a reject member, so " +
			"stripping one cannot orphan anything and this case would assert nothing")
	}
	sort.Strings(shared)
	target := shared[0]
	for _, item := range vectorsOf(m) {
		row, _ := item.(map[string]any)
		if kind, _ := row["kind"].(string); kind != "accept" {
			continue
		}
		carried, _ := row["conditions"].([]any)
		kept := make([]any, 0, len(carried))
		for _, value := range carried {
			if text, ok := value.(string); ok && text == target {
				continue
			}
			kept = append(kept, value)
		}
		row["conditions"] = kept
	}
}

// oeUnnameTheBlob rewrites every member's payload so that no read row names the
// blob the reader reconstructs.
//
// The reader states that blob itself and checks that some member's payload names
// its digest, because the range-preimage rule SKIPS a row whose blob it does not
// hold: a corpus that narrated a different blob would leave that rule exercised
// by nothing and still be reported clean. Every member is rewritten rather than
// one, because the check asks whether ANY payload names it.
func oeUnnameTheBlob(t *testing.T, d string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(d, corpora.ManifestName)) // #nosec G304 -- a test reading its own copy
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	rewritten := 0
	for _, item := range vectorsOf(manifest) {
		row, _ := item.(map[string]any)
		rel, _ := row["file"].(string)
		if rel == "" {
			continue
		}
		if oeRenameBlobIn(t, filepath.Join(d, rel)) {
			rewritten++
		}
	}
	if rewritten == 0 {
		t.Fatal("no member carried a read row to rewrite, so the blob was never named " +
			"and this case would assert nothing")
	}
}

// oeRenameBlobIn points every read row in one member at a different blob, and
// reports whether it changed anything.
func oeRenameBlobIn(t *testing.T, path string) bool {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return false
	}
	encoded, _ := envelope["payload"].(string)
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	var statement map[string]any
	if err := json.Unmarshal(payload, &statement); err != nil {
		return false
	}
	predicate, _ := statement["predicate"].(map[string]any)
	reads, _ := predicate["reads"].([]any)
	changed := false
	for _, item := range reads {
		read, _ := item.(map[string]any)
		if read == nil {
			continue
		}
		if _, has := read["blobDigest"]; has {
			read["blobDigest"] = strings.Repeat("b", 64)
			changed = true
		}
	}
	if !changed {
		return false
	}
	body, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope["payload"] = base64.StdEncoding.EncodeToString(body)
	out, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return true
}
