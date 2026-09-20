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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/astrogilda/agent-evidence-vectors/corpora"
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
	copied := filepath.Join(t.TempDir(), dir)
	copyTree(t, corpusPath(dir), copied)
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
// report, and every refusal of the verifier inside it that the corpus does not
// already exercise.
//
// The second half is the part worth the lines. The corpus names one code per
// reject member, so every rule it exercises is covered by the clean run; the
// rules it does not exercise would be sentences, and a sentence in a verifier
// reads exactly like a rule until an input reaches it. Each case below reaches
// one, by rewriting a member's payload and requiring the reader to name the code
// in the mismatch it reports.
func observedEffectFindings() []findingCase {
	const dir = "vectors-observed-effect"
	return append(observedEffectCorpusFindings(dir), observedEffectRuleFindings(dir)...)
}

// observedEffectCorpusFindings covers the reader's own sentences: the member
// bookkeeping and the corpus-level checks that make the corpus scoreable.
func observedEffectCorpusFindings(dir string) []findingCase {
	return []findingCase{
		{"oe/duplicate-id", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rows := vectorsOf(m)
				m["vectors"] = append(rows, rows[0])
			})
		}, "duplicate id"},
		{"oe/no-file", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["file"] = ""
			})
		}, "MANIFEST row declares no file"},
		{"oe/missing-body", dir, func(t *testing.T, d string) {
			removeFile(t, d, oeMemberFile(t, d, kindIs("reject")))
		}, "vector body missing"},
		{"oe/id-does-not-hash", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, kindIs("accept")),
				func(pred map[string]any) { pred["intervalId"] = "iv-9999" })
		}, "file bytes do not hash to the identifier"},
		{"oe/reject-wrong-verdict", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")), "valid", "expected", "verdict")
			})
		}, "expected valid, got"},
		{"oe/reject-wrong-code", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, kindIs("reject")),
					[]any{"a-code-no-rule-emits"}, "expected", "codes")
			})
		}, "expected codes [a-code-no-rule-emits], got"},
		{"oe/indeterminate-one-reading", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, kindIs("indeterminate"))
				readings, _ := row["readings"].([]any)
				row["readings"] = readings[:1]
			})
		}, "a member with fewer than two is a reject member"},
		{"oe/indeterminate-outside-the-set", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("indeterminate"))["readings"] = []any{
					map[string]any{"verdict": "invalid", "rationale": "one"},
					map[string]any{"verdict": "malformed", "rationale": "another"},
				}
			})
		}, "which is outside the declared set"},
		{"oe/unknown-kind", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["kind"] = "maybe"
			})
		}, "which this reader does not replay"},
		{"oe/counts", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
			})
		}, "counts disagree"},
		{"oe/condition-only-rejected", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { oeStripConditionFromAccepts(m, "oe-chain") })
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
				row["conditions"] = append(row["conditions"].([]any), "oe-never-declared")
			})
		}, "is used by a member and the manifest does not declare it"},
		{"oe/condition-has-no-reject", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				conditions, _ := m["conditions"].(map[string]any)
				conditions["oe-accepted-only"] = "carried by an accept member and by no reject one"
				row := firstRowWhere(t, m, kindIs("accept"))
				row["conditions"] = append(row["conditions"].([]any), "oe-accepted-only")
			})
		}, "has no reject member"},
		{"oe/reject-without-parent", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				delete(firstRowWhere(t, m, kindIs("reject")), "parent")
			})
		}, "names no parent"},
		{"oe/parent-is-not-a-member", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, kindIs("reject"))["parent"] = "vnotamemberatall"
			})
		}, "which is not a member of this corpus"},
		{"oe/empty-tree-absent", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				constants, _ := m["emptyTree"].(map[string]any)
				delete(constants, "sha1")
			})
		}, "publishes no empty-tree constant for sha1"},
		{"oe/empty-tree-wrong", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				constants, _ := m["emptyTree"].(map[string]any)
				constants["sha256"] = strings.Repeat("0", 64)
			})
		}, "empty-tree constant for sha256 is"},
		{"oe/corpus-digest", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["corpusDigest"] = strings.Repeat("0", 64)
			})
		}, "corpusDigest does not match the members on disk"},
		{"oe/no-observer-key", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				keys, _ := m["keys"].(map[string]any)
				delete(keys, "observer")
			})
		}, "names no keys.observer.publicKey"},
		{"oe/no-vectors", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["vectors"] = []any{} })
		}, "carries no vectors"},
		{"oe/manifest-shape", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["counts"] = "not an object" })
		}, "does not parse"},
	}
}

// observedEffectRuleFindings reaches one rule of the verifier per case. Every
// one of them rewrites an ACCEPT member, so the reader's own mismatch sentence
// carries the code the rule refused with: a rule that stopped refusing would
// leave the member accepted and the case with nothing to find.
func observedEffectRuleFindings(dir string) []findingCase {
	accept := kindIs("accept")
	return []findingCase{
		{"oe/rule-required-member", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept),
				func(pred map[string]any) { delete(pred, "tier") })
		}, "required-member-absent:tier"},
		{"oe/rule-tier-unknown", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept),
				func(pred map[string]any) { pred["tier"] = "supreme" })
		}, "tier-unknown"},
		{"oe/rule-mutation-unknown", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept),
				func(pred map[string]any) { pred["mutation"] = "perhaps" })
		}, "mutation-unknown"},
		{"oe/rule-hash-algorithm-unknown", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept),
				func(pred map[string]any) { pred["hashAlgorithm"] = "md5" })
		}, "hash-algorithm-unknown"},
		{"oe/rule-issued-before-sealed", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				pred["issuedAt"] = "2026-01-01T00:00:00Z"
			})
		}, "issued-before-sealed"},
		{"oe/rule-path-scope-not-absolute", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				pred["pathScope"] = []any{"srv/app/"}
			})
		}, "path-scope-not-absolute"},
		{"oe/rule-mutation-none-moved-root", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, oeSlugIs("mutation-none-read-only")),
				func(pred map[string]any) {
					interval, _ := pred["interval"].(map[string]any)
					interval["afterRoot"] = strings.Repeat("a", 64)
				})
		}, "mutation-none-with-moved-root"},
		{"oe/rule-read-state-unknown", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				oeFirstRead(t, pred)["readState"] = "maybe-read"
			})
		}, "read-state-unknown"},
		{"oe/rule-read-state-carries-range", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				oeFirstRead(t, pred)["readState"] = "no-bytes-read"
			})
		}, "read-state-carries-range"},
		{"oe/rule-byte-range-not-integer", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				span, _ := oeFirstRead(t, pred)["byteRange"].(map[string]any)
				span["end"] = 64.5
			})
		}, "byte-range-not-integer"},
		{"oe/rule-byte-range-negative", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				span, _ := oeFirstRead(t, pred)["byteRange"].(map[string]any)
				span["start"] = -1.0
			})
		}, "byte-range-negative"},
		{"oe/rule-agreement-unknown", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				rows, _ := pred["dualValues"].([]any)
				row, _ := rows[0].(map[string]any)
				row["agreement"] = "sort-of"
			})
		}, "agreement-unknown"},
		{"oe/rule-tier-recompute-mismatch", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept),
				func(pred map[string]any) { pred["tier"] = "voluntary" })
		}, "tier-recompute-mismatch"},
		{"oe/rule-coverage-incomplete", dir, func(t *testing.T, d string) {
			oeRewritePredicate(t, d, oeMemberFile(t, d, accept), func(pred map[string]any) {
				observation, _ := pred["observation"].(map[string]any)
				coverage, _ := observation["coverage"].(map[string]any)
				coverage["scopeComplete"] = false
				coverage["gaps"] = []any{"/srv/app/unseen"}
			})
		}, "authoritative-coverage-incomplete"},
		{"oe/statement-type", dir, func(t *testing.T, d string) {
			oeRewriteStatement(t, d, oeMemberFile(t, d, accept), func(statement map[string]any) {
				statement["_type"] = "https://in-toto.io/Statement/v0.1"
			})
		}, "statement-type-unexpected"},
		{"oe/predicate-absent", dir, func(t *testing.T, d string) {
			oeRewriteStatement(t, d, oeMemberFile(t, d, accept), func(statement map[string]any) {
				delete(statement, "predicate")
			})
		}, "required-member-absent:predicate"},
		{"oe/payload-not-parseable", dir, func(t *testing.T, d string) {
			oeEditEnvelope(t, d, oeMemberFile(t, d, accept), func(envelope map[string]any) {
				envelope["payload"] = "%%% not base64 %%%"
			})
		}, "not-parseable"},
		{"oe/signature-invalid", dir, func(t *testing.T, d string) {
			oeEditEnvelope(t, d, oeMemberFile(t, d, accept), func(envelope map[string]any) {
				oeFirstSignature(t, envelope)["sig"] =
					base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			})
		}, "envelope-signature-invalid"},
		{"oe/signature-unreadable", dir, func(t *testing.T, d string) {
			oeEditEnvelope(t, d, oeMemberFile(t, d, accept), func(envelope map[string]any) {
				oeFirstSignature(t, envelope)["sig"] = "%%% not base64 %%%"
			})
		}, "envelope-signature-unreadable"},
		{"oe/duplicate-member", dir, func(t *testing.T, d string) {
			// A duplicate member cannot be written through a Go map, which holds
			// one value per name by construction, so the bytes are written out.
			writeFile(t, d, oeMemberFile(t, d, accept),
				`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","payload":"e30="}`)
		}, "duplicate-member"},
	}
}

// oeSlugIs picks a member by the slug the manifest gives it. A slug is prose
// somebody wrote and is stable across a regeneration, unlike an identifier,
// which is a digest of bytes and moves whenever they do.
func oeSlugIs(slug string) func(map[string]any) bool {
	return func(row map[string]any) bool { return row["slug"] == slug }
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

// oeFirstRead is the first read row of a predicate, for a case that needs one.
func oeFirstRead(t *testing.T, pred map[string]any) map[string]any {
	t.Helper()
	rows, _ := pred["reads"].([]any)
	if len(rows) == 0 {
		t.Fatal("the chosen member carries no read, so this case would assert nothing")
	}
	row, _ := rows[0].(map[string]any)
	return row
}

func oeFirstSignature(t *testing.T, envelope map[string]any) map[string]any {
	t.Helper()
	rows, _ := envelope["signatures"].([]any)
	if len(rows) == 0 {
		t.Fatal("the member carries no signature, so this case would assert nothing")
	}
	row, _ := rows[0].(map[string]any)
	return row
}

// oeEditEnvelope rewrites one member's DSSE envelope through edit.
func oeEditEnvelope(t *testing.T, dir, rel string, edit func(envelope map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, rel)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	edit(envelope)
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// oeRewriteStatement rewrites the in-toto statement inside one member's payload.
//
// The signature is left STALE deliberately, and that is safe for exactly one
// reason worth stating: the envelope signature is checked last, after every rule
// has held, so a rule refusal always precedes it. A case whose rule stopped
// refusing would therefore reach the signature and fail on the signature, which
// is a different sentence from the one it asserts. Re-signing would need the
// corpus's signing key, which this repository does not hold.
func oeRewriteStatement(t *testing.T, dir, rel string, edit func(statement map[string]any)) {
	t.Helper()
	oeEditEnvelope(t, dir, rel, func(envelope map[string]any) {
		encoded, _ := envelope["payload"].(string)
		payload, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		var statement map[string]any
		if err := json.Unmarshal(payload, &statement); err != nil {
			t.Fatal(err)
		}
		edit(statement)
		body, err := json.Marshal(statement)
		if err != nil {
			t.Fatal(err)
		}
		envelope["payload"] = base64.StdEncoding.EncodeToString(body)
	})
}

// oeRewritePredicate rewrites the predicate inside one member's payload.
func oeRewritePredicate(t *testing.T, dir, rel string, edit func(pred map[string]any)) {
	t.Helper()
	oeRewriteStatement(t, dir, rel, func(statement map[string]any) {
		pred, ok := statement["predicate"].(map[string]any)
		if !ok {
			t.Fatal("the member carries no predicate object, so this case would mutate nothing")
		}
		edit(pred)
	})
}

// oeStripConditionFromAccepts removes one condition from every accept member,
// leaving it carried by reject members alone, which is the state that gives a
// refuse-everything verifier full marks on it.
func oeStripConditionFromAccepts(m map[string]any, condition string) {
	for _, item := range vectorsOf(m) {
		row, _ := item.(map[string]any)
		if kind, _ := row["kind"].(string); kind != "accept" {
			continue
		}
		carried, _ := row["conditions"].([]any)
		kept := make([]any, 0, len(carried))
		for _, value := range carried {
			if text, ok := value.(string); ok && text == condition {
				continue
			}
			kept = append(kept, value)
		}
		row["conditions"] = kept
	}
}
