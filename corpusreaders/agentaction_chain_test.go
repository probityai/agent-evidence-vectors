package corpora_test

// Findings the AI Agent Action reader owes for the chain-break members, the
// deployment profiles and the per-member basis. Each case makes one change to a
// staged copy of the corpus and names the sentence the reader must say about it,
// in the same shape as findings_test.go.
//
// Two of these cases are the semantic errors that a reader checking only the
// last-line chain hash reported as clean: an accept member that carries a
// priorHead-null break under a profile that forbids one, and a reject member
// whose "pre-break identifier" is not the identifier of any chain at all.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conditionIs picks a row by a condition it declares, never by its identifier.
func conditionIs(condition string, kind string) func(map[string]any) bool {
	return func(row map[string]any) bool {
		if row["kind"] != kind {
			return false
		}
		conditions, _ := row["conditions"].([]any)
		for _, c := range conditions {
			if c == condition {
				return true
			}
		}
		return false
	}
}

func profileIs(profile string) func(map[string]any) bool {
	return func(row map[string]any) bool { return row["profile"] == profile }
}

// specBasisRow picks a reject row whose basis cites the vendored specification.
func specBasisRow(row map[string]any) bool {
	basis, _ := row["basis"].(map[string]any)
	_, hasQuote := basis["quote"]
	return row["kind"] == "reject" && hasQuote
}

// rewriteSubject replaces a member statement's subject digest. The member's
// identifier stops recomputing too, which the reader also reports; the cases
// below search for the finding they exist to reach, not for silence elsewhere.
func rewriteSubject(t *testing.T, dir string, row map[string]any, digest string) {
	t.Helper()
	rel := row["file"].(string)
	raw, err := os.ReadFile(filepath.Join(dir, rel)) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	var statement map[string]any
	if err := json.Unmarshal(raw, &statement); err != nil {
		t.Fatal(err)
	}
	subject := statement["subject"].([]any)[0].(map[string]any)
	subject["digest"].(map[string]any)["sha256"] = digest
	body, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, rel, string(body))
}

// rewriteSidecar applies an edit to one line of a member's record sidecar.
func rewriteSidecar(t *testing.T, dir string, row map[string]any, index int, edit func(string) string) {
	t.Helper()
	rel := row["records"].(string)
	raw, err := os.ReadFile(filepath.Join(dir, rel)) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	edited := edit(lines[index])
	if edited == lines[index] {
		t.Fatal("the sidecar edit changed nothing, so this case would assert nothing")
	}
	lines[index] = edited
	writeFile(t, dir, rel, strings.Join(lines, "\n")+"\n")
}

func agentActionChainFindings() []findingCase {
	const dir = "vectors-ai-agent-action"
	const resistant = "compromised-attestor-resistant"
	return []findingCase{
		{"agent-action/basis-missing", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				delete(firstRowWhere(t, m, kindIs("reject")), "basis")
			})
		}, "declares no basis"},
		{"agent-action/basis-on-accept", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				basis := firstRowWhere(t, m, specBasisRow)["basis"]
				firstRowWhere(t, m, kindIs("accept"))["basis"] = basis
			})
		}, "an accept member declares a basis"},
		{"agent-action/basis-quote", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, specBasisRow), "words the text never held", "basis", "quote")
			})
		}, "does not occur in lines"},
		{"agent-action/basis-lines", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, specBasisRow), "99990-99999", "basis", "lines")
			})
		}, "outside the vendored specification"},
		{"agent-action/basis-source", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, specBasisRow), "in-toto/attestation#588@0000000", "basis", "source")
			})
		}, "is neither the vendored specification"},
		{"agent-action/proposal-section", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, func(r map[string]any) bool {
					basis, _ := r["basis"].(map[string]any)
					_, has := basis["section"]
					return has
				})
				setDeep(t, row, "", "basis", "section")
			})
		}, "names no section of proposedText"},
		{"agent-action/profile-undefined", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, profileIs("default"))["profile"] = "nowhere"
			})
		}, "profile \"nowhere\" is not defined"},
		{"agent-action/profile-rule", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				profiles := m["profiles"].(map[string]any)
				profiles[resistant].(map[string]any)["nullPriorHead"] = "sometimes"
			})
		}, "nullPriorHead must be permitted or forbidden"},
		{"agent-action/profile-cites", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				profiles := m["profiles"].(map[string]any)
				cites := profiles[resistant].(map[string]any)["cites"].(map[string]any)
				cites["quote"] = "words the text never held"
			})
		}, "does not occur in lines"},
		{"agent-action/profile-missing", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				delete(firstRowWhere(t, m, profileIs("default")), "profile")
			})
		}, "declares no profile"},
		// The first semantic error: an accept member whose sidecar holds a
		// priorHead-null break, judged under the profile that forbids one.
		{"agent-action/null-under-forbidding-profile", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, conditionIs("aia-c-17", "accept"))["profile"] = resistant
			})
		}, "which that profile forbids"},
		{"agent-action/prohibition-under-permitting-profile", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, conditionIs("aia-c-18", "reject"))["profile"] = "default"
			})
		}, "which does not forbid priorHead null"},
		{"agent-action/prohibition-without-null", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-18", "reject"))
				rewriteSidecar(t, d, row, 0, func(line string) string {
					return strings.Replace(line, `"priorHead":null`,
						`"priorHead":"`+strings.Repeat("a", 64)+`"`, 1)
				})
			})
		}, "carries no chain_break with priorHead null"},
		{"agent-action/profile-twin", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				firstRowWhere(t, m, conditionIs("aia-c-18", "accept"))["profile"] = "default"
			})
		}, "reject conditions with no accepting twin"},
		{"agent-action/break-prior-members", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-17", "accept"))
				rewriteSidecar(t, d, row, 0, func(line string) string {
					return strings.Replace(line, `"priorSequence":null,`, "", 1)
				})
			})
		}, "omits priorSequence"},
		{"agent-action/chain-root", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				setDeep(t, firstRowWhere(t, m, declares("chainRoot")), strings.Repeat("0", 64), "expected", "chainRoot")
			})
		}, "chainRoot does not recompute from the first sidecar record"},
		{"agent-action/root-not-a-root", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-19", "accept"))
				rewriteSidecar(t, d, row, 0, func(line string) string {
					return strings.Replace(line, `"previousHash":"genesis"`,
						`"previousHash":"`+strings.Repeat("b", 64)+`"`, 1)
				})
			})
		}, "is not a root"},
		{"agent-action/accept-subject-not-root", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rewriteSubject(t, d, firstRowWhere(t, m, conditionIs("aia-c-17", "accept")), strings.Repeat("c", 64))
			})
		}, "an accept member's subject digest is not its chain root"},
		{"agent-action/segment-not-break-rooted", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-17", "reject"))
				rewriteSidecar(t, d, row, 0, func(line string) string {
					return strings.Replace(line, `"priorHead":null`,
						`"priorHead":"`+strings.Repeat("a", 64)+`"`, 1)
				})
			})
		}, "is not rooted at a chain_break with priorHead null"},
		// The second semantic error: a "pre-break identifier" that identifies
		// no chain this corpus carries.
		{"agent-action/pre-break-identifier-not-a-chain", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-17", "reject"))
				other := strings.Repeat("d", 64)
				rewriteSubject(t, d, row, other)
				setDeep(t, row, other, "expected", "preBreakIdentifier")
			})
		}, "is not the genesis identifier of any chain this corpus carries"},
		{"agent-action/pre-break-identifier-is-root", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-17", "reject"))
				root := row["expected"].(map[string]any)["chainRoot"]
				setDeep(t, row, root, "expected", "preBreakIdentifier")
			})
		}, "preBreakIdentifier is the segment's own root"},
		{"agent-action/pre-break-identifier-not-carried", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-17", "reject"))
				rewriteSubject(t, d, row, strings.Repeat("e", 64))
			})
		}, "subject digest is not the declared preBreakIdentifier"},
		{"agent-action/pre-break-identifier-missing", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-17", "reject"))
				delete(row["expected"].(map[string]any), "preBreakIdentifier")
			})
		}, "declares no preBreakIdentifier"},
		{"agent-action/re-root-elsewhere", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rewriteSubject(t, d, firstRowWhere(t, m, conditionIs("aia-c-19", "reject")), strings.Repeat("f", 64))
			})
		}, "does not carry the chain hash of the break it re-roots at"},
		{"agent-action/known-head-unlinked", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				row := firstRowWhere(t, m, conditionIs("aia-c-19", "accept"))
				rewriteSidecar(t, d, row, 1, func(line string) string {
					head := line[strings.Index(line, `"priorHead":"`)+len(`"priorHead":"`):]
					return strings.Replace(line, head[:64], strings.Repeat("9", 64), 1)
				})
			})
		}, "no chain_break whose priorHead is the chain hash of the record before it"},
	}
}
