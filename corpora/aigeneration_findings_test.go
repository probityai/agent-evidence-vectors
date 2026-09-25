package corpora_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every refusal the AI generation reader can report, provoked by one change to
// a staged copy. Rows are picked by what they declare, never by identifier,
// because an identifier is a digest and moves with the bytes.

const agDir = "vectors-ai-generation"

func agCarries(condition string) func(map[string]any) bool {
	return func(row map[string]any) bool {
		carried, _ := row["conditions"].([]any)
		for _, c := range carried {
			if c == condition {
				return true
			}
		}
		return false
	}
}

func agFormIs(form string) func(map[string]any) bool {
	return func(row map[string]any) bool { return row["form"] == form }
}

func agAll(picks ...func(map[string]any) bool) func(map[string]any) bool {
	return func(row map[string]any) bool {
		for _, pick := range picks {
			if !pick(row) {
				return false
			}
		}
		return true
	}
}

// agRowField reads one string field of the first row a picker selects.
func agRowField(t *testing.T, dir string, pick func(map[string]any) bool, field string) string {
	t.Helper()
	var value string
	editManifest(t, dir, func(m map[string]any) {
		value, _ = firstRowWhere(t, m, pick)[field].(string)
	})
	if value == "" {
		t.Fatalf("the selected row carries no %q", field)
	}
	return value
}

func agEdit(pick func(map[string]any) bool, edit func(t *testing.T, row map[string]any)) func(*testing.T, string) {
	return func(t *testing.T, d string) {
		editManifest(t, d, func(m map[string]any) { edit(t, firstRowWhere(t, m, pick)) })
	}
}

func agWriteMember(pick func(map[string]any) bool, body string) func(*testing.T, string) {
	return func(t *testing.T, d string) {
		writeFile(t, d, agRowField(t, d, pick, "file"), body)
	}
}

func agProposalText(t *testing.T, d, body string) {
	t.Helper()
	path := filepath.Join(filepath.Dir(d), "docs", "proposals", "ai-generation-v01-findings.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func aiGenerationFindings() []findingCase {
	reject := kindIs("reject")
	accept := agAll(kindIs("accept"), agFormIs("attestation"))
	golden := agFormIs("statement")
	signoffs := declares("distinctSignoffKeys")
	overlap := agAll(kindIs("proposed"), agCarries("ofg-p-6"))
	return []findingCase{
		{"ag/unknown-kind", agDir, agEdit(reject, func(t *testing.T, r map[string]any) { r["kind"] = "maybe" }),
			"which this reader does not grade"},
		{"ag/no-condition", agDir, agEdit(reject, func(t *testing.T, r map[string]any) { r["conditions"] = []any{} }),
			"cites no condition"},
		{"ag/undeclared-condition", agDir, agEdit(reject, func(t *testing.T, r map[string]any) {
			r["conditions"] = []any{"ofg-c-nope"}
		}), "the manifest does not define"},
		{"ag/no-parent", agDir, agEdit(reject, func(t *testing.T, r map[string]any) { delete(r, "parent") }),
			"names no parent"},
		{"ag/parent-not-a-member", agDir, agEdit(reject, func(t *testing.T, r map[string]any) {
			r["parent"] = "vnotamemberatall"
		}), "which is not a member"},
		{"ag/parent-not-accept", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				other, _ := firstRowWhere(t, m, kindIs("proposed"))["id"].(string)
				firstRowWhere(t, m, reject)["parent"] = other
			})
		}, "which is not an accept member"},
		{"ag/missing-member-file", agDir, func(t *testing.T, d string) {
			removeFile(t, d, agRowField(t, d, reject, "file"))
		}, "the member file is missing"},
		{"ag/missing-trailer", agDir, func(t *testing.T, d string) {
			removeFile(t, d, agRowField(t, d, declaresTrailer, "trailer"))
		}, "the trailer file is missing"},
		{"ag/identifier", agDir, agWriteMember(reject, "{}\n"),
			"identifier does not recompute"},
		{"ag/unknown-form", agDir, agEdit(reject, func(t *testing.T, r map[string]any) { r["form"] = "blob" }),
			"neither statement nor attestation"},
		{"ag/golden-kind", agDir, agEdit(golden, func(t *testing.T, r map[string]any) { r["kind"] = "proposed" }),
			"the golden member is not an accept member"},
		{"ag/golden-declaration", agDir, agEdit(golden, func(t *testing.T, r map[string]any) {
			setDeep(t, r, strings.Repeat("0", 64), "expected", "canonicalSha256")
		}), "does not declare the length and sha256"},
		{"ag/golden-pin", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				pin, _ := m["goldenSource"].(map[string]any)
				pin["canonicalSha256"] = strings.Repeat("0", 64)
			})
		}, "not the pinned"},
		{"ag/golden-unparseable", agDir, agWriteMember(golden, "{"), "the golden statement does not parse"},
		{"ag/golden-out-of-domain", agDir, agWriteMember(golden, `{"n":1}`),
			"the golden statement does not canonicalize"},
		{"ag/golden-orders-differ", agDir, agWriteMember(golden, "{\"｡\":\"a\",\"\U0001f600\":\"b\"}"),
			"code-point form and its RFC 8785 form differ"},
		{"ag/not-an-envelope", agDir, agWriteMember(reject, "[]"), "not an attestation envelope"},
		{"ag/statement-not-object", agDir, agWriteMember(reject, `{"statement":"x"}`),
			"the statement is not a JSON object"},
		{"ag/artifact-file-missing", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				artifacts, _ := firstRowWhere(t, m, accept)["artifacts"].([]any)
				first, _ := artifacts[0].(map[string]any)
				first["file"] = "artifacts/absent.txt"
			})
		}, "the artifact file is missing"},
		{"ag/accept-refused", agDir, agEdit(accept, func(t *testing.T, r map[string]any) { r["artifacts"] = []any{} }),
			"an accept member that revision 0.1.3 refuses"},
		{"ag/accept-refused-by-proposal", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				other, _ := firstRowWhere(t, m, agAll(declaresTrailer, kindIs("proposed")))["trailer"].(string)
				firstRowWhere(t, m, agAll(declaresTrailer, kindIs("accept")))["trailer"] = other
			})
		}, "an accept member that the proposal refuses"},
		{"ag/reject-without-code", agDir, agEdit(reject, func(t *testing.T, r map[string]any) {
			setDeep(t, r, "", "expected", "code")
		}), "declares no invalid verdict and code"},
		{"ag/reject-wrong-code", agDir, agEdit(reject, func(t *testing.T, r map[string]any) {
			setDeep(t, r, "a-code-no-rule-emits", "expected", "code")
		}), "under revision 0.1.3, got"},
		{"ag/proposed-half-declared", agDir, agEdit(overlap, func(t *testing.T, r map[string]any) {
			expected, _ := r["expected"].(map[string]any)
			delete(expected, "rev013")
		}), "does not declare both"},
		{"ag/proposed-wrong-proposal", agDir, agEdit(overlap, func(t *testing.T, r map[string]any) {
			setDeep(t, r, map[string]any{"verdict": "invalid", "code": "trailer-disagrees"},
				"expected", "proposal")
		}), "under the proposal, got"},
		{"ag/proposed-same-outcomes", agDir, agEdit(overlap, func(t *testing.T, r map[string]any) {
			setDeep(t, r, map[string]any{"verdict": "valid"}, "expected", "proposal")
		}), "the proposal changes nothing"},
		{"ag/signoffs-undeclared", agDir, agEdit(signoffs, func(t *testing.T, r map[string]any) {
			expected, _ := r["expected"].(map[string]any)
			delete(expected, "distinctSignoffKeys")
		}), "declares no distinctSignoffKeys"},
		{"ag/signoffs-miscounted", agDir, agEdit(signoffs, func(t *testing.T, r map[string]any) {
			setDeep(t, r, 5.0, "expected", "distinctSignoffKeys")
		}), "distinct sign-off keys and carries"},
		{"ag/mode", agDir, agEdit(declares("mode"), func(t *testing.T, r map[string]any) {
			setDeep(t, r, "conformance", "expected", "mode")
		}), "declares mode"},
		{"ag/acceptance", agDir, agEdit(declares("acceptance"), func(t *testing.T, r map[string]any) {
			setDeep(t, r, "conformant", "expected", "acceptance")
		}), "can only report it as self-reported"},
		{"ag/predicate-type", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["predicateType"] = "https://example.invalid/p" })
		}, "is not the generation predicate's type"},
		{"ag/vendored-drift", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["schemaDigest"] = strings.Repeat("0", 64) })
		}, "does not match its pinned digest"},
		{"ag/counts", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0, "proposed": 1.0}
			})
		}, "counts disagree"},
		{"ag/corpus-digest", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["corpusDigest"] = strings.Repeat("0", 64) })
		}, "corpusDigest does not recompute"},
		{"ag/refused-never-accepted", agDir, agEdit(agAll(kindIs("accept"), agCarries("ofg-c-6")),
			func(t *testing.T, r map[string]any) { r["conditions"] = []any{"ofg-c-7"} }),
			"conditions refused and never accepted"},
		{"ag/proposal-refuses-never-accepts", agDir, agEdit(agAll(kindIs("accept"), agCarries("ofg-p-6")),
			func(t *testing.T, r map[string]any) { r["conditions"] = []any{"ofg-p-7"} }),
			"conditions the proposal refuses and never accepts"},
		{"ag/idle-condition", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				conditions, _ := m["conditions"].(map[string]any)
				conditions["ofg-c-idle"] = map[string]any{"requires": "nothing carries this"}
			})
		}, "conditions declared and carried by no member"},
		{"ag/no-vectors", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["vectors"] = []any{} })
		}, "carries no vectors"},
		{"ag/manifest-shape", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { m["counts"] = "not an object" })
		}, "does not parse"},
		{"ag/no-proposed-text", agDir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { delete(m, "proposedText") })
		}, "names no proposedText"},
		{"ag/proposed-text-missing", agDir, func(*testing.T, string) {},
			"is missing or unreadable"},
		{"ag/proposed-text-stale", agDir, func(t *testing.T, d string) {
			agProposalText(t, d, "The member vdeadbeefdeadbeef shows it.\n")
		}, "which are not members of this corpus"},
	}
}

// declaresTrailer picks a row that ships a commit-message sidecar.
func declaresTrailer(row map[string]any) bool {
	_, has := row["trailer"]
	return has
}
