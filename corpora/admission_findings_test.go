package corpora_test

import (
	"os"
	"path/filepath"
	"testing"
)

// admissionFindings provokes every finding the admission reader can report,
// one change per case.
func admissionFindings() []findingCase {
	const dir = "vectors-admission"
	edit := func(f func(t *testing.T, d string, m map[string]any)) func(t *testing.T, d string) {
		return func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { f(t, d, m) })
		}
	}
	first := func(m map[string]any, kind string) map[string]any {
		for _, item := range vectorsOf(m) {
			if row := item.(map[string]any); row["kind"] == kind {
				return row
			}
		}
		return nil
	}
	write := func(t *testing.T, d, rel, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(d, rel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return []findingCase{
		{"adm/counts", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0, "gap": 1.0}
		}), "counts[accept] is 1"},
		{"adm/counts-extra-kind", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["counts"].(map[string]any)["gap"] = 1.0
		}), "counts declares kind gap that no member carries"},
		{"adm/corpus-digest", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["corpusDigest"] = zeros()
		}), "corpus digest over the files on disk is"},
		{"adm/statement-missing", dir, edit(func(t *testing.T, d string, m map[string]any) {
			removeFile(t, d, first(m, "accept")["file"].(string))
		}), "statement unreadable"},
		{"adm/policy-missing", dir, edit(func(t *testing.T, d string, m map[string]any) {
			removeFile(t, d, first(m, "reject")["policy"].(string))
		}), "policy unreadable"},
		{"adm/policy-refused", dir, edit(func(t *testing.T, d string, m map[string]any) {
			write(t, d, first(m, "accept")["policy"].(string), `{"expectedSubjectDigests":"x"}`)
		}), "policy refused"},
		{"adm/no-expectation", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			delete(first(m, "accept")["expected"].(map[string]any), "admitted")
		}), "declares no expected admission answer"},
		{"adm/kind-disagrees", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			first(m, "accept")["kind"] = "reject"
		}), "disagrees with expected admitted=true"},
		{"adm/answer", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			row := first(m, "reject")
			row["kind"] = "accept"
			row["expected"].(map[string]any)["admitted"] = true
		}), "admitted=false, the manifest declares true"},
		{"adm/codes", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			first(m, "reject")["expected"].(map[string]any)["policyCodes"] = []any{"no-such-code"}
		}), "the manifest declares [no-such-code]"},
		{"adm/invalid-statement", dir, edit(func(t *testing.T, d string, m map[string]any) {
			write(t, d, first(m, "accept")["file"].(string), `{"_type":"x"}`)
		}), "every member of this corpus is a valid statement"},
		{"adm/undefined-condition", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			first(m, "accept")["conditions"] = []any{"adm-c-99"}
		}), "cites condition adm-c-99, which the manifest does not define"},
		{"adm/one-sided-condition", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			for _, item := range vectorsOf(m) {
				if row := item.(map[string]any); row["kind"] == "accept" {
					row["conditions"] = []any{}
				}
			}
		}), "is not carried by both an admitted and a refused member"},
		{"adm/quote-gone", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			cond := m["conditions"].(map[string]any)["adm-c-1"].(map[string]any)
			cond["quote"] = "a sentence no specification carries"
		}), "quotes a sentence"},
		{"adm/cited-file-gone", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			cond := m["conditions"].(map[string]any)["adm-c-1"].(map[string]any)
			cond["file"] = "spec/no-such-file.md"
		}), "which cannot be read"},
	}
}
