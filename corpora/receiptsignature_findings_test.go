package corpora_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// receiptSignatureFindings provokes every finding the receipt-signature reader
// can report, one change per case.
func receiptSignatureFindings() []findingCase {
	const dir = "vectors-receipt-signature"
	edit := func(f func(t *testing.T, d string, m map[string]any)) func(t *testing.T, d string) {
		return func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) { f(t, d, m) })
		}
	}
	cases := []findingCase{
		{"rs/counts", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["counts"] = map[string]any{"accept": 1.0, "reject": 1.0}
		}), "counts disagree"},
		{"rs/corpus-digest", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["corpusDigest"] = zeros()
		}), "corpusDigest does not match the receipt files on disk"},
		{"rs/spec-digest", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["specDigest"] = zeros()
		}), "does not match its pinned digest"},
		{"rs/spec-missing", dir, edit(func(t *testing.T, d string, m map[string]any) {
			removeFile(t, d, m["specVendored"].(string))
		}), "is missing, so nothing records what this corpus certifies against"},
		{"rs/contract-missing", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["contract"] = "NO-SUCH-CONTRACT.md"
		}), "names the verifier contract at"},
	}
	cases = append(cases, rsRequirementFindings(dir, edit)...)
	cases = append(cases, rsKeySetFindings(dir, edit)...)
	cases = append(cases, rsDeclarationFindings(dir, edit)...)
	cases = append(cases, rsMemberFindings(dir, edit)...)
	return append(cases, rsCorpusFindings(dir, edit)...)
}

type rsEdit = func(f func(t *testing.T, d string, m map[string]any)) func(t *testing.T, d string)

func zeros() string {
	return "0000000000000000000000000000000000000000000000000000000000000000"
}

func rsList(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	list, ok := m[key].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("the manifest carries no %s to edit", key)
	}
	return list
}

func rsFirstRequirement(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	return rsList(t, m, "requirements")[0].(map[string]any)
}

func rsRequirementFindings(dir string, edit rsEdit) []findingCase {
	return []findingCase{
		{"rs/requirement-twice", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			m["requirements"] = append(rsList(t, m, "requirements"), rsFirstRequirement(t, m))
		}), "is declared twice"},
		{"rs/requirement-not-in-text", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsFirstRequirement(t, m)["sentence"] = "Verifiers MUST do something the draft never says."
		}), "quotes a sentence the vendored specification does not contain"},
		{"rs/requirement-digest", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsFirstRequirement(t, m)["sentenceDigest"] = zeros()
		}), "has a sentenceDigest that is not the digest of its sentence"},
		{"rs/requirement-level-unknown", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsFirstRequirement(t, m)["level"] = "MAY"
		}), `declares level "MAY"`},
		{"rs/requirement-level-unsaid", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsFirstRequirement(t, m)["level"] = "SHOULD"
		}), "and its sentence does not say SHOULD"},
	}
}

func rsKeySetPath(t *testing.T, m map[string]any, name string) string {
	t.Helper()
	sets := m["keySets"].(map[string]any)
	return sets[name].(map[string]any)["file"].(string)
}

// rsRewriteKeys edits one key set on disk.
func rsRewriteKeys(t *testing.T, d, rel string, f func(keys []any) []any) {
	t.Helper()
	path := filepath.Join(d, rel)
	raw, err := os.ReadFile(path) // #nosec G304 -- a test editing its own copy
	if err != nil {
		t.Fatal(err)
	}
	var set map[string]any
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	set["keys"] = f(set["keys"].([]any))
	out, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, d, rel, string(out))
}

func rsKeySetFindings(dir string, edit rsEdit) []findingCase {
	keysEdit := func(name string, f func(keys []any) []any) func(t *testing.T, d string) {
		return edit(func(t *testing.T, d string, m map[string]any) {
			rsRewriteKeys(t, d, rsKeySetPath(t, m, name), f)
		})
	}
	return []findingCase{
		{"rs/keyset-missing", dir, edit(func(t *testing.T, d string, m map[string]any) {
			removeFile(t, d, rsKeySetPath(t, m, "withWindows"))
		}), "key set keys/jwks.json cannot be read"},
		{"rs/keyset-digest", dir, keysEdit("withWindows", func(keys []any) []any { return keys }),
			"key set keys/jwks.json does not match its pinned digest"},
		{"rs/keyset-unparsed", dir, edit(func(t *testing.T, d string, m map[string]any) {
			writeFile(t, d, rsKeySetPath(t, m, "withoutWindows"), "not json")
		}), "key set keys/jwks-no-window.json does not parse"},
		{"rs/keyset-kid-twice", dir, keysEdit("withWindows", func(keys []any) []any {
			return append(keys, keys[0])
		}), "names key sb:issuer:"},
		{"rs/keyset-disagree", dir, keysEdit("withoutWindows", func(keys []any) []any {
			keys[0].(map[string]any)["x"] = "AAAA"
			return keys
		}), "the key sets disagree on key"},
		{"rs/keyset-sizes", dir, keysEdit("withoutWindows", func(keys []any) []any {
			return keys[:1]
		}), "the key sets carry 2 and 1 keys"},
		{"rs/keyset-bare-windowed", dir, keysEdit("withoutWindows", func(keys []any) []any {
			keys[0].(map[string]any)["valid_until"] = "2026-06-01T00:00:00Z"
			return keys
		}), "the windowless key set carries a window on key"},
		{"rs/keyset-no-window", dir, keysEdit("withWindows", func(keys []any) []any {
			for _, k := range keys {
				delete(k.(map[string]any), "valid_from")
				delete(k.(map[string]any), "valid_until")
			}
			return keys
		}), "the two passes are the same pass"},
	}
}

func rsRow(t *testing.T, m map[string]any, kind string) map[string]any {
	t.Helper()
	return firstRowWhere(t, m, kindIs(kind))
}

func rsRejectWithCode(code string) func(map[string]any) bool {
	return func(row map[string]any) bool {
		expected, _ := row["expected"].(map[string]any)
		return row["kind"] == "reject" && expected["code"] == code
	}
}

func rsDeclarationFindings(dir string, edit rsEdit) []findingCase {
	valid := map[string]any{"verdict": "valid", "code": nil}
	return []findingCase{
		{"rs/duplicate-id", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			m["vectors"] = append(rsList(t, m, "vectors"), rsRow(t, m, "accept"))
		}), "duplicate identifier"},
		{"rs/no-condition", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["conditions"] = []any{}
		}), "cites no condition"},
		{"rs/undefined-condition", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["conditions"] = []any{"rs-c-nope"}
		}), "the manifest does not define"},
		{"rs/unregistered-code", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			setDeep(t, rsRow(t, m, "reject"), "nope", "expected", "code")
		}), "the code registry does not define"},
		{"rs/accept-not-valid", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			setDeep(t, rsRow(t, m, "accept"), "invalid", "expected", "verdict")
		}), "accept member expecting something other than valid"},
		{"rs/accept-second-outcome", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "accept")["expectedIfNotHonoured"] = valid
		}), "is an accept member carrying expectedIfNotHonoured"},
		{"rs/reject-valid-without-windows", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["expectedWithoutWindows"] = valid
		}), "not expected invalid in both passes"},
		{"rs/reject-without-must", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["conditions"] = []any{"rs-c-2"}
		}), "citing no MUST"},
		{"rs/reject-second-outcome", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["expectedIfNotHonoured"] = valid
		}), "is a reject member carrying expectedIfNotHonoured"},
		{"rs/indeterminate-cites-must", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "indeterminate")["conditions"] = []any{"rs-c-1"}
		}), "do not cite only SHOULD-level requirements"},
		{"rs/indeterminate-one-outcome", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			delete(rsRow(t, m, "indeterminate"), "expectedIfNotHonoured")
		}), "with no expectedIfNotHonoured"},
		{"rs/indeterminate-outcomes", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			setDeep(t, rsRow(t, m, "indeterminate"), "invalid", "expectedIfNotHonoured", "verdict")
		}), "two outcomes are not invalid when honoured and valid when not"},
		{"rs/indeterminate-invalid-bare", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			setDeep(t, rsRow(t, m, "indeterminate"), "invalid", "expectedWithoutWindows", "verdict")
		}), "expected invalid without the windows"},
		{"rs/unknown-kind", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["kind"] = "maybe"
		}), `declares kind "maybe"`},
	}
}

func rsMemberFindings(dir string, edit rsEdit) []findingCase {
	return []findingCase{
		{"rs/file-gone", dir, edit(func(t *testing.T, d string, m map[string]any) {
			removeFile(t, d, rsRow(t, m, "reject")["file"].(string))
		}), "names a receipt file that does not exist"},
		{"rs/identifier", dir, func(t *testing.T, d string) {
			editManifest(t, d, func(m map[string]any) {
				rel := firstRowWhere(t, m, rsRejectWithCode("signature_in_signing_input"))["file"].(string)
				raw, err := os.ReadFile(filepath.Join(d, rel)) // #nosec G304 -- a test editing its own copy
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, d, rel, string(raw)+"\n")
			})
		}, "identifier does not recompute from the receipt's own bytes"},
		{"rs/windowed-outcome", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			setDeep(t, rsRow(t, m, "indeterminate"), "signature_invalid", "expected", "code")
		}), "with the windowed key set the reference verification is"},
		{"rs/bare-outcome", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			row := firstRowWhere(t, m, rsRejectWithCode("signature_invalid"))
			setDeep(t, row, "signature_in_signing_input", "expectedWithoutWindows", "code")
		}), "without the windows the reference verification is"},
		{"rs/key-id", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "accept")["keyId"] = "sb:issuer:nobody"
		}), "keyId is not the kid the receipt's signature names"},
		{"rs/signed-input-not-hex", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "accept")["signedInputHex"] = "zz"
		}), "signedInputHex is not hex"},
		{"rs/signed-input-unsigned", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "accept")["signedInputHex"] = "00"
		}), "the signature does not verify over signedInputHex"},
		{"rs/signed-input-not-jcs", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			rsRow(t, m, "reject")["kind"] = "accept"
		}), "its signedInputHex is not JCS(payload)"},
	}
}

func rsCorpusFindings(dir string, edit rsEdit) []findingCase {
	return []findingCase{
		{"rs/orphan-condition", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			var kept []any
			for _, item := range rsList(t, m, "vectors") {
				row := item.(map[string]any)
				conditions, _ := row["conditions"].([]any)
				if row["kind"] == "accept" && len(conditions) == 1 && conditions[0] == "rs-c-4" {
					continue
				}
				kept = append(kept, row)
			}
			m["vectors"] = kept
		}), "conditions that are refused and never accepted"},
		{"rs/idle-condition", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			m["conditions"].(map[string]any)["rs-c-9"] = map[string]any{"requirements": []any{"RS-R-001"}}
		}), "conditions declared and carried by no member"},
		{"rs/undeclared-requirement", dir, edit(func(_ *testing.T, _ string, m map[string]any) {
			cond := m["conditions"].(map[string]any)["rs-c-1"].(map[string]any)
			cond["requirements"] = []any{"RS-R-001", "RS-R-009"}
		}), "cites requirement RS-R-009 the manifest does not declare"},
		{"rs/uncited-requirement", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			extra := map[string]any{}
			for k, v := range rsFirstRequirement(t, m) {
				extra[k] = v
			}
			extra["id"] = "RS-R-009"
			m["requirements"] = append(rsList(t, m, "requirements"), extra)
		}), "requirements declared and cited by no condition"},
		{"rs/origin-unknown-member", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			origin := m["origin"].(map[string]any)
			rsList(t, origin, "members")[0].(map[string]any)["id"] = "v0000000000000000"
		}), "and the manifest has no such member"},
		{"rs/origin-not-upstream", dir, edit(func(t *testing.T, _ string, m map[string]any) {
			origin := m["origin"].(map[string]any)
			rsList(t, origin, "members")[0].(map[string]any)["sha256"] = zeros()
		}), "is not the upstream bytes of"},
	}
}
