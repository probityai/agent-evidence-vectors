package corpusreaders

// The dimension-exercising members, read independently of the manifest. The
// committed-corpus test already holds every declared status to the bytes; this
// one pins the statuses the corpus is built to exercise, so a manifest that is
// later loosened (a declared dimension deleted, a code blanked) cannot make the
// reader's reading of those members unobserved.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOCSFDecisionExercisedDimensions(t *testing.T) {
	type want struct {
		verdict, code string
		dims          map[string]string
	}
	cases := map[string]want{
		"baseline-published-signed-pair": {"accept", "", map[string]string{
			"fingerprint": "verified", "signature": "verified", "key_binding": "verified", "chain_links": "verified", "tail": "not_checked"}},
		"baseline-published-duplicate-member-rides-seal": {"reject", "structural_validity:failed", map[string]string{
			"structural_validity": "failed"}},
		"baseline-key-id-swapped": {"reject", "key_binding:failed", map[string]string{
			"signature": "verified", "key_binding": "failed"}},
		"baseline-resigned-under-retired-key": {"reject", "key_binding:failed", map[string]string{
			"signature": "verified", "key_binding": "failed"}},
		"baseline-tail-dropped-with-head": {"reject", "tail:failed", map[string]string{"tail": "failed"}},
		"baseline-tail-dropped-no-head": {"accept", "", map[string]string{
			"tail": "not_checked", "chain_links": "verified"}},
		"strict-chain-complete": {"accept", "", map[string]string{
			"strict.signature_required": "verified", "strict.key_named_by_signed_bytes": "verified",
			"strict.tail_anchored": "verified", "strict.opening_supplied": "verified", "strict.numbers_interoperable": "verified"}},
		"strict-epoch-a-double-cannot-hold": {"reject", "numbers_interoperable:failed", map[string]string{
			"strict.numbers_interoperable": "failed"}},
		"strict-opening-not-supplied": {"reject", "opening_supplied:unavailable", map[string]string{
			"strict.opening_supplied": "unavailable"}},
	}
	dir := filepath.Join("..", "corpora", "vectors-ocsf-decision", "members")
	for id, w := range cases {
		t.Run(id, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(dir, id+".json")) // #nosec G304 -- committed member
			if err != nil {
				t.Fatal(err)
			}
			value, err := ocsfParse(string(body))
			if err != nil {
				t.Fatal(err)
			}
			member := value.(map[string]any)
			profile, _ := member["profile"].(string)
			rep := ocsfRead(member["records"].(string), member["trust_policy"], member["relying_party"])
			verdict, code := ocsfVerdict(rep, profile)
			if verdict != w.verdict || code != w.code {
				t.Errorf("read %s %q, want %s %q (%s)", verdict, code, w.verdict, w.code, ocsfSummary(rep))
			}
			for name, status := range w.dims {
				got := rep.dims[name]
				if len(name) > 7 && name[:7] == "strict." {
					got = rep.strict[name[7:]]
				}
				if got.status != status {
					t.Errorf("%s: read %s, want %s (%s)", name, got.status, status, ocsfSummary(rep))
				}
			}
			t.Logf("%s => %s %q | %s", id, verdict, code, ocsfSummary(rep))
		})
	}
}
