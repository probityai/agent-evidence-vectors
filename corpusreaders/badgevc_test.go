package corpora_test

// The badge credential reader derives every decision from the case alone.
// Swapping one member's case into another must move the derived decision, and
// the reader must report the move.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/probityai/agent-evidence-vectors/corpora"
)

const bvDir = "vectors-badge-vc-verify"

func bvStage(t *testing.T, member, from string) string {
	t.Helper()
	copied := filepath.Join(t.TempDir(), bvDir)
	copyTree(t, corpusPath(bvDir), copied)
	body, err := os.ReadFile(filepath.Join(corpusPath(bvDir), "cases", from, "case.json")) // #nosec G304 -- a test reading its own corpus
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "cases", member, "case.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestBadgeVcCommittedCorpusIsClean(t *testing.T) {
	result, err := corpora.Judge(corpusPath(bvDir))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if !result.OK() || len(result.Members) == 0 {
		t.Fatalf("findings: %v %v", result.Findings, result.Members)
	}
	counts := result.CountsByVerdict()
	if counts["allow"] == 0 || counts["deny"] == 0 {
		t.Fatalf("both verdicts must be present: %v", counts)
	}
}

func TestBadgeVcEachCheckMovesTheVerdict(t *testing.T) {
	denied := map[string]string{
		"contract-id-missing":                         "contract_id_missing",
		"contract-id-unknown":                         "contract_id_unknown",
		"case-status-missing":                         "malformed_case",
		"jws-alg-none":                                "jws_malformed",
		"jws-two-parts":                               "jws_malformed",
		"credential-type-lacks-verifiable-credential": "credential_malformed",
		"credential-issuance-unparseable":             "credential_malformed",
		"issuer-untrusted":                            "issuer_not_trusted",
		"issuer-claim-differs-from-kid":               "issuer_key_binding",
		"kid-fragment-not-an-issuer-key":              "issuer_key_binding",
		"signed-by-stranger-key":                      "signature_invalid",
		"payload-altered-after-signing":               "signature_invalid",
		"not-yet-valid":                               "not_yet_valid",
		"expired-years-ago":                           "expired",
		"expiration-equals-verification-time":         "expired",
		"revoked-in-issuer-store":                     "revoked",
	}
	for from, reason := range denied {
		t.Run("allow-plain with the case of "+from, func(t *testing.T) {
			dir := bvStage(t, "allow-plain", from)
			if got := scDerived(t, dir, "allow-plain"); !strings.Contains(got, "derived deny/"+reason) {
				t.Fatalf("want a derived deny/%s, got %q", reason, got)
			}
		})
	}
	t.Run("a denied member with the conformant case", func(t *testing.T) {
		dir := bvStage(t, "revoked-in-issuer-store", "allow-plain")
		if got := scDerived(t, dir, "revoked-in-issuer-store"); !strings.Contains(got, "derived allow/verified") {
			t.Fatalf("want a derived allow, got %q", got)
		}
	})
}
