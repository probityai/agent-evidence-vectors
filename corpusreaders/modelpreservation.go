package corpusreaders

import (
	"crypto/ed25519"
	"crypto/sha1" // #nosec G505 -- git names a blob by SHA-1; the reader recomputes that name, it does not rely on SHA-1 for integrity
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
)

func init() { register(modelPreservation{}) }

// modelPreservation judges corpora/vectors-model-preservation/. Each member is one signed
// record and the verifier's inputs. A reference record is an in-toto Statement v1 carrying
// the OpenSSF model-signing v1.0 predicate, signed in a DSSE envelope by the endpoint that
// fetched the model, and is checked against the files of a copy someone else kept. A swap
// record names the old model, the new model as its subject, the test set and the verdict,
// signed by whoever made the swap. The reader applies the checks the Python reader applies,
// in the same order, and names the first one that fails:
//
//  1. a signature names a trusted keyid: rejected / signer_not_trusted;
//  2. it verifies over the DSSE pre-authentication encoding: rejected / signature_invalid;
//  3. the payload type, statement type and predicate type are the ones the case asks
//     about: rejected / unexpected_predicate_type.
//
// Reference: the subject digest is the SHA-256 over the resource digests
// (root_digest_inconsistent); the record predates a withdrawal the case names
// (not_established / record_after_withdrawal); the copy's file set equals the record's
// (mismatch / file_missing, file_not_in_record); every file has its recorded digest,
// rebuilding the large-file pointer for a git-lfs-pointer resource (file_digest_mismatch).
//
// Swap: the signer is the swapper (signer_not_swapper); the old model is named by a
// digest or by a service and date (not_established / old_model_not_identified); the test
// set is the required one (mismatch / test_set_not_required); the deployed model is the
// subject (mismatch / deployed_model_not_swapped_in); the verdict is pass (failed /
// swap_failed_test). A passing swap whose old model has no digest is verified with
// swap_passed_old_model_unproven. A record missing a member these checks read is
// rejected / malformed_record.
type modelPreservation struct{}

func (modelPreservation) Suite() string { return "model-preservation/v1" }

const (
	mpPayloadType   = "application/vnd.in-toto+json"
	mpStatementType = "https://in-toto.io/Statement/v1"
	mpReference     = "https://model_signing/signature/v1.0"
	mpSwap          = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/model-swap"
	mpPointer       = "git-lfs-pointer"
)

type mpVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained struct {
		PredicateType        string `json:"predicateType"`
		RootDigestConsistent *bool  `json:"rootDigestConsistent"`
	} `json:"retained"`
}

type mpTrusted struct {
	Key   string `json:"key"`
	KeyID string `json:"keyid"`
	Party string `json:"party"`
}

type mpCase struct {
	Kind            string            `json:"kind"`
	Record          string            `json:"record"`
	Trusted         []mpTrusted       `json:"trusted"`
	Copy            map[string]string `json:"copy"`
	WithdrawnAt     *string           `json:"withdrawnAt"`
	RequiredTestSet map[string]string `json:"requiredTestSet"`
	Deployed        map[string]string `json:"deployed"`
}

type mpEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type mpResource struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Name      string `json:"name"`
}

type mpStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Resources []mpResource `json:"resources"`
		Fetch     *struct {
			FetchedAt string `json:"fetchedAt"`
		} `json:"fetch"`
		Swapper  string         `json:"swapper"`
		OldModel map[string]any `json:"oldModel"`
		TestSet  *struct {
			Digest map[string]string `json:"digest"`
		} `json:"testSet"`
		Verdict string `json:"verdict"`
	} `json:"predicate"`
}

func (modelPreservation) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v mpVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = mpJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func mpJudgeMember(caseDir string, v mpVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c mpCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	var env mpEnvelope
	if err := scReadJSON(caseDir, c.Record, &env); err != nil {
		return append(findings, err.Error())
	}
	if got := mpDecide(caseDir, c, env); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	var st mpStatement
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil || strictUnmarshal(payload, &st) != nil {
		return append(findings, "the record's payload does not decode")
	}
	if st.PredicateType != v.Retained.PredicateType {
		findings = append(findings, "the predicate type is not the one the manifest declares")
	}
	if st.PredicateType == mpReference {
		consistent := len(st.Subject) == 1 && st.Subject[0].Digest["sha256"] == mpRootDigest(st.Predicate.Resources)
		if v.Retained.RootDigestConsistent == nil || *v.Retained.RootDigestConsistent != consistent {
			findings = append(findings, fmt.Sprintf("root digest consistent %t, which the manifest does not declare", consistent))
		}
	}
	return findings
}

func mpRootDigest(resources []mpResource) string {
	h := sha256.New()
	for _, r := range resources {
		raw, err := hex.DecodeString(r.Digest)
		if err != nil {
			return ""
		}
		h.Write(raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mpPointerID(data []byte) string {
	sum := sha256.Sum256(data)
	pointer := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n",
		hex.EncodeToString(sum[:]), len(data))
	h := sha1.New() // #nosec G401 -- the git blob name of the pointer, see the import
	fmt.Fprintf(h, "blob %d\x00%s", len(pointer), pointer)
	return hex.EncodeToString(h.Sum(nil))
}

func mpPAE(payloadType string, body []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(body), body))
}

func mpDecide(caseDir string, c mpCase, env mpEnvelope) scDecision {
	malformed := scDecision{"rejected", "malformed_record"}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return malformed
	}
	trusted := map[string]mpTrusted{}
	for _, t := range c.Trusted {
		trusted[t.KeyID] = t
	}
	var signer *mpTrusted
	named := false
	for _, s := range env.Signatures {
		t, ok := trusted[s.KeyID]
		if !ok {
			continue
		}
		named = true
		key, kerr := hex.DecodeString(t.Key)
		sig, serr := base64.StdEncoding.Strict().DecodeString(s.Sig)
		if kerr == nil && serr == nil && len(key) == ed25519.PublicKeySize &&
			ed25519.Verify(ed25519.PublicKey(key), mpPAE(env.PayloadType, payload), sig) {
			signer = &t
			break
		}
	}
	if signer == nil {
		if named {
			return scDecision{"rejected", "signature_invalid"}
		}
		return scDecision{"rejected", "signer_not_trusted"}
	}
	var st mpStatement
	if strictUnmarshal(payload, &st) != nil {
		return malformed
	}
	want := map[string]string{"reference": mpReference, "swap": mpSwap}[c.Kind]
	if env.PayloadType != mpPayloadType || st.Type != mpStatementType || st.PredicateType != want {
		return scDecision{"rejected", "unexpected_predicate_type"}
	}
	if len(st.Subject) != 1 {
		return malformed
	}
	if c.Kind == "reference" {
		return mpReferenceDecide(caseDir, c, st)
	}
	return mpSwapDecide(c, st, *signer)
}

func mpReferenceDecide(caseDir string, c mpCase, st mpStatement) scDecision {
	res := st.Predicate.Resources
	if len(res) == 0 || st.Predicate.Fetch == nil {
		return scDecision{"rejected", "malformed_record"}
	}
	if st.Subject[0].Digest["sha256"] != mpRootDigest(res) {
		return scDecision{"rejected", "root_digest_inconsistent"}
	}
	if c.WithdrawnAt != nil && st.Predicate.Fetch.FetchedAt >= *c.WithdrawnAt {
		return scDecision{"not_established", "record_after_withdrawal"}
	}
	recorded := map[string]mpResource{}
	names := make([]string, 0, len(res))
	for _, r := range res {
		recorded[r.Name] = r
		names = append(names, r.Name)
	}
	for name := range recorded {
		if _, ok := c.Copy[name]; !ok {
			return scDecision{"mismatch", "file_missing"}
		}
	}
	for name := range c.Copy {
		if _, ok := recorded[name]; !ok {
			return scDecision{"mismatch", "file_not_in_record"}
		}
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := readIn(caseDir, c.Copy[name])
		if err != nil {
			return scDecision{"mismatch", "file_missing"}
		}
		got := sha(data)
		if recorded[name].Algorithm == mpPointer {
			got = mpPointerID(data)
		}
		if got != recorded[name].Digest {
			return scDecision{"mismatch", "file_digest_mismatch"}
		}
	}
	return scDecision{"verified", "copy_matches_record"}
}

func mpSwapDecide(c mpCase, st mpStatement, signer mpTrusted) scDecision {
	p := st.Predicate
	if p.TestSet == nil || p.OldModel == nil {
		return scDecision{"rejected", "malformed_record"}
	}
	if signer.Party != p.Swapper {
		return scDecision{"rejected", "signer_not_swapper"}
	}
	digest, hasDigest := p.OldModel["digest"].(map[string]any)
	if hasDigest {
		_, hasDigest = digest["sha256"].(string)
	}
	_, hasService := p.OldModel["service"].(string)
	_, hasDate := p.OldModel["observedOn"].(string)
	if !hasDigest && !(hasService && hasDate) {
		return scDecision{"not_established", "old_model_not_identified"}
	}
	if !mpSameDigest(p.TestSet.Digest, c.RequiredTestSet) {
		return scDecision{"mismatch", "test_set_not_required"}
	}
	if !mpSameDigest(st.Subject[0].Digest, c.Deployed) {
		return scDecision{"mismatch", "deployed_model_not_swapped_in"}
	}
	if p.Verdict != "pass" {
		return scDecision{"failed", "swap_failed_test"}
	}
	if _, ok := p.OldModel["digest"].(map[string]any); !ok {
		return scDecision{"verified", "swap_passed_old_model_unproven"}
	}
	return scDecision{"verified", "swap_passed"}
}

func mpSameDigest(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
