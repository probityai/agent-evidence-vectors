package corpusreaders

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
)

func init() { register(keyRevocation{}) }

// keyRevocation judges corpora/vectors-key-revocation-list/. Each member is one signed
// list of revoked keys, the verifier's trust inputs and clock, and one question: is this
// key revoked at this time? The reader applies the checks the Python reader applies, in
// the same order, and names the first one that fails:
//
//  1. the list's signing key is trusted, chosen by the thumbprint of the key itself and
//     never by the one the list claims: rejected / signer_not_trusted;
//  2. the list verifies under that key: rejected / list_signature_invalid;
//  3. the list was not issued before the last list accepted:
//     rejected / list_older_than_accepted;
//  4. the verifier's clock is not past the list's next update: stale / list_stale.
//
// A list that passes is read with the revocations already seen, which a later list cannot
// remove. A key effective at the time asked is revoked; a key with a later effective time
// is not_revoked until then; a covered key with no entry is not_revoked; an uncovered key
// no earlier list revoked is no_statement. The reader also recomputes each member's
// declared signature facts from the stored bytes.
type keyRevocation struct{}

func (keyRevocation) Suite() string { return "key-revocation-list/v1" }

type krVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained struct {
		SignerThumbprintHonest           *bool `json:"signerThumbprintHonest"`
		SignatureVerifiesUnderCarriedKey *bool `json:"signatureVerifiesUnderCarriedKey"`
	} `json:"retained"`
}

type krEntry struct {
	EffectiveFrom string `json:"effectiveFrom"`
	Thumbprint    string `json:"thumbprint"`
}

type krCase struct {
	List  string `json:"list"`
	Now   string `json:"now"`
	Prior struct {
		AcceptedIssuedAt *string   `json:"acceptedIssuedAt"`
		Seen             []krEntry `json:"seen"`
	} `json:"prior"`
	Query struct {
		At  string `json:"at"`
		Key string `json:"key"`
	} `json:"query"`
	Trusted []string `json:"trusted"`
}

type krBody struct {
	IssuedAt    string    `json:"issuedAt"`
	KeysCovered []string  `json:"keysCovered"`
	NextUpdate  string    `json:"nextUpdate"`
	Revoked     []krEntry `json:"revoked"`
}

type krEnvelope struct {
	List   json.RawMessage `json:"list"`
	Sig    string          `json:"sig"`
	Signer struct {
		Key        string `json:"key"`
		Thumbprint string `json:"thumbprint"`
	} `json:"signer"`
}

func (keyRevocation) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v krVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = krJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func krJudgeMember(caseDir string, v krVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c krCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	var env krEnvelope
	if err := scReadJSON(caseDir, c.List, &env); err != nil {
		return append(findings, err.Error())
	}
	key, err := hex.DecodeString(env.Signer.Key)
	if err != nil {
		return append(findings, "the list's signer key is not hex")
	}
	var body krBody
	if err := json.Unmarshal(env.List, &body); err != nil {
		return append(findings, fmt.Sprintf("the list does not parse: %v", err))
	}
	if got := krDecide(c, env, body, key); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	honest := env.Signer.Thumbprint == krThumbprint(key)
	signed := acSigned(env.List, env.Sig, key)
	if krFact(v.Retained.SignerThumbprintHonest) != fmt.Sprintf("%t", honest) ||
		krFact(v.Retained.SignatureVerifiesUnderCarriedKey) != fmt.Sprintf("%t", signed) {
		findings = append(findings, fmt.Sprintf(
			"signer thumbprint honest %t and signature verifies %t, which the manifest does not declare", honest, signed))
	}
	return findings
}

func krThumbprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func krDecide(c krCase, env krEnvelope, body krBody, key []byte) scDecision {
	if !krContains(c.Trusted, krThumbprint(key)) {
		return scDecision{"rejected", "signer_not_trusted"}
	}
	if !acSigned(env.List, env.Sig, key) {
		return scDecision{"rejected", "list_signature_invalid"}
	}
	if last := c.Prior.AcceptedIssuedAt; last != nil && body.IssuedAt < *last {
		return scDecision{"rejected", "list_older_than_accepted"}
	}
	if c.Now > body.NextUpdate {
		return scDecision{"stale", "list_stale"}
	}
	return krRead(c, body)
}

func krRead(c krCase, body krBody) scDecision {
	entries := map[string]string{}
	for _, e := range body.Revoked {
		entries[e.Thumbprint] = e.EffectiveFrom
	}
	kept := map[string]string{}
	for _, e := range c.Prior.Seen {
		kept[e.Thumbprint] = e.EffectiveFrom
	}
	key, at := c.Query.Key, c.Query.At
	if from, ok := entries[key]; ok && from <= at {
		return scDecision{"revoked", "revoked_in_list"}
	}
	if from, ok := kept[key]; ok && from <= at {
		return scDecision{"revoked", "revoked_kept_from_earlier_list"}
	}
	_, inList := entries[key]
	_, inKept := kept[key]
	if inList || inKept {
		return scDecision{"not_revoked", "revocation_not_yet_effective"}
	}
	if !krContains(body.KeysCovered, key) {
		return scDecision{"no_statement", "key_not_covered"}
	}
	return scDecision{"not_revoked", "covered_no_entry"}
}

func krFact(b *bool) string {
	if b == nil {
		return "absent"
	}
	return fmt.Sprintf("%t", *b)
}

func krContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
