package corpusreaders

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func init() { register(statusReceipt{}) }

// statusReceipt judges corpora/vectors-status-receipt-binding/. Each member is an
// agent credential and an authority's status receipt for it, both DSSE envelopes
// signed with Ed25519, and case.json naming the check time and the authority's
// public key. The reader derives each member's decision with the checks the
// Python reader applies, in the same order, and names the first one that fails:
//
//  1. the receipt has its payload type, one signature, exactly its four members,
//     a known status and an ordered window: receipt_malformed;
//  2. the receipt's signature verifies under the authority key:
//     receipt_signature_invalid;
//  3. the receipt names the credential by digest: receipt_unbound;
//  4. the credential has its payload type, exactly its four members, a sorted
//     duplicate-free capability list and Ed25519 keys with distinct kids:
//     credential_malformed;
//  5. every credential signature verifies under the key its keyid names in the
//     credential's own list: credential_signature_invalid;
//  6. the receipt names the credential's id: credential_id_mismatch;
//  7. the receipt's digest is the SHA-256 of the credential payload bytes:
//     credential_digest_mismatch;
//  8. the check time is in the window: receipt_not_yet_valid, receipt_expired;
//  9. the status is active: credential_not_active.
//
// The reader also recomputes each member's two declared signature properties and
// its sharedReceipt list, because the corpus's claim is that the unbound rejects
// carry signatures that verify and, for four of them, the control's own receipt.
type statusReceipt struct{}

func (statusReceipt) Suite() string { return "status-receipt-binding/v1" }

const (
	srbCredentialType = "application/vnd.agent-evidence.agent-credential+json"
	srbReceiptType    = "application/vnd.agent-evidence.credential-status-receipt+json"
)

var (
	srbTime  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	srbHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type srbVector struct {
	ID                          string            `json:"id"`
	Path                        string            `json:"path"`
	Files                       map[string]string `json:"files"`
	Expected                    scDecision        `json:"expected"`
	ReceiptSignatureVerifies    bool              `json:"receiptSignatureVerifies"`
	CredentialSignatureVerifies bool              `json:"credentialSignatureVerifies"`
	SharedReceipt               []string          `json:"sharedReceipt"`
}

// srbEnvelope is a DSSE envelope as read; a part that does not parse is nil.
type srbEnvelope struct {
	payloadType *string
	payload     []byte
	signatures  []srbSignature // nil when the member is not a well formed list
	body        map[string]any
}

type srbSignature struct {
	keyID string
	sig   []byte
}

type srbCase struct {
	now          *time.Time
	authorityKey ed25519.PublicKey
	credential   srbEnvelope
	receipt      srbEnvelope
}

func (statusReceipt) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	var rows []srbVector
	for _, entry := range manifest.Vectors {
		var v srbVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		rows = append(rows, v)
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = srbJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, srbSharedFindings(rows)...)
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// srbSharedFindings checks every row's sharedReceipt against the rows whose
// receipt.json has the same digest.
func srbSharedFindings(rows []srbVector) []string {
	var findings []string
	for _, row := range rows {
		want := []string{}
		for _, other := range rows {
			if other.ID != row.ID && other.Files["receipt.json"] == row.Files["receipt.json"] {
				want = append(want, other.ID)
			}
		}
		sort.Strings(want)
		got := append([]string{}, row.SharedReceipt...)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			findings = append(findings, fmt.Sprintf("%s: sharedReceipt %v, the receipt files say %v", row.ID, got, want))
		}
	}
	return findings
}

func srbJudgeMember(caseDir string, v srbVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	c, err := srbLoad(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if got := c.receiptSignatureVerifies(); got != v.ReceiptSignatureVerifies {
		findings = append(findings, fmt.Sprintf(
			"the receipt signature verifies: %t, the manifest declares %t", got, v.ReceiptSignatureVerifies))
	}
	if got := c.credentialSignatureVerifies(); got != v.CredentialSignatureVerifies {
		findings = append(findings, fmt.Sprintf(
			"the credential signature verifies: %t, the manifest declares %t", got, v.CredentialSignatureVerifies))
	}
	if got := c.decide(); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func srbLoad(caseDir string) (*srbCase, error) {
	var file struct {
		Now          string `json:"now"`
		AuthorityKey string `json:"authorityKey"`
		Credential   string `json:"credential"`
		Receipt      string `json:"receipt"`
	}
	if err := scReadJSON(caseDir, "case.json", &file); err != nil {
		return nil, err
	}
	c := &srbCase{}
	if srbTime.MatchString(file.Now) {
		if at, err := time.Parse(time.RFC3339, file.Now); err == nil {
			c.now = &at
		}
	}
	if key, err := decodeCanonical(base64.StdEncoding, file.AuthorityKey); err == nil && len(key) == ed25519.PublicKeySize {
		c.authorityKey = ed25519.PublicKey(key)
	}
	c.credential = srbReadEnvelope(caseDir, file.Credential)
	c.receipt = srbReadEnvelope(caseDir, file.Receipt)
	return c, nil
}

func srbReadEnvelope(caseDir, name string) srbEnvelope {
	var raw map[string]json.RawMessage
	if name == "" || !existsIn(caseDir, name) || scReadJSON(caseDir, name, &raw) != nil {
		return srbEnvelope{}
	}
	if !srbExactly(raw, "payload", "payloadType", "signatures") {
		return srbEnvelope{}
	}
	env := srbEnvelope{}
	if payloadType, ok := srbString(raw["payloadType"]); ok {
		env.payloadType = &payloadType
	}
	if payload, ok := srbString(raw["payload"]); ok {
		if decoded, err := decodeCanonical(base64.StdEncoding, payload); err == nil {
			env.payload = decoded
		}
	}
	env.signatures = srbSignatures(raw["signatures"])
	if env.payload != nil {
		var body map[string]any
		if strictUnmarshal(env.payload, &body) == nil && body != nil {
			env.body = body
		}
	}
	return env
}

func srbSignatures(raw json.RawMessage) []srbSignature {
	var entries []map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || len(entries) == 0 {
		return nil
	}
	out := make([]srbSignature, 0, len(entries))
	for _, entry := range entries {
		keyID, okKey := srbString(entry["keyid"])
		sig, okSig := srbString(entry["sig"])
		if !srbExactly(entry, "keyid", "sig") || !okKey || !okSig {
			return nil
		}
		decoded, err := decodeCanonical(base64.StdEncoding, sig)
		if err != nil {
			return nil
		}
		out = append(out, srbSignature{keyID, decoded})
	}
	return out
}

// srbString decodes a JSON string member; null and every other type are refused.
func srbString(raw json.RawMessage) (string, bool) {
	var text string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &text) != nil {
		return "", false
	}
	return text, true
}

// srbExactly reports whether an object carries exactly the named members.
func srbExactly[V any](object map[string]V, names ...string) bool {
	if len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}

func (c *srbCase) decide() scDecision {
	checks := []struct {
		reason string
		fails  func() bool
	}{
		{"receipt_malformed", func() bool { return !srbReceiptWellFormed(c.receipt) }},
		{"receipt_signature_invalid", func() bool { return !c.receiptSignatureVerifies() }},
		{"receipt_unbound", func() bool { _, ok := srbBinding(c.receipt.body)["digest"]; return !ok }},
		{"credential_malformed", func() bool { return !srbCredentialWellFormed(c.credential) }},
		{"credential_signature_invalid", func() bool { return !c.credentialSignatureVerifies() }},
		{"credential_id_mismatch", c.idMismatch},
		{"credential_digest_mismatch", c.digestMismatch},
		{"receipt_not_yet_valid", func() bool {
			start, _, ok := srbWindow(c.receipt.body)
			return !ok || c.now == nil || c.now.Before(start)
		}},
		{"receipt_expired", func() bool {
			_, end, ok := srbWindow(c.receipt.body)
			return !ok || c.now == nil || !c.now.Before(end)
		}},
		{"credential_not_active", func() bool { return c.receipt.body["status"] != "active" }},
	}
	for _, check := range checks {
		if check.fails() {
			return scDecision{"reject", check.reason}
		}
	}
	return scDecision{"accept", "credential_bound"}
}

func srbBinding(body map[string]any) map[string]any {
	binding, _ := body["credential"].(map[string]any)
	return binding
}

func srbWindow(body map[string]any) (time.Time, time.Time, bool) {
	var times [2]time.Time
	for i, name := range []string{"issuedAt", "validUntil"} {
		text, _ := body[name].(string)
		if !srbTime.MatchString(text) {
			return time.Time{}, time.Time{}, false
		}
		parsed, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return time.Time{}, time.Time{}, false
		}
		times[i] = parsed
	}
	return times[0], times[1], true
}

func srbReceiptWellFormed(r srbEnvelope) bool {
	if r.payloadType == nil || *r.payloadType != srbReceiptType || len(r.signatures) != 1 || r.body == nil {
		return false
	}
	if !srbExactly(r.body, "credential", "issuedAt", "status", "validUntil") {
		return false
	}
	binding := srbBinding(r.body)
	if binding == nil || (!srbExactly(binding, "id") && !srbExactly(binding, "digest", "id")) {
		return false
	}
	if id, ok := binding["id"].(string); !ok || id == "" {
		return false
	}
	if raw, ok := binding["digest"]; ok {
		digest, _ := raw.(map[string]any)
		hex, _ := digest["sha256"].(string)
		if !srbExactly(digest, "sha256") || !srbHex64.MatchString(hex) {
			return false
		}
	}
	switch r.body["status"] {
	case "active", "revoked", "suspended":
	default:
		return false
	}
	start, end, ok := srbWindow(r.body)
	return ok && start.Before(end)
}

// srbKeys returns the credential's keys by kid, or nil when the list is not well formed.
func srbKeys(cred srbEnvelope) map[string]ed25519.PublicKey {
	list, _ := cred.body["keys"].([]any)
	if len(list) == 0 {
		return nil
	}
	found := map[string]ed25519.PublicKey{}
	for _, entry := range list {
		jwk, _ := entry.(map[string]any)
		kid, _ := jwk["kid"].(string)
		x, _ := jwk["x"].(string)
		if !srbExactly(jwk, "crv", "kid", "kty", "x") || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || kid == "" {
			return nil
		}
		raw, err := decodeCanonical(base64.RawURLEncoding, x)
		if _, seen := found[kid]; err != nil || len(raw) != ed25519.PublicKeySize || seen {
			return nil
		}
		found[kid] = ed25519.PublicKey(raw)
	}
	return found
}

func srbCredentialWellFormed(cred srbEnvelope) bool {
	if cred.payloadType == nil || *cred.payloadType != srbCredentialType || cred.signatures == nil || cred.body == nil {
		return false
	}
	if !srbExactly(cred.body, "capabilities", "id", "keys", "name") {
		return false
	}
	if id, ok := cred.body["id"].(string); !ok || id == "" {
		return false
	}
	if _, ok := cred.body["name"].(string); !ok {
		return false
	}
	caps, _ := cred.body["capabilities"].([]any)
	if len(caps) == 0 {
		return false
	}
	previous := ""
	for i, entry := range caps {
		capability, ok := entry.(string)
		if !ok || capability == "" || (i > 0 && capability <= previous) {
			return false
		}
		previous = capability
	}
	return srbKeys(cred) != nil
}

func srbVerifies(key ed25519.PublicKey, env srbEnvelope, sig []byte) bool {
	if env.payloadType == nil || env.payload == nil {
		return false
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(*env.payloadType), *env.payloadType, len(env.payload))
	return ed25519.Verify(key, append([]byte(pae), env.payload...), sig)
}

func (c *srbCase) receiptSignatureVerifies() bool {
	if c.authorityKey == nil || len(c.receipt.signatures) != 1 {
		return false
	}
	return srbVerifies(c.authorityKey, c.receipt, c.receipt.signatures[0].sig)
}

// credentialSignatureVerifies reports whether every credential signature
// verifies under the key its keyid names in the credential's own list: the
// holder's proof over the bytes, which whoever writes the list can make.
func (c *srbCase) credentialSignatureVerifies() bool {
	keys := srbKeys(c.credential)
	if keys == nil || len(c.credential.signatures) == 0 {
		return false
	}
	for _, s := range c.credential.signatures {
		key, ok := keys[s.keyID]
		if !ok || !srbVerifies(key, c.credential, s.sig) {
			return false
		}
	}
	return true
}

func (c *srbCase) idMismatch() bool {
	bound, ok1 := srbBinding(c.receipt.body)["id"].(string)
	presented, ok2 := c.credential.body["id"].(string)
	return !ok1 || !ok2 || bound != presented
}

func (c *srbCase) digestMismatch() bool {
	digest, _ := srbBinding(c.receipt.body)["digest"].(map[string]any)
	declared, _ := digest["sha256"].(string)
	return c.credential.payload == nil || declared != sha(c.credential.payload)
}
