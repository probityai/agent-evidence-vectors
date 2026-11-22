package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(principalBinding{}) }

// principalBinding judges corpora/vectors-principal-binding/. Each member is one
// binding of an agent to the principal it acts for and the scope it holds,
// written in a native form, and the relying party's request. Two forms are read:
// the UMA for Agents terms agreement (a compact EdDSA JWS the agent signs with
// the key in its header, echoing the owner's proffered template) and a Human
// Context Protocol grant inside an envelope the Authorization Service signs over
// the grant's RFC 8785 form. The reader applies the Python reader's checks in the
// same order and names the first one that fails:
//
//  1. the binding verifies under the key the case trusts, and a UMA iss is the
//     identifier of that key: signature_invalid;
//  2. UMA: the echo matches the template and aud is proffered_by: echo_mismatch;
//  3. UMA: no prohibition dropped, expires_in not extended: terms_weakened;
//  4. HCP: status is active: grant_inactive;
//  5. HCP: every scope string is derived from access: scope_not_backed;
//  6. the binding's agent is the request's agent: agent_mismatch;
//  7. the binding's principal is the request's principal, and an HCP grant with
//     no delegation names the Context Subject: principal_mismatch;
//  8. the request's scope is within the binding's scope: scope_exceeded.
//
// A binding that passes every check is verified with agent_bound.
type principalBinding struct{}

func (principalBinding) Suite() string { return "agent-principal-binding/v1" }

type pbVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Signed   bool              `json:"bindingSignatureVerifies"`
}

type pbCase struct {
	Profile  string            `json:"profile"`
	Binding  string            `json:"binding"`
	Keys     map[string]string `json:"keys"`
	Request  pbRequest         `json:"request"`
	Template json.RawMessage   `json:"template"`
}

type pbRequest struct {
	Agent     string   `json:"agent"`
	Principal string   `json:"principal"`
	Scope     []string `json:"scope"`
}

// pbBinding is one binding read from its bytes: whether its signature
// verifies, and the body the checks read as generic JSON.
type pbBinding struct {
	signed bool
	body   map[string]any
}

var pbEchoed = []string{"template_id", "terms_uri", "purpose", "scope", "family", "nonce"}

func (principalBinding) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v pbVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = pbJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func pbJudgeMember(caseDir string, v pbVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c pbCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	raw, err := readIn(caseDir, c.Binding)
	if err != nil {
		return append(findings, fmt.Sprintf("%s cannot be read: %v", c.Binding, err))
	}
	b, err := pbRead(c, raw)
	if err != nil {
		return append(findings, err.Error())
	}
	if b.signed != v.Signed {
		findings = append(findings, fmt.Sprintf(
			"the binding signature verifies: %t, the manifest declares %t", b.signed, v.Signed))
	}
	if got := pbFirstFailure(c, b); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func pbRead(c pbCase, raw []byte) (pbBinding, error) {
	switch c.Profile {
	case "uma-for-agents":
		return pbReadJWS(c, bytes.TrimSpace(raw)), nil
	case "hcp-grant":
		return pbReadEnvelope(c, raw), nil
	}
	return pbBinding{}, fmt.Errorf("unknown profile %q", c.Profile)
}

func pbB64u(text string) ([]byte, error) {
	if strings.Contains(text, "=") {
		return nil, fmt.Errorf("padded base64url")
	}
	return base64.RawURLEncoding.DecodeString(text)
}

func pbReadJWS(c pbCase, token []byte) pbBinding {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return pbBinding{}
	}
	headerRaw, herr := pbB64u(parts[0])
	payloadRaw, perr := pbB64u(parts[1])
	sig, serr := pbB64u(parts[2])
	var header struct {
		Alg string `json:"alg"`
		JWK struct {
			X string `json:"x"`
		} `json:"jwk"`
	}
	var body map[string]any
	if herr != nil || perr != nil || serr != nil ||
		strictUnmarshal(headerRaw, &header) != nil || strictUnmarshal(payloadRaw, &body) != nil {
		return pbBinding{}
	}
	key, kerr := pbB64u(header.JWK.X)
	trusted, terr := hex.DecodeString(c.Keys["agent"])
	if kerr != nil || terr != nil || len(key) != ed25519.PublicKeySize {
		return pbBinding{body: body}
	}
	digest := sha256.Sum256(key)
	signed := header.Alg == "EdDSA" && bytes.Equal(key, trusted) &&
		body["iss"] == "agent:"+hex.EncodeToString(digest[:])[:16] &&
		ed25519.Verify(ed25519.PublicKey(key), []byte(parts[0]+"."+parts[1]), sig)
	return pbBinding{signed: signed, body: body}
}

func pbReadEnvelope(c pbCase, raw []byte) pbBinding {
	var envelope struct {
		Grant json.RawMessage `json:"grant"`
		Sig   string          `json:"sig"`
	}
	var body map[string]any
	if strictUnmarshal(raw, &envelope) != nil || strictUnmarshal(envelope.Grant, &body) != nil {
		return pbBinding{}
	}
	key, kerr := hex.DecodeString(c.Keys["authorization-service"])
	sig, serr := base64.StdEncoding.DecodeString(envelope.Sig)
	canonical, cerr := aee.Canonicalize(envelope.Grant)
	signed := kerr == nil && serr == nil && cerr == nil && len(key) == ed25519.PublicKeySize &&
		ed25519.Verify(ed25519.PublicKey(key), canonical, sig)
	return pbBinding{signed: signed, body: body}
}

func pbFirstFailure(c pbCase, b pbBinding) scDecision {
	if !b.signed {
		return scDecision{"rejected", "signature_invalid"}
	}
	var checks []pbCheck
	switch c.Profile {
	case "uma-for-agents":
		checks = pbUMAChecks(c, b)
	case "hcp-grant":
		checks = pbHCPChecks(b)
	}
	agent, principal, scope := pbStated(c.Profile, b.body)
	checks = append(checks,
		pbCheck{"agent_mismatch", func() bool { return agent != c.Request.Agent }},
		pbCheck{"principal_mismatch", func() bool {
			return principal != c.Request.Principal || (c.Profile == "hcp-grant" &&
				!pbHasDelegation(b.body) && principal != pbField(b.body, "subject", "id"))
		}},
		pbCheck{"scope_exceeded", func() bool { return !pbSubset(pbStringSet(c.Request.Scope), pbStrings(scope)) }},
	)
	for _, check := range checks {
		if check.fails() {
			return scDecision{"rejected", check.reason}
		}
	}
	return scDecision{"verified", "agent_bound"}
}

// pbCheck is one named check; the reader runs them in order and names the
// first that fails.
type pbCheck struct {
	reason string
	fails  func() bool
}

func pbUMAChecks(c pbCase, b pbBinding) []pbCheck {
	var template map[string]any
	parsed := json.Unmarshal(c.Template, &template) == nil
	return []pbCheck{
		{"echo_mismatch", func() bool { return !parsed || pbEchoMismatch(template, b.body) }},
		{"terms_weakened", func() bool { return pbTermsWeakened(template, b.body) }},
	}
}

func pbHCPChecks(b pbBinding) []pbCheck {
	return []pbCheck{
		{"grant_inactive", func() bool { return b.body["status"] != "active" }},
		{"scope_not_backed", func() bool { return !pbSubset(pbStrings(b.body["scopes"]), pbDerivedScopes(b.body)) }},
	}
}

// pbStated returns the agent, principal and scope a binding states, read from
// the fields its native form uses for them.
func pbStated(profile string, body map[string]any) (agent, principal, scope any) {
	if profile == "hcp-grant" {
		return pbField(body, "client", "id"), pbField(body, "authorizingPrincipal", "id"), body["scopes"]
	}
	return body["iss"], body["aud"], body["scope"]
}

func pbStringSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, s := range items {
		out[s] = true
	}
	return out
}

func pbEchoMismatch(template, body map[string]any) bool {
	for _, field := range pbEchoed {
		if !pbEqual(template[field], body[field]) {
			return true
		}
	}
	return body["aud"] != template["proffered_by"] || template["proffered_by"] == nil
}

func pbTermsWeakened(template, body map[string]any) bool {
	if !pbSubset(pbStrings(template["prohibited"]), pbStrings(body["prohibited"])) {
		return true
	}
	expires, ok := body["expires_in"].(float64)
	limit, lok := template["expires_in"].(float64)
	return !ok || !lok || expires != float64(int64(expires)) || expires > limit
}

func pbEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ja, aerr := json.Marshal(a)
	jb, berr := json.Marshal(b)
	return aerr == nil && berr == nil && bytes.Equal(ja, jb)
}

func pbStrings(value any) map[string]bool {
	out := map[string]bool{}
	items, _ := value.([]any)
	for _, item := range items {
		if s, ok := item.(string); ok {
			out[s] = true
		}
	}
	return out
}

func pbSubset(small, big map[string]bool) bool {
	for s := range small {
		if !big[s] {
			return false
		}
	}
	return true
}

func pbField(body map[string]any, object, field string) any {
	inner, _ := body[object].(map[string]any)
	return inner[field]
}

func pbHasDelegation(body map[string]any) bool {
	inner, _ := body["authorizingPrincipal"].(map[string]any)
	_, ok := inner["delegation"]
	return ok
}

func pbDerivedScopes(body map[string]any) map[string]bool {
	out := map[string]bool{}
	details, _ := body["access"].([]any)
	for _, d := range details {
		detail, _ := d.(map[string]any)
		for category := range pbStrings(detail["categories"]) {
			for action := range pbStrings(detail["actions"]) {
				out["hcp:"+category+":"+action] = true
			}
		}
	}
	return out
}
