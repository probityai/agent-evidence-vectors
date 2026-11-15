package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(principalAction{}) }

// principalAction judges corpora/vectors-principal-action/. Each member is a
// producer's Ed25519 key, the verifier's pin set (issuer to accepted RFC 7638
// thumbprints) and one DSSE envelope over an in-toto Statement v1 whose
// predicate binds one action to up to four principals (user, agent, sponsor,
// approver), each bound to its credential by digest and to its issuer key by
// thumbprint. The reader derives each decision with the checks of
// spec/predicates/principal-action.md, in its order, and names the first that
// fails; a principal's failure is principal_<role>:<code>. A record that passes
// is verified, strict or basic, with delegation act-chain or act-absent.
type principalAction struct{}

const (
	paSuite         = "principal-action/v1"
	paPredicateType = "https://w3id.org/agent-evidence/predicate/v1/principal-action"
	paStatementType = "https://in-toto.io/Statement/v1"
	paPayloadType   = "application/vnd.in-toto+json"
)

var (
	paRoles    = []string{"user", "agent", "sponsor", "approver"}
	paRequired = []string{"issuer", "subject", "clientId", "audience", "authMethod", "source", "tokenDigest",
		"issuedAt", "expiresAt", "kid", "key", "keyThumbprint", "jwksDigest"}
	paOptional  = []string{"tenant", "identityProvider", "pinnedThumbprint", "act", "idJag"}
	paSources   = map[string]bool{"jwt-access-token": true, "id-token": true, "jwt-assertion": true, "id-jag": true}
	paAuthMeths = map[string]bool{"none": true, "client_secret_post": true, "client_secret_basic": true,
		"client_secret_jwt": true, "private_key_jwt": true, "tls_client_auth": true,
		"self_signed_tls_client_auth": true}
	paProviders = map[string]bool{"okta": true, "entra": true, "auth0": true, "keycloak": true,
		"self_issued": true, "other": true}
	paThumbMembers = map[string][]string{"RSA": {"e", "kty", "n"}, "EC": {"crv", "kty", "x", "y"},
		"OKP": {"crv", "kty", "x"}}
	paPrivate    = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
	paHex64      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	paThumbShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	paUTC        = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)
	paEntraHosts = map[string]bool{"login.microsoftonline.com": true, "login.microsoftonline.us": true,
		"login.chinacloudapi.cn": true, "sts.windows.net": true}
)

func (principalAction) Suite() string { return paSuite }

type paExpected struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	Delegation string `json:"delegation,omitempty"`
}

type paVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected paExpected        `json:"expected"`
}

type paCaseFile struct {
	Envelope    string              `json:"envelope"`
	ProducerKey string              `json:"producerKey"`
	Pins        map[string][]string `json:"pins"`
}

type paEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

func paText(v any) bool { s, ok := v.(string); return ok && s != "" }

func paDigest(v any) bool { s, ok := v.(string); return ok && paHex64.MatchString(s) }

func paInstant(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || !paUTC.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func paCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return aee.Canonicalize(raw)
}

func paSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func paThumbprint(key map[string]any) (string, error) {
	sub := map[string]any{}
	for _, m := range paThumbMembers[key["kty"].(string)] {
		sub[m] = key[m]
	}
	b, err := paCanonical(sub)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(s[:]), nil
}

// paProvider is the provider an https issuer names by host and path.
func paProvider(issuer string) string {
	if t := strings.TrimRight(issuer, "/"); t == "https://self-issued.me" || t == "https://self-issued.me/v2" {
		return "self_issued"
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return "other"
	}
	host := strings.ToLower(u.Hostname())
	for _, s := range []string{".okta.com", ".oktapreview.com", ".okta-emea.com", ".okta-gov.com"} {
		if strings.HasSuffix(host, s) {
			return "okta"
		}
	}
	if paEntraHosts[host] || strings.HasSuffix(host, ".ciamlogin.com") {
		return "entra"
	}
	if strings.HasSuffix(host, ".auth0.com") {
		return "auth0"
	}
	var segs []string
	for _, s := range strings.Split(u.Path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if len(segs) > 0 && segs[0] == "auth" {
		segs = segs[1:]
	}
	if len(segs) == 2 && segs[0] == "realms" {
		return "keycloak"
	}
	return "other"
}

// paActSubjects is the actor chain, outermost first; ok is false when malformed.
func paActSubjects(act any) ([]string, bool) {
	var out []string
	for act != nil {
		m, isMap := act.(map[string]any)
		if !isMap || !paText(m["sub"]) {
			return nil, false
		}
		for k := range m {
			if k != "sub" && k != "act" {
				return nil, false
			}
		}
		out = append(out, m["sub"].(string))
		act = m["act"]
	}
	return out, true
}

func paMembersOK(p map[string]any) bool {
	for _, m := range []string{"subject", "clientId", "kid", "keyThumbprint"} {
		if !paText(p[m]) {
			return false
		}
	}
	aud, ok := p["audience"].([]any)
	if !ok || len(aud) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, a := range aud {
		if !paText(a) || seen[a.(string)] {
			return false
		}
		seen[a.(string)] = true
	}
	src, _ := p["source"].(string)
	meth, _ := p["authMethod"].(string)
	if !paSources[src] || !paAuthMeths[meth] || !paDigest(p["tokenDigest"]) || !paDigest(p["jwksDigest"]) {
		return false
	}
	if v, ok := p["tenant"]; ok && !paText(v) {
		return false
	}
	if v, ok := p["identityProvider"]; ok {
		if s, isStr := v.(string); !isStr || !paProviders[s] {
			return false
		}
	}
	if v, ok := p["pinnedThumbprint"]; ok {
		if s, isStr := v.(string); !isStr || !paThumbShape.MatchString(s) {
			return false
		}
	}
	return true
}

func paKeyOK(v any) (map[string]any, bool) {
	key, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	kty, _ := key["kty"].(string)
	members, known := paThumbMembers[kty]
	if !known {
		return nil, false
	}
	for _, m := range paPrivate {
		if _, has := key[m]; has {
			return nil, false
		}
	}
	for _, m := range members {
		if !paText(key[m]) {
			return nil, false
		}
	}
	return key, true
}

func paCheckPrincipal(v any, at time.Time, pins map[string][]string) string {
	p, ok := v.(map[string]any)
	if !ok {
		return "principal_malformed"
	}
	for _, m := range paRequired {
		if _, has := p[m]; !has {
			return "principal_member_missing"
		}
	}
	allowed := map[string]bool{}
	for _, m := range append(append([]string{}, paRequired...), paOptional...) {
		allowed[m] = true
	}
	for k := range p {
		if !allowed[k] {
			return "principal_member_unknown"
		}
	}
	issuer, _ := p["issuer"].(string)
	if !strings.HasPrefix(issuer, "https://") || len(issuer) <= len("https://") {
		return "principal_issuer_invalid"
	}
	if !paMembersOK(p) {
		return "principal_malformed"
	}
	key, ok := paKeyOK(p["key"])
	if !ok {
		return "principal_key_invalid"
	}
	thumb, err := paThumbprint(key)
	if err != nil || thumb != p["keyThumbprint"] {
		return "principal_thumbprint_mismatch"
	}
	if key["kid"] != p["kid"] {
		return "principal_kid_mismatch"
	}
	if declared, has := p["identityProvider"]; has {
		if derived := paProvider(issuer); derived != "other" && declared != derived {
			return "principal_provider_mismatch"
		}
	}
	if pin, has := p["pinnedThumbprint"]; has && pin != p["keyThumbprint"] {
		return "principal_pin_mismatch"
	}
	issued, ok1 := paInstant(p["issuedAt"])
	expires, ok2 := paInstant(p["expiresAt"])
	if !ok1 || !ok2 || !expires.After(issued) {
		return "principal_malformed"
	}
	if at.Before(issued) {
		return "principal_not_yet_valid"
	}
	if !at.Before(expires) {
		return "principal_expired"
	}
	accepted, trusted := pins[issuer]
	if !trusted {
		return "principal_issuer_untrusted"
	}
	pinned := false
	for _, t := range accepted {
		pinned = pinned || t == thumb
	}
	if !pinned {
		return "principal_key_not_pinned"
	}
	if act, has := p["act"]; has {
		if _, ok := paActSubjects(act); !ok {
			return "principal_act_malformed"
		}
	}
	if _, has := p["idJag"]; has {
		return "principal_idjag_undefined"
	}
	return ""
}

func paApprovalOK(v any) (string, bool) {
	a, ok := v.(map[string]any)
	if !ok || len(a) != 2 || !paText(a["subject"]) || !paDigest(a["approvalDigest"]) {
		return "", false
	}
	return a["subject"].(string), true
}

// paStatement decodes and shape-checks the statement; ok is false when malformed.
func paStatement(payload []byte) (map[string]any, map[string]any, []string, bool) {
	var stmt map[string]any
	if json.Unmarshal(payload, &stmt) != nil || stmt == nil {
		return nil, nil, nil, false
	}
	if stmt["_type"] != paStatementType || stmt["predicateType"] != paPredicateType {
		return nil, nil, nil, false
	}
	subs, ok := stmt["subject"].([]any)
	if !ok || len(subs) != 1 {
		return nil, nil, nil, false
	}
	sub, ok := subs[0].(map[string]any)
	if !ok || sub["name"] != "action" {
		return nil, nil, nil, false
	}
	dig, ok := sub["digest"].(map[string]any)
	if _, isStr := dig["sha256"].(string); !ok || len(dig) != 1 || !isStr {
		return nil, nil, nil, false
	}
	pred, ok := stmt["predicate"].(map[string]any)
	if !ok {
		return nil, nil, nil, false
	}
	for k := range pred {
		if k != "action" && k != "principals" && k != "approvals" {
			return nil, nil, nil, false
		}
	}
	if _, isMap := pred["action"].(map[string]any); !isMap {
		return nil, nil, nil, false
	}
	if _, isMap := pred["principals"].(map[string]any); !isMap {
		return nil, nil, nil, false
	}
	signers := []string{}
	if raw, has := pred["approvals"]; has {
		list, isList := raw.([]any)
		if !isList {
			return nil, nil, nil, false
		}
		for _, a := range list {
			s, ok := paApprovalOK(a)
			if !ok {
				return nil, nil, nil, false
			}
			signers = append(signers, s)
		}
	}
	return stmt, pred, signers, true
}

func paDecide(raw []byte, producer ed25519.PublicKey, pins map[string][]string) paExpected {
	reject := func(r string) paExpected { return paExpected{Decision: "rejected", Reason: r} }
	var env paEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return reject("statement_malformed")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return reject("statement_malformed")
	}
	stmt, pred, signers, ok := paStatement(payload)
	if !ok {
		return reject("statement_malformed")
	}
	if env.PayloadType != paPayloadType || len(env.Signatures) != 1 {
		return reject("recorder_signature_invalid")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signatures[0].Sig)
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(paPayloadType), paPayloadType, len(payload), payload))
	if err != nil || !ed25519.Verify(producer, pae, sig) {
		return reject("recorder_signature_invalid")
	}
	canonical, err := aee.Canonicalize(payload)
	if err != nil || !bytes.Equal(canonical, payload) {
		return reject("statement_not_canonical")
	}
	action := pred["action"].(map[string]any)
	at, timeOK := paInstant(action["at"])
	if len(action) != 3 || !paText(action["tool"]) || !paDigest(action["argumentsDigest"]) || !timeOK {
		return reject("action_malformed")
	}
	actionBytes, err := paCanonical(action)
	subject := stmt["subject"].([]any)[0].(map[string]any)["digest"].(map[string]any)["sha256"]
	if err != nil || subject != paSHA(actionBytes) {
		return reject("action_digest_mismatch")
	}
	block := pred["principals"].(map[string]any)
	if len(block) == 0 {
		return reject("principals_malformed")
	}
	for k := range block {
		if !paContains(paRoles, k) {
			return reject("principals_malformed")
		}
	}
	for _, role := range paRoles {
		if p, has := block[role]; has {
			if code := paCheckPrincipal(p, at, pins); code != "" {
				return reject("principal_" + role + ":" + code)
			}
		}
	}
	user, hasUser := block["user"].(map[string]any)
	agent, hasAgent := block["agent"].(map[string]any)
	if !hasUser || !hasAgent {
		return reject("principals_need_user_and_agent")
	}
	var chain []string
	if act, has := user["act"]; has {
		chain, _ = paActSubjects(act)
	}
	if len(chain) > 0 && chain[0] != agent["subject"] && chain[0] != agent["clientId"] {
		return reject("principal_act_names_another_agent")
	}
	if approver, has := block["approver"].(map[string]any); has && !paContains(signers, approver["subject"].(string)) {
		return reject("principal_approver_not_an_approval_signer")
	}
	delegation := "act-absent"
	if _, has := user["act"]; has {
		delegation = "act-chain"
	}
	grade := "basic"
	if len(chain) > 0 && len(block) == len(paRoles) {
		grade = "strict"
	}
	return paExpected{Decision: "verified", Reason: grade, Delegation: delegation}
}

func paContains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func paJudgeMember(caseDir string, v paVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	raw, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, err.Error())
	}
	var cf paCaseFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return append(findings, fmt.Sprintf("case.json does not parse: %v", err))
	}
	key, err := base64.StdEncoding.DecodeString(cf.ProducerKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return append(findings, "case.json producerKey is not an Ed25519 public key")
	}
	body, err := readIn(caseDir, cf.Envelope)
	if err != nil {
		return append(findings, err.Error())
	}
	if got := paDecide(body, key, cf.Pins); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s/%s, the manifest declares %s/%s/%s",
			got.Decision, got.Reason, got.Delegation, v.Expected.Decision, v.Expected.Reason, v.Expected.Delegation))
	}
	return findings
}

func (principalAction) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v paVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = paJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}
