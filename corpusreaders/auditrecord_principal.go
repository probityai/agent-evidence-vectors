package corpusreaders

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// The principal member (revision 04, rows PR1 to PR16): the IdP-authenticated
// principal a decision point established, carried inside the signed bytes. It
// is bound to the agent by its credential digest (tokenDigest equals
// agent.credentialDigest), to the delegation by its subject, and to the
// issuer's key by the RFC 7638 thumbprint of the JWK that kid selects. The
// rule restates packaging/agent_evidence_vectors/auditrecord.py
// (_rule_principal) and refuses in the same order with the same codes.

var arPrincipalMembers = []string{
	"issuer", "subject", "clientId", "audience", "authMethod", "source", "tokenDigest",
	"issuedAt", "expiresAt", "kid", "key", "keyThumbprint", "jwksDigest",
}

var arPrincipalOptional = []string{"tenant"}

// arPrincipalAuthMethods is the IANA registry "OAuth Token Endpoint
// Authentication Methods" as RFC 7591 and RFC 8705 populate it.
var arPrincipalAuthMethods = []string{
	"none", "client_secret_post", "client_secret_basic", "client_secret_jwt",
	"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth",
}

// arPrincipalSources: an RFC 9068 access token, an OpenID Connect ID token, or
// an RFC 7523 assertion, each a JWS whose header kid names a key of the
// issuer's JWKS.
var arPrincipalSources = []string{"jwt-access-token", "id-token", "jwt-assertion"}

// arThumbprintMembers are the members RFC 7638 Section 3.2 hashes, by key type
// (OKP from RFC 8037 Section 2).
var arThumbprintMembers = map[string][]string{
	"RSA": {"e", "kty", "n"},
	"EC":  {"crv", "kty", "x", "y"},
	"OKP": {"crv", "kty", "x"},
}

var arJWKPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// arPrincipalChecks names each sentence of the rule after the shape, so a test
// can weaken one at a time and see exactly its member fail.
var arPrincipalChecks = map[string]bool{
	"unknown": true, "subject": true, "credential": true, "not-yet-valid": true,
	"expired": true, "kid": true, "thumbprint": true,
}

// arJWKThumbprint is the RFC 7638 SHA-256 thumbprint of a public JWK, base64url
// without padding: the RFC 8785 bytes of the required members only.
func arJWKThumbprint(key map[string]any) (string, error) {
	body := map[string]any{}
	for _, name := range arThumbprintMembers[arStr(key, "kty")] {
		body[name] = key[name]
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	canonical, err := aee.Canonicalize(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func arNonEmpty(value any) bool {
	text, ok := value.(string)
	return ok && text != ""
}

func arPrincipalKeyShape(raw any) error {
	key, ok := raw.(map[string]any)
	if !ok {
		return arRefuse("principal-malformed")
	}
	members, known := arThumbprintMembers[arStr(key, "kty")]
	if !known {
		return arRefuse("principal-malformed")
	}
	for _, name := range arJWKPrivateMembers {
		if _, has := key[name]; has {
			return arRefuse("principal-malformed")
		}
	}
	for _, name := range members {
		if !arNonEmpty(key[name]) {
			return arRefuse("principal-malformed")
		}
	}
	return nil
}

func arPrincipalIssuerAudience(principal map[string]any) error {
	issuer, _ := principal["issuer"].(string)
	if !strings.HasPrefix(issuer, "https://") || len(issuer) == len("https://") {
		return arRefuse("principal-malformed")
	}
	audience, ok := principal["audience"].([]any)
	if !ok || len(audience) == 0 {
		return arRefuse("principal-malformed")
	}
	seen := map[string]bool{}
	for _, item := range audience {
		text, _ := item.(string)
		if text == "" || seen[text] {
			return arRefuse("principal-malformed")
		}
		seen[text] = true
	}
	return nil
}

func arPrincipalShape(raw any) (map[string]any, error) {
	principal, ok := raw.(map[string]any)
	if !ok {
		return nil, arRefuse("principal-malformed")
	}
	for _, name := range arPrincipalMembers {
		if _, has := principal[name]; !has {
			return nil, arRefuse("principal-member-missing")
		}
	}
	if arPrincipalChecks["unknown"] {
		for name := range principal {
			if !arContains(arPrincipalMembers, name) && !arContains(arPrincipalOptional, name) {
				return nil, arRefuse("principal-member-unknown")
			}
		}
	}
	for _, name := range []string{"subject", "clientId", "kid", "keyThumbprint"} {
		if !arNonEmpty(principal[name]) {
			return nil, arRefuse("principal-malformed")
		}
	}
	if err := arPrincipalIssuerAudience(principal); err != nil {
		return nil, err
	}
	if !arContains(arPrincipalAuthMethods, arStr(principal, "authMethod")) ||
		!arContains(arPrincipalSources, arStr(principal, "source")) ||
		!arIsDigest(arStr(principal, "tokenDigest")) || !arIsDigest(arStr(principal, "jwksDigest")) {
		return nil, arRefuse("principal-malformed")
	}
	if tenant, has := principal["tenant"]; has && !arNonEmpty(tenant) {
		return nil, arRefuse("principal-malformed")
	}
	return principal, arPrincipalKeyShape(principal["key"])
}

// arPrincipalSkew says whether the skew tolerance applies on each side of the
// token's lifetime: to its issue (PR13, PR15) and to its expiry (PR12, PR14).
// A test sets one false.
var arPrincipalSkew = map[string]bool{"issued": true, "expires": true}

// arSkewOn is the tolerance on one side of a lifetime, or none.
func arSkewOn(side string) time.Duration {
	if arPrincipalSkew[side] {
		return arSkewTolerance
	}
	return 0
}

func arPrincipalLifetime(principal map[string]any, reportedAt string) error {
	issued, errIssued := arInstant(arStr(principal, "issuedAt"))
	expires, errExpires := arInstant(arStr(principal, "expiresAt"))
	if errIssued != nil || errExpires != nil || !expires.After(issued) {
		return arRefuse("principal-malformed")
	}
	decided, err := arInstant(reportedAt)
	if err != nil {
		return err
	}
	if arPrincipalChecks["not-yet-valid"] && issued.Sub(decided) > arSkewOn("issued") {
		return arRefuse("principal-not-yet-valid")
	}
	if arPrincipalChecks["expired"] && decided.Sub(expires) > arSkewOn("expires") {
		return arRefuse("principal-expired")
	}
	return nil
}

func arRulePrincipal(s *arState) error {
	raw, present := s.pred["principal"]
	if !present {
		return nil
	}
	principal, err := arPrincipalShape(raw)
	if err != nil {
		return err
	}
	if arPrincipalChecks["subject"] && arStr(s.pred, "delegation.subjectKind") == "user" &&
		arStr(principal, "subject") != arStr(s.pred, "delegation.subject") {
		return arRefuse("principal-subject-mismatch")
	}
	if arPrincipalChecks["credential"] &&
		arStr(principal, "tokenDigest") != arStr(s.pred, "agent.credentialDigest") {
		return arRefuse("principal-credential-unbound")
	}
	if err := arPrincipalLifetime(principal, arStr(s.pred, "decision.reportedAt")); err != nil {
		return err
	}
	key, _ := principal["key"].(map[string]any)
	if arPrincipalChecks["kid"] && key["kid"] != principal["kid"] {
		return arRefuse("principal-kid-mismatch")
	}
	thumbprint, err := arJWKThumbprint(key)
	if err != nil {
		return arRefuse("principal-malformed")
	}
	if arPrincipalChecks["thumbprint"] && arStr(principal, "keyThumbprint") != thumbprint {
		return arRefuse("principal-thumbprint-mismatch")
	}
	return nil
}
