package corpusreaders

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"
)

func init() { register(agentRequestProof{}) }

// agentRequestProof judges corpora/vectors-agent-request-proof/. Each member is
// a recorder's Ed25519 key and an ordered list of DSSE envelopes, each over an
// in-toto Statement v1 whose predicate records one HTTP request and the RS256
// proof JWT the agent sent with it. The reader derives the last envelope's
// decision with the checks the Python reader applies, in the same order, and
// names the first one that fails; an earlier envelope that fails decides first:
//
//  1. statement_malformed;  2. recorder_signature_invalid;  3. typ_mismatch;
//  4. alg_not_allowed;  5. thumbprint_mismatch (RFC 7638);
//  6. proof_signature_invalid (RS256, modulus of at least 2048 bits);
//  7. principal_mismatch;  8. audience_mismatch;  9. kid_mismatch;
//  10. tenant_mismatch;  11. htm_htu_mismatch;  12. body_digest_mismatch;
//  13. proof_expired;  14. replayed_jti.
//
// Checks 8 to 10 read the pins in case.json (audience, kid, claims): the
// relying party's policy, not part of the record. A pin the case does not name
// switches its check off.
//
// The reader also recomputes each member's declared proofSignatureVerifies.
type agentRequestProof struct{}

const (
	arpSuite         = "agent-request-proof/v1"
	arpPredicateType = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-request-proof"
	arpStatementType = "https://in-toto.io/Statement/v1"
	arpPayloadType   = "application/vnd.in-toto+json"
	arpMinModulus    = 2048
)

// arpProfiles are the proof profiles the suite reads, by header typ.
var arpProfiles = map[string]struct {
	alg         string
	maxLifetime int64
}{
	"openbox-agent-proof+jwt": {"RS256", 60},
}

func (agentRequestProof) Suite() string { return arpSuite }

type arpVector struct {
	ID                     string            `json:"id"`
	Path                   string            `json:"path"`
	Files                  map[string]string `json:"files"`
	Expected               scDecision        `json:"expected"`
	ProofSignatureVerifies bool              `json:"proofSignatureVerifies"`
}

type arpPins struct {
	Audience *string        `json:"audience"`
	Kid      *string        `json:"kid"`
	Claims   map[string]any `json:"claims"`
}

type arpCaseFile struct {
	Envelopes   []string `json:"envelopes"`
	RecorderKey string   `json:"recorderKey"`
	Pins        arpPins  `json:"pins"`
}

type arpEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

type arpJWK struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

type arpStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate *struct {
		ObservedAt string `json:"observedAt"`
		Principal  *struct {
			Issuer        *string `json:"issuer"`
			Subject       *string `json:"subject"`
			JWK           *arpJWK `json:"jwk"`
			JWKThumbprint *string `json:"jwkThumbprint"`
		} `json:"principal"`
		Proof *struct {
			JWS *string `json:"jws"`
			Typ *string `json:"typ"`
		} `json:"proof"`
		Request *struct {
			BodyBase64 *string `json:"bodyBase64"`
			Method     *string `json:"method"`
			Path       *string `json:"path"`
		} `json:"request"`
	} `json:"predicate"`
}

type arpRecord struct {
	env          arpEnvelope
	stmt         arpStatement
	header       map[string]any
	claims       map[string]any
	signingInput []byte
	proofSig     []byte
	body         []byte
	observed     time.Time
	ok           bool
}

func arpB64url(s string) ([]byte, error) {
	if strings.Contains(s, "=") {
		return nil, fmt.Errorf("padded base64url")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func arpDecode(raw []byte) arpRecord {
	var r arpRecord
	if json.Unmarshal(raw, &r.env) != nil {
		return r
	}
	payload, err := base64.StdEncoding.DecodeString(r.env.Payload)
	if err != nil || json.Unmarshal(payload, &r.stmt) != nil {
		return r
	}
	if !arpStatementShaped(r.stmt) {
		return r
	}
	p := r.stmt.Predicate
	if r.observed, err = time.Parse(time.RFC3339, p.ObservedAt); err != nil {
		return r
	}
	parts := strings.Split(*p.Proof.JWS, ".")
	if len(parts) != 3 {
		return r
	}
	head, err1 := arpB64url(parts[0])
	claims, err2 := arpB64url(parts[1])
	sig, err3 := arpB64url(parts[2])
	body, err4 := base64.StdEncoding.DecodeString(*p.Request.BodyBase64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return r
	}
	if arpDecodeJSON(head, &r.header) != nil || arpDecodeJSON(claims, &r.claims) != nil ||
		len(r.header) == 0 || len(r.claims) == 0 {
		return r
	}
	r.signingInput = []byte(parts[0] + "." + parts[1])
	r.proofSig, r.body, r.ok = sig, body, true
	return r
}

// arpStatementShaped reports whether the statement carries the request-proof
// types, one sha256 subject, and every predicate member the readers dereference.
func arpStatementShaped(s arpStatement) bool {
	if s.Type != arpStatementType || s.PredicateType != arpPredicateType || len(s.Subject) != 1 {
		return false
	}
	if _, has := s.Subject[0].Digest["sha256"]; !has {
		return false
	}
	p := s.Predicate
	return p != nil && p.Principal != nil && p.Proof != nil && p.Request != nil &&
		p.Principal.Issuer != nil && p.Principal.Subject != nil && p.Principal.JWK != nil &&
		p.Principal.JWKThumbprint != nil && p.Proof.JWS != nil && p.Proof.Typ != nil &&
		p.Request.BodyBase64 != nil && p.Request.Method != nil && p.Request.Path != nil
}

// arpDecodeJSON decodes one JSON object keeping numbers exact.
func arpDecodeJSON(b []byte, into *map[string]any) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	return d.Decode(into)
}

func (r arpRecord) recorderSigned(key ed25519.PublicKey) bool {
	if len(r.env.Signatures) != 1 || r.env.PayloadType != arpPayloadType {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.env.Signatures[0].Sig)
	payload, err2 := base64.StdEncoding.DecodeString(r.env.Payload)
	if err != nil || err2 != nil {
		return false
	}
	return ed25519.Verify(key, adPAE(arpPayloadType, payload), sig)
}

func arpThumbprint(k arpJWK) string {
	member := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	sum := sha256.Sum256([]byte(member))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (r arpRecord) proofVerifies() bool {
	k := r.stmt.Predicate.Principal.JWK
	n, err := arpB64url(k.N)
	e, err2 := arpB64url(k.E)
	if err != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
		return false
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < arpMinModulus || pub.E < 3 {
		return false
	}
	digest := sha256.Sum256(r.signingInput)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], r.proofSig) == nil
}

func arpInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func (r arpRecord) expired() bool {
	iat, ok1 := arpInt(r.claims["iat"])
	exp, ok2 := arpInt(r.claims["exp"])
	if !ok1 || !ok2 {
		return true
	}
	profile, known := arpProfiles[*r.stmt.Predicate.Proof.Typ]
	obs := r.observed.Unix()
	return !known || obs < iat || obs >= exp || exp-iat > profile.maxLifetime
}

func (r arpRecord) replayKey() string {
	return fmt.Sprint(r.claims["iss"]) + "\x00" + fmt.Sprint(r.claims["jti"])
}

func (r arpRecord) audienceMismatch(pins arpPins) bool {
	return pins.Audience != nil && r.claims["aud"] != *pins.Audience
}

func (r arpRecord) kidMismatch(pins arpPins) bool {
	return pins.Kid != nil && r.header["kid"] != *pins.Kid
}

func (r arpRecord) tenantMismatch(pins arpPins) bool {
	for name, want := range pins.Claims {
		got, has := r.claims[name]
		if !has || got != want {
			return true
		}
	}
	return false
}

func (r arpRecord) firstFailure(recorder ed25519.PublicKey, seen map[string]bool, pins arpPins) string {
	if !r.ok {
		return "statement_malformed"
	}
	p := r.stmt.Predicate
	profile, known := arpProfiles[*p.Proof.Typ]
	digest := sha(r.body)
	checks := []struct {
		name string
		fail func() bool
	}{
		{"recorder_signature_invalid", func() bool { return !r.recorderSigned(recorder) }},
		{"typ_mismatch", func() bool { return !known || r.header["typ"] != *p.Proof.Typ }},
		{"alg_not_allowed", func() bool {
			for _, k := range []string{"jwk", "jku", "x5u", "x5c"} {
				if _, has := r.header[k]; has {
					return true
				}
			}
			return r.header["alg"] != profile.alg
		}},
		{"thumbprint_mismatch", func() bool {
			return arpThumbprint(*p.Principal.JWK) != *p.Principal.JWKThumbprint
		}},
		{"proof_signature_invalid", func() bool { return !r.proofVerifies() }},
		{"principal_mismatch", func() bool {
			return r.claims["iss"] != *p.Principal.Issuer || r.claims["sub"] != *p.Principal.Subject
		}},
		{"audience_mismatch", func() bool { return r.audienceMismatch(pins) }},
		{"kid_mismatch", func() bool { return r.kidMismatch(pins) }},
		{"tenant_mismatch", func() bool { return r.tenantMismatch(pins) }},
		{"htm_htu_mismatch", func() bool {
			return r.claims["htm"] != *p.Request.Method || r.claims["htu"] != *p.Request.Path
		}},
		{"body_digest_mismatch", func() bool {
			return r.claims["body_sha256"] != digest || r.stmt.Subject[0].Digest["sha256"] != digest
		}},
		{"proof_expired", r.expired},
		{"replayed_jti", func() bool { return seen[r.replayKey()] }},
	}
	for _, c := range checks {
		if c.fail() {
			return c.name
		}
	}
	return ""
}

type arpCase struct {
	recorder ed25519.PublicKey
	records  []arpRecord
	pins     arpPins
}

func arpLoad(caseDir string) (arpCase, error) {
	var c arpCase
	raw, err := readIn(caseDir, "case.json")
	if err != nil {
		return c, err
	}
	var cf arpCaseFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return c, fmt.Errorf("case.json does not parse: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(cf.RecorderKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return c, fmt.Errorf("case.json recorderKey is not an Ed25519 public key")
	}
	c.recorder, c.pins = key, cf.Pins
	for _, name := range cf.Envelopes {
		body, err := readIn(caseDir, name)
		if err != nil {
			return c, err
		}
		c.records = append(c.records, arpDecode(body))
	}
	if len(c.records) == 0 {
		return c, fmt.Errorf("case.json names no envelope")
	}
	return c, nil
}

func (c arpCase) decide() scDecision {
	seen := map[string]bool{}
	for _, r := range c.records {
		if reason := r.firstFailure(c.recorder, seen, c.pins); reason != "" {
			return scDecision{Decision: "rejected", Reason: reason}
		}
		seen[r.replayKey()] = true
	}
	return scDecision{Decision: "verified", Reason: "request_bound"}
}

func (c arpCase) proofSignatureVerifies() bool {
	last := c.records[len(c.records)-1]
	return last.ok && last.proofVerifies()
}

func arpJudgeMember(caseDir string, v arpVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	c, err := arpLoad(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if got := c.proofSignatureVerifies(); got != v.ProofSignatureVerifies {
		findings = append(findings, fmt.Sprintf(
			"the proof signature verifies: %t, the manifest declares %t", got, v.ProofSignatureVerifies))
	}
	if got := c.decide(); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func (agentRequestProof) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v arpVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = arpJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// arpHex is kept for diagnostics that print a digest.
var _ = hex.EncodeToString
