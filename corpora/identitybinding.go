package corpora

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() { register(identityBinding{}) }

// identityBinding judges vectors-identity-binding/. Each member is a DSSE
// envelope over an agent record whose subject is a did:web or did:wba DID, and
// the resolution fixtures (version histories of DID documents) for the DIDs it
// names. The reader derives each member's decision with the checks the Python
// reader applies, in the same order, and names the first one that fails:
//
//  1. the subject and signer DIDs are well formed: did_malformed;
//  2. the signer DID is the subject: signer_not_subject;
//  3. a resolution fixture exists for it: did_unresolvable;
//  4. a did:wba path DID's e1_ segment is the RFC 7638 thumbprint of an Ed25519
//     Multikey under authentication: binding_fingerprint_mismatch;
//  5. the version in effect at signing still authorises the key and is not
//     deactivated, where an earlier version authorised it: key_rotated_out;
//  6. that version lists the key under authentication or assertionMethod:
//     key_not_authorized;
//  7. the DSSE signature verifies under that key: signature_invalid.
//
// The reader also recomputes each member's declared signatureVerifies, because
// the corpus's claim is that several rejected records carry a good signature.
type identityBinding struct{}

func (identityBinding) Suite() string { return "agent-did-identity-binding/v1" }

type ibVector struct {
	ID                string            `json:"id"`
	Path              string            `json:"path"`
	Files             map[string]string `json:"files"`
	Expected          scDecision        `json:"expected"`
	SignatureVerifies bool              `json:"signatureVerifies"`
}

type ibCaseFile struct {
	Envelope    string            `json:"envelope"`
	Resolutions map[string]string `json:"resolutions"`
}

type ibEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type ibVersion struct {
	Doc  map[string]any `json:"didDocument"`
	Meta struct {
		Updated     string `json:"updated"`
		Deactivated bool   `json:"deactivated"`
	} `json:"didDocumentMetadata"`
	updated time.Time
}

type ibCase struct {
	env      ibEnvelope
	payload  []byte
	subject  string
	signedAt time.Time
	keyID    string
	signer   string
	versions []ibVersion // nil when the signer DID has no resolution fixture
}

const (
	ibHost    = `(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:%3A[0-9]{1,5})?`
	ibSegment = `[A-Za-z0-9._-]+`
	ibB58     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

var (
	ibDIDWeb = regexp.MustCompile(`^did:web:` + ibHost + `(?::` + ibSegment + `)*$`)
	ibDIDWBA = regexp.MustCompile(`^did:wba:` + ibHost + `(?:(?::` + ibSegment + `)*:e1_[A-Za-z0-9_-]{43})?$`)
)

func ibWellFormed(did string) bool { return ibDIDWeb.MatchString(did) || ibDIDWBA.MatchString(did) }

func (identityBinding) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ibVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ibJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ibJudgeMember(caseDir string, v ibVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	c, err := ibLoad(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if got := c.signatureVerifies(); got != v.SignatureVerifies {
		findings = append(findings, fmt.Sprintf(
			"the signature verifies: %t, the manifest declares %t", got, v.SignatureVerifies))
	}
	if got := c.decide(); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func ibLoad(caseDir string) (*ibCase, error) {
	var file ibCaseFile
	if err := scReadJSON(caseDir, "case.json", &file); err != nil {
		return nil, err
	}
	c := &ibCase{}
	if err := scReadJSON(caseDir, file.Envelope, &c.env); err != nil {
		return nil, err
	}
	if len(c.env.Signatures) == 0 {
		return nil, fmt.Errorf("the envelope carries no signature")
	}
	payload, err := base64.StdEncoding.DecodeString(c.env.Payload)
	if err != nil {
		return nil, fmt.Errorf("the payload is not base64: %w", err)
	}
	var record struct {
		SignedAt string `json:"signedAt"`
		Subject  struct {
			ID string `json:"id"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, fmt.Errorf("the payload does not parse: %w", err)
	}
	if c.signedAt, err = time.Parse(time.RFC3339, record.SignedAt); err != nil {
		return nil, fmt.Errorf("signedAt %q does not parse: %w", record.SignedAt, err)
	}
	c.payload, c.subject, c.keyID = payload, record.Subject.ID, c.env.Signatures[0].KeyID
	c.signer, _, _ = strings.Cut(c.keyID, "#")
	name, ok := file.Resolutions[c.signer]
	if !ok || !existsIn(caseDir, name) {
		return c, nil
	}
	var resolution struct {
		Versions []ibVersion `json:"versions"`
	}
	if err := scReadJSON(caseDir, name, &resolution); err != nil {
		return nil, err
	}
	for i := range resolution.Versions {
		updated, err := time.Parse(time.RFC3339, resolution.Versions[i].Meta.Updated)
		if err != nil {
			return nil, fmt.Errorf("%s: updated %q does not parse", name, resolution.Versions[i].Meta.Updated)
		}
		resolution.Versions[i].updated = updated
	}
	c.versions = append([]ibVersion{}, resolution.Versions...)
	return c, nil
}

func (c *ibCase) decide() scDecision {
	checks := []struct {
		reason string
		fails  func() bool
	}{
		{"did_malformed", func() bool { return !ibWellFormed(c.subject) || !ibWellFormed(c.signer) }},
		{"signer_not_subject", func() bool { return c.signer != c.subject }},
		{"did_unresolvable", func() bool { return c.versions == nil }},
		{"binding_fingerprint_mismatch", c.fingerprintMismatch},
		{"key_rotated_out", c.rotatedOut},
		{"key_not_authorized", func() bool {
			v := c.inEffect()
			return v == nil || !ibAuthorised(v.Doc, c.keyID)
		}},
		{"signature_invalid", func() bool { return !c.signatureVerifies() }},
	}
	for _, check := range checks {
		if check.fails() {
			return scDecision{"rejected", check.reason}
		}
	}
	return scDecision{"verified", "subject_bound"}
}

// reached is every version updated at or before the signing time, in order.
func (c *ibCase) reached() []ibVersion {
	var out []ibVersion
	for _, v := range c.versions {
		if !v.updated.After(c.signedAt) {
			out = append(out, v)
		}
	}
	return out
}

func (c *ibCase) inEffect() *ibVersion {
	reached := c.reached()
	if len(reached) == 0 {
		return nil
	}
	return &reached[len(reached)-1]
}

func (c *ibCase) fingerprintMismatch() bool {
	v := c.inEffect()
	if !strings.HasPrefix(c.signer, "did:wba:") || !strings.Contains(c.signer, ":e1_") || v == nil {
		return false
	}
	segment := c.signer[strings.LastIndex(c.signer, ":")+1:]
	methods := ibMethods(v.Doc)
	for _, ref := range ibRefs(v.Doc, "authentication") {
		method := methods[ref]
		if method == nil || method["type"] != "Multikey" {
			continue
		}
		if key := ibPublicKey(method); key != nil && segment == "e1_"+ibThumbprint(key) {
			return false
		}
	}
	return true
}

func (c *ibCase) rotatedOut() bool {
	v := c.inEffect()
	if v == nil {
		return false
	}
	ever := false
	for _, earlier := range c.reached() {
		ever = ever || ibAuthorised(earlier.Doc, c.keyID)
	}
	if !ever {
		return false
	}
	if v.Doc["deactivated"] == true || v.Meta.Deactivated {
		return true
	}
	return !ibAuthorised(v.Doc, c.keyID)
}

// signatureVerifies reports whether the DSSE signature verifies under the key
// keyid names in any version of the signer's document.
func (c *ibCase) signatureVerifies() bool {
	var key ed25519.PublicKey
	for i := len(c.versions) - 1; i >= 0 && key == nil; i-- {
		if method := ibMethods(c.versions[i].Doc)[c.keyID]; method != nil {
			key = ibPublicKey(method)
		}
	}
	sig, err := base64.StdEncoding.DecodeString(c.env.Signatures[0].Sig)
	if key == nil || err != nil {
		return false
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d ", len(c.env.PayloadType), c.env.PayloadType, len(c.payload))
	return ed25519.Verify(key, append([]byte(pae), c.payload...), sig)
}

func ibAbsolute(doc map[string]any, ref string) string {
	if strings.HasPrefix(ref, "#") {
		id, _ := doc["id"].(string)
		return id + ref
	}
	return ref
}

// ibRefs lists the absolute ids a verification relationship names, whether as
// a string reference or an embedded method.
func ibRefs(doc map[string]any, relationship string) []string {
	entries, _ := doc[relationship].([]any)
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		ref, _ := entry.(string)
		if method, ok := entry.(map[string]any); ok {
			ref, _ = method["id"].(string)
		}
		out = append(out, ibAbsolute(doc, ref))
	}
	return out
}

func ibMethods(doc map[string]any) map[string]map[string]any {
	found := map[string]map[string]any{}
	for _, relationship := range []string{"verificationMethod", "authentication", "assertionMethod"} {
		entries, _ := doc[relationship].([]any)
		for _, entry := range entries {
			if method, ok := entry.(map[string]any); ok {
				id, _ := method["id"].(string)
				found[ibAbsolute(doc, id)] = method
			}
		}
	}
	return found
}

func ibAuthorised(doc map[string]any, keyID string) bool {
	for _, relationship := range []string{"authentication", "assertionMethod"} {
		for _, ref := range ibRefs(doc, relationship) {
			if ref == keyID {
				return true
			}
		}
	}
	return false
}

// ibPublicKey returns the Ed25519 key of a Multikey or a JsonWebKey method.
func ibPublicKey(method map[string]any) ed25519.PublicKey {
	if multibase, ok := method["publicKeyMultibase"].(string); ok {
		raw := ibB58Decode(strings.TrimPrefix(multibase, "z"))
		if strings.HasPrefix(multibase, "z") && len(raw) == 34 && raw[0] == 0xed && raw[1] == 0x01 {
			return ed25519.PublicKey(raw[2:])
		}
		return nil
	}
	jwk, _ := method["publicKeyJwk"].(map[string]any)
	x, _ := jwk["x"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || err != nil || len(raw) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(raw)
}

// ibB58Decode decodes base58-btc, returning nil for a character outside it.
func ibB58Decode(text string) []byte {
	number := new(big.Int)
	for _, char := range text {
		index := strings.IndexRune(ibB58, char)
		if index < 0 {
			return nil
		}
		number.Mul(number, big.NewInt(58)).Add(number, big.NewInt(int64(index)))
	}
	zeros := len(text) - len(strings.TrimLeft(text, "1"))
	return append(bytes.Repeat([]byte{0}, zeros), number.Bytes()...)
}

// ibThumbprint is the RFC 7638 thumbprint of an Ed25519 key, base64url unpadded.
func ibThumbprint(key ed25519.PublicKey) string {
	member := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`
	sum := sha256.Sum256([]byte(member))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
