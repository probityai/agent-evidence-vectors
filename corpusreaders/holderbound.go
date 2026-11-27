package corpusreaders

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

func init() { register(holderBound{}) }

// holderBound judges corpora/vectors-holder-bound-credential/. A record is one credential
// and the DPoP proofs (RFC 9449) of possession presented with it; a record is accepted
// only when every proof is signed by the key the credential confirms. The twenty checks
// and their order are those of the Python reference reader
// (packaging/agent_evidence_vectors/holderbound.py), and the answer is derived from the
// record alone, never from the manifest.
type holderBound struct{}

func (holderBound) Suite() string { return "holder-bound-credential/v1" }

const (
	hbContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/holder-bound-credential"
	hbMaxAge     = 60
	hbMaxAhead   = 5
)

var (
	hbB64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	// Ed25519 (RFC 8032): p = 2^255 - 19, the curve -x^2 + y^2 = 1 + d x^2 y^2, and the
	// prime order L of the base point's subgroup.
	hbP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	hbL = func() *big.Int {
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return l
	}()
	hbD = func() *big.Int {
		inv := new(big.Int).ModInverse(big.NewInt(121666), hbP)
		d := new(big.Int).Mul(big.NewInt(-121665), inv)
		return d.Mod(d, hbP)
	}()
	hbSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(hbP, big.NewInt(1)), 2), hbP)
)

// hbUnB64 is the bytes of canonical unpadded base64url text, or false when it is not.
func hbUnB64(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || !hbB64URL.MatchString(s) || len(s)%4 == 1 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != s {
		return nil, false
	}
	return data, true
}

func hbB64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// Curve arithmetic -------------------------------------------------------------------

type hbPoint struct{ x, y *big.Int }

func hbMod(v *big.Int) *big.Int { return v.Mod(v, hbP) }

func hbInv(v *big.Int) *big.Int { return new(big.Int).ModInverse(v, hbP) }

func hbAdd(a, b hbPoint) hbPoint {
	xy := hbMod(new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y)))
	dxy := hbMod(new(big.Int).Mul(hbD, xy))
	x := hbMod(new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(b.x, a.y)))
	y := hbMod(new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x)))
	x = hbMod(x.Mul(x, hbInv(hbMod(new(big.Int).Add(big.NewInt(1), dxy)))))
	y = hbMod(y.Mul(y, hbInv(hbMod(new(big.Int).Sub(big.NewInt(1), dxy)))))
	return hbPoint{x, y}
}

func hbMul(k *big.Int, p hbPoint) hbPoint {
	result := hbPoint{big.NewInt(0), big.NewInt(1)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = hbAdd(result, result)
		if k.Bit(i) == 1 {
			result = hbAdd(result, p)
		}
	}
	return result
}

// hbDecompress reads a point as RFC 8032 section 5.1.3 does, refusing a y that is not
// reduced and the sign bit on x = 0.
func hbDecompress(raw []byte) (hbPoint, bool) {
	if len(raw) != 32 {
		return hbPoint{}, false
	}
	little := make([]byte, 32)
	for i := range raw {
		little[31-i] = raw[i]
	}
	n := new(big.Int).SetBytes(little)
	sign := n.Bit(255)
	n.SetBit(n, 255, 0)
	if n.Cmp(hbP) >= 0 {
		return hbPoint{}, false
	}
	y := n
	yy := new(big.Int).Mul(y, y)
	num := hbMod(new(big.Int).Sub(yy, big.NewInt(1)))
	den := hbMod(new(big.Int).Add(new(big.Int).Mul(hbD, yy), big.NewInt(1)))
	xx := hbMod(num.Mul(num, hbInv(den)))
	x := new(big.Int).Exp(xx, new(big.Int).Rsh(new(big.Int).Add(hbP, big.NewInt(3)), 3), hbP)
	if hbMod(new(big.Int).Sub(new(big.Int).Mul(x, x), xx)).Sign() != 0 {
		x = hbMod(x.Mul(x, hbSqrtM1))
	}
	if hbMod(new(big.Int).Sub(new(big.Int).Mul(x, x), xx)).Sign() != 0 {
		return hbPoint{}, false
	}
	if x.Sign() == 0 && sign == 1 {
		return hbPoint{}, false
	}
	if x.Bit(0) != sign {
		x = new(big.Int).Sub(hbP, x)
	}
	return hbPoint{x, y}, true
}

func hbIsIdentity(p hbPoint) bool { return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0 }

// hbPrimeOrder reports whether raw encodes a point of the prime-order subgroup other
// than the identity, as an honest key does. A point of small order verifies a forged
// signature over a message the forger chooses, and a point with a torsion component is
// read differently by cofactored and cofactorless verifiers.
func hbPrimeOrder(raw []byte) bool {
	point, ok := hbDecompress(raw)
	return ok && !hbIsIdentity(point) && hbIsIdentity(hbMul(hbL, point))
}

// Shape ------------------------------------------------------------------------------

type hbProof struct {
	atInt          *big.Int
	method0, uri0  string
	signingInput   []byte
	header, claims map[string]any
	signature      []byte
}

func hbIsText(v any) bool { s, ok := v.(string); return ok && s != "" }

func hbKeys(m map[string]any, names ...string) bool {
	if len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}

// hbShape reports whether the record has the shape this contract reads.
func hbShape(record map[string]any) bool {
	if !hbKeys(record, "contractId", "subject", "credential", "presentations") || !hbIsText(record["subject"]) {
		return false
	}
	credential, ok := record["credential"].(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"issuer", "iat", "exp", "token"} {
		if _, present := credential[k]; !present {
			return false
		}
	}
	extra := len(credential) - 4
	if _, hasCnf := credential["cnf"]; extra != 0 && !(extra == 1 && hasCnf) || !hbIsText(credential["issuer"]) {
		return false
	}
	iat, okIat := deInt(credential["iat"])
	exp, okExp := deInt(credential["exp"])
	if !okIat || !okExp || iat.Cmp(exp) >= 0 {
		return false
	}
	token, _ := credential["token"].(string)
	if token == "" {
		return false
	}
	for _, r := range token {
		if r > 127 {
			return false
		}
	}
	if raw, present := credential["cnf"]; present {
		cnf, ok := raw.(map[string]any)
		if !ok || !hbKeys(cnf, "jkt") {
			return false
		}
		if jkt, ok := hbUnB64(cnf["jkt"]); !ok || len(jkt) != 32 {
			return false
		}
	}
	presentations, ok := record["presentations"].([]any)
	if !ok || len(presentations) == 0 {
		return false
	}
	for _, raw := range presentations {
		item, ok := raw.(map[string]any)
		if !ok || !hbKeys(item, "at", "request", "proof") {
			return false
		}
		if _, ok := deInt(item["at"]); !ok {
			return false
		}
		request, ok := item["request"].(map[string]any)
		if !ok || !hbKeys(request, "htm", "htu") || !hbIsText(request["htm"]) || !hbIsText(request["htu"]) {
			return false
		}
		if strings.ContainsAny(request["htu"].(string), "?#") {
			return false
		}
		proof, ok := item["proof"].(map[string]any)
		if !ok || !hbKeys(proof, "protected", "payload", "signature") {
			return false
		}
		for _, v := range proof {
			if _, ok := v.(string); !ok {
				return false
			}
		}
	}
	return true
}

// hbDecode decodes one presentation; a proof that is not a JWS leaves header nil. The
// proof is the flattened JWS JSON serialization of RFC 7515 section 7.2.2, and the bytes
// that were signed are protected + "." + payload.
func hbDecode(raw any) hbProof {
	item := raw.(map[string]any)
	request := item["request"].(map[string]any)
	at, _ := deInt(item["at"])
	blank := hbProof{atInt: at, method0: request["htm"].(string), uri0: request["htu"].(string)}
	proof := item["proof"].(map[string]any)
	protected, payload, signature := proof["protected"].(string), proof["payload"].(string), proof["signature"].(string)
	head, okHead := hbUnB64(protected)
	body, okBody := hbUnB64(payload)
	var sig []byte
	okSig := true
	if signature != "" {
		sig, okSig = hbUnB64(signature)
	}
	if !okHead || !okBody || !okSig {
		return blank
	}
	object := func(b []byte) map[string]any {
		if !utf8.Valid(b) {
			return nil
		}
		value, err := decodeJSONNumbers(b)
		m, _ := value.(map[string]any)
		if err != nil {
			return nil
		}
		return m
	}
	header, claims := object(head), object(body)
	if header == nil || claims == nil {
		return blank
	}
	if _, crit := header["crit"]; crit {
		return blank
	}
	blank.signingInput = []byte(protected + "." + payload)
	blank.header, blank.claims, blank.signature = header, claims, sig
	return blank
}

// Checks -----------------------------------------------------------------------------

func hbKey(p hbProof) map[string]any {
	jwk, ok := p.header["jwk"].(map[string]any)
	if !ok || !hbKeys(jwk, "kty", "crv", "x") || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return nil
	}
	raw, ok := hbUnB64(jwk["x"])
	if !ok || len(raw) != 32 || !hbPrimeOrder(raw) {
		return nil
	}
	return jwk
}

func hbSignatureHolds(p hbProof) bool {
	jwk := hbKey(p)
	if jwk == nil || len(p.signature) != ed25519.SignatureSize {
		return false
	}
	key, _ := hbUnB64(jwk["x"])
	return ed25519.Verify(ed25519.PublicKey(key), p.signingInput, p.signature)
}

func hbThumbprint(jwk map[string]any) string {
	text := `{"crv":"` + jwk["crv"].(string) + `","kty":"` + jwk["kty"].(string) + `","x":"` + jwk["x"].(string) + `"}`
	digest := sha256.Sum256([]byte(text))
	return hbB64(digest[:])
}

func hbAth(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hbB64(digest[:])
}

func hbClaimsOK(p hbProof) bool {
	_, okIat := deInt(p.claims["iat"])
	return hbIsText(p.claims["jti"]) && hbIsText(p.claims["htm"]) && hbIsText(p.claims["htu"]) && okIat
}

// hbASCIIFold lower-cases the ASCII letters only, as the Python reader does: JOSE algorithm
// names are ASCII, so a name with any other letter is not a MAC name, and neither Go's simple
// nor Python's full Unicode case mapping may make it one.
func hbASCIIFold(text string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, text)
}

// hbAlgText is Python's str() of the header's alg for the two comparisons that read it:
// a missing or null alg reads "None".
func hbAlgText(header map[string]any) string {
	switch alg := header["alg"].(type) {
	case nil:
		return "None"
	case string:
		return alg
	}
	return "?"
}

func hbDecide(record map[string]any) scDecision {
	reject := func(reason string) scDecision { return scDecision{Decision: "reject", Reason: reason} }
	if _, present := record["contractId"]; !present {
		return reject("contract_id_missing")
	}
	if record["contractId"] != hbContractID {
		return reject("contract_id_unknown")
	}
	if !hbShape(record) {
		return reject("record_malformed")
	}
	credential := record["credential"].(map[string]any)
	if _, bound := credential["cnf"]; !bound {
		return reject("credential_not_holder_bound")
	}
	iat, _ := deInt(credential["iat"])
	exp, _ := deInt(credential["exp"])
	var proofs, decoded []hbProof
	for _, raw := range record["presentations"].([]any) {
		p := hbDecode(raw)
		proofs = append(proofs, p)
		if p.header != nil && p.claims != nil {
			decoded = append(decoded, p)
		}
	}
	for _, p := range proofs {
		if p.atInt.Cmp(iat) < 0 {
			return reject("credential_not_yet_valid")
		}
	}
	for _, p := range proofs {
		if p.atInt.Cmp(exp) >= 0 {
			return reject("credential_expired")
		}
	}
	for _, p := range proofs {
		if p.header == nil || p.claims == nil {
			return reject("proof_malformed")
		}
	}
	token := credential["token"].(string)
	jkt := credential["cnf"].(map[string]any)["jkt"]
	anyDecoded := func(test func(hbProof) bool) bool {
		for _, p := range decoded {
			if test(p) {
				return true
			}
		}
		return false
	}
	tests := []struct {
		reason string
		fails  func(hbProof) bool
	}{
		{"proof_type_wrong", func(p hbProof) bool { return p.header["typ"] != "dpop+jwt" }},
		{"proof_alg_forbidden", func(p hbProof) bool {
			alg := hbAlgText(p.header)
			folded := hbASCIIFold(alg)
			return folded == "none" || strings.HasPrefix(folded, "hs")
		}},
		{"proof_alg_unsupported", func(p hbProof) bool { return p.header["alg"] != "EdDSA" }},
		{"proof_key_invalid", func(p hbProof) bool { return hbKey(p) == nil }},
		{"proof_signature_invalid", func(p hbProof) bool { return !hbSignatureHolds(p) }},
		{"proof_claims_malformed", func(p hbProof) bool { return !hbClaimsOK(p) }},
		{"proof_method_mismatch", func(p hbProof) bool { return p.claims["htm"] != p.method0 }},
		{"proof_uri_mismatch", func(p hbProof) bool { return p.claims["htu"] != p.uri0 }},
		{"proof_stale", func(p hbProof) bool {
			iat, _ := deInt(p.claims["iat"])
			return iat.Cmp(new(big.Int).Sub(p.atInt, big.NewInt(hbMaxAge))) < 0
		}},
		{"proof_from_future", func(p hbProof) bool {
			iat, _ := deInt(p.claims["iat"])
			return iat.Cmp(new(big.Int).Add(p.atInt, big.NewInt(hbMaxAhead))) > 0
		}},
		{"proof_ath_missing", func(p hbProof) bool { _, present := p.claims["ath"]; return !present }},
		{"proof_ath_mismatch", func(p hbProof) bool { return p.claims["ath"] != hbAth(token) }},
		{"proof_key_not_bound", func(p hbProof) bool {
			key := hbKey(p)
			return key != nil && hbThumbprint(key) != jkt
		}},
	}
	for _, t := range tests {
		if anyDecoded(t.fails) {
			return reject(t.reason)
		}
	}
	seen := map[string]bool{}
	for _, p := range proofs {
		if jti, present := p.claims["jti"].(string); present {
			if seen[jti] {
				return reject("proof_replayed")
			}
			seen[jti] = true
		}
	}
	return scDecision{Decision: "accept", Reason: "holder_bound"}
}

type hbRetained struct {
	Subject *string `json:"subject"`
	Jkt     *string `json:"jkt"`
}

type hbVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained hbRetained        `json:"retained"`
}

func hbRetain(record map[string]any) hbRetained {
	if record == nil || !hbShape(record) {
		return hbRetained{}
	}
	subject := record["subject"].(string)
	out := hbRetained{Subject: &subject}
	if cnf, ok := record["credential"].(map[string]any)["cnf"].(map[string]any); ok {
		jkt := cnf["jkt"].(string)
		out.Jkt = &jkt
	}
	return out
}

// Judge ------------------------------------------------------------------------------

func (holderBound) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v hbVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = hbJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func hbJudgeMember(caseDir string, v hbVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read")
	}
	var record map[string]any
	if value, err := decodeJSONNumbers(body); err == nil {
		record, _ = value.(map[string]any)
	}
	if !reflect.DeepEqual(hbRetain(record), v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	got := scDecision{Decision: "reject", Reason: "record_malformed"}
	if record != nil {
		got = hbDecide(record)
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}
