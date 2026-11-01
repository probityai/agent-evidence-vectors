package corpora

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

func init() { register(badgeVC{}) }

// badgeVC judges vectors-badge-vc-verify/. Each member is one case.json: an
// agent badge issued as a W3C Verifiable Credential in a compact JWS signed
// with EdDSA, the verification time, the key material resolved for each issuer
// DID, the issuers the verifier trusts, and the issuer's own revocation store.
// The reader derives each member's decision with the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the case carries contractId: contract_id_missing;
//  2. contractId is the badge contract: contract_id_unknown;
//  3. the case has the fields and types the contract names: malformed_case;
//  4. the credential is three base64url parts and the header names EdDSA and a
//     <did>#<fragment> key id: jws_malformed;
//  5. the payload is a credential object with the members the contract names
//     and RFC 3339 times: credential_malformed;
//  6. the issuer is trusted: issuer_not_trusted;
//  7. the key id belongs to the credential's issuer: issuer_key_binding;
//  8. the Ed25519 signature verifies over header.payload: signature_invalid;
//  9. issuanceDate is not after the verification time: not_yet_valid;
//  10. expirationDate is after the verification time: expired;
//  11. the credential is not in the issuer's revoked list: revoked.
type badgeVC struct{}

const bvContractID = "https://probityai.github.io/agent-evidence-vectors/contract/badge-vc-verify/v1"

var (
	bvKidPattern   = regexp.MustCompile(`^(did:[a-z0-9]+:[^#\s]+)#([^#\s]+)$`)
	bvTimePattern  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$`)
	errBVDuplicate = errors.New("duplicate member")
	errBVNotJSON   = errors.New("not JSON")
)

func (badgeVC) Suite() string { return "badge-vc-verify/v1" }

func (badgeVC) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v drVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = bvJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func bvJudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c map[string]any
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	got := bvDecide(c)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func bvDeny(reason string) scDecision { return scDecision{"deny", reason} }

func bvDecide(c map[string]any) scDecision {
	id, present := c["contractId"]
	if !present {
		return bvDeny("contract_id_missing")
	}
	if id != bvContractID {
		return bvDeny("contract_id_unknown")
	}
	at, keys, ok := bvCase(c)
	if !ok {
		return bvDeny("malformed_case")
	}
	token := c["credential"].(string)
	parts := strings.Split(token, ".")
	kidDID, kidFragment, ok := bvHeader(parts)
	if !ok {
		return bvDeny("jws_malformed")
	}
	payload, ok := bvPayload(parts[1])
	if !ok {
		return bvDeny("credential_malformed")
	}
	issuer := payload["issuer"].(string)
	if !bvContains(c["trustedIssuers"], issuer) {
		return bvDeny("issuer_not_trusted")
	}
	key, known := keys[kidDID][kidFragment]
	if kidDID != issuer || !known {
		return bvDeny("issuer_key_binding")
	}
	signature, _ := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if !ed25519.Verify(ed25519.PublicKey(key), []byte(parts[0]+"."+parts[1]), signature) {
		return bvDeny("signature_invalid")
	}
	if issued, _ := time.Parse(time.RFC3339Nano, payload["issuanceDate"].(string)); issued.After(at) {
		return bvDeny("not_yet_valid")
	}
	if text, has := payload["expirationDate"].(string); has {
		if expires, _ := time.Parse(time.RFC3339Nano, text); !expires.After(at) {
			return bvDeny("expired")
		}
	}
	revoked := c["status"].(map[string]any)["revoked"]
	if bvContains(revoked, payload["id"].(string)) {
		return bvDeny("revoked")
	}
	return scDecision{"allow", "verified"}
}

// bvCase checks the case's fields and types, and returns the verification
// time and the issuers' keys as raw bytes by DID and fragment.
func bvCase(c map[string]any) (time.Time, map[string]map[string][]byte, bool) {
	var at time.Time
	if text, ok := c["credential"].(string); !ok || text == "" {
		return at, nil, false
	}
	at, ok := bvTime(c["verificationTime"])
	if !ok {
		return at, nil, false
	}
	if list, ok := c["trustedIssuers"].([]any); !ok || !bvAllText(list) {
		return at, nil, false
	}
	status, ok := c["status"].(map[string]any)
	if !ok {
		return at, nil, false
	}
	if list, ok := status["revoked"].([]any); !ok || !bvAllText(list) {
		return at, nil, false
	}
	issuers, ok := c["issuers"].(map[string]any)
	if !ok {
		return at, nil, false
	}
	keys, ok := bvKeys(issuers)
	return at, keys, ok
}

// bvKeys reads each issuer's declared keys; one malformed entry refuses the case.
func bvKeys(issuers map[string]any) (map[string]map[string][]byte, bool) {
	keys := map[string]map[string][]byte{}
	for did, entry := range issuers {
		holder, ok := entry.(map[string]any)
		if !ok {
			return nil, false
		}
		declared, ok := holder["keys"].(map[string]any)
		if !ok {
			return nil, false
		}
		held, ok := bvHeld(declared)
		if !ok {
			return nil, false
		}
		keys[did] = held
	}
	return keys, true
}

func bvHeld(declared map[string]any) (map[string][]byte, bool) {
	held := map[string][]byte{}
	for fragment, value := range declared {
		text, ok := value.(string)
		if !ok || fragment == "" {
			return nil, false
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, false
		}
		held[fragment] = raw
	}
	return held, true
}

func bvAllText(list []any) bool {
	for _, item := range list {
		if text, ok := item.(string); !ok || text == "" {
			return false
		}
	}
	return true
}

func bvContains(list any, want string) bool {
	items, _ := list.([]any)
	for _, item := range items {
		if text, ok := item.(string); ok && text == want {
			return true
		}
	}
	return false
}

func bvTime(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !bvTimePattern.MatchString(text) {
		return time.Time{}, false
	}
	moment, err := time.Parse(time.RFC3339Nano, text)
	return moment, err == nil
}

// bvHeader checks the token's shape and its header, and returns the key id's
// DID and fragment.
func bvHeader(parts []string) (string, string, bool) {
	if len(parts) != 3 {
		return "", "", false
	}
	var decoded [3][]byte
	for i, part := range parts {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			return "", "", false
		}
		decoded[i] = raw
	}
	value, err := bvParse(decoded[0])
	header, ok := value.(map[string]any)
	if err != nil || !ok || header["alg"] != "EdDSA" {
		return "", "", false
	}
	kid, ok := header["kid"].(string)
	if !ok {
		return "", "", false
	}
	match := bvKidPattern.FindStringSubmatch(kid)
	if match == nil {
		return "", "", false
	}
	return match[1], match[2], true
}

// bvPayload decodes the credential and checks the members the contract names.
func bvPayload(part string) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(part)
	if err != nil {
		return nil, false
	}
	value, err := bvParse(raw)
	payload, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, false
	}
	for _, name := range []string{"id", "issuer"} {
		if text, ok := payload[name].(string); !ok || text == "" {
			return nil, false
		}
	}
	if !bvIsCredential(payload["type"]) {
		return nil, false
	}
	subject, ok := payload["credentialSubject"].(map[string]any)
	if !ok {
		return nil, false
	}
	if text, ok := subject["id"].(string); !ok || text == "" {
		return nil, false
	}
	if _, ok := bvTime(payload["issuanceDate"]); !ok {
		return nil, false
	}
	if expires, has := payload["expirationDate"]; has {
		if _, ok := bvTime(expires); !ok {
			return nil, false
		}
	}
	return payload, true
}

func bvIsCredential(kinds any) bool {
	switch v := kinds.(type) {
	case string:
		return v == "VerifiableCredential"
	case []any:
		return bvContains(v, "VerifiableCredential")
	}
	return false
}

// bvParse decodes strictly: valid UTF-8, one value, no duplicate member at any
// depth, and no NaN or Infinity.
func bvParse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errBVNotJSON
	}
	if err := bvNoDuplicates(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errBVNotJSON
	}
	return value, nil
}

// bvNoDuplicates walks the token stream once and refuses a member name that
// repeats inside one object.
func bvNoDuplicates(dec *json.Decoder) error {
	type frame struct {
		object bool
		seen   map[string]bool
		key    bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.object {
					top.key = true
				}
				stack = append(stack, &frame{object: delim == '{', seen: map[string]bool{}, key: true})
			default:
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.key {
			name, _ := tok.(string)
			if top.seen[name] {
				return errBVDuplicate
			}
			top.seen[name] = true
			top.key = false
			continue
		}
		top.key = true
	}
}
