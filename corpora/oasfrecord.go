package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

func init() { register(oasfRecord{}) }

// oasfRecord judges vectors-oasf-record/. Each member is an OASF record's
// bytes (record.json) and a case (case.json) carrying the digest the producer
// claims for it, the identity of the certificate that signed that digest, and
// the identity the consumer's policy names. The reader derives each member's
// decision with the checks the Python reader applies, in the same order, and
// names the first one that fails:
//
//  1. the case carries contractId: contract_id_missing;
//  2. contractId is the OASF record contract: contract_id_unknown;
//  3. the case has a sha256: digest, a signer and a policy, each with a
//     subject and an issuer: malformed_case;
//  4. the record is UTF-8 JSON with no duplicate member: record_not_json;
//  5. every integer is inside the exact double range: number_not_exact;
//  6. the record carries the fields OASF marks required: oasf_required_field;
//  7. the digest is SHA-256 over the record's RFC 8785 bytes: digest_mismatch;
//  8. the signer equals the policy exactly: signer_not_policy.
type oasfRecord struct{}

const orContractID = "https://probityai.github.io/agent-evidence-vectors/contract/oasf-record/v1"

var (
	orDigestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	orRFC3339Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	orExactLimit     = new(big.Int).SetInt64(1<<53 - 1)
	errORDuplicate   = errors.New("duplicate member")
)

func (oasfRecord) Suite() string { return "oasf-record/v1" }

func (oasfRecord) Judge(dir string, raw []byte) (*Result, error) {
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
		member.Findings = orJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func orJudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c map[string]any
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	record, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, fmt.Sprintf("record.json cannot be read: %v", err))
	}
	got := orDecide(c, record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func orDecide(c map[string]any, record []byte) scDecision {
	id, present := c["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != orContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	digest, ok := c["recordDigest"].(string)
	signer, signerOK := orIdentity(c["signer"])
	policy, policyOK := orIdentity(c["policy"])
	if !ok || !orDigestPattern.MatchString(digest) || !signerOK || !policyOK {
		return scDecision{"deny", "malformed_case"}
	}
	value, err := orParse(record)
	if err != nil {
		return scDecision{"deny", "record_not_json"}
	}
	if !orExact(value) {
		return scDecision{"deny", "number_not_exact"}
	}
	if orRequiredMissing(value) {
		return scDecision{"deny", "oasf_required_field"}
	}
	var buf strings.Builder
	if err := a2aWrite(&buf, value); err != nil {
		return scDecision{"deny", "number_not_exact"}
	}
	sum := sha256.Sum256([]byte(buf.String()))
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return scDecision{"deny", "digest_mismatch"}
	}
	if signer != policy {
		return scDecision{"deny", "signer_not_policy"}
	}
	return scDecision{"allow", "conformant"}
}

func orIdentity(value any) ([2]string, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return [2]string{}, false
	}
	subject, okS := m["subject"].(string)
	issuer, okI := m["issuer"].(string)
	return [2]string{subject, issuer}, okS && okI && subject != "" && issuer != ""
}

// orParse decodes record bytes strictly: valid UTF-8, one value, no duplicate
// member at any depth. Numbers stay json.Number so integers keep their digits.
func orParse(record []byte) (any, error) {
	if !utf8.Valid(record) || a2aLoneSurrogate(record) {
		return nil, errA2ARefused
	}
	if err := orNoDuplicates(json.NewDecoder(bytes.NewReader(record))); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(record))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errA2ARefused
	}
	return value, nil
}

// orNoDuplicates walks the token stream once and refuses a member name that
// repeats inside one object.
func orNoDuplicates(dec *json.Decoder) error {
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
		top := (*frame)(nil)
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
				return errORDuplicate
			}
			top.seen[name] = true
			top.key = false
			continue
		}
		top.key = true
	}
}

func orExact(value any) bool {
	switch v := value.(type) {
	case json.Number:
		text := string(v)
		if strings.ContainsAny(text, ".eE") {
			return true
		}
		n, ok := new(big.Int).SetString(text, 10)
		return ok && new(big.Int).Abs(n).Cmp(orExactLimit) <= 0
	case []any:
		for _, item := range v {
			if !orExact(item) {
				return false
			}
		}
	case map[string]any:
		for _, item := range v {
			if !orExact(item) {
				return false
			}
		}
	}
	return true
}

func orRequiredMissing(value any) bool {
	record, ok := value.(map[string]any)
	if !ok {
		return true
	}
	for _, name := range []string{"name", "version", "schema_version", "description"} {
		if text, ok := record[name].(string); !ok || text == "" {
			return true
		}
	}
	authors, ok := record["authors"].([]any)
	if !ok || len(authors) == 0 {
		return true
	}
	for _, author := range authors {
		if text, ok := author.(string); !ok || text == "" {
			return true
		}
	}
	created, ok := record["created_at"].(string)
	if !ok || !orRFC3339Pattern.MatchString(created) {
		return true
	}
	if _, err := time.Parse(time.RFC3339Nano, created); err != nil {
		return true
	}
	skills, ok := record["skills"].([]any)
	if !ok || len(skills) == 0 {
		return true
	}
	for _, skill := range skills {
		if !orSkill(skill) {
			return true
		}
	}
	return false
}

func orSkill(value any) bool {
	skill, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if name, ok := skill["name"].(string); ok && name != "" {
		return true
	}
	number, ok := skill["id"].(json.Number)
	return ok && !strings.ContainsAny(string(number), ".eE")
}
