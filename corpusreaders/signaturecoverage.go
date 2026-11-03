package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

func init() { register(signatureCoverage{}) }

// signatureCoverage judges corpora/vectors-signature-coverage/. Each member is
// one signed structure: the source as readers see it (a map is
// {"entries": [[key, value], ...]}, in order, repeats kept), the signed payload
// with its Ed25519 signature, the keys declared outside the signature, and the
// paths a consumer reads. The reader derives each member's decision with the
// checks the Python reader applies, in the same order:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. signature_invalid: the signature verifies over the payload bytes;
//  4. payload_repeated_member: the payload repeats no member at any depth;
//  5. number_not_interoperable: no integer in the payload or the source is
//     outside the range every JSON parser reads exactly;
//  6. source_repeated_key: the source repeats no key at any depth;
//  7. reading_differs_from_signed: outside the declared keys, the source and
//     the payload hold the same members with the same values;
//  8. consumer_reads_unsigned: no consumer path starts at a declared key.
type signatureCoverage struct{}

const sigCovContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/signature-coverage"

func (signatureCoverage) Suite() string { return "signature-coverage/v1" }

type sigCovRetained struct {
	ConsumerReads int    `json:"consumerReads"`
	Excluded      int    `json:"excluded"`
	PayloadSha256 string `json:"payloadSha256"`
	SourceEntries int    `json:"sourceEntries"`
}

type sigCovVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained sigCovRetained    `json:"retained"`
}

type sigCovRecord struct {
	ContractID    json.RawMessage `json:"contractId"`
	ConsumerReads [][]string      `json:"consumerReads"`
	Envelope      struct {
		Excluded  []string `json:"excluded"`
		Payload   string   `json:"payload"`
		PublicKey string   `json:"publicKey"`
		Signature string   `json:"signature"`
	} `json:"envelope"`
	Source json.RawMessage `json:"source"`
}

func (signatureCoverage) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v sigCovVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = sigCovJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	if finding := sigCovPairsFinding(dir, raw); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func sigCovPairsFinding(dir string, raw []byte) string {
	var declared struct {
		SignerPairsSha256 string `json:"signerPairsSha256"`
	}
	if err := json.Unmarshal(raw, &declared); err != nil {
		return fmt.Sprintf("MANIFEST.json does not parse: %v", err)
	}
	body, err := readIn(dir, "signer-pairs.json")
	if err != nil {
		return "signer-pairs.json cannot be read"
	}
	if sha(body) != declared.SignerPairsSha256 {
		return "signer-pairs.json does not match its manifest digest"
	}
	return ""
}

func sigCovJudgeMember(caseDir string, v sigCovVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record sigCovRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	payload, key, signature, err := sigCovBytes(record)
	if err != nil {
		return append(findings, err.Error())
	}
	source, err := sigCovDecode(record.Source)
	if err != nil {
		return append(findings, "record.json source does not parse: "+err.Error())
	}
	kept := sigCovRetained{ConsumerReads: len(record.ConsumerReads), Excluded: len(record.Envelope.Excluded),
		PayloadSha256: sha(payload), SourceEntries: sigCovEntryCount(source)}
	if kept != v.Retained {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := sigCovDecide(record, source, payload, key, signature); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func sigCovBytes(r sigCovRecord) (payload, key, signature []byte, err error) {
	if payload, err = base64.StdEncoding.DecodeString(r.Envelope.Payload); err != nil {
		return nil, nil, nil, fmt.Errorf("record.json payload is not base64: %w", err)
	}
	if key, err = base64.StdEncoding.DecodeString(r.Envelope.PublicKey); err != nil {
		return nil, nil, nil, fmt.Errorf("record.json public key is not base64: %w", err)
	}
	if signature, err = base64.StdEncoding.DecodeString(r.Envelope.Signature); err != nil {
		return nil, nil, nil, fmt.Errorf("record.json signature is not base64: %w", err)
	}
	return payload, key, signature, nil
}

func sigCovDecode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	err := dec.Decode(&value)
	return value, err
}

// sigCovEntries returns a source map's entries, and whether value is a map.
func sigCovEntries(value any) ([][]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 {
		return nil, false
	}
	raw, ok := object["entries"].([]any)
	if !ok {
		return nil, false
	}
	entries := make([][]any, 0, len(raw))
	for _, item := range raw {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			return nil, false
		}
		entries = append(entries, pair)
	}
	return entries, true
}

func sigCovChildren(value any) []any {
	if entries, ok := sigCovEntries(value); ok {
		children := make([]any, 0, len(entries))
		for _, pair := range entries {
			children = append(children, pair[1])
		}
		return children
	}
	list, _ := value.([]any)
	return list
}

func sigCovEntryCount(value any) int {
	entries, _ := sigCovEntries(value)
	count := len(entries)
	for _, child := range sigCovChildren(value) {
		count += sigCovEntryCount(child)
	}
	return count
}

func sigCovRepeats(value any) bool {
	if entries, ok := sigCovEntries(value); ok {
		seen := map[any]bool{}
		for _, pair := range entries {
			if seen[pair[0]] {
				return true
			}
			seen[pair[0]] = true
		}
	}
	return slices.ContainsFunc(sigCovChildren(value), sigCovRepeats)
}

func sigCovFlatten(value any) any {
	if entries, ok := sigCovEntries(value); ok {
		flat := make(map[string]any, len(entries))
		for _, pair := range entries {
			key, _ := pair[0].(string)
			flat[key] = sigCovFlatten(pair[1])
		}
		return flat
	}
	if list, ok := value.([]any); ok {
		flat := make([]any, len(list))
		for i, item := range list {
			flat[i] = sigCovFlatten(item)
		}
		return flat
	}
	return value
}

func sigCovInexactInteger(value any) bool {
	switch v := value.(type) {
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			return false
		}
		n, ok := new(big.Int).SetString(v.String(), 10)
		return !ok || n.CmpAbs(big.NewInt(1<<53-1)) > 0
	case []any:
		return slices.ContainsFunc(v, sigCovInexactInteger)
	case map[string]any:
		for _, item := range v {
			if sigCovInexactInteger(item) {
				return true
			}
		}
	}
	return false
}

// sigCovSame compares two JSON values, numbers by value. Reached only after
// sigCovInexactInteger, so every integer here converts to float64 exactly.
func sigCovSame(left, right any) bool {
	if a, ok := left.(json.Number); ok {
		b, ok := right.(json.Number)
		if !ok {
			return false
		}
		x, errX := a.Float64()
		y, errY := b.Float64()
		return errX == nil && errY == nil && x == y
	}
	switch a := left.(type) {
	case map[string]any:
		b, ok := right.(map[string]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for key, item := range a {
			other, present := b[key]
			if !present || !sigCovSame(item, other) {
				return false
			}
		}
		return true
	case []any:
		b, ok := right.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !sigCovSame(a[i], b[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(left, right)
}

func sigCovReadingDiffers(source, payload any, excluded []string) bool {
	reading, ok := sigCovFlatten(source).(map[string]any)
	if !ok {
		return true
	}
	covered := make(map[string]any, len(reading))
	for key, item := range reading {
		if !slices.Contains(excluded, key) {
			covered[key] = item
		}
	}
	return !sigCovSame(covered, payload)
}

func sigCovDecide(r sigCovRecord, source any, payload, key, signature []byte) scDecision {
	var contract string
	known := len(r.ContractID) > 0 && json.Unmarshal(r.ContractID, &contract) == nil && contract == sigCovContractID
	verified := len(key) == ed25519.PublicKeySize && ed25519.Verify(key, payload, signature)
	repeated := bvNoDuplicates(json.NewDecoder(bytes.NewReader(payload))) != nil
	parsed, err := sigCovDecode(payload)
	readsUnsigned := slices.ContainsFunc(r.ConsumerReads, func(path []string) bool {
		return len(path) > 0 && slices.Contains(r.Envelope.Excluded, path[0])
	})
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", len(r.ContractID) == 0},
		{"contract_id_unknown", len(r.ContractID) > 0 && !known},
		{"signature_invalid", !verified},
		{"payload_repeated_member", repeated || err != nil},
		{"number_not_interoperable", sigCovInexactInteger(parsed) || sigCovInexactInteger(source)},
		{"source_repeated_key", sigCovRepeats(source)},
		{"reading_differs_from_signed", sigCovReadingDiffers(source, parsed, r.Envelope.Excluded)},
		{"consumer_reads_unsigned", readsUnsigned},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "signature_covers_reading"}
}
