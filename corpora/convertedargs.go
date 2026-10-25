package corpora

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func init() { register(convertedArgs{}) }

// convertedArgs judges vectors-converted-argument-binding/. Each member is one
// approved tool call: the arguments the model gave, the arguments as converted
// and shown to the approver, the rebuild of the approved arguments, the
// arguments the tool ran with, and the digests that bind the approval. The
// reader derives each member's decision with the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the converted-argument-binding contract:
//     contract_id_unknown;
//  3. the approval's shownSha256 is the digest of shown.json:
//     approval_not_bound_to_shown;
//  4. shown.json is I-JSON: shown_not_storable;
//  5. raw.json satisfies the declared types and enums: invalid_call_approved;
//  6. under modify, modified.json carries every defaulted parameter and no
//     undeclared one: modify_not_full_call;
//  7. the RFC 8785 form of rebuilt.json equals that of the approved arguments:
//     rebuild_not_identical;
//  8. under approve, the call's digest is unchanged by the approval chain:
//     call_mutated_after_approval;
//  9. the RFC 8785 form of executed.json equals that of the approved
//     arguments: shown_not_executed.
//
// The reader also recomputes each member's declared shownEqualsExecuted.
type convertedArgs struct{}

const (
	caContractID = "https://probityai.github.io/agent-evidence-observer/contract/converted-argument-binding/v1"
	caSafeBits   = 53
)

func (convertedArgs) Suite() string { return "converted-argument-binding/v1" }

type caVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Equal    bool              `json:"shownEqualsExecuted"`
}

type caParam struct {
	Type    string            `json:"type"`
	Enum    []json.RawMessage `json:"enum"`
	Default json.RawMessage   `json:"default"`
}

type caRecord struct {
	ContractID *string            `json:"contractId"`
	Parameters map[string]caParam `json:"parameters"`
	Approval   struct {
		Decision string `json:"decision"`
		ShownSha string `json:"shownSha256"`
	} `json:"approval"`
	Before string `json:"callCopyBeforeSha256"`
	After  string `json:"callCopyAfterSha256"`
}

// caFiles holds the bytes of each argument file; an absent file is nil.
type caFiles struct{ raw, shown, rebuilt, executed, modified []byte }

func (convertedArgs) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v caVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = caJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func caJudgeMember(caseDir string, v caVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record caRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	files := caFiles{
		raw: caOptional(caseDir, "raw.json"), shown: caOptional(caseDir, "shown.json"),
		rebuilt: caOptional(caseDir, "rebuilt.json"), executed: caOptional(caseDir, "executed.json"),
		modified: caOptional(caseDir, "modified.json"),
	}
	shown := caCanonical(files.shown)
	equal := shown != nil && bytes.Equal(shown, caCanonical(files.executed))
	if equal != v.Equal {
		findings = append(findings, fmt.Sprintf(
			"shown equals executed: %t, the manifest declares %t", equal, v.Equal))
	}
	got := caDecide(record, files)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func caOptional(caseDir, name string) []byte {
	body, err := readIn(caseDir, name)
	if err != nil {
		return nil
	}
	return body
}

func caDecide(r caRecord, f caFiles) scDecision {
	modifying := r.Approval.Decision == "modify"
	approvedBytes := f.shown
	if modifying {
		approvedBytes = f.modified
	}
	approved := caCanonical(approvedBytes)
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", r.ContractID == nil},
		{"contract_id_unknown", r.ContractID != nil && *r.ContractID != caContractID},
		{"approval_not_bound_to_shown", r.Approval.ShownSha != sha(f.shown)},
		{"shown_not_storable", caStrictError(f.shown) != nil},
		{"invalid_call_approved", caInvalidCall(r, f.raw)},
		{"modify_not_full_call", modifying && caNotFullCall(r, f.modified)},
		{"rebuild_not_identical", approved == nil || !bytes.Equal(caCanonical(f.rebuilt), approved)},
		{"call_mutated_after_approval", !modifying && r.Before != r.After},
		{"shown_not_executed", approved == nil || !bytes.Equal(caCanonical(f.executed), approved)},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "bound"}
}

// caStrict parses I-JSON bytes: UTF-8, no unpaired surrogate, no duplicate
// member, no NaN or Infinity, and no integer of magnitude 2^53 or more.
func caStrict(data []byte) (any, error) {
	if data == nil || !utf8.Valid(data) || a2aLoneSurrogate(data) {
		return nil, errors.New("not I-JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := caDecode(dec)
	if err != nil {
		return nil, err
	}
	if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
		return nil, errors.New("trailing data")
	}
	if !caSafe(value) {
		return nil, errors.New("integer outside the I-JSON range")
	}
	return value, nil
}

func caDecode(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	if delim == '[' {
		list := []any{}
		for dec.More() {
			item, err := caDecode(dec)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
		}
		_, err = dec.Token()
		return list, err
	}
	object := map[string]any{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		if _, seen := object[name]; seen {
			return nil, fmt.Errorf("duplicate member %q", name)
		}
		item, err := caDecode(dec)
		if err != nil {
			return nil, err
		}
		object[name] = item
	}
	_, err = dec.Token()
	return object, err
}

// caSafe is false when any integer literal has magnitude 2^53 or more.
func caSafe(value any) bool {
	switch v := value.(type) {
	case json.Number:
		text := string(v)
		if strings.ContainsAny(text, ".eE") {
			return true
		}
		n, ok := new(big.Int).SetString(text, 10)
		return !ok || new(big.Int).Abs(n).BitLen() <= caSafeBits
	case []any:
		for _, item := range v {
			if !caSafe(item) {
				return false
			}
		}
	case map[string]any:
		for _, item := range v {
			if !caSafe(item) {
				return false
			}
		}
	}
	return true
}

func caStrictError(data []byte) error {
	_, err := caStrict(data)
	return err
}

// caCanonical is the RFC 8785 form of I-JSON bytes, or nil when they are absent
// or are not I-JSON.
func caCanonical(data []byte) []byte {
	value, err := caStrict(data)
	if err != nil {
		return nil
	}
	var buf strings.Builder
	if err := a2aWrite(&buf, value); err != nil {
		return nil
	}
	return []byte(buf.String())
}

func caTypeHolds(kind string, value any) bool {
	switch kind {
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		n, ok := value.(json.Number)
		return ok && !strings.ContainsAny(string(n), ".eE")
	case "number":
		_, ok := value.(json.Number)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	}
	return false
}

func caEnumHolds(param caParam, value any) bool {
	if param.Enum == nil {
		return true
	}
	var want strings.Builder
	if err := a2aWrite(&want, value); err != nil {
		return false
	}
	for _, item := range param.Enum {
		if caCanonical(item) != nil && bytes.Equal(caCanonical(item), []byte(want.String())) {
			return true
		}
	}
	return false
}

func caInvalidCall(r caRecord, raw []byte) bool {
	value, err := caStrict(raw)
	arguments, isObject := value.(map[string]any)
	if err != nil || !isObject {
		return true
	}
	for name, argument := range arguments {
		param, declared := r.Parameters[name]
		if !declared || !caTypeHolds(param.Type, argument) || !caEnumHolds(param, argument) {
			return true
		}
	}
	return false
}

func caNotFullCall(r caRecord, modified []byte) bool {
	value, err := caStrict(modified)
	members, isObject := value.(map[string]any)
	if err != nil || !isObject {
		return true
	}
	for name, param := range r.Parameters {
		if _, present := members[name]; param.Default != nil && !present {
			return true
		}
	}
	for name := range members {
		if _, declared := r.Parameters[name]; !declared {
			return true
		}
	}
	return false
}
