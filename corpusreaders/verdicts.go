package corpusreaders

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Verdict is the decision and reason a v2 reader derives from one record.json.
type Verdict struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// verdictDeciders maps each v2 suite to the derivation its reader applies to a
// decoded record. Judge calls the same functions, so a verdict printed here is
// the one the corpus check compares to the manifest.
var verdictDeciders = map[string]func(map[string]any) scDecision{
	"attenuated-delegation/v1":         attnDecide,
	"grant-use/v1":                     guDecide,
	"revocation-epoch/v1":              reDecide,
	"durable-history/v1":               dhDecide,
	"approval-binding/v2":              func(record map[string]any) scDecision { return ab2Decide(record) },
	"decision-client-failure-modes/v1": dcDecide,
}

// RecordVerdict derives the verdict of one record.json for a suite from the
// record's bytes alone. It returns an error for an unknown suite or a record
// that is not a JSON object.
func RecordVerdict(suite string, record []byte) (Verdict, error) {
	decide, known := verdictDeciders[suite]
	if !known {
		return Verdict{}, fmt.Errorf("suite %q has no v2 verdict reader", suite)
	}
	value, err := decodeJSONNumbers(record)
	if err != nil {
		return Verdict{}, fmt.Errorf("record.json does not parse: %w", err)
	}
	object, isObject := value.(map[string]any)
	if !isObject {
		return Verdict{}, errors.New("record.json is not a JSON object")
	}
	got := decide(object)
	return Verdict{Decision: got.Decision, Reason: got.Reason}, nil
}

// AttenuatedDelegationVerdict is RecordVerdict for attenuated-delegation/v1.
func AttenuatedDelegationVerdict(record []byte) (Verdict, error) {
	return RecordVerdict("attenuated-delegation/v1", record)
}

// GrantUseVerdict is RecordVerdict for grant-use/v1.
func GrantUseVerdict(record []byte) (Verdict, error) {
	return RecordVerdict("grant-use/v1", record)
}

// RevocationEpochVerdict is RecordVerdict for revocation-epoch/v1.
func RevocationEpochVerdict(record []byte) (Verdict, error) {
	return RecordVerdict("revocation-epoch/v1", record)
}

// DurableHistoryVerdict is RecordVerdict for durable-history/v1.
func DurableHistoryVerdict(record []byte) (Verdict, error) {
	return RecordVerdict("durable-history/v1", record)
}

// ApprovalBindingV2Verdict is RecordVerdict for approval-binding/v2.
func ApprovalBindingV2Verdict(record []byte) (Verdict, error) {
	return RecordVerdict("approval-binding/v2", record)
}

// DecisionClientVerdict is RecordVerdict for decision-client-failure-modes/v1.
func DecisionClientVerdict(record []byte) (Verdict, error) {
	return RecordVerdict("decision-client-failure-modes/v1", record)
}

// VerdictLines reads a corpus directory and returns, for every manifest vector
// in manifest order, the line "<id>\t<decision>\t<reason>" derived from that
// case's record.json alone. The manifest's expected answers are never read.
func VerdictLines(dir string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName)) // #nosec G304 -- the caller names the corpus by design
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Suite   string `json:"suite"`
		Vectors []struct {
			ID   string `json:"id"`
			Path string `json:"path"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", filepath.Join(dir, ManifestName), err)
	}
	if _, known := verdictDeciders[manifest.Suite]; !known {
		return nil, fmt.Errorf("unknown suite %q", manifest.Suite)
	}
	lines := make([]string, 0, len(manifest.Vectors))
	for _, vector := range manifest.Vectors {
		body, err := readIn(filepath.Join(dir, vector.Path), "record.json")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", vector.ID, err)
		}
		verdict, err := RecordVerdict(manifest.Suite, body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", vector.ID, err)
		}
		lines = append(lines, vector.ID+"\t"+verdict.Decision+"\t"+verdict.Reason)
	}
	return lines, nil
}
