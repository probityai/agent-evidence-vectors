package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

func init() { register(chunkedExport{}) }

// chunkedExport judges vectors-chunked-export/. Each member is an export
// gate's view when one chunk of a flagged dataset is presented: the chunks
// already exported, the reconstruction rule the issuer committed to, and the
// class the seal declares. The reader derives the composed class from the
// exported chunks and the rule, then applies the checks the Python reader
// applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the chunked-export contract: contract_id_unknown;
//  3. the rule was committed no later than the first chunk left:
//     threshold_not_precommitted;
//  4. the seal's maxClass is the composed class: seal_understates_composition;
//  5. the composed class is reversible: export_irreversible.
//
// The composed class is irreversible when an exported chunk's own step is
// irreversible, or when the rule holds over the exported chunks: a count rule
// once k chunks have left, a sets rule once one minimal reconstructing set has
// left whole. The reader also recomputes each member's declared composedClass
// and checks every chunk payload against its stated digest.
type chunkedExport struct{}

const ceContractID = "https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1"

func (chunkedExport) Suite() string { return "chunked-export/v1" }

type ceVector struct {
	ID            string            `json:"id"`
	Path          string            `json:"path"`
	Files         map[string]string `json:"files"`
	Expected      scDecision        `json:"expected"`
	ComposedClass string            `json:"composedClass"`
}

type ceChunk struct {
	Index         int    `json:"index"`
	LeftAt        string `json:"leftAt"`
	PayloadFile   string `json:"payloadFile"`
	PayloadSha256 string `json:"payloadSha256"`
	StepClass     string `json:"stepClass"`
}

type ceRule struct {
	Kind        string  `json:"kind"`
	K           int     `json:"k"`
	MinimalSets [][]int `json:"minimalSets"`
	CommittedAt string  `json:"committedAt"`
}

type ceRecord struct {
	ContractID     *string   `json:"contractId"`
	Chunks         []ceChunk `json:"chunks"`
	Exported       []int     `json:"exported"`
	Reconstruction ceRule    `json:"reconstruction"`
	Seal           struct {
		MaxClass string `json:"maxClass"`
	} `json:"seal"`
}

func (chunkedExport) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ceVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ceJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ceJudgeMember(caseDir string, v ceVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record ceRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	for _, chunk := range record.Chunks {
		payload, err := readIn(caseDir, chunk.PayloadFile)
		if err != nil {
			return append(findings, fmt.Sprintf("%s cannot be read: %v", chunk.PayloadFile, err))
		}
		if sha(payload) != chunk.PayloadSha256 {
			findings = append(findings, fmt.Sprintf("%s does not match its stated digest", chunk.PayloadFile))
		}
	}
	composed, err := ceComposed(record)
	if err != nil {
		return append(findings, err.Error())
	}
	if composed != v.ComposedClass {
		findings = append(findings, fmt.Sprintf("composed class %s, the manifest declares %s",
			composed, v.ComposedClass))
	}
	got, err := ceDecide(record, composed)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// ceExported returns the exported chunks in the order the record lists them.
func ceExported(r ceRecord) ([]ceChunk, error) {
	byIndex := map[int]ceChunk{}
	for _, chunk := range r.Chunks {
		byIndex[chunk.Index] = chunk
	}
	exported := make([]ceChunk, 0, len(r.Exported))
	for _, index := range r.Exported {
		chunk, ok := byIndex[index]
		if !ok {
			return nil, fmt.Errorf("exported chunk %d is not in chunks", index)
		}
		exported = append(exported, chunk)
	}
	if len(exported) == 0 {
		return nil, fmt.Errorf("the record exports no chunk")
	}
	return exported, nil
}

func ceComposed(r ceRecord) (string, error) {
	exported, err := ceExported(r)
	if err != nil {
		return "", err
	}
	left := map[int]bool{}
	for _, chunk := range exported {
		if chunk.StepClass == "irreversible" {
			return "irreversible", nil
		}
		left[chunk.Index] = true
	}
	holds, err := ceRuleHolds(r.Reconstruction, left)
	if err != nil {
		return "", err
	}
	if holds {
		return "irreversible", nil
	}
	return "reversible", nil
}

func ceRuleHolds(rule ceRule, left map[int]bool) (bool, error) {
	switch rule.Kind {
	case "count":
		return len(left) >= rule.K, nil
	case "sets":
		for _, subset := range rule.MinimalSets {
			whole := true
			for _, index := range subset {
				whole = whole && left[index]
			}
			if whole {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unknown reconstruction rule kind %q", rule.Kind)
	}
}

func ceDecide(r ceRecord, composed string) (scDecision, error) {
	committed, err := time.Parse(time.RFC3339, r.Reconstruction.CommittedAt)
	if err != nil {
		return scDecision{}, fmt.Errorf("timestamp %q does not parse", r.Reconstruction.CommittedAt)
	}
	exported, err := ceExported(r)
	if err != nil {
		return scDecision{}, err
	}
	var firstLeft time.Time
	for i, chunk := range exported {
		left, err := time.Parse(time.RFC3339, chunk.LeftAt)
		if err != nil {
			return scDecision{}, fmt.Errorf("timestamp %q does not parse", chunk.LeftAt)
		}
		if i == 0 || left.Before(firstLeft) {
			firstLeft = left
		}
	}
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", r.ContractID == nil},
		{"contract_id_unknown", r.ContractID != nil && *r.ContractID != ceContractID},
		{"threshold_not_precommitted", committed.After(firstLeft)},
		{"seal_understates_composition", r.Seal.MaxClass != composed},
		{"export_irreversible", composed == "irreversible"},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}, nil
		}
	}
	return scDecision{"allow", "reversible_so_far"}, nil
}
