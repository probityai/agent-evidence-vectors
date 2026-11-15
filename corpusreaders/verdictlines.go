package corpusreaders

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// VerdictLineSchema is the identifier of the shared verdict-line format
// (vectors/verdict-line.schema.json). Every verifier's corpus mode prints one
// such line per corpus member, so the lines of several verifiers can be
// compared member by member.
const VerdictLineSchema = "https://probityai.github.io/agent-evidence-vectors/schema/verdict-line/v1"

// Verifier names the program that produced a verdict line.
type Verifier struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// VerdictLine is one verifier's answer for one corpus member.
type VerdictLine struct {
	Schema       string   `json:"schema"`
	Suite        string   `json:"suite"`
	CorpusDigest string   `json:"corpusDigest"`
	Vector       string   `json:"vector"`
	Verdict      string   `json:"verdict"`
	Reason       *string  `json:"reason"`
	Result       string   `json:"result,omitempty"`
	Verifier     Verifier `json:"verifier"`
}

type vlManifest struct {
	Suite        string `json:"suite"`
	CorpusDigest string `json:"corpusDigest"`
	Vectors      []struct {
		ID   string `json:"id"`
		File string `json:"file"`
		Path string `json:"path"`
	} `json:"vectors"`
}

// VerdictLines answers every member of the corpus at dir. The AEE corpus is
// replayed through aee.Verify with no consumer key policy; the approval-binding
// and uncertain-effect corpora are decided by their readers. Every member of a
// suite this binary does not answer per member gets a not-applicable line, so
// the output always covers the whole manifest and never reads as a pass.
func VerdictLines(dir string, verifier Verifier) ([]VerdictLine, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json")) // #nosec G304 -- the caller names the corpus
	if err != nil {
		return nil, err
	}
	var m vlManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	if m.Suite == "" || m.CorpusDigest == "" || len(m.Vectors) == 0 {
		return nil, fmt.Errorf("%s/MANIFEST.json names no suite, no corpusDigest or no vectors", dir)
	}
	lines := make([]VerdictLine, 0, len(m.Vectors))
	for _, v := range m.Vectors {
		line := VerdictLine{Schema: VerdictLineSchema, Suite: m.Suite, CorpusDigest: m.CorpusDigest,
			Vector: v.ID, Verifier: verifier}
		switch m.Suite {
		case aeeCorpus{}.Suite():
			vlAEE(dir, v.File, &line)
		case approvalBinding{}.Suite():
			vlDecision(&line, vlApproval(filepath.Join(dir, v.Path)))
		case uncertainEffect{}.Suite():
			vlDecision(&line, vlUncertain(filepath.Join(dir, v.Path)))
		default:
			vlSet(&line, "not-applicable", "suite-not-implemented")
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func vlSet(line *VerdictLine, verdict, reason string) {
	line.Verdict = verdict
	if reason != "" {
		line.Reason = &reason
	}
}

func vlAEE(dir, file string, line *VerdictLine) {
	body, err := readIn(dir, file)
	if err != nil {
		vlSet(line, "error", "vector-unreadable: "+err.Error())
		return
	}
	report := verifyBare(body)
	switch {
	case report == nil:
		vlSet(line, "error", "verifier-panicked")
	case report.Verdict == aee.VerdictValid:
		vlSet(line, "accept", "")
		line.Result = string(report.Result)
	default:
		vlSet(line, "reject", string(report.PrimaryCode))
	}
}

type vlAnswer struct {
	decision scDecision
	err      error
}

func vlDecision(line *VerdictLine, a vlAnswer) {
	switch {
	case a.err != nil:
		vlSet(line, "error", a.err.Error())
	case a.decision.Decision == "allow":
		vlSet(line, "accept", a.decision.Reason)
	default:
		vlSet(line, "reject", a.decision.Reason)
	}
}

func vlApproval(caseDir string) vlAnswer {
	var record abRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return vlAnswer{err: err}
	}
	used, err := readIn(caseDir, record.Use["payloadFile"])
	if err != nil {
		return vlAnswer{err: err}
	}
	got, err := abDecide(record, abMatches(record, used))
	return vlAnswer{decision: got, err: err}
}

func vlUncertain(caseDir string) vlAnswer {
	var record ueRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return vlAnswer{err: err}
	}
	if err := ueValidateTimes(record); err != nil {
		return vlAnswer{err: err}
	}
	return vlAnswer{decision: ueDecide(record)}
}
