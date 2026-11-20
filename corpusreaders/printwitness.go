package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(printWitness{}) }

// printWitness judges corpora/vectors-print-witness/. Each member is one machine
// job seen by a witness that sits between the controlling agent and the machine:
// the job file the witness forwarded, the log it signed (an intake record naming
// the job file, progress records, a closing record), and the consumer's trust
// inputs. The reader derives each member's decision with the checks the Python
// reader applies, in the same order, and names the first one that fails:
//
//  1. every log record verifies under the trusted witness key its kid names, and
//     names that witness: signature_invalid;
//  2. the first record is the intake record: intake_missing;
//  3. every record is signed by the witness that signed the intake:
//     witness_changed;
//  4. every record names the intake's job: job_mismatch;
//  5. record i carries seq i and names the digest of the line before it:
//     chain_link_broken;
//  6. the job file is the one the intake names: gcode_altered;
//  7. the intake names the job file the consumer ordered: gcode_not_ordered;
//  8. the log ends with a closing record: log_truncated;
//  9. the closing record says every declared layer finished:
//     print_not_finished.
//
// A log that passes all nine is verified with print_witnessed. The reader also
// recomputes each member's declared signature property, because the corpus's
// claim is that most rejected logs pass every signature check.
type printWitness struct{}

func (printWitness) Suite() string { return "print-witness/v1" }

type pwVector struct {
	ID              string            `json:"id"`
	Path            string            `json:"path"`
	Files           map[string]string `json:"files"`
	Expected        scDecision        `json:"expected"`
	SignaturesClean bool              `json:"logSignaturesVerify"`
}

type pwCase struct {
	Job       string            `json:"job"`
	Log       string            `json:"log"`
	Order     map[string]string `json:"order"`
	Witnesses map[string]string `json:"witnesses"`
}

type pwEnvelope struct {
	Kid    string          `json:"kid"`
	Record json.RawMessage `json:"record"`
	Sig    string          `json:"sig"`
}

// pwRecord holds the fields the checks read. Pointers tell an absent field from
// a zero one, so a record that omits seq never passes for record 0.
type pwRecord struct {
	Type          string `json:"type"`
	Witness       string `json:"witness"`
	Job           string `json:"job"`
	Seq           *int   `json:"seq"`
	Prev          string `json:"prev"`
	GcodeSHA256   string `json:"gcode_sha256"`
	Layers        *int   `json:"layers"`
	LayersPrinted *int   `json:"layers_printed"`
	Status        string `json:"status"`
}

const pwGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

func (printWitness) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v pwVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = pwJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func pwJudgeMember(caseDir string, v pwVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	got, clean, err := pwDecide(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if clean != v.SignaturesClean {
		findings = append(findings, fmt.Sprintf(
			"every log signature verifies: %t, the manifest declares %t", clean, v.SignaturesClean))
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// pwDecide applies the nine checks to one member and reports whether every log
// record's signature verifies. An error means an input could not be read at
// all, which is a finding, not a decision.
func pwDecide(caseDir string) (scDecision, bool, error) {
	var c pwCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return scDecision{}, false, err
	}
	job, err := readIn(caseDir, c.Job)
	if err != nil {
		return scDecision{}, false, fmt.Errorf("%s cannot be read: %w", c.Job, err)
	}
	log, err := readIn(caseDir, c.Log)
	if err != nil {
		return scDecision{}, false, fmt.Errorf("%s cannot be read: %w", c.Log, err)
	}
	lines, envs, records, err := pwParseLog(log)
	if err != nil {
		return scDecision{}, false, err
	}
	clean := len(envs) > 0
	for i, env := range envs {
		clean = clean && pwSigned(env, records[i], c.Witnesses)
	}
	return pwFirstFailure(c, job, lines, records, clean), clean, nil
}

func pwParseLog(log []byte) ([][]byte, []pwEnvelope, []pwRecord, error) {
	var lines [][]byte
	var envs []pwEnvelope
	var records []pwRecord
	for _, line := range bytes.Split(log, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var env pwEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, nil, nil, fmt.Errorf("a log line does not parse: %w", err)
		}
		var record pwRecord
		if err := json.Unmarshal(env.Record, &record); err != nil {
			return nil, nil, nil, fmt.Errorf("a log record does not parse: %w", err)
		}
		lines, envs, records = append(lines, line), append(envs, env), append(records, record)
	}
	return lines, envs, records, nil
}

func pwFirstFailure(c pwCase, job []byte, lines [][]byte, records []pwRecord, clean bool) scDecision {
	if !clean {
		return scDecision{"rejected", "signature_invalid"}
	}
	intake, last := records[0], records[len(records)-1]
	checks := []struct {
		reason string
		fails  func() bool
	}{
		{"intake_missing", func() bool { return intake.Type != "intake" }},
		{"witness_changed", func() bool { return pwAny(records, func(r pwRecord) bool { return r.Witness != intake.Witness }) }},
		{"job_mismatch", func() bool { return pwAny(records, func(r pwRecord) bool { return r.Job != intake.Job }) }},
		{"chain_link_broken", func() bool { return pwChainBroken(lines, records) }},
		{"gcode_altered", func() bool { return sha(job) != intake.GcodeSHA256 }},
		{"gcode_not_ordered", func() bool { return intake.GcodeSHA256 != c.Order["gcode_sha256"] }},
		{"log_truncated", func() bool { return last.Type != "close" }},
		{"print_not_finished", func() bool { return !pwFinished(intake, last) }},
	}
	for _, check := range checks {
		if check.fails() {
			return scDecision{"rejected", check.reason}
		}
	}
	return scDecision{"verified", "print_witnessed"}
}

func pwAny(records []pwRecord, pred func(pwRecord) bool) bool {
	for _, r := range records {
		if pred(r) {
			return true
		}
	}
	return false
}

// pwChainBroken reports whether some record does not carry its own position as
// seq, or does not name the digest of the line before it (64 zeros for the first).
func pwChainBroken(lines [][]byte, records []pwRecord) bool {
	for i, r := range records {
		want := pwGenesis
		if i > 0 {
			want = sha(lines[i-1])
		}
		if r.Seq == nil || *r.Seq != i || r.Prev != want {
			return true
		}
	}
	return false
}

// pwFinished reports whether the closing record says the job finished every
// layer the intake declared.
func pwFinished(intake, last pwRecord) bool {
	return last.Type == "close" && last.Status == "finished" && last.LayersPrinted != nil &&
		intake.Layers != nil && *last.LayersPrinted == *intake.Layers
}

// pwSigned reports whether a log line's signature is a valid Ed25519 signature,
// over the RFC 8785 form of its record, by the trusted witness its kid names,
// and whether the record names that same witness.
func pwSigned(env pwEnvelope, record pwRecord, witnesses map[string]string) bool {
	keyHex, trusted := witnesses[env.Kid]
	if !trusted || record.Witness != env.Kid || len(env.Record) == 0 {
		return false
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return false
	}
	canonical, err := aee.Canonicalize(env.Record)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), canonical, raw)
}
