package corpora

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func init() { register(sourceCoverage{}) }

// sourceCoverage judges vectors-source-coverage/. Each member is a directory
// holding a case (the bound artifacts), a consumer policy (the source witness,
// the time window and the passages that must be carried) and the artifact
// bytes. The reader re-derives each member's decision from those bytes with the
// five rules the manifest's expectations encode, in this order, and compares
// the result with the declared decision and reason:
//
//  1. a source capture or record that is absent, or whose bytes do not match
//     the digests the case and the policy bind: not_established,
//     artifact_unavailable_or_unbound;
//  2. a capture taken outside the policy's source window: not_established,
//     witness_outside_source_window;
//  3. a selected passage absent from the capture's article text:
//     not_established, selected_span_not_in_witness;
//  4. a selected passage absent from the record: contradicted,
//     selected_span_missing_from_record;
//  5. otherwise: supported, all_selected_spans_present.
//
// The corpus also defines an external-verifier contract. This reader is the
// repository's own implementation of the same rules, so the corpus is judged
// by the one binary that judges every other corpus here.
type sourceCoverage struct{}

func (sourceCoverage) Suite() string { return "source-text-coverage/v1" }

type scManifest struct {
	CorpusDigest string            `json:"corpusDigest"`
	Vectors      []json.RawMessage `json:"vectors"`
}

type scVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

type scDecision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type scArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type scCase struct {
	CaseID    string                `json:"case_id"`
	Artifacts map[string]scArtifact `json:"artifacts"`
}

type scWitness struct {
	Artifact     string `json:"artifact"`
	SHA256       string `json:"sha256"`
	CapturedAt   string `json:"captured_at"`
	SourceFormat string `json:"source_format"`
}

type scAssessment struct {
	SourceWitness  string `json:"source_witness"`
	RecordArtifact string `json:"record_artifact"`
	RecordSHA256   string `json:"record_sha256"`
	SourceWindow   struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"source_window"`
	RequiredSpans []struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	} `json:"required_spans"`
}

type scPolicy struct {
	Witnesses   map[string]scWitness    `json:"witnesses"`
	Assessments map[string]scAssessment `json:"assessments"`
}

const scArticleFormat = "html_article_text/v1"

var (
	scUnbound   = scDecision{"not_established", "artifact_unavailable_or_unbound"}
	scOutside   = scDecision{"not_established", "witness_outside_source_window"}
	scNotInWit  = scDecision{"not_established", "selected_span_not_in_witness"}
	scMissing   = scDecision{"contradicted", "selected_span_missing_from_record"}
	scSupported = scDecision{"supported", "all_selected_spans_present"}
	scTag       = regexp.MustCompile(`<[^>]*>`)
)

func (sourceCoverage) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v scVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = scJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// scJudgeMember checks the member's committed bytes against the manifest, then
// derives its decision and compares it with the declared one.
func scJudgeMember(caseDir string, v scVector) []string {
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return []string{fmt.Sprintf("the member directory cannot be read: %v", err)}
	}
	var findings []string
	present := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			present[e.Name()] = true
		}
	}
	for _, name := range sortedKeys(present) {
		if _, declared := v.Files[name]; !declared {
			findings = append(findings, name+" is in the member and not in the manifest")
		}
	}
	for _, name := range sortedKeys(v.Files) {
		body, err := readIn(caseDir, name)
		if err != nil {
			findings = append(findings, name+" is declared and absent")
		} else if sha(body) != v.Files[name] {
			findings = append(findings, name+" does not match its manifest digest")
		}
	}
	got, err := scDecide(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// scDecide applies the five rules to one member directory. An error means the
// case or policy could not be read at all, which is a finding, not a decision.
func scDecide(caseDir string) (scDecision, error) {
	var c scCase
	var p scPolicy
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return scDecision{}, err
	}
	if err := scReadJSON(caseDir, "policy.json", &p); err != nil {
		return scDecision{}, err
	}
	a, ok := p.Assessments[c.CaseID]
	if !ok {
		return scDecision{}, fmt.Errorf("policy.json has no assessment for case %q", c.CaseID)
	}
	w, ok := p.Witnesses[a.SourceWitness]
	if !ok {
		return scDecision{}, fmt.Errorf("policy.json names witness %q and defines none", a.SourceWitness)
	}
	source, sourceOK := scBound(caseDir, c.Artifacts[w.Artifact], w.SHA256)
	record, recordOK := scBound(caseDir, c.Artifacts[a.RecordArtifact], a.RecordSHA256)
	if !sourceOK || !recordOK {
		return scUnbound, nil
	}
	inside, err := scWithin(w.CapturedAt, a.SourceWindow.Start, a.SourceWindow.End)
	if err != nil {
		return scDecision{}, err
	}
	if !inside {
		return scOutside, nil
	}
	if w.SourceFormat != scArticleFormat {
		return scDecision{}, fmt.Errorf("source_format %q is not %s", w.SourceFormat, scArticleFormat)
	}
	article := scArticleText(source)
	for _, span := range a.RequiredSpans {
		if !strings.Contains(article, span.Text) {
			return scNotInWit, nil
		}
	}
	for _, span := range a.RequiredSpans {
		if !bytes.Contains(record, []byte(span.Text)) {
			return scMissing, nil
		}
	}
	return scSupported, nil
}

func scReadJSON(caseDir, name string, into any) error {
	body, err := readIn(caseDir, name)
	if err != nil {
		return fmt.Errorf("%s cannot be read: %w", name, err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s does not parse: %w", name, err)
	}
	return nil
}

// scBound returns an artifact's bytes when they are present and match both the
// digest the case binds and the digest the policy binds.
func scBound(caseDir string, artifact scArtifact, policyDigest string) ([]byte, bool) {
	if artifact.Path == "" || !existsIn(caseDir, artifact.Path) {
		return nil, false
	}
	body, err := readIn(caseDir, artifact.Path)
	if err != nil {
		return nil, false
	}
	digest := sha(body)
	return body, digest == artifact.SHA256 && digest == policyDigest
}

func scWithin(at, start, end string) (bool, error) {
	var times [3]time.Time
	for i, value := range []string{at, start, end} {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return false, fmt.Errorf("timestamp %q does not parse: %w", value, err)
		}
		times[i] = parsed
	}
	return !times[0].Before(times[1]) && !times[0].After(times[2]), nil
}

// scArticleText is the html_article_text/v1 reading of a capture: the text
// inside its article element, with every tag a boundary. Anything outside the
// article, including a script in the head, is not witness text.
func scArticleText(source []byte) string {
	text := string(source)
	open, end := strings.Index(text, "<article>"), strings.Index(text, "</article>")
	if open < 0 || end < open {
		return ""
	}
	return scTag.ReplaceAllString(text[open+len("<article>"):end], "\n")
}

// scCorpusDigest recomputes the published corpus digest: SHA-256 over the
// manifest rows as CPython's json.dumps(indent=2, sort_keys=True) writes them,
// plus a newline.
func scCorpusDigest(manifest scManifest) string {
	rows := make([]any, 0, len(manifest.Vectors))
	for _, entry := range manifest.Vectors {
		value, err := decodeJSONNumbers(entry)
		if err != nil {
			return fmt.Sprintf("a manifest row does not parse: %v", err)
		}
		rows = append(rows, value)
	}
	compact, err := pythonCompactJSON(rows)
	if err != nil {
		return fmt.Sprintf("the manifest rows cannot be re-encoded: %v", err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "  "); err != nil {
		return fmt.Sprintf("the manifest rows cannot be re-encoded: %v", err)
	}
	indented.WriteByte('\n')
	if got := sha(indented.Bytes()); got != manifest.CorpusDigest {
		return fmt.Sprintf("corpusDigest %s does not match the recomputed %s",
			short(manifest.CorpusDigest), short(got))
	}
	return ""
}
