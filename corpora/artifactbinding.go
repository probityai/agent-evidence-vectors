package corpora

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(artifactBinding{}) }

// artifactBinding judges vectors-artifact-binding/. It asks a different
// question from the regenerability gate: that gate asks whether the committed
// bytes are the bytes the generator emits, and this asks whether those bytes
// BEHAVE as declared.
//
// It carries the reference verifier with it, restated in Go from
// tools/artifact-binding/verify.py, because the corpus is not checkable without
// one: a member claiming a digest mismatch has to actually mismatch, and a
// member claiming not-established has to reach neither neighbour.
type artifactBinding struct{}

func (artifactBinding) Suite() string { return "artifact-binding-conformance" }

const (
	bindingVerified       = "verified"
	bindingFailed         = "failed"
	bindingNotEstablished = "not-established"
	bindingSchemaVersion  = "artifact-binding/v1"
	bindingProfileName    = "harbor/single-step/v1"
)

// bindingRequiredRoles is the completeness bar for harbor/single-step/v1. It is
// held on the CONSUMER side rather than read from the record, because a
// producer that chooses its own bar can withdraw a role and still look complete.
var bindingRequiredRoles = []string{
	"atif_trajectory", "trial_result", "verifier_files",
	"reward", "grading_stdout", "grading_stderr",
}

// bindingInconclusive are the codes that mean the record could not be checked
// to a conclusion, as against the ones that mean the bytes contradict it. A
// checker that folds the first into the second reports a producer as dishonest
// for a file nobody captured.
var bindingInconclusive = map[string]bool{
	"artifact-absent": true, "required-role-absent": true, "dependencies-incomplete": true,
}

type bindingManifest struct {
	PublicKey    string          `json:"publicKey"`
	Counts       map[string]int  `json:"counts"`
	CorpusDigest string          `json:"corpusDigest"`
	Vectors      []bindingVector `json:"vectors"`
}

type bindingVector struct {
	ID        string `json:"id"`
	Case      string `json:"case"`
	Trial     string `json:"trial"`
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
	Expected  struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
}

// bindingOutcome is one verdict, the codes that produced it, and a line naming
// what failed.
type bindingOutcome struct {
	Verdict  string
	Codes    []string
	Messages []string
}

func (o *bindingOutcome) note(code, message string) {
	o.Codes = append(o.Codes, code)
	o.Messages = append(o.Messages, message)
}

func (o *bindingOutcome) has(code string) bool {
	for _, c := range o.Codes {
		if c == code {
			return true
		}
	}
	return false
}

func (a artifactBinding) Judge(dir string, raw []byte) (*Result, error) {
	var m bindingManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	publicKey, err := hex.DecodeString(m.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s/MANIFEST.json publishes a publicKey that is not %d hex-encoded bytes",
			dir, ed25519.PublicKeySize)
	}
	result := &Result{}
	// The corpus publishes the key its members were signed with. A corpus whose
	// published key is not the key its passing member names would report every
	// member as a signer mismatch while looking like a signing bug.
	if finding := a.checkPublishedKey(dir, m.Vectors, publicKey); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	verdicts := map[string]bool{}
	for _, v := range m.Vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Verdict}
		verdicts[v.Expected.Verdict] = true
		a.judgeMember(dir, v, publicKey, &member)
		if v.Expected.Verdict == bindingVerified && strings.Contains(v.Case, "regrade") {
			a.checkLineage(dir, v, &member)
		}
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, a.checkCorpus(&m, raw, verdicts)...)
	return result, nil
}

// checkCorpus asserts the properties that belong to no single member: both
// outcomes a refusing verifier could not fake, the declared counts, and the
// digest over the vectors array.
func (artifactBinding) checkCorpus(m *bindingManifest, raw []byte, verdicts map[string]bool) []string {
	var findings []string
	if !verdicts[bindingVerified] {
		findings = append(findings,
			"the corpus contains no verified member, so a verifier that refuses everything "+
				"would score full marks")
	}
	if !verdicts[bindingNotEstablished] {
		findings = append(findings,
			"the corpus contains no not-established member, so the third outcome is untested")
	}
	measured := map[string]int{"verified": 0, "failed": 0, "notEstablished": 0}
	for _, v := range m.Vectors {
		switch v.Expected.Verdict {
		case bindingVerified:
			measured["verified"]++
		case bindingFailed:
			measured["failed"]++
		case bindingNotEstablished:
			measured["notEstablished"]++
		}
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		findings = append(findings, strings.Replace(bad,
			"counts disagree", "MANIFEST.json declares counts that the entries do not carry", 1))
	}
	// The corpus digest is over the canonical bytes of the vectors array as the
	// manifest carries it, so it is taken from the manifest's own bytes rather
	// than from a re-marshalling of a Go struct that drops unmodelled fields.
	var vectorsRaw struct {
		Vectors json.RawMessage `json:"vectors"`
	}
	if json.Unmarshal(raw, &vectorsRaw) != nil {
		return findings
	}
	canonical, err := aee.Canonicalize(vectorsRaw.Vectors)
	switch {
	case err != nil:
		findings = append(findings, "the vectors array does not canonicalize: "+err.Error())
	case aee.SHA256Hex(canonical) != m.CorpusDigest:
		findings = append(findings, "corpusDigest does not match the vectors it names")
	}
	return findings
}

func (a artifactBinding) judgeMember(dir string, v bindingVector, publicKey ed25519.PublicKey, out *Member) {
	if !existsIn(dir, v.Manifest) {
		out.Findings = append(out.Findings, path.Join(dir, v.Manifest)+" is missing")
		return
	}
	// The identifier is a digest over the record's bytes and the case's own
	// name. Without it a flipped byte inside a record whose member already
	// expects a failure changes nothing a verdict comparison can see: the
	// member still fails, still emits its declared code, and still reads clean.
	if body, err := readIn(dir, v.Manifest); err == nil {
		payload := append(append([]byte{}, body...), []byte(path.Base(v.Case))...)
		if idFromBytes(payload) != v.ID {
			out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
		}
	}

	outcome := a.verify(dir, v, publicKey)
	if outcome.Verdict != v.Expected.Verdict {
		sorted := append([]string{}, outcome.Codes...)
		sort.Strings(sorted)
		out.Findings = append(out.Findings, fmt.Sprintf(
			"the manifest expects %q and the reference verifier answered %q (codes: %v)",
			v.Expected.Verdict, outcome.Verdict, uniqueSorted(sorted)))
		return
	}
	var missing []string
	for _, want := range v.Expected.Codes {
		if !outcome.has(want) {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		out.Findings = append(out.Findings, fmt.Sprintf("expected code(s) %v were not emitted", sortedStrings(missing)))
	}
	// The reverse of the subset test above, which is the half a subset cannot
	// see: a member already expected to fail absorbs a second fault of the same
	// class in silence, because both faults raise the same code. Mutating a
	// covered file inside the changed-byte case leaves the verdict `failed` and
	// the code set unchanged, so a subset check reports the corpus clean over
	// bytes its own generator never wrote.
	declared := map[string]bool{}
	for _, want := range v.Expected.Codes {
		declared[want] = true
	}
	var unexpected []string
	for _, got := range uniqueSorted(outcome.Codes) {
		if !declared[got] {
			unexpected = append(unexpected, got)
		}
	}
	if len(unexpected) > 0 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"code(s) %v were emitted and the manifest declares none of them", sortedStrings(unexpected)))
	}
	if outcome.Verdict != bindingVerified && len(outcome.Messages) == 0 {
		out.Findings = append(out.Findings, "a non-verified verdict named nothing")
	}
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// verify is tools/artifact-binding/verify.py restated: it checks one record
// against the bytes it names and never re-runs any grading.
func (a artifactBinding) verify(dir string, v bindingVector, publicKey ed25519.PublicKey) *bindingOutcome {
	out := &bindingOutcome{Verdict: bindingVerified}
	raw, err := readIn(dir, v.Manifest)
	if err != nil {
		out.note("manifest-unparseable", "the manifest could not be read")
		out.Verdict = bindingFailed
		return out
	}
	record := a.checkEncoding(raw, out)
	if record == nil {
		out.Verdict = bindingFailed
		return out
	}
	a.checkSigner(record, publicKey, out)
	if !out.has("signer-key-mismatch") {
		a.checkSignature(dir, v, raw, publicKey, out)
	}
	trial := path.Join(dir, v.Trial)
	roles, absent := a.checkArtifacts(trial, record, out)
	missing := a.checkProfile(roles, out)
	incomplete := a.checkDependencies(record, out)
	a.checkOutcome(trial, record, out)
	a.checkATIF(trial, record, out)

	for _, code := range out.Codes {
		if !bindingInconclusive[code] {
			out.Verdict = bindingFailed
			return out
		}
	}
	if absent || missing || incomplete {
		out.Verdict = bindingNotEstablished
	}
	return out
}

// checkEncoding asserts the manifest parses, is canonical, and declares this
// contract version.
func (artifactBinding) checkEncoding(raw []byte, out *bindingOutcome) map[string]any {
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		out.note("manifest-unparseable", "the manifest is not a JSON object")
		return nil
	}
	canonical, err := aee.Canonicalize(raw)
	if err != nil || string(canonical) != string(raw) {
		out.note("manifest-encoding-not-canonical",
			"the manifest bytes are not the RFC 8785 form of the value they parse to; "+
				"a signature over them verifies only for the party that wrote them")
	}
	if version, _ := record["schema_version"].(string); version != bindingSchemaVersion {
		out.note("schema-version-unsupported", fmt.Sprintf(
			"schema_version is %v, and this verifier implements %q",
			record["schema_version"], bindingSchemaVersion))
	}
	return record
}

// checkSigner asserts the record names the key the consumer pinned, by identity
// and BEFORE the signature is checked, so a record signed by an unexpected key
// is refused by name rather than by a signature failure that reads like
// corruption.
func (artifactBinding) checkSigner(record map[string]any, publicKey ed25519.PublicKey, out *bindingOutcome) {
	expected := sha(publicKey)
	declared, _ := record["signer_key_id"].(string)
	if declared != expected {
		out.note("signer-key-mismatch", fmt.Sprintf(
			"the record names signer %q and the pinned key is %q", declared, expected))
	}
}

func (artifactBinding) checkSignature(dir string, v bindingVector, raw []byte,
	publicKey ed25519.PublicKey, out *bindingOutcome) {
	body, err := readIn(dir, v.Signature)
	if err != nil {
		out.note("signature-invalid", "the detached signature could not be read")
		return
	}
	trimmed := strings.TrimSpace(string(body))
	blob := []byte(trimmed)
	if len(trimmed) == 2*ed25519.SignatureSize {
		if decoded, err := hex.DecodeString(trimmed); err == nil {
			blob = decoded
		}
	}
	if len(blob) != ed25519.SignatureSize || !ed25519.Verify(publicKey, raw, blob) {
		out.note("signature-invalid",
			"the detached signature does not verify over the manifest bytes as stored")
	}
}

// checkArtifacts asserts every covered file exists with its declared length and
// digest. It returns the roles that were checked and whether any covered file
// was ABSENT, because absence and mismatch are different verdicts.
func (artifactBinding) checkArtifacts(trial string, record map[string]any, out *bindingOutcome) (map[string]bool, bool) {
	roles, absent := map[string]bool{}, false
	entries, _ := record["artifacts"].([]any)
	if inputs, ok := record["verification_inputs"].(map[string]any); ok {
		if grading, ok := inputs["grading_inputs"].([]any); ok {
			entries = append(append([]any{}, entries...), grading...)
		}
	}
	for _, item := range entries {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := entry["role"].(string)
		rel, _ := entry["path"].(string)
		roles[role] = true
		if path.IsAbs(rel) || hasParentSegment(rel) {
			out.note("artifact-path-unsafe", rel+": the declared path escapes the trial directory")
			continue
		}
		if !existsIn(trial, rel) {
			absent = true
			out.note("artifact-absent", rel+": covered by the record and not present on disk")
			continue
		}
		blob, err := readIn(trial, rel)
		if err != nil {
			absent = true
			out.note("artifact-absent", rel+": covered by the record and not readable")
			continue
		}
		if declared, ok := numberOf(entry["length"]); !ok || declared != len(blob) {
			out.note("artifact-length-mismatch", fmt.Sprintf(
				"%s: the record declares %v bytes and the file is %d", rel, entry["length"], len(blob)))
		}
		if actual := sha(blob); actual != fmt.Sprintf("%v", entry["sha256"]) {
			out.note("artifact-digest-mismatch", fmt.Sprintf(
				"%s: the record declares sha256 %v and the file hashes to %s", rel, entry["sha256"], actual))
		}
	}
	return roles, absent
}

// hasParentSegment is the ".." in Path(rel).parts test: a segment that is
// exactly "..", not a filename that merely contains two dots.
func hasParentSegment(rel string) bool {
	for _, segment := range strings.Split(strings.ReplaceAll(rel, `\`, "/"), "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

// checkProfile asserts every role the profile requires is present, and reports
// whether any is missing.
func (artifactBinding) checkProfile(roles map[string]bool, out *bindingOutcome) bool {
	missing := false
	for _, role := range bindingRequiredRoles {
		if !roles[role] {
			missing = true
			out.note("required-role-absent", fmt.Sprintf(
				"role %q is required by profile %s and the record carries no entry for it",
				role, bindingProfileName))
		}
	}
	return missing
}

// checkOutcome re-derives graded_outcome from the covered bytes, never trusting it.
func (artifactBinding) checkOutcome(trial string, record map[string]any, out *bindingOutcome) {
	graded, ok := record["graded_outcome"].(map[string]any)
	if !ok {
		return
	}
	source, ok := graded["source_path"].(string)
	if !ok || !existsIn(trial, source) {
		return
	}
	body, err := readIn(trial, source)
	if err != nil {
		return
	}
	actual, err := strconv.ParseFloat(strings.TrimSpace(string(body)), 64)
	if err != nil {
		return
	}
	declared, ok := floatOf(graded["reward"])
	if !ok || declared != actual {
		out.note("graded-outcome-mismatch", fmt.Sprintf(
			"%s: the record declares reward %v and the covered bytes say %v",
			source, graded["reward"], actual))
	}
}

func floatOf(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

// checkATIF asserts the ATIF pointer agrees with the document the record hashed.
func (artifactBinding) checkATIF(trial string, record map[string]any, out *bindingOutcome) {
	atif, ok := record["atif"].(map[string]any)
	if !ok || isFalsy(atif["present"]) {
		return
	}
	entries, _ := record["artifacts"].([]any)
	var covered map[string]any
	for _, item := range entries {
		entry, ok := item.(map[string]any)
		if ok && entry["role"] == "atif_trajectory" {
			covered = entry
			break
		}
	}
	if covered == nil {
		return
	}
	if fmt.Sprintf("%v", atif["document_sha256"]) != fmt.Sprintf("%v", covered["sha256"]) {
		out.note("atif-document-digest-mismatch", fmt.Sprintf(
			"atif.document_sha256 does not equal the digest of the covered atif_trajectory entry at %v",
			covered["path"]))
	}
	rel, _ := covered["path"].(string)
	if !existsIn(trial, rel) {
		return
	}
	body, err := readIn(trial, rel)
	if err != nil {
		return
	}
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return
	}
	if fmt.Sprintf("%v", atif["trajectory_id"]) != fmt.Sprintf("%v", payload["trajectory_id"]) {
		out.note("atif-trajectory-id-mismatch", fmt.Sprintf(
			"the record names trajectory_id %v and the document says %v",
			atif["trajectory_id"], payload["trajectory_id"]))
	}
}

// checkDependencies: a record naming a dependency it does not cover is never
// verified.
func (artifactBinding) checkDependencies(record map[string]any, out *bindingOutcome) bool {
	dependencies, ok := record["dependencies"].(map[string]any)
	if !ok || dependencies["status"] != "incomplete" {
		return false
	}
	out.Codes = append(out.Codes, "dependencies-incomplete")
	listed, _ := dependencies["uncovered"].([]any)
	for _, item := range listed {
		if entry, ok := item.(map[string]any); ok {
			out.Messages = append(out.Messages, fmt.Sprintf(
				"uncovered dependency %v: %v", entry["reference"], entry["reason"]))
		}
	}
	if len(listed) == 0 {
		out.Messages = append(out.Messages, "the record reports its dependency coverage as incomplete")
	}
	return true
}

// checkPublishedKey asserts the published key is the key the passing member names.
func (artifactBinding) checkPublishedKey(dir string, vectors []bindingVector, publicKey ed25519.PublicKey) string {
	var intact *bindingVector
	for i := range vectors {
		if vectors[i].Expected.Verdict == bindingVerified && !strings.Contains(vectors[i].Case, "regrade") {
			intact = &vectors[i]
			break
		}
	}
	if intact == nil {
		return "the corpus has no plain verified member to anchor the published key against"
	}
	body, err := readIn(dir, intact.Manifest)
	if err != nil {
		return "the plain verified member's record is unreadable: " + err.Error()
	}
	var record map[string]any
	var named any
	if json.Unmarshal(body, &record) == nil {
		named = record["signer_key_id"]
	}
	expected := sha(publicKey)
	if fmt.Sprintf("%v", named) != expected {
		return fmt.Sprintf(
			"MANIFEST.json publishes a key whose id is %s and the intact member names %v", expected, named)
	}
	return ""
}

// checkLineage asserts the regrade member really derives from a record over the
// same archive: two preserved outcomes, one archive, two different rewards.
func (artifactBinding) checkLineage(dir string, v bindingVector, out *Member) {
	body, err := readIn(dir, v.Manifest)
	if err != nil {
		out.Findings = append(out.Findings, "the regrade record is unreadable")
		return
	}
	var record map[string]any
	if json.Unmarshal(body, &record) != nil {
		out.Findings = append(out.Findings, "the regrade record is not a JSON object")
		return
	}
	sourceRel := path.Join(v.Case, "source", "binding", "manifest.json")
	if !existsIn(dir, sourceRel) {
		out.Findings = append(out.Findings, "the record it derives from is not in the case directory")
		return
	}
	sourceBody, err := readIn(dir, sourceRel)
	if err != nil {
		out.Findings = append(out.Findings, "the source record is unreadable")
		return
	}
	var parent map[string]any
	if json.Unmarshal(sourceBody, &parent) != nil {
		out.Findings = append(out.Findings, "the source record is not a JSON object")
		return
	}
	canonical, err := aee.Canonicalize(sourceBody)
	if err != nil {
		out.Findings = append(out.Findings, "the source record does not canonicalize: "+err.Error())
		return
	}
	if fmt.Sprintf("%v", record["source_record_digest"]) != aee.SHA256Hex(canonical) {
		out.Findings = append(out.Findings, "source_record_digest does not resolve to the source record")
	}
	if fmt.Sprintf("%v", record["source_archive_digest"]) != fmt.Sprintf("%v", parent["source_archive_digest"]) {
		out.Findings = append(out.Findings, "the two records do not share one source_archive_digest")
	}
	graded, gradedOK := record["graded_outcome"].(map[string]any)
	parentGraded, parentOK := parent["graded_outcome"].(map[string]any)
	if gradedOK && parentOK && fmt.Sprintf("%v", graded["reward"]) == fmt.Sprintf("%v", parentGraded["reward"]) {
		out.Findings = append(out.Findings,
			"the changed verifier produced the same reward, so the member does not demonstrate "+
				"two preserved outcomes")
	}
}
