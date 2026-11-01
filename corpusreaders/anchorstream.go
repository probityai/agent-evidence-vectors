package corpora

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
)

func init() { register(anchorStream{}) }

// anchorStream judges vectors-anchor-stream/. It is the Go statement of what
// that corpus's check_vectors.py asserted: every property a member declares
// about its own bytes is recomputed from those bytes, so a generator bug fails
// here instead of shipping a corpus that measures nothing.
//
// The corpus's other Python file, run_verifier.py, is a different program and
// is NOT replaced by this reader. It imports a third party's anchors_verify.py
// as a Python module, replaces that module's network fetchers, and reproduces
// its outcome path against every member. Nothing in Go can import a Python
// module, so that file stays where it is; what it measures is agreement between
// this corpus and somebody else's build, which is not a property of the corpus.
type anchorStream struct{}

func (anchorStream) Suite() string { return "anchor-stream-conformance" }

// stopReasons is the vocabulary a reject member may declare. A member naming
// something outside it has invented a vocabulary nobody can score against.
var stopReasons = map[string]bool{
	"digest-mismatch":      true,
	"sidecar-coverage":     true,
	"witness-unreachable":  true,
	"malformed-row":        true,
	"unknown-rule-version": true,
	"invalid-line-count":   true,
	"invalid-byte-length":  true,
	"binding-repo-absent":  true,
	"truncation":           true,
}

// outcomes is every outcome the vendored contract's table defines, paired with
// the exit code the contract pairs it with, and nothing else.
var outcomes = map[string]int{
	"VERIFY OK":         0,
	"VERIFY FAILED":     1,
	"VERIFY UNATTESTED": 2,
	"VERIFY PARTIAL":    3,
	"VERIFY UNPINNED":   4,
}

type anchorManifest struct {
	Target        string `json:"target"`
	TargetCommit  string `json:"targetCommit"`
	SpecVendored  string `json:"specVendored"`
	SpecDigest    string `json:"specDigest"`
	SpecAuthority string `json:"specAuthority"`
	Conditions    map[string]struct {
		Basis string `json:"basis"`
	} `json:"conditions"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []anchorVector `json:"vectors"`
}

type anchorVector struct {
	ID            string         `json:"id"`
	Kind          string         `json:"kind"`
	Stream        string         `json:"stream"`
	Sidecar       string         `json:"sidecar"`
	Witness       string         `json:"witness"`
	Conditions    []string       `json:"conditions"`
	ContractBasis string         `json:"contractBasis"`
	StreamSha256  string         `json:"streamSha256"`
	Expected      anchorExpected `json:"expected"`
	Properties    map[string]any `json:"properties"`
}

type anchorExpected struct {
	Outcome    string  `json:"outcome"`
	Exit       int     `json:"exit"`
	StopReason *string `json:"stopReason"`
}

type anchorWitness struct {
	ByRef []struct {
		Repo                       string `json:"repo"`
		Commit                     string `json:"commit"`
		BytesBase64                string `json:"bytesBase64"`
		ReachableFromDefaultBranch bool   `json:"reachableFromDefaultBranch"`
	} `json:"byRef"`
	DefaultBranch struct {
		BytesBase64 string `json:"bytesBase64"`
	} `json:"defaultBranch"`
}

func (a anchorStream) Judge(dir string, raw []byte) (*Result, error) {
	var m anchorManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	accepted, rejected, used := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ids, files := make([]string, 0, len(m.Vectors)), make([]string, 0, len(m.Vectors))

	for _, v := range m.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate id")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.Stream)
		for _, c := range v.Conditions {
			used[c] = true
			switch v.Kind {
			case "accept":
				accepted[c] = true
			case "reject":
				rejected[c] = true
			}
		}
		a.judgeMember(dir, &m, v, &member)
		result.Members = append(result.Members, member)
	}

	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		result.Findings = append(result.Findings,
			fmt.Sprintf("reject conditions with no accepting twin: %v", orphan))
	}
	if idle := declaredMinusUsed(m.Conditions, used); len(idle) > 0 {
		result.Findings = append(result.Findings,
			fmt.Sprintf("conditions declared and carried by no member: %v", idle))
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the streams on disk")
	}
	result.Findings = append(result.Findings, a.checkVendoredContract(dir, &m)...)
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, v := range m.Vectors {
		if _, known := measured[v.Kind]; known {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	return result, nil
}

func (a anchorStream) judgeMember(dir string, m *anchorManifest, v anchorVector, out *Member) {
	if v.Kind != "accept" && v.Kind != "reject" {
		out.Findings = append(out.Findings, "unknown kind "+v.Kind)
	}
	for _, key := range []struct{ name, rel string }{
		{"stream", v.Stream}, {"sidecar", v.Sidecar}, {"witness", v.Witness},
	} {
		if !existsIn(dir, key.rel) {
			out.Findings = append(out.Findings,
				"manifest names a "+key.name+" file that does not exist")
			return
		}
	}
	stream, err := readIn(dir, v.Stream)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	sidecarRaw, err := readIn(dir, v.Sidecar)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	witnessRaw, err := readIn(dir, v.Witness)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	if sha(stream) != v.StreamSha256 {
		out.Findings = append(out.Findings, "declared streamSha256 does not recompute from the file")
	}
	// The identifier is a digest over the member's own three files, so an edit
	// to any one of them without regenerating leaves a name describing bytes
	// that are no longer there.
	witnessValue, err := decodeJSONNumbers(witnessRaw)
	if err != nil {
		out.Findings = append(out.Findings, "the witness file does not parse: "+err.Error())
		return
	}
	witnessCanon, err := pythonCompactJSON(witnessValue)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	payload := append(append(append([]byte{}, stream...), sidecarRaw...), witnessCanon...)
	if v.ID != "v"+sha(payload)[:16] {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}

	checkAnchorExpectation(v, out)

	var witness anchorWitness
	if err := json.Unmarshal(witnessRaw, &witness); err != nil {
		out.Findings = append(out.Findings, "the witness file does not parse as a witness: "+err.Error())
		return
	}
	for _, condition := range v.Conditions {
		declared, known := m.Conditions[condition]
		if !known {
			out.Findings = append(out.Findings,
				"cites condition "+condition+" the manifest does not define")
			continue
		}
		if v.ContractBasis != declared.Basis {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"declares contractBasis %q and cites %s, whose basis is %q",
				v.ContractBasis, condition, declared.Basis))
		}
		anchorConditionCheck(dir, condition, v, stream, sidecarRaw, &witness, out)
	}
}

// anchorConditionCheck dispatches the per-condition property recompute. The
// switch is the Go form of that corpus's CHECKS table; a condition with no arm
// here has no property to recompute, which is a fact about the condition rather
// than a gap in this reader.
func anchorConditionCheck(dir, condition string, v anchorVector, stream, sidecar []byte, witness *anchorWitness, out *Member) {
	switch condition {
	case "ans-c-1":
		if v.Kind == "reject" {
			checkSeparatorMember(dir, v, stream, out)
		}
	case "ans-c-2":
		checkTerminator(dir, v, stream, out)
	case "ans-c-3":
		checkSidecarCoverage(v, stream, sidecar, out)
	case "ans-c-5":
		checkReachability(v, stream, witness, out)
	case "ans-c-6":
		checkEventCollision(v, stream, out)
	case "ans-c-7":
		checkRuleVersion(v, stream, out)
	case "ans-c-8":
		if v.Kind == "reject" {
			checkBooleanField(v, stream, out)
		}
	case "ans-c-9":
		checkBindingRepo(v, stream, out)
	case "ans-c-10":
		if _, declared := v.Properties["defaultBranchLines"]; declared {
			checkDefaultBranch(v, witness, out)
		}
	}
}

func checkAnchorExpectation(v anchorVector, out *Member) {
	code, defined := outcomes[v.Expected.Outcome]
	if !defined {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares an outcome %q the contract does not define", v.Expected.Outcome))
	} else if code != v.Expected.Exit {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares outcome %s with exit %d, and the contract pairs it with %d",
			v.Expected.Outcome, v.Expected.Exit, code))
	}
	if v.Kind == "reject" {
		if v.Expected.Outcome != "VERIFY FAILED" {
			out.Findings = append(out.Findings, "is a reject member that does not expect the failing outcome")
		}
		if v.Expected.StopReason == nil || !stopReasons[*v.Expected.StopReason] {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"declares stop reason %v, which is not in the corpus vocabulary", derefOrNil(v.Expected.StopReason)))
		}
		return
	}
	if v.Expected.StopReason != nil {
		out.Findings = append(out.Findings, "is an accept member carrying a stop reason")
	}
}

func derefOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// splitStreamLines is the corpus's own line split: every line keeps its
// terminator, and a final line without one is still a line. The distinction is
// the whole subject of two members.
func splitStreamLines(raw []byte) [][]byte {
	parts := strings.Split(string(raw), "\n")
	lines := make([][]byte, 0, len(parts))
	for _, part := range parts[:len(parts)-1] {
		lines = append(lines, []byte(part+"\n"))
	}
	if last := parts[len(parts)-1]; last != "" {
		lines = append(lines, []byte(last))
	}
	return lines
}

func checkSeparatorMember(dir string, v anchorVector, stream []byte, out *Member) {
	codepoint, _ := v.Properties["insertedCodepoint"].(string)
	offsetValue, ok := v.Properties["insertedAtByteOffset"].(float64)
	if !ok || !strings.HasPrefix(codepoint, "U+") {
		out.Findings = append(out.Findings, "declares no readable inserted code point and offset")
		return
	}
	offset := int(offsetValue)
	value, err := strconv.ParseInt(codepoint[2:], 16, 32)
	if err != nil {
		out.Findings = append(out.Findings, "declares an unparseable code point "+codepoint)
		return
	}
	encoded := []byte(string(rune(value)))
	if offset < 0 || offset+len(encoded) > len(stream) ||
		string(stream[offset:offset+len(encoded)]) != string(encoded) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares %s at byte %d and does not carry it there", codepoint, offset))
		return
	}
	if rune(value) == '\n' {
		out.Findings = append(out.Findings, "declares the JSONL delimiter as a separator-only byte")
	}
	rest := append(append([]byte{}, stream[:offset]...), stream[offset+len(encoded):]...)
	baseline, err := readIn(dir, path.Join("baseline", "ANCHORS.jsonl"))
	if err != nil {
		out.Findings = append(out.Findings, "the baseline stream is unreadable: "+err.Error())
		return
	}
	if sha(rest) != sha(baseline) {
		out.Findings = append(out.Findings,
			"removing the declared code point does not restore the baseline stream, "+
				"so the member carries a second change nobody declared")
	}
	if regenerated, _ := v.Properties["sidecarRegenerated"].(bool); regenerated {
		out.Findings = append(out.Findings,
			"declares a regenerated sidecar and this family does not regenerate one")
	}
}

func checkTerminator(dir string, v anchorVector, stream []byte, out *Member) {
	ends := len(stream) > 0 && stream[len(stream)-1] == '\n'
	declared, _ := v.Properties["endsWithNewline"].(bool)
	if ends != declared {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares endsWithNewline=%t and measures %t", declared, ends))
	}
	if v.Kind != "reject" {
		return
	}
	baselinePath := path.Join("baseline", "ANCHORS.jsonl")
	if own, ok := v.Properties["baselineStream"].(string); ok && own != "" {
		baselinePath = own
	}
	baseline, err := readIn(dir, baselinePath)
	if err != nil {
		out.Findings = append(out.Findings, "the baseline stream is unreadable: "+err.Error())
		return
	}
	if sha(append(append([]byte{}, stream...), '\n')) != sha(baseline) {
		out.Findings = append(out.Findings,
			"is the missing-terminator member and adding the byte back does not restore "+
				"the baseline, so it carries a second change")
	}
}

func checkSidecarCoverage(v anchorVector, stream, sidecarRaw []byte, out *Member) {
	var sidecar struct {
		LineSha256 []string `json:"line_sha256"`
	}
	if err := json.Unmarshal(sidecarRaw, &sidecar); err != nil {
		out.Findings = append(out.Findings, "the sidecar does not parse: "+err.Error())
		return
	}
	entries, lines := len(sidecar.LineSha256), len(splitStreamLines(stream))
	if declared, ok := v.Properties["sidecarEntries"].(float64); ok && int(declared) != entries {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares %d sidecar entries and carries %d", int(declared), entries))
	}
	if declared, ok := v.Properties["streamLines"].(float64); ok && int(declared) != lines {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares %d lines and carries %d", int(declared), lines))
	}
	if v.Kind == "reject" && entries >= lines {
		out.Findings = append(out.Findings,
			"is a coverage-gap reject member whose sidecar covers every line")
	}
	if v.Kind == "accept" && entries != lines {
		out.Findings = append(out.Findings,
			"is the covered twin and its sidecar does not cover every line")
	}
}

func checkBooleanField(v anchorVector, stream []byte, out *Member) {
	field, _ := v.Properties["field"].(string)
	jsonType, _ := v.Properties["jsonType"].(string)
	wantBoolean := jsonType == "boolean"
	found := false
	for _, line := range splitStreamLines(stream) {
		var row map[string]any
		if json.Unmarshal(line, &row) != nil {
			continue
		}
		attestation, ok := row["attestation"].(map[string]any)
		if !ok {
			continue
		}
		prefix, ok := attestation["prefix"].(map[string]any)
		if !ok {
			continue
		}
		value, present := prefix[field]
		if !present {
			continue
		}
		if _, isBool := value.(bool); isBool == wantBoolean {
			found = true
		}
	}
	if !found {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares %s carrying a JSON %s and no row in the stream carries one", field, jsonType))
	}
}

func checkReachability(v anchorVector, stream []byte, witness *anchorWitness, out *Member) {
	commit, _ := v.Properties["witnessCommit"].(string)
	declared, _ := v.Properties["reachableFromDefaultBranch"].(bool)
	served, found := false, false
	for _, ref := range witness.ByRef {
		if ref.Commit == commit {
			served, found = ref.ReachableFromDefaultBranch, true
		}
	}
	if !found {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"names witness commit %s and the platform file serves no such commit", shortCommit(commit)))
		return
	}
	if served != declared {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares reachable=%t and the platform file says %t", declared, served))
	}
	if !strings.Contains(string(stream), commit) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares witness commit %s and the stream does not name it", shortCommit(commit)))
	}
	if v.Kind == "reject" {
		forged, _ := v.Properties["forgedRowsInsidePrefix"].(float64)
		if int(forged) < 1 {
			out.Findings = append(out.Findings,
				"is the unreachable-witness reject member and forges nothing inside the prefix")
		}
	}
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func checkEventCollision(v anchorVector, stream []byte, out *Member) {
	recordFields := []string{"asset_id", "sha256", "size_bytes"}
	collides := false
	for _, line := range splitStreamLines(stream) {
		var row map[string]any
		if json.Unmarshal(line, &row) != nil {
			continue
		}
		if _, hasEvent := row["event"]; !hasEvent {
			continue
		}
		for _, field := range recordFields {
			if _, present := row[field]; present {
				collides = true
			}
		}
	}
	declared, _ := v.Properties["carriesRecordFields"].(bool)
	if collides != declared {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares carriesRecordFields=%t and measures %t", declared, collides))
	}
}

func checkRuleVersion(v anchorVector, stream []byte, out *Member) {
	known := map[string]bool{"witness-ref-v1": true, "signature-suite-v1": true, "position-binding-v1": true}
	seen := map[string]bool{}
	for _, line := range splitStreamLines(stream) {
		var row map[string]any
		if json.Unmarshal(line, &row) != nil {
			continue
		}
		if value, present := row["rule_version"]; present {
			if s, ok := value.(string); ok {
				seen[s] = true
			}
		}
	}
	if v.Kind == "reject" {
		declared, _ := v.Properties["ruleVersion"].(string)
		if !seen[declared] {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"declares rule_version %q and the stream carries %v", declared, sortedKeys(seen)))
		}
		if known[declared] {
			out.Findings = append(out.Findings, fmt.Sprintf(
				"declares %q unrecognised and it is one of the three the format defines", declared))
		}
		return
	}
	var unknown []string
	for value := range seen {
		if !known[value] {
			unknown = append(unknown, value)
		}
	}
	if len(unknown) > 0 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"is the known-rule-set twin and carries %v", sortedStrings(unknown)))
	}
}

func checkBindingRepo(v anchorVector, stream []byte, out *Member) {
	declared, _ := v.Properties["bindingRepo"].(string)
	var found []string
	for _, line := range splitStreamLines(stream) {
		var row map[string]any
		if json.Unmarshal(line, &row) != nil {
			continue
		}
		attestation, ok := row["attestation"].(map[string]any)
		if !ok {
			continue
		}
		witness, ok := attestation["witness"].(map[string]any)
		if !ok {
			continue
		}
		if repo, present := witness["repo"].(string); present {
			found = append(found, repo)
		}
	}
	for _, repo := range found {
		if repo == declared {
			return
		}
	}
	out.Findings = append(out.Findings, fmt.Sprintf(
		"declares a binding repo of %q and the stream carries %v", declared, found))
}

func checkDefaultBranch(v anchorVector, witness *anchorWitness, out *Member) {
	branch, err := base64.StdEncoding.DecodeString(witness.DefaultBranch.BytesBase64)
	if err != nil {
		out.Findings = append(out.Findings, "the default-branch bytes do not decode: "+err.Error())
		return
	}
	measured := len(splitStreamLines(branch))
	declared, _ := v.Properties["defaultBranchLines"].(float64)
	if measured != int(declared) {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares a default branch of %d lines and carries %d", int(declared), measured))
	}
}

func (anchorStream) checkVendoredContract(dir string, m *anchorManifest) []string {
	var findings []string
	if m.SpecAuthority != "specDigest" {
		findings = append(findings,
			"specAuthority names something other than specDigest. A tag is a name the "+
				"upstream project can re-point, and this one has published a tag against "+
				"the wrong commit already; the digest is the only pin this corpus can enforce.")
	}
	stem := strings.TrimSuffix(path.Base(m.SpecVendored), path.Ext(m.SpecVendored))
	if len(m.TargetCommit) >= 7 {
		if shortSha := m.TargetCommit[:7]; !strings.HasSuffix(stem, shortSha) {
			findings = append(findings, fmt.Sprintf(
				"the vendored contract is named %q while the manifest pins commit %s, "+
					"so the file name and the pin disagree", stem, shortSha))
		}
	}
	if bad := checkVendored(dir, m.SpecVendored, m.SpecDigest, "contract"); bad != "" {
		findings = append(findings, bad)
	}
	return findings
}
