package corpora

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(aiGeneration{}) }

// aiGeneration judges vectors-ai-generation/, the conformance corpus for the
// generation predicate at specification revision 0.1.5 in its default
// attest-only mode.
//
// Revision 0.1.5 requires non-overlapping attribution ranges and agreement
// with every supplied Assisted-by trailer. Both grading modes enforce these
// rules; the proposal grading vocabulary remains for historical controls.
type aiGeneration struct{}

func (aiGeneration) Suite() string { return "ai-generation-v01-conformance" }

const aiGenerationPredicateType = "https://open-fab.ai/attestation/generation/v0.1"

// The verdicts and codes a member can declare. They are the reader's
// vocabulary, so a manifest naming a code outside it names a rule nothing here
// can produce.
const (
	agValid         = "valid"
	agInvalid       = "invalid"
	agIndeterminate = "indeterminate"
	agHumanSignoff  = "human-signoff"
	agFab           = "fab"
)

type agManifest struct {
	PredicateType   string                     `json:"predicateType"`
	SpecVendored    string                     `json:"specVendored"`
	SpecDigest      string                     `json:"specDigest"`
	SchemaVendored  string                     `json:"schemaVendored"`
	SchemaDigest    string                     `json:"schemaDigest"`
	LicenseVendored string                     `json:"licenseVendored"`
	LicenseDigest   string                     `json:"licenseDigest"`
	GoldenSource    agGolden                   `json:"goldenSource"`
	ProposedText    string                     `json:"proposedText"`
	Conditions      map[string]json.RawMessage `json:"conditions"`
	Counts          map[string]int             `json:"counts"`
	CorpusDigest    string                     `json:"corpusDigest"`
	Vectors         []agVector                 `json:"vectors"`
}

type agGolden struct {
	CanonicalLength int    `json:"canonicalLength"`
	CanonicalSha256 string `json:"canonicalSha256"`
}

// agSource names the upstream file a member was copied from, byte for byte.
type agSource struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

type agArtifact struct {
	Name string `json:"name"`
	File string `json:"file"`
}

type agVector struct {
	ID         string       `json:"id"`
	Kind       string       `json:"kind"`
	Form       string       `json:"form"`
	File       string       `json:"file"`
	Parent     string       `json:"parent"`
	Trailer    string       `json:"trailer"`
	Conditions []string     `json:"conditions"`
	Artifacts  []agArtifact `json:"artifacts"`
	Source     *agSource    `json:"source"`
	Expected   agExpected   `json:"expected"`
}

// agOutcome is one verifier's answer for one member.
type agOutcome struct {
	Verdict string `json:"verdict"`
	Code    string `json:"code,omitempty"`
}

func (o agOutcome) String() string {
	if o.Code == "" {
		return o.Verdict
	}
	return o.Verdict + " " + o.Code
}

type agExpected struct {
	agOutcome
	Mode                string     `json:"mode"`
	Acceptance          string     `json:"acceptance"`
	CanonicalLength     *int       `json:"canonicalLength"`
	CanonicalSha256     string     `json:"canonicalSha256"`
	DistinctSignoffKeys *int       `json:"distinctSignoffKeys"`
	AsWritten           *agOutcome `json:"asWritten"`
	Proposal            *agOutcome `json:"proposal"`
}

func (r aiGeneration) Judge(dir string, raw []byte) (*Result, error) {
	var manifest agManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	if len(manifest.Vectors) == 0 {
		result.Findings = append(result.Findings, "the manifest carries no vectors")
	}
	ids := make([]string, 0, len(manifest.Vectors))
	files := make([]string, 0, len(manifest.Vectors))
	seen := map[string]bool{}
	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.File)
		judgeAGMember(dir, &manifest, v, &member)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, agCorpusFindings(dir, &manifest, ids, files)...)
	return result, nil
}

// agCorpusFindings are the checks that belong to no single member.
func agCorpusFindings(dir string, m *agManifest, ids, files []string) []string {
	var out []string
	if m.PredicateType != aiGenerationPredicateType {
		out = append(out, fmt.Sprintf("predicateType %q is not the generation predicate's type %q",
			m.PredicateType, aiGenerationPredicateType))
	}
	for _, pin := range [][3]string{
		{m.SpecVendored, m.SpecDigest, "specification"},
		{m.SchemaVendored, m.SchemaDigest, "JSON Schema"},
		{m.LicenseVendored, m.LicenseDigest, "licence"},
	} {
		if bad := checkVendored(dir, pin[0], pin[1], pin[2]); bad != "" {
			out = append(out, bad)
		}
	}
	measured := map[string]int{"accept": 0, "reject": 0, "proposed": 0}
	for _, v := range m.Vectors {
		if _, known := measured[v.Kind]; known {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(m.Counts, measured); bad != "" {
		out = append(out, bad)
	}
	if digest, err := orderedCorpusDigest(dir, ids, files); err != nil || digest != m.CorpusDigest {
		out = append(out, "corpusDigest does not recompute from the member files on disk")
	}
	out = append(out, agTwinFindings(m)...)
	out = append(out, agProposedTextFindings(dir, m, ids)...)
	return out
}

var agMemberIdentifier = regexp.MustCompile(`\bv[0-9a-f]{16}\b`)

// agProposedTextFindings holds the proposal document to the corpus. It cites
// members by identifier, and an identifier is a digest of bytes, so a
// regenerated member leaves the document naming bytes that are gone.
func agProposedTextFindings(dir string, m *agManifest, ids []string) []string {
	if m.ProposedText == "" {
		return []string{"the manifest names no proposedText, so the proposed members cite no rule"}
	}
	text, err := readIn(corpusParent(dir), m.ProposedText)
	if err != nil {
		return []string{"proposedText " + m.ProposedText + " is missing or unreadable"}
	}
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	var stale []string
	for _, cited := range agMemberIdentifier.FindAllString(string(text), -1) {
		if !known[cited] {
			stale = append(stale, cited)
		}
	}
	if len(stale) > 0 {
		return []string{fmt.Sprintf("proposedText cites %v, which are not members of this corpus", sortedStrings(stale))}
	}
	return nil
}

// agTwinFindings makes each refusal scoreable. A condition refused under
// the revision as written needs an accept member carrying it, and a condition refused
// under the proposal needs a member the proposal accepts, or a verifier that
// refuses everything scores full marks on it.
func agTwinFindings(m *agManifest) []string {
	accepted, rejected := map[string]bool{}, map[string]bool{}
	proposalValid, proposalInvalid := map[string]bool{}, map[string]bool{}
	used := map[string]bool{}
	for _, v := range m.Vectors {
		for _, c := range v.Conditions {
			used[c] = true
			switch {
			case v.Kind == "accept":
				accepted[c], proposalValid[c] = true, true
			case v.Kind == "reject":
				rejected[c] = true
			case v.Expected.Proposal != nil && v.Expected.Proposal.Verdict == agValid:
				proposalValid[c] = true
			default:
				proposalInvalid[c] = true
			}
		}
	}
	var out []string
	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		out = append(out, fmt.Sprintf("conditions refused and never accepted: %v", orphan))
	}
	if orphan := orphanTwins(proposalValid, proposalInvalid); len(orphan) > 0 {
		out = append(out, fmt.Sprintf("conditions the proposal refuses and never accepts: %v", orphan))
	}
	if idle := declaredMinusUsed(m.Conditions, used); len(idle) > 0 {
		out = append(out, fmt.Sprintf("conditions declared and carried by no member: %v", idle))
	}
	return out
}

func judgeAGMember(dir string, m *agManifest, v agVector, out *Member) {
	if v.Kind != "accept" && v.Kind != "reject" && v.Kind != "proposed" {
		out.Findings = append(out.Findings, fmt.Sprintf("declares kind %q, which this reader does not grade", v.Kind))
		return
	}
	if len(v.Conditions) == 0 {
		out.Findings = append(out.Findings, "cites no condition")
	}
	for _, c := range v.Conditions {
		if _, defined := m.Conditions[c]; !defined {
			out.Findings = append(out.Findings, "cites condition "+c+" the manifest does not define")
		}
	}
	out.Findings = append(out.Findings, agParentFindings(m, v)...)
	body, err := readIn(dir, v.File)
	if err != nil {
		out.Findings = append(out.Findings, "the member file is missing or unreadable: "+v.File)
		return
	}
	trailer, ok := agTrailer(dir, v, out)
	if !ok {
		return
	}
	preimage := body
	if trailer != nil {
		preimage = append(append(append([]byte{}, body...), 0), trailer...)
	}
	if idFromBytes(preimage) != v.ID {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}
	out.Findings = append(out.Findings, agSourceFindings(v, body)...)
	switch v.Form {
	case "statement":
		out.Findings = append(out.Findings, judgeAGGolden(m, v, body)...)
	case "attestation":
		out.Findings = append(out.Findings, judgeAGAttestation(dir, v, body, trailer)...)
	default:
		out.Findings = append(out.Findings, fmt.Sprintf("declares form %q, which is neither statement nor attestation", v.Form))
	}
}

// agParentFindings holds a refusal to the member it was derived from. A reject
// member, and a proposed member the proposal refuses, is one change to a
// member that is accepted, and it names that member.
func agParentFindings(m *agManifest, v agVector) []string {
	needs := v.Kind == "reject" || (v.Kind == "proposed" && v.Expected.Proposal != nil &&
		v.Expected.Proposal.Verdict != agValid)
	if !needs {
		return nil
	}
	if v.Parent == "" {
		return []string{"a refused member names no parent it was derived from"}
	}
	for _, other := range m.Vectors {
		if other.ID != v.Parent {
			continue
		}
		if v.Kind == "reject" && other.Kind != "accept" {
			return []string{"names parent " + v.Parent + ", which is not an accept member"}
		}
		return nil
	}
	return []string{"names parent " + v.Parent + ", which is not a member"}
}

// agSourceFindings holds a copied member to the upstream file it names. The
// member's bytes are that file's bytes, so its digest is the upstream digest,
// and a member someone else produced is only ever offered as an accept.
func agSourceFindings(v agVector, body []byte) []string {
	if v.Source == nil {
		return nil
	}
	var out []string
	if v.Source.Repo == "" || v.Source.Commit == "" || v.Source.Path == "" {
		out = append(out, "a source names no repository, commit or path")
	}
	if sha(body) != v.Source.Sha256 {
		out = append(out, "the member's bytes are not the upstream file its source pins")
	}
	if v.Kind != "accept" {
		out = append(out, "a member copied from upstream is not an accept member")
	}
	return out
}

func agTrailer(dir string, v agVector, out *Member) ([]byte, bool) {
	if v.Trailer == "" {
		return nil, true
	}
	trailer, err := readIn(dir, v.Trailer)
	if err != nil {
		out.Findings = append(out.Findings, "the trailer file is missing or unreadable: "+v.Trailer)
		return nil, false
	}
	return trailer, true
}

// judgeAGGolden checks the golden member: its RFC 8785 form, which revision
// 0.1.4 names as the canonical form, is the pinned bytes.
func judgeAGGolden(m *agManifest, v agVector, body []byte) []string {
	var out []string
	if v.Kind != "accept" {
		out = append(out, "the golden member is not an accept member")
	}
	if v.Expected.CanonicalLength == nil || *v.Expected.CanonicalLength != m.GoldenSource.CanonicalLength ||
		v.Expected.CanonicalSha256 != m.GoldenSource.CanonicalSha256 {
		out = append(out, "the golden member does not declare the length and sha256 goldenSource pins")
	}
	canonical, err := aee.Canonicalize(body)
	if err != nil {
		return append(out, "the golden statement does not canonicalize: "+err.Error())
	}
	if len(canonical) != m.GoldenSource.CanonicalLength || sha(canonical) != m.GoldenSource.CanonicalSha256 {
		out = append(out, fmt.Sprintf("the golden statement canonicalizes to %d bytes with sha256 %s, "+
			"not the pinned %d bytes with sha256 %s", len(canonical), short(sha(canonical)),
			m.GoldenSource.CanonicalLength, short(m.GoldenSource.CanonicalSha256)))
	}
	return out
}

func judgeAGAttestation(dir string, v agVector, body, trailer []byte) []string {
	subject, err := newAGSubject(dir, v, body, trailer)
	if err != "" {
		return []string{err}
	}
	rev := subject.evaluate(agRevision)
	prop := subject.evaluate(agProposal)
	out := agGrade(v, rev, prop)
	out = append(out, agSignoffCount(v, subject)...)
	out = append(out, agModeFindings(v)...)
	return out
}

// agGrade compares the two verifiers' answers with the member's declaration.
func agGrade(v agVector, rev, prop agOutcome) []string {
	valid := agOutcome{Verdict: agValid}
	switch v.Kind {
	case "accept":
		var out []string
		if rev != valid {
			out = append(out, "an accept member that the revision refuses: "+rev.String())
		}
		if prop != valid {
			out = append(out, "an accept member that the proposal refuses: "+prop.String())
		}
		return out
	case "reject":
		if v.Expected.Verdict != agInvalid || v.Expected.Code == "" {
			return []string{"a reject member that declares no invalid verdict and code"}
		}
		if rev != v.Expected.agOutcome {
			return []string{fmt.Sprintf("expected %s under the revision, got %s", v.Expected.agOutcome, rev)}
		}
		return nil
	default:
		return agGradeProposed(v, rev, prop)
	}
}

func agGradeProposed(v agVector, rev, prop agOutcome) []string {
	if v.Expected.AsWritten == nil || v.Expected.Proposal == nil {
		return []string{"a proposed member that does not declare both its asWritten and its proposal outcome"}
	}
	var out []string
	if rev != *v.Expected.AsWritten {
		out = append(out, fmt.Sprintf("expected %s under the revision, got %s", *v.Expected.AsWritten, rev))
	}
	if prop != *v.Expected.Proposal {
		out = append(out, fmt.Sprintf("expected %s under the proposal, got %s", *v.Expected.Proposal, prop))
	}
	if *v.Expected.AsWritten == *v.Expected.Proposal {
		out = append(out, "a proposed member whose two outcomes are the same, so the proposal changes nothing about it")
	}
	return out
}

// agSignoffCount holds the one number N-of-M is about: distinct signing keys.
func agSignoffCount(v agVector, s *agSubject) []string {
	keys := map[string]bool{}
	for _, sig := range s.env.Signatures {
		if sig.Role == agHumanSignoff {
			keys[sig.KeyID] = true
		}
	}
	declared := v.Expected.DistinctSignoffKeys
	switch {
	case len(keys) == 0 && declared == nil:
		return nil
	case declared == nil:
		return []string{"carries sign-off signatures and declares no distinctSignoffKeys"}
	case *declared != len(keys):
		return []string{fmt.Sprintf("declares %d distinct sign-off keys and carries %d", *declared, len(keys))}
	}
	return nil
}

// agModeFindings: an attest-only reader executes nothing, so the only
// acceptance it can report is the producer's own claim.
func agModeFindings(v agVector) []string {
	var out []string
	if v.Expected.Mode != "" && v.Expected.Mode != "attest-only" {
		out = append(out, fmt.Sprintf("declares mode %q; this reader verifies attest-only and executes nothing", v.Expected.Mode))
	}
	if v.Expected.Acceptance != "" && v.Expected.Acceptance != "self-reported" {
		out = append(out, fmt.Sprintf("declares acceptance %q; attest-only verification can only report it as self-reported", v.Expected.Acceptance))
	}
	return out
}

// ---------------------------------------------------------------------------
// The subject: one envelope, its statement decoded, its artifacts loaded.

type agMode int

const (
	agRevision agMode = iota
	agProposal
)

type agSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
	Role  string `json:"role"`
}

type agEnvelope struct {
	PayloadSHA256 string          `json:"payload_sha256"`
	Statement     json.RawMessage `json:"statement"`
	Signatures    []agSignature   `json:"signatures"`
}

type agSubject struct {
	env       agEnvelope
	stmt      map[string]any
	artifacts map[string][]byte
	trailer   []byte
}

func newAGSubject(dir string, v agVector, body, trailer []byte) (*agSubject, string) {
	s := &agSubject{artifacts: map[string][]byte{}, trailer: trailer}
	if err := json.Unmarshal(body, &s.env); err != nil {
		return nil, "the member is not an attestation envelope: " + err.Error()
	}
	value, err := agDecode(s.env.Statement)
	if err != nil {
		return nil, "the statement does not parse: " + err.Error()
	}
	stmt, ok := value.(map[string]any)
	if !ok {
		return nil, "the statement is not a JSON object"
	}
	s.stmt = stmt
	for _, a := range v.Artifacts {
		content, err := readIn(dir, a.File)
		if err != nil {
			return nil, "the artifact file is missing or unreadable: " + a.File
		}
		s.artifacts[a.Name] = content
	}
	return s, ""
}

func agDecode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// evaluate runs the attest-only verification in order and returns the first
// refusal. The order is part of the contract: each member breaks one rule, and
// the code it declares is the first one this sequence reaches.
func (s *agSubject) evaluate(mode agMode) agOutcome {
	steps := []func(agMode) (agOutcome, bool){
		s.valueDomain, s.omission, s.fieldTable, s.envelopeBytes, s.artifactDigests, s.proposalRules,
	}
	for _, step := range steps {
		if out, stop := step(mode); stop {
			return out
		}
	}
	return agOutcome{Verdict: agValid}
}

func agRefuse(code string) (agOutcome, bool) { return agOutcome{Verdict: agInvalid, Code: code}, true }

// valueDomain: revision 0.1.4 admits I-JSON: integers within the safe range,
// no floating-point numbers, and unique member names.
func (s *agSubject) valueDomain(agMode) (agOutcome, bool) {
	err := aee.CheckIJSON(s.env.Statement)
	switch {
	case err == nil:
		return agOutcome{}, false
	case errors.Is(err, aee.ErrDuplicateMember):
		return agRefuse("duplicate-member")
	case errors.Is(err, aee.ErrUnsafeInteger):
		return agRefuse("unsafe-integer")
	case errors.Is(err, aee.ErrNonIntegerNumber):
		return agRefuse("floating-point-number")
	default:
		return agRefuse("not-i-json")
	}
}

func agMap(value any, name string) map[string]any {
	parent, _ := value.(map[string]any)
	child, _ := parent[name].(map[string]any)
	return child
}

func agList(value any, name string) []any {
	parent, _ := value.(map[string]any)
	child, _ := parent[name].([]any)
	return child
}

// omission: the producer omission rule, the same in both readings.
func (s *agSubject) omission(agMode) (agOutcome, bool) {
	predicate := agMap(s.stmt, "predicate")
	for _, name := range []string{"acceptance", "signoffs"} {
		if list, present := predicate[name].([]any); present && len(list) == 0 {
			return agRefuse("empty-array-serialized")
		}
	}
	agent := agMap(predicate, "agent")
	for _, name := range []string{"id", "tools"} {
		if value, present := agent[name]; present && value == nil {
			return agRefuse("null-optional-serialized")
		}
	}
	for _, material := range agList(predicate, "materials") {
		if value, present := material.(map[string]any)["sha256"]; present && value == nil {
			return agRefuse("null-optional-serialized")
		}
	}
	return agOutcome{}, false
}

// fieldTable: the one enumerated field the revision's table defines.
func (s *agSubject) fieldTable(agMode) (agOutcome, bool) {
	for _, entry := range agList(agMap(s.stmt, "predicate"), "generated") {
		author, _ := entry.(map[string]any)["author"].(string)
		if author != "ai" && author != "human" {
			return agRefuse("author-not-in-enum")
		}
	}
	return agOutcome{}, false
}

// envelopeBytes checks payload_sha256 and every signature against the bytes
// revision 0.1.4's Signature coverage says each covers: the fab signature and
// payload_sha256 the statement without signoffs, the n-th sign-off the first n
// records, its own included, and each record naming the key that signed it.
func (s *agSubject) envelopeBytes(agMode) (agOutcome, bool) {
	records := agList(agMap(s.stmt, "predicate"), "signoffs")
	var humans []agSignature
	for _, sig := range s.env.Signatures {
		if sig.Role == agHumanSignoff {
			humans = append(humans, sig)
		}
	}
	if len(records) != len(humans) {
		return agRefuse("signoff-records-and-signatures-disagree")
	}
	for i, record := range records {
		if did, _ := record.(map[string]any)["did"].(string); did != humans[i].KeyID {
			return agRefuse("signoff-signer-mismatch")
		}
	}
	payload, err := agRFC8785(s.withSignoffs(records, 0))
	if err != nil {
		return agRefuse("not-canonicalizable")
	}
	if sha(payload) != s.env.PayloadSHA256 {
		return agRefuse("payload-digest-mismatch")
	}
	return s.eachSignature(records, payload)
}

func (s *agSubject) eachSignature(records []any, fabPayload []byte) (agOutcome, bool) {
	signed := 0
	for _, sig := range s.env.Signatures {
		switch sig.Role {
		case agFab:
			if code := agVerify(sig, fabPayload); code != "" {
				return agRefuse(code)
			}
		case agHumanSignoff:
			signed++
			message, err := agRFC8785(s.withSignoffs(records, signed))
			if err != nil {
				return agRefuse("not-canonicalizable")
			}
			if code := agVerify(sig, message); code == "signature-invalid" {
				return agRefuse("signoff-signature-invalid")
			} else if code != "" {
				return agRefuse(code)
			}
		default:
			return agRefuse("unknown-signature-role")
		}
	}
	return agOutcome{}, false
}

// withSignoffs is the statement with only the first keep sign-off records, the
// array omitted when none are kept, as the producer omission rule requires.
func (s *agSubject) withSignoffs(records []any, keep int) map[string]any {
	out := make(map[string]any, len(s.stmt))
	for k, v := range s.stmt {
		out[k] = v
	}
	predicate := map[string]any{}
	for k, v := range agMap(s.stmt, "predicate") {
		predicate[k] = v
	}
	if keep == 0 {
		delete(predicate, "signoffs")
	} else {
		predicate["signoffs"] = records[:keep]
	}
	out["predicate"] = predicate
	return out
}

// artifactDigests is attest-only step 1: every subject and every generated
// range recomputes from the artifact bytes. A range's digest is over exactly
// the LF-terminated lines it names; the revision does not say, and the corpus
// README states this reading.
func (s *agSubject) artifactDigests(agMode) (agOutcome, bool) {
	for _, entry := range agList(s.stmt, "subject") {
		name, _ := entry.(map[string]any)["name"].(string)
		want, _ := agMap(entry, "digest")["sha256"].(string)
		if code := s.artifactCode(name, "", want); code != "" {
			return agRefuse(code)
		}
	}
	for _, entry := range agList(agMap(s.stmt, "predicate"), "generated") {
		fields, _ := entry.(map[string]any)
		path, _ := fields["path"].(string)
		lines, _ := fields["lines"].(string)
		want, _ := fields["sha256"].(string)
		if code := s.artifactCode(path, lines, want); code != "" {
			return agRefuse(code)
		}
	}
	return agOutcome{}, false
}

func (s *agSubject) artifactCode(name, lines, want string) string {
	content, ok := s.artifacts[name]
	if !ok {
		return "artifact-missing"
	}
	if lines != "" {
		start, end, ok := agRange(lines)
		all := bytes.SplitAfter(content, []byte("\n"))
		if !ok || end > len(all) {
			return "artifact-digest-mismatch"
		}
		content = bytes.Join(all[start-1:end], nil)
	}
	if sha(content) != want {
		return "artifact-digest-mismatch"
	}
	return ""
}

var agLineRange = regexp.MustCompile(`^[0-9]+(?:-[0-9]+)?$`)

func agRange(lines string) (int, int, bool) {
	if !agLineRange.MatchString(lines) {
		return 0, 0, false
	}
	first, last, found := strings.Cut(lines, "-")
	if !found {
		last = first
	}
	start, err1 := strconv.Atoi(first)
	end, err2 := strconv.Atoi(last)
	if !agBoundsValid(start, end, err1, err2) {
		return 0, 0, false
	}
	return start, end, true
}

func agBoundsValid(start, end int, err1, err2 error) bool {
	return err1 == nil && err2 == nil && start > 0 && end >= start
}

// proposalRules enforces both findings adopted by revision 0.1.5.
func (s *agSubject) proposalRules(agMode) (agOutcome, bool) {
	if agRangesOverlap(agList(agMap(s.stmt, "predicate"), "generated")) {
		return agRefuse("attribution-ranges-overlap")
	}
	if s.trailer != nil && !s.trailerAgrees() {
		return agRefuse("trailer-disagrees")
	}
	return agOutcome{}, false
}

func agRangesOverlap(generated []any) bool {
	type span struct{ start, end int }
	byPath := map[string][]span{}
	for _, entry := range generated {
		fields, _ := entry.(map[string]any)
		path, _ := fields["path"].(string)
		lines, _ := fields["lines"].(string)
		start, end, ok := agRange(lines)
		if !ok {
			continue
		}
		for _, other := range byPath[path] {
			if start <= other.end && other.start <= end {
				return true
			}
		}
		byPath[path] = append(byPath[path], span{start, end})
	}
	return false
}

// trailerAgrees checks each supplied identifier and every listed tool.
func (s *agSubject) trailerAgrees() bool {
	agent := agMap(agMap(s.stmt, "predicate"), "agent")
	want, _ := agent["id"].(string)
	tools := map[string]bool{}
	for _, tool := range agList(agent, "tools") {
		name, _ := tool.(string)
		tools[name] = true
	}
	found := false
	for _, line := range strings.Split(string(s.trailer), "\n") {
		value, ok := strings.CutPrefix(line, "Assisted-by: ")
		if !ok {
			continue
		}
		found = true
		if !agTrailerMatches(value, want, tools) {
			return false
		}
	}
	return found
}

func agTrailerMatches(value, want string, tools map[string]bool) bool {
	fields := strings.Fields(value)
	if len(fields) == 0 || fields[0] != want {
		return false
	}
	for _, tool := range fields[1:] {
		if !tools[tool] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Canonical forms and keys.

// agRFC8785 is the repository's RFC 8785 canonicalization over a decoded
// value. json.Marshal only carries the value to aee.Canonicalize, which parses
// it again and emits the canonical bytes.
func agRFC8785(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return aee.Canonicalize(raw)
}

// agVerify checks one signature over message. It returns "" or a code.
func agVerify(sig agSignature, message []byte) string {
	public, ok := agDidKey(sig.KeyID)
	if !ok {
		return "keyid-not-ed25519-did-key"
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(public, message, raw) {
		return "signature-invalid"
	}
	return ""
}

const agBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// agDidKey recovers an ed25519 public key from a did:key: multibase base58btc
// over the multicodec prefix 0xed 0x01 and the raw key bytes.
func agDidKey(did string) (ed25519.PublicKey, bool) {
	encoded, ok := strings.CutPrefix(did, "did:key:z")
	if !ok {
		return nil, false
	}
	number := new(big.Int)
	for _, r := range encoded {
		digit := strings.IndexRune(agBase58, r)
		if digit < 0 {
			return nil, false
		}
		number.Mul(number, big.NewInt(58))
		number.Add(number, big.NewInt(int64(digit)))
	}
	decoded := number.Bytes()
	if len(decoded) != 2+ed25519.PublicKeySize || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, false
	}
	return ed25519.PublicKey(decoded[2:]), true
}
