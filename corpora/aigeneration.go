package corpora

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(aiGeneration{}) }

// aiGeneration judges vectors-ai-generation/, the conformance corpus for the
// generation predicate at specification revision 0.1.3 in its default
// attest-only mode.
//
// It is two verifiers, not one. The first reads revision 0.1.3 as written:
// every signature covers the canonical form of the statement as received, keys
// ordered by code point, no numbers in the value domain. The second reads the
// proposal the corpus puts forward: RFC 8785 member order, I-JSON integers,
// sign-offs covering stated parts of the statement and bound to their records.
// Every member is run through both, and what each returns is compared with
// what the member declares. An accept member must be valid under both; a
// reject member must fail revision 0.1.3 with the code it names; a proposed
// member must produce exactly the two outcomes it declares, and they must
// differ, or it is an accept or a reject wearing the wrong label.
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
	Rev013              *agOutcome `json:"rev013"`
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
	text, err := readIn(filepath.Dir(dir), m.ProposedText)
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
// revision 0.1.3 needs an accept member carrying it, and a condition refused
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

// judgeAGGolden checks the golden member: its canonical form, under the
// revision's code-point order and under RFC 8785 alike, is the pinned bytes.
func judgeAGGolden(m *agManifest, v agVector, body []byte) []string {
	var out []string
	if v.Kind != "accept" {
		out = append(out, "the golden member is not an accept member")
	}
	if v.Expected.CanonicalLength == nil || *v.Expected.CanonicalLength != m.GoldenSource.CanonicalLength ||
		v.Expected.CanonicalSha256 != m.GoldenSource.CanonicalSha256 {
		out = append(out, "the golden member does not declare the length and sha256 goldenSource pins")
	}
	value, err := agDecode(body)
	if err != nil {
		return append(out, "the golden statement does not parse: "+err.Error())
	}
	codePoint, err := agCodePointCanonical(value)
	if err != nil {
		return append(out, "the golden statement does not canonicalize: "+err.Error())
	}
	rfc8785, err := aee.Canonicalize(body)
	if err != nil || !bytes.Equal(codePoint, rfc8785) {
		out = append(out, "the golden statement's code-point form and its RFC 8785 form differ")
	}
	if len(codePoint) != m.GoldenSource.CanonicalLength || sha(codePoint) != m.GoldenSource.CanonicalSha256 {
		out = append(out, fmt.Sprintf("the golden statement canonicalizes to %d bytes with sha256 %s, "+
			"not the pinned %d bytes with sha256 %s", len(codePoint), short(sha(codePoint)),
			m.GoldenSource.CanonicalLength, short(m.GoldenSource.CanonicalSha256)))
	}
	return out
}

func judgeAGAttestation(dir string, v agVector, body, trailer []byte) []string {
	subject, err := newAGSubject(dir, v, body, trailer)
	if err != "" {
		return []string{err}
	}
	rev := subject.evaluate(agRev013)
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
			out = append(out, "an accept member that revision 0.1.3 refuses: "+rev.String())
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
			return []string{fmt.Sprintf("expected %s under revision 0.1.3, got %s", v.Expected.agOutcome, rev)}
		}
		return nil
	default:
		return agGradeProposed(v, rev, prop)
	}
}

func agGradeProposed(v agVector, rev, prop agOutcome) []string {
	if v.Expected.Rev013 == nil || v.Expected.Proposal == nil {
		return []string{"a proposed member that does not declare both its rev013 and its proposal outcome"}
	}
	var out []string
	if rev != *v.Expected.Rev013 {
		out = append(out, fmt.Sprintf("expected %s under revision 0.1.3, got %s", *v.Expected.Rev013, rev))
	}
	if prop != *v.Expected.Proposal {
		out = append(out, fmt.Sprintf("expected %s under the proposal, got %s", *v.Expected.Proposal, prop))
	}
	if *v.Expected.Rev013 == *v.Expected.Proposal {
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
	agRev013 agMode = iota
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

// valueDomain: revision 0.1.3 admits strings, booleans, objects and arrays
// only, and says nothing of duplicate names. The proposal admits I-JSON: safe
// integers, unique names.
func (s *agSubject) valueDomain(mode agMode) (agOutcome, bool) {
	err := aee.CheckIJSON(s.env.Statement)
	if mode == agRev013 {
		if errors.Is(err, aee.ErrDuplicateMember) {
			return agOutcome{Verdict: agIndeterminate}, true
		}
		if code := agNumberCode(s.stmt); code != "" {
			return agRefuse(code)
		}
		return agOutcome{}, false
	}
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

// agNumberCode walks a decoded value for the first number, in sorted member
// order so the answer does not depend on map iteration.
func agNumberCode(value any) string {
	switch t := value.(type) {
	case json.Number:
		if strings.ContainsAny(string(t), ".eE") {
			return "floating-point-number"
		}
		return "number-outside-value-domain"
	case []any:
		for _, item := range t {
			if code := agNumberCode(item); code != "" {
				return code
			}
		}
	case map[string]any:
		for _, name := range sortedKeys(t) {
			if code := agNumberCode(t[name]); code != "" {
				return code
			}
		}
	}
	return ""
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
// each is said to cover.
func (s *agSubject) envelopeBytes(mode agMode) (agOutcome, bool) {
	if mode == agRev013 {
		payload, err := agCodePointCanonical(s.stmt)
		if err != nil {
			return agRefuse("not-canonicalizable")
		}
		if sha(payload) != s.env.PayloadSHA256 {
			return agRefuse("payload-digest-mismatch")
		}
		for _, sig := range s.env.Signatures {
			if code := agVerify(sig, payload); code != "" {
				return agRefuse(code)
			}
		}
		return agOutcome{}, false
	}
	return s.proposalSignatures()
}

// proposalSignatures: the fab signature and payload_sha256 cover the statement
// without signoffs; the n-th sign-off covers the first n records, its own
// included; each record names the key that signed it.
func (s *agSubject) proposalSignatures() (agOutcome, bool) {
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
	return s.proposalEachSignature(records, payload)
}

func (s *agSubject) proposalEachSignature(records []any, fabPayload []byte) (agOutcome, bool) {
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

func agRange(lines string) (int, int, bool) {
	first, last, found := strings.Cut(lines, "-")
	start, err1 := strconv.Atoi(first)
	end, err2 := strconv.Atoi(last)
	if !found || err1 != nil || err2 != nil || start < 1 || end < start {
		return 0, 0, false
	}
	return start, end, true
}

// proposalRules are the two checks the revision leaves to a MAY or to nothing.
func (s *agSubject) proposalRules(mode agMode) (agOutcome, bool) {
	if mode == agRev013 {
		return agOutcome{}, false
	}
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

// trailerAgrees: the commit's Assisted-by lines are exactly agent.id followed
// by agent.tools, the kernel convention the revision adopts.
func (s *agSubject) trailerAgrees() bool {
	agent := agMap(agMap(s.stmt, "predicate"), "agent")
	want, _ := agent["id"].(string)
	for _, tool := range agList(agent, "tools") {
		name, _ := tool.(string)
		want += " " + name
	}
	var found []string
	for _, line := range strings.Split(string(s.trailer), "\n") {
		if value, ok := strings.CutPrefix(line, "Assisted-by: "); ok {
			found = append(found, value)
		}
	}
	return len(found) == 1 && found[0] == want
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

// agCodePointCanonical is revision 0.1.3's form: RFC 8785 in every respect but
// member order, which is by Unicode code point. Strings are emitted through
// aee.Canonicalize, so the escaping is the repository's one spelling of it.
func agCodePointCanonical(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := agAppendCodePoint(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func agAppendCodePoint(buf *bytes.Buffer, value any) error {
	switch t := value.(type) {
	case nil, bool, string:
		scalar, err := agRFC8785(t)
		if err != nil {
			return err
		}
		buf.Write(scalar)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := agAppendCodePoint(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		return agAppendObject(buf, t)
	default:
		return fmt.Errorf("a %T is outside the revision's value domain", value)
	}
	return nil
}

func agAppendObject(buf *bytes.Buffer, object map[string]any) error {
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	// Go orders strings by their UTF-8 bytes, and UTF-8 byte order is code-point
	// order: this is the line that differs from RFC 8785.
	sort.Strings(names)
	buf.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := agAppendCodePoint(buf, name); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := agAppendCodePoint(buf, object[name]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
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
