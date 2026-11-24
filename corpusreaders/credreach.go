package corpusreaders

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"time"
)

func init() { register(credentialReachability{}) }

// credentialReachability judges corpora/vectors-credential-reachability/. Each member is
// one signed credential-reachability/v1 record (spec/predicates/credential-reachability.md):
// a probe ran inside an agent's environment and tried every ambient credential class of a
// closed list, and a key outside the agent's reach signed what it found. The rules, their
// order and the reason codes are the ones the Python reader
// (packaging/agent_evidence_vectors/credreach.py) applies; every class verdict and the result
// are recomputed from the attempts, never copied.
type credentialReachability struct{}

func (credentialReachability) Suite() string { return "credential-reachability/v1" }

const (
	reachPredicate = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/credential-reachability"
	reachClassSet  = "credential-reachability/v1"
)

var (
	credClasses = []string{"ssh-agent", "ssh-key-file", "cloud-metadata", "cloud-config-file",
		"registry-config-file", "browser-cookie-store", "environment-token",
		"cluster-service-account", "git-credential", "host-keyring"}
	credVerdictWords = []string{"reachable", "not_reachable", "could_not_test"}
	credOutcomes     = []string{"found", "issued_to_agent", "placeholder", "absent", "denied", "error", "not_run"}
	credResults      = []string{"contained", "incomplete", "exposed"} // best first
	credMembers      = []string{"classSet", "audience", "challenge", "probedAt", "vantage", "probe",
		"placeholders", "issuedToAgent", "classes", "result"}
	credFields = []string{"audience", "challenge", "probedAt", "vantage", "probe", "placeholders",
		"issuedToAgent", "classes", "result"}
	credAttemptMembers = map[string]bool{"locator": true, "outcome": true, "digestPrefix": true, "detail": true}

	credHex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	credHex12   = regexp.MustCompile(`^[0-9a-f]{12}$`)
	credText200 = regexp.MustCompile(`^[\x20-\x7e]{1,200}$`)
	credText512 = regexp.MustCompile(`^[\x20-\x7e]{1,512}$`)
	credDetail  = regexp.MustCompile(`^[\x20-\x7e]{0,200}$`)
	credUTC     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

type credVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Twin     string            `json:"twin"`
}

type credPolicy struct {
	PayloadType    string            `json:"payload_type"`
	TrustedSigners map[string]string `json:"trusted_signers"`
	AgentKeys      map[string]string `json:"agent_keys"`
	Environment    struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	} `json:"environment"`
	Audience      string   `json:"audience"`
	Challenge     string   `json:"challenge"`
	JudgedAt      string   `json:"judged_at"`
	MaxAgeSeconds int64    `json:"max_age_seconds"`
	ProbeDigests  []string `json:"probe_digests"`
}

type credCase struct {
	Envelope string     `json:"envelope"`
	Policy   credPolicy `json:"policy"`
}

func (credentialReachability) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	supported := map[string]bool{}
	var vectors []credVector
	for _, entry := range manifest.Vectors {
		var v credVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		supported[v.ID] = v.Expected.Decision == "supported"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = credJudgeMember(filepath.Join(dir, v.Path), v)
		if v.Expected.Decision != "supported" && !supported[v.Twin] {
			member.Findings = append(member.Findings, "a refused member must name a supported twin")
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func credJudgeMember(caseDir string, v credVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c credCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	envelope, err := readIn(caseDir, c.Envelope)
	if err != nil {
		return append(findings, c.Envelope+" cannot be read")
	}
	if got := credDecide(envelope, c.Policy); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type credRefusal struct{ decision, reason string }

func credRefuse(decision, reason string) *credRefusal { return &credRefusal{decision, reason} }

// credDecide is the reader's decision and reason for one envelope under one
// verifier policy.
func credDecide(envelope []byte, policy credPolicy) scDecision {
	result, refusal := credVerify(envelope, policy)
	if refusal != nil {
		return scDecision{Decision: refusal.decision, Reason: refusal.reason}
	}
	return scDecision{Decision: "supported", Reason: result + "_verified"}
}

func credKeys(table map[string]string) (map[string]ed25519.PublicKey, bool) {
	keys := map[string]ed25519.PublicKey{}
	for kid, encoded := range table {
		raw, err := decodeCanonical(base64.StdEncoding, encoded)
		if err != nil || len(raw) != ed25519.PublicKeySize || !credHex64.MatchString(kid) {
			return nil, false
		}
		keys[kid] = ed25519.PublicKey(raw)
	}
	return keys, true
}

func credVerify(envelope []byte, policy credPolicy) (string, *credRefusal) {
	trusted, okT := credKeys(policy.TrustedSigners)
	agent, okA := credKeys(policy.AgentKeys)
	if !okT || !okA || len(trusted) == 0 || !credUTC.MatchString(policy.JudgedAt) {
		return "", credRefuse("no_verdict", "policy_invalid")
	}
	for _, t := range trusted {
		for _, a := range agent {
			if string(t) == string(a) {
				return "", credRefuse("no_verdict", "policy_invalid")
			}
		}
	}
	payloadType, body, sigs, ok := caParse(envelope)
	if !ok {
		return "", credRefuse("no_verdict", "malformed_envelope")
	}
	if payloadType != policy.PayloadType {
		return "", credRefuse("not_established", "unsupported_payload_type")
	}
	if r := credSignatures(payloadType, body, sigs, trusted, agent); r != nil {
		return "", r
	}
	p, r := credStatement(body, policy)
	if r != nil {
		return "", r
	}
	if r := credWellFormed(p); r != nil {
		return "", r
	}
	if r := credBinding(p, policy); r != nil {
		return "", r
	}
	if r := credCoverage(p); r != nil {
		return "", r
	}
	return credVerdicts(p)
}

func credSignatures(payloadType string, body []byte, sigs []caSig,
	trusted, agent map[string]ed25519.PublicKey) *credRefusal {
	message := caPAE(payloadType, body)
	for _, s := range sigs {
		for _, key := range agent {
			if ed25519.Verify(key, message, s.sig) {
				return credRefuse("contradicted", "signed_by_agent_key")
			}
		}
	}
	named := false
	for _, s := range sigs {
		key, pinned := trusted[s.keyid]
		if !pinned {
			continue
		}
		named = true
		if ed25519.Verify(key, message, s.sig) {
			return nil
		}
	}
	if named {
		return credRefuse("contradicted", "signature_invalid")
	}
	return credRefuse("contradicted", "untrusted_key")
}

func credText(v any, re *regexp.Regexp) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

func credExact(v any, members ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(members) {
		return nil, false
	}
	for _, name := range members {
		if _, present := m[name]; !present {
			return nil, false
		}
	}
	return m, true
}

func credIn(v any, words []string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, w := range words {
		if s == w {
			return true
		}
	}
	return false
}

func credTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || !credUTC.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	return t, err == nil
}

func credStatement(body []byte, policy credPolicy) (map[string]any, *credRefusal) {
	var payload any
	if strictUnmarshal(body, &payload) != nil {
		payload = nil
	}
	obj, isObj := payload.(map[string]any)
	if !isObj {
		return nil, credRefuse("not_established", "payload_not_json_object")
	}
	if obj["_type"] != caStatementV1 {
		return nil, credRefuse("not_established", "unsupported_statement_type")
	}
	if obj["predicateType"] != reachPredicate {
		return nil, credRefuse("not_established", "unsupported_predicate")
	}
	subjects, _ := obj["subject"].([]any)
	if len(subjects) != 1 {
		return nil, credRefuse("not_established", "subject_malformed")
	}
	subject, shaped := credExact(subjects[0], "name", "digest")
	var digest map[string]any
	if shaped {
		digest, shaped = credExact(subject["digest"], "sha256")
	}
	if !shaped || !credText(subject["name"], credText512) || !credText(digest["sha256"], credHex64) {
		return nil, credRefuse("not_established", "subject_malformed")
	}
	if subject["name"] != policy.Environment.Name || digest["sha256"] != policy.Environment.SHA256 {
		return nil, credRefuse("contradicted", "environment_mismatch")
	}
	p, isPred := obj["predicate"].(map[string]any)
	if !isPred {
		return nil, credRefuse("not_established", "predicate_field_invalid:predicate")
	}
	return p, nil
}

func credAttemptOK(v any) bool {
	a, ok := v.(map[string]any)
	if !ok || !credText(a["locator"], credText512) || !credIn(a["outcome"], credOutcomes) {
		return false
	}
	detail, has := a["detail"]
	return !has || credText(detail, credDetail)
}

func credList(v any, each func(any) bool) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if !each(item) {
			return false
		}
	}
	return true
}

func credClassOK(v any) bool {
	c, ok := credExact(v, "class", "verdict", "attempts")
	if !ok || !credIn(c["class"], credClasses) || !credIn(c["verdict"], credVerdictWords) {
		return false
	}
	attempts, isList := c["attempts"].([]any)
	return isList && len(attempts) > 0 && credList(attempts, credAttemptOK)
}

func credFieldOK(field string, p map[string]any) bool {
	value := p[field]
	switch field {
	case "audience", "vantage":
		return credText(value, credText200)
	case "challenge":
		return credText(value, credHex64)
	case "probedAt":
		_, ok := credTime(value)
		return ok
	case "probe":
		probe, ok := credExact(value, "name", "version", "digest")
		if !ok || !credText(probe["name"], credText200) || !credText(probe["version"], credText200) {
			return false
		}
		digest, ok := credExact(probe["digest"], "sha256")
		return ok && credText(digest["sha256"], credHex64)
	case "placeholders":
		return credList(value, func(e any) bool {
			m, ok := credExact(e, "prefix")
			return ok && credText(m["prefix"], credText200)
		})
	case "issuedToAgent":
		return credList(value, func(e any) bool {
			m, ok := credExact(e, "id", "digestPrefix")
			return ok && credText(m["id"], credText200) && credText(m["digestPrefix"], credHex12)
		})
	case "classes":
		return credList(value, credClassOK)
	}
	return credIn(value, credResults)
}

// credClassList is the predicate's classes, each an object; credWellFormed has already shaped them.
func credClassList(p map[string]any) []map[string]any {
	list, _ := p["classes"].([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if c, ok := item.(map[string]any); ok {
			out = append(out, c)
		}
	}
	return out
}

func credAttempts(c map[string]any) []map[string]any {
	list, _ := c["attempts"].([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if a, ok := item.(map[string]any); ok {
			out = append(out, a)
		}
	}
	return out
}

func credWellFormed(p map[string]any) *credRefusal {
	if _, exact := credExact(p, credMembers...); !exact {
		return credRefuse("not_established", "predicate_field_invalid:members")
	}
	if p["classSet"] != reachClassSet {
		return credRefuse("not_established", "class_set_unsupported")
	}
	for _, field := range credFields {
		if !credFieldOK(field, p) {
			return credRefuse("not_established", "predicate_field_invalid:"+field)
		}
	}
	for _, c := range credClassList(p) {
		for _, a := range credAttempts(c) {
			needs := a["outcome"] == "found" || a["outcome"] == "issued_to_agent"
			prefix, has := a["digestPrefix"]
			extra := false
			for name := range a {
				extra = extra || !credAttemptMembers[name]
			}
			if extra || has != needs || (needs && !credText(prefix, credHex12)) {
				return credRefuse("contradicted", "attempt_fields")
			}
		}
	}
	return nil
}

func credBinding(p map[string]any, policy credPolicy) *credRefusal {
	if p["vantage"] != "agent-process" {
		return credRefuse("not_established", "vantage_not_agent")
	}
	if p["audience"] != policy.Audience {
		return credRefuse("contradicted", "audience_mismatch")
	}
	if p["challenge"] != policy.Challenge {
		return credRefuse("contradicted", "challenge_mismatch")
	}
	judged, _ := credTime(policy.JudgedAt)
	probed, _ := credTime(p["probedAt"])
	if probed.After(judged) {
		return credRefuse("contradicted", "probed_in_future")
	}
	if judged.Sub(probed) > time.Duration(policy.MaxAgeSeconds)*time.Second {
		return credRefuse("not_established", "result_stale")
	}
	if len(policy.ProbeDigests) > 0 {
		probe, _ := p["probe"].(map[string]any)
		digest, _ := probe["digest"].(map[string]any)
		if !credIn(digest["sha256"], policy.ProbeDigests) {
			return credRefuse("not_established", "probe_not_pinned")
		}
	}
	return nil
}

func credCoverage(p map[string]any) *credRefusal {
	seen := map[string]bool{}
	for _, c := range credClassList(p) {
		name, _ := c["class"].(string)
		if seen[name] {
			return credRefuse("contradicted", "class_duplicate:"+name)
		}
		seen[name] = true
	}
	for _, name := range credClasses {
		if !seen[name] {
			return credRefuse("contradicted", "class_missing:"+name)
		}
	}
	declared := map[string]bool{}
	issued, _ := p["issuedToAgent"].([]any)
	for _, item := range issued {
		entry, _ := item.(map[string]any)
		if prefix, ok := entry["digestPrefix"].(string); ok {
			declared[prefix] = true
		}
	}
	placeholders, _ := p["placeholders"].([]any)
	var attempts []map[string]any
	for _, c := range credClassList(p) {
		attempts = append(attempts, credAttempts(c)...)
	}
	for _, a := range attempts {
		prefix, _ := a["digestPrefix"].(string)
		if a["outcome"] == "issued_to_agent" && !declared[prefix] {
			return credRefuse("contradicted", "issued_to_agent_undeclared")
		}
	}
	for _, a := range attempts {
		if a["outcome"] == "placeholder" && len(placeholders) == 0 {
			return credRefuse("contradicted", "placeholder_undeclared")
		}
	}
	return nil
}

// credDerive is a class verdict derived from its attempts' outcomes.
func credDerive(outcomes []string) string {
	found, untested := false, false
	for _, o := range outcomes {
		found = found || o == "found"
		untested = untested || o == "error" || o == "not_run"
	}
	switch {
	case found:
		return "reachable"
	case untested:
		return "could_not_test"
	}
	return "not_reachable"
}

func credRank(word any) int {
	for i, w := range credResults {
		if word == w {
			return i
		}
	}
	return len(credResults)
}

func credVerdicts(p map[string]any) (string, *credRefusal) {
	byClass := map[string]map[string]any{}
	for _, c := range credClassList(p) {
		name, _ := c["class"].(string)
		byClass[name] = c
	}
	reachable, untested := false, false
	for _, name := range credClasses {
		c := byClass[name]
		var outcomes []string
		for _, a := range credAttempts(c) {
			o, _ := a["outcome"].(string)
			outcomes = append(outcomes, o)
		}
		want := credDerive(outcomes)
		reachable = reachable || want == "reachable"
		untested = untested || want == "could_not_test"
		if said := c["verdict"]; said != want {
			switch {
			case said == "not_reachable" && want == "reachable":
				return "", credRefuse("contradicted", "reachable_reported_clean:"+name)
			case said == "not_reachable":
				return "", credRefuse("contradicted", "untested_reported_clean:"+name)
			}
			return "", credRefuse("contradicted", "class_verdict_mismatch:"+name)
		}
	}
	result := "contained"
	switch {
	case reachable:
		result = "exposed"
	case untested:
		result = "incomplete"
	}
	if said := p["result"]; said != result {
		if credRank(said) < credRank(result) {
			return "", credRefuse("contradicted", "result_overstates")
		}
		return "", credRefuse("contradicted", "result_mismatch")
	}
	return result, nil
}
