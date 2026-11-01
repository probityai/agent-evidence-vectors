package corpora

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

func init() { register(agenticProcess{}) }

// agenticProcess judges vectors-agentic-process-evidence/. Each member is one
// DSSE v1 envelope over an in-toto Statement v1 carrying the Agentic Process
// Evidence predicate, version 0.1, proposed in in-toto/attestation#609
// (https://github.com/in-toto/attestation/pull/609) and specified in
// jfrog/agentic-process-evidence, with the consumer policy that judges it.
// The checks, their order and the reason codes are the ones the Python reader
// (packaging/agent_evidence_vectors/agenticprocess.py) applies:
//
//  1. the envelope parses as DSSE v1, else no verdict (malformed_envelope);
//  2. the payload type is the pinned one (unsupported_payload_type);
//  3. a signature naming a pinned keyid verifies over the DSSE PAE
//     (untrusted_key, signature_invalid);
//  4. the payload is an object (payload_not_json_object) and a Statement v1
//     (unsupported_statement_type);
//  5. the predicate type is the pinned one (unsupported_predicate);
//  6. every constrained field is well formed (field_invalid:<field>).
type agenticProcess struct{}

func (agenticProcess) Suite() string { return "agentic-process-evidence/v0.1" }

type apVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Twin     string            `json:"twin"`
}

type apPolicy struct {
	PayloadType   string            `json:"payload_type"`
	PredicateType string            `json:"predicate_type"`
	TrustedKeys   map[string]string `json:"trusted_keys"`
}

type apCase struct {
	Envelope string   `json:"envelope"`
	Policy   apPolicy `json:"policy"`
}

const apStatementV1 = "https://in-toto.io/Statement/v1"

var (
	apTimestamp = regexp.MustCompile(
		`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$`)
	apURI          = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:[^\x00-\x20\x7f]+$`)
	apHex          = regexp.MustCompile(`^[0-9a-f]+$`)
	apDigestLength = map[string][]int{"sha256": {64}, "sha512": {128}, "sha1": {40}, "gitCommit": {40, 64}}
	apResults      = map[string]bool{"COMPLETED": true, "FAILED": true, "CANCELLED": true,
		"APPROVED": true, "REJECTED": true, "ALIGNED": true, "MISALIGNED": true}
)

// apFields is the order the fields are checked in: the Statement's own fields,
// then the predicate's required fields in the order of the specification's
// table, then its optional fields in the same order.
var apFields = []string{
	"createdAt", "createdBy", "subject", "predicate",
	"predicate.processType", "predicate.providers", "predicate.providers[].harness",
	"predicate.providers[].agent", "predicate.providers[].languageModels",
	"predicate.result", "predicate.owner", "predicate.startTimestamp",
	"predicate.endTimestamp", "predicate.traceId", "predicate.sessionsLogs",
	"predicate.tools", "predicate.contextArtifacts", "predicate.custom",
	"predicate.intents", "predicate.processSummary", "predicate.reviewers",
}

func (agenticProcess) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	supported := map[string]bool{}
	var vectors []apVector
	for _, entry := range manifest.Vectors {
		var v apVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		supported[v.ID] = v.Expected.Decision == "supported"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = apJudgeMember(filepath.Join(dir, v.Path), v)
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

func apJudgeMember(caseDir string, v apVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c apCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	envelope, err := readIn(caseDir, c.Envelope)
	if err != nil {
		return append(findings, c.Envelope+" cannot be read")
	}
	if got := apDecide(envelope, c.Policy); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type apRefusal struct{ decision, reason string }

func apDecide(envelope []byte, policy apPolicy) scDecision {
	if r := apVerify(envelope, policy); r != nil {
		return scDecision{Decision: r.decision, Reason: r.reason}
	}
	return scDecision{Decision: "supported", Reason: "process_evidence_verified"}
}

func apVerify(envelope []byte, policy apPolicy) *apRefusal {
	payloadType, body, sigs, ok := apParse(envelope)
	if !ok {
		return &apRefusal{"no_verdict", "malformed_envelope"}
	}
	if payloadType != policy.PayloadType {
		return &apRefusal{"not_established", "unsupported_payload_type"}
	}
	if r := apSignature(payloadType, body, sigs, policy.TrustedKeys); r != nil {
		return r
	}
	var payload any
	if json.Unmarshal(body, &payload) != nil {
		payload = nil
	}
	statement, isObj := payload.(map[string]any)
	if !isObj {
		return &apRefusal{"not_established", "payload_not_json_object"}
	}
	if statement["_type"] != apStatementV1 {
		return &apRefusal{"not_established", "unsupported_statement_type"}
	}
	if statement["predicateType"] != policy.PredicateType {
		return &apRefusal{"not_established", "unsupported_predicate"}
	}
	for _, field := range apFields {
		if !apFieldOK(field, statement) {
			return &apRefusal{"not_established", "field_invalid:" + field}
		}
	}
	return nil
}

func apParse(envelope []byte) (string, []byte, []caSig, bool) {
	if len(envelope) > 4*1024*1024 {
		return "", nil, nil, false
	}
	var doc map[string]any
	if json.Unmarshal(envelope, &doc) != nil || doc == nil {
		return "", nil, nil, false
	}
	payloadType, ok := doc["payloadType"].(string)
	entries, listed := doc["signatures"].([]any)
	if !ok || payloadType == "" || !listed || len(entries) == 0 {
		return "", nil, nil, false
	}
	var sigs []caSig
	for _, raw := range entries {
		entry, isObj := raw.(map[string]any)
		keyid, hasID := entry["keyid"].(string)
		sig, decoded := caB64(entry["sig"])
		if !isObj || !hasID || !decoded {
			return "", nil, nil, false
		}
		sigs = append(sigs, caSig{keyid, sig})
	}
	body, decoded := caB64(doc["payload"])
	if !decoded {
		return "", nil, nil, false
	}
	return payloadType, body, sigs, true
}

func apSignature(payloadType string, body []byte, sigs []caSig, trusted map[string]string) *apRefusal {
	message := caPAE(payloadType, body)
	named := false
	for _, s := range sigs {
		encoded, pinned := trusted[s.keyid]
		if !pinned {
			continue
		}
		named = true
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil && len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, s.sig) {
			return nil
		}
	}
	if named {
		return &apRefusal{"contradicted", "signature_invalid"}
	}
	return &apRefusal{"contradicted", "untrusted_key"}
}

// apText is a non-empty string.
func apText(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func apOptionalText(d map[string]any, key string) bool {
	v, present := d[key]
	return !present || apText(v)
}

func apMatches(re *regexp.Regexp, v any) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

func apDigestSet(v any) bool {
	set, ok := v.(map[string]any)
	if !ok || len(set) == 0 {
		return false
	}
	for algorithm, value := range set {
		digest, isString := value.(string)
		if !isString || digest == "" {
			return false
		}
		lengths, known := apDigestLength[algorithm]
		if !known {
			continue
		}
		fits := false
		for _, n := range lengths {
			fits = fits || len(digest) == n
		}
		if !fits || !apHex.MatchString(digest) {
			return false
		}
	}
	return true
}

func apDescriptor(v any) bool {
	d, ok := v.(map[string]any)
	return ok && apMatches(apURI, d["uri"]) && apDigestSet(d["digest"])
}

// apObjects returns the list's entries when it is a list of objects.
func apObjects(v any, nonempty bool) ([]map[string]any, bool) {
	list, ok := v.([]any)
	if !ok || (nonempty && len(list) == 0) {
		return nil, false
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		obj, isObj := item.(map[string]any)
		if !isObj {
			return nil, false
		}
		out = append(out, obj)
	}
	return out, true
}

func apStrings(v any) bool {
	list, ok := v.([]any)
	for _, item := range list {
		if _, isString := item.(string); !isString {
			return false
		}
	}
	return ok
}

func apOptional(d map[string]any, key string, ok func(any) bool) bool {
	v, present := d[key]
	return !present || ok(v)
}

func apEveryProvider(d map[string]any, ok func(map[string]any) bool) bool {
	providers, _ := apObjects(d["providers"], false)
	for _, p := range providers {
		if !ok(p) {
			return false
		}
	}
	return true
}

func apHarness(p map[string]any) bool {
	h, ok := p["harness"].(map[string]any)
	return ok && apText(h["name"]) && apText(h["version"])
}

func apAgent(p map[string]any) bool {
	v, present := p["agent"]
	if !present {
		return true
	}
	a, ok := v.(map[string]any)
	return ok && apOptionalText(a, "id") && apOptionalText(a, "name") && apOptionalText(a, "version")
}

func apModels(p map[string]any) bool {
	v, present := p["languageModels"]
	if !present {
		return true
	}
	models, ok := apObjects(v, false)
	for _, m := range models {
		if !apOptionalText(m, "inferenceProvider") || !apOptionalText(m, "resolved") {
			return false
		}
	}
	return ok
}

func apTools(v any) bool {
	tools, ok := apObjects(v, false)
	for _, t := range tools {
		if !apText(t["name"]) || !apOptionalText(t, "version") {
			return false
		}
	}
	return ok
}

func apArtifact(a map[string]any) bool {
	uri, hasURI := a["uri"]
	data, hasData := a["data"]
	if hasURI == hasData {
		return false
	}
	if hasURI && !apMatches(apURI, uri) {
		return false
	}
	if _, isString := data.(string); hasData && !isString {
		return false
	}
	if digest, present := a["digest"]; present && !apDigestSet(digest) {
		return false
	}
	return apOptional(a, "tags", apStrings)
}

func apEach(v any, ok func(map[string]any) bool) bool {
	list, isList := apObjects(v, false)
	for _, item := range list {
		if !ok(item) {
			return false
		}
	}
	return isList
}

// apStatementChecks are the Statement's own fields, read before the predicate.
var apStatementChecks = map[string]func(map[string]any) bool{
	"createdAt": func(s map[string]any) bool { return apMatches(apTimestamp, s["createdAt"]) },
	"createdBy": func(s map[string]any) bool { return apText(s["createdBy"]) },
	"subject":   apSubjects,
	"predicate": func(s map[string]any) bool { _, ok := s["predicate"].(map[string]any); return ok },
}

// apPredicateChecks are the predicate's fields, keyed without the "predicate." prefix.
var apPredicateChecks = map[string]func(map[string]any) bool{
	"processType": func(d map[string]any) bool { return apText(d["processType"]) },
	"providers": func(d map[string]any) bool {
		_, ok := apObjects(d["providers"], true)
		return ok
	},
	"providers[].harness":        func(d map[string]any) bool { return apEveryProvider(d, apHarness) },
	"providers[].agent":          func(d map[string]any) bool { return apEveryProvider(d, apAgent) },
	"providers[].languageModels": func(d map[string]any) bool { return apEveryProvider(d, apModels) },
	"result":                     apResult,
	"owner":                      func(d map[string]any) bool { return apText(d["owner"]) },
	"startTimestamp":             func(d map[string]any) bool { return apMatches(apTimestamp, d["startTimestamp"]) },
	"endTimestamp":               func(d map[string]any) bool { return apMatches(apTimestamp, d["endTimestamp"]) },
	"traceId":                    func(d map[string]any) bool { return apOptionalText(d, "traceId") },
	"sessionsLogs":               func(d map[string]any) bool { return apOptional(d, "sessionsLogs", apDescriptors) },
	"tools":                      func(d map[string]any) bool { return apOptional(d, "tools", apTools) },
	"contextArtifacts":           func(d map[string]any) bool { return apOptional(d, "contextArtifacts", apArtifacts) },
	"custom":                     func(d map[string]any) bool { return apOptional(d, "custom", apIsObject) },
	"intents":                    func(d map[string]any) bool { return apOptional(d, "intents", apStrings) },
	"processSummary":             func(d map[string]any) bool { return apOptional(d, "processSummary", apIsString) },
	"reviewers":                  func(d map[string]any) bool { return apOptional(d, "reviewers", apStrings) },
}

func apSubjects(s map[string]any) bool {
	subjects, ok := apObjects(s["subject"], true)
	for _, subject := range subjects {
		if !apDescriptor(subject) {
			return false
		}
	}
	return ok
}

func apResult(d map[string]any) bool {
	result, ok := d["result"].(string)
	return ok && apResults[result]
}

func apDescriptors(v any) bool {
	return apEach(v, func(e map[string]any) bool { return apDescriptor(e) })
}

func apArtifacts(v any) bool { return apEach(v, apArtifact) }

func apIsObject(v any) bool { _, ok := v.(map[string]any); return ok }

func apIsString(v any) bool { _, ok := v.(string); return ok }

func apFieldOK(field string, statement map[string]any) bool {
	if check, ok := apStatementChecks[field]; ok {
		return check(statement)
	}
	// A predicate that is not an object is refused by the "predicate" rule,
	// which runs first; read as empty here so that rule stays the one that names it.
	d, ok := statement["predicate"].(map[string]any)
	if !ok {
		d = map[string]any{}
	}
	check, known := apPredicateChecks[strings.TrimPrefix(field, "predicate.")]
	return known && check(d)
}
