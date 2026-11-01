package corpora

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func init() { register(changeAdmission{}) }

// changeAdmission judges vectors-agent-change-admission/. Each member is one
// signed decision about whether a proposed change to an AI agent's harness was
// admitted, under the agent-change-admission predicate, version 1
// (https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md),
// with the consumer policy that judges it and the stored reports it names. The
// checks, their order and the reason codes are the ones the Python reader
// (packaging/agent_evidence_vectors/changeadmission.py) applies:
//
//  1. the envelope parses as DSSE v1, else no verdict (malformed_envelope);
//  2. the payload type is the pinned one (unsupported_payload_type);
//  3. a signature naming a pinned keyid verifies over the DSSE PAE
//     (untrusted_key, signature_invalid);
//  4. the payload is an object (payload_not_json_object) and, in the in-toto
//     carriage, a Statement v1 (unsupported_statement_type);
//  5. the predicate type is the pinned one (unsupported_predicate);
//  6. every required field is well formed (payload_field_invalid:<field>);
//  7. in the in-toto carriage a subject carries the candidate digest
//     (subject_digest_mismatch);
//  8. the gate record agrees with the admitted flag (gate_missing:<gate>,
//     admitted_with_failed_gate:<gate>, rejected_with_all_gates_passed);
//  9. supplied reports are named and match their digests (report_not_named,
//     report_digest_mismatch, report_not_supplied).
type changeAdmission struct{}

func (changeAdmission) Suite() string { return "agent-change-admission/v1" }

type caVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Twin     string            `json:"twin"`
}

type caPolicy struct {
	PayloadType    string            `json:"payload_type"`
	PredicateType  string            `json:"predicate_type"`
	TrustedKeys    map[string]string `json:"trusted_keys"`
	RequiredGates  []string          `json:"required_gates"`
	RequireReports bool              `json:"require_reports"`
}

type caCase struct {
	Carriage string            `json:"carriage"`
	Envelope string            `json:"envelope"`
	Reports  map[string]string `json:"reports"`
	Policy   caPolicy          `json:"policy"`
}

var (
	caHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	caName  = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,200}$`)
)

var caFields = []string{"parent", "candidate", "candidate_digest", "evaluator",
	"evaluator.components.suite_file", "exceptions", "admitted", "checks",
	"corpus_digests", "report_digests"}

const caStatementV1 = "https://in-toto.io/Statement/v1"

func (changeAdmission) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	supported := map[string]bool{}
	var vectors []caVector
	for _, entry := range manifest.Vectors {
		var v caVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		supported[v.ID] = v.Expected.Decision == "supported"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = caJudgeMember(filepath.Join(dir, v.Path), v)
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

func caJudgeMember(caseDir string, v caVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c caCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	envelope, err := readIn(caseDir, c.Envelope)
	if err != nil {
		return append(findings, c.Envelope+" cannot be read")
	}
	supplied := map[string][]byte{}
	for name, file := range c.Reports {
		body, err := readIn(caseDir, file)
		if err != nil {
			return append(findings, file+" cannot be read")
		}
		supplied[name] = body
	}
	if got := caDecide(envelope, c, supplied); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type caRefusal struct{ decision, reason string }

func caB64(value any) ([]byte, bool) {
	s, ok := value.(string)
	if !ok || strings.ContainsAny(s, "\r\n") {
		return nil, false
	}
	out, err := base64.StdEncoding.DecodeString(s)
	return out, err == nil
}

func caPAE(payloadType string, body []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(body), body))
}

func caDecide(envelope []byte, c caCase, supplied map[string][]byte) scDecision {
	d, refusal := caVerify(envelope, c, supplied)
	if refusal != nil {
		return scDecision{Decision: refusal.decision, Reason: refusal.reason}
	}
	if d["admitted"] == true {
		return scDecision{Decision: "supported", Reason: "admitted_receipt_verified"}
	}
	return scDecision{Decision: "supported", Reason: "rejection_receipt_verified"}
}

func caVerify(envelope []byte, c caCase, supplied map[string][]byte) (map[string]any, *caRefusal) {
	payloadType, body, sigs, ok := caParse(envelope)
	if !ok {
		return nil, &caRefusal{"no_verdict", "malformed_envelope"}
	}
	if payloadType != c.Policy.PayloadType {
		return nil, &caRefusal{"not_established", "unsupported_payload_type"}
	}
	if r := caSignature(payloadType, body, sigs, c.Policy.TrustedKeys); r != nil {
		return nil, r
	}
	var payload any
	if json.Unmarshal(body, &payload) != nil {
		payload = nil
	}
	obj, isObj := payload.(map[string]any)
	if !isObj {
		return nil, &caRefusal{"not_established", "payload_not_json_object"}
	}
	d := obj
	if c.Carriage == "dsse-intoto" {
		if obj["_type"] != caStatementV1 {
			return nil, &caRefusal{"not_established", "unsupported_statement_type"}
		}
		if obj["predicateType"] != c.Policy.PredicateType {
			return nil, &caRefusal{"not_established", "unsupported_predicate"}
		}
		pred, isPred := obj["predicate"].(map[string]any)
		if !isPred {
			return nil, &caRefusal{"not_established", "payload_field_invalid:predicate"}
		}
		d = pred
	} else if obj["predicateType"] != c.Policy.PredicateType {
		return nil, &caRefusal{"not_established", "unsupported_predicate"}
	}
	for _, field := range caFields {
		if !caFieldOK(field, d) {
			return nil, &caRefusal{"not_established", "payload_field_invalid:" + field}
		}
	}
	if c.Carriage == "dsse-intoto" && !caSubjectMatches(obj["subject"], d["candidate_digest"]) {
		return nil, &caRefusal{"contradicted", "subject_digest_mismatch"}
	}
	if r := caGates(d, c.Policy.RequiredGates); r != nil {
		return nil, r
	}
	if r := caReports(d, supplied, c.Policy.RequireReports); r != nil {
		return nil, r
	}
	return d, nil
}

type caSig struct {
	keyid string
	sig   []byte
}

func caParse(envelope []byte) (string, []byte, []caSig, bool) {
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

func caSignature(payloadType string, body []byte, sigs []caSig, trusted map[string]string) *caRefusal {
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
		return &caRefusal{"contradicted", "signature_invalid"}
	}
	return &caRefusal{"contradicted", "untrusted_key"}
}

func caString(v any, hex bool) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	return !hex || caHex64.MatchString(s)
}

func caDigestMap(v any, nonempty bool) bool {
	m, ok := v.(map[string]any)
	if !ok || (nonempty && len(m) == 0) {
		return false
	}
	for name, digest := range m {
		if !caName.MatchString(name) || !caString(digest, true) {
			return false
		}
	}
	return true
}

func caFieldOK(field string, d map[string]any) bool {
	value := d[strings.SplitN(field, ".", 2)[0]]
	switch field {
	case "parent", "candidate":
		return caString(value, false)
	case "candidate_digest":
		return caString(value, true)
	case "evaluator":
		e, ok := value.(map[string]any)
		return ok && caString(e["version"], false)
	case "evaluator.components.suite_file":
		e, _ := value.(map[string]any)
		components, _ := e["components"].(map[string]any)
		return caString(components["suite_file"], true)
	case "exceptions":
		list, ok := value.([]any)
		for _, item := range list {
			if _, isString := item.(string); !isString {
				return false
			}
		}
		return ok
	case "admitted":
		_, ok := value.(bool)
		return ok
	case "checks":
		list, ok := value.([]any)
		for _, item := range list {
			check, isObj := item.(map[string]any)
			_, named := check["name"].(string)
			_, passed := check["passed"].(bool)
			if !isObj || !named || !passed {
				return false
			}
		}
		return ok
	}
	return caDigestMap(value, field == "report_digests")
}

func caSubjectMatches(subjects any, candidate any) bool {
	list, _ := subjects.([]any)
	for _, item := range list {
		subject, _ := item.(map[string]any)
		digest, _ := subject["digest"].(map[string]any)
		if digest != nil && digest["sha256"] == candidate {
			return true
		}
	}
	return false
}

func caGates(d map[string]any, required []string) *caRefusal {
	passed := map[string]bool{}
	for _, item := range d["checks"].([]any) {
		check := item.(map[string]any)
		passed[check["name"].(string)] = check["passed"].(bool)
	}
	var failed []string
	for _, gate := range required {
		ok, recorded := passed[gate]
		if !recorded {
			return &caRefusal{"not_established", "gate_missing:" + gate}
		}
		if !ok {
			failed = append(failed, gate)
		}
	}
	admitted := d["admitted"].(bool)
	if admitted && len(failed) > 0 {
		return &caRefusal{"contradicted", "admitted_with_failed_gate:" + failed[0]}
	}
	if !admitted && len(failed) == 0 {
		return &caRefusal{"contradicted", "rejected_with_all_gates_passed"}
	}
	return nil
}

func caReports(d map[string]any, supplied map[string][]byte, require bool) *caRefusal {
	named := d["report_digests"].(map[string]any)
	names := make([]string, 0, len(supplied))
	for name := range supplied {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := named[name]; !ok {
			return &caRefusal{"contradicted", "report_not_named:" + name}
		}
	}
	for _, name := range names {
		if sha(supplied[name]) != named[name] {
			return &caRefusal{"contradicted", "report_digest_mismatch:" + name}
		}
	}
	if !require {
		return nil
	}
	var missing []string
	for name := range named {
		if _, ok := supplied[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return &caRefusal{"not_established", "report_not_supplied:" + missing[0]}
	}
	return nil
}
