package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
)

func init() { register(controlDecision{}) }

// controlDecision judges corpora/vectors-acs-decision-record/, the corpus for the
// control-decision/v1 record: a DSSE envelope over an in-toto Statement saying what
// a policy decision point judged, under which policy, with what verdict.
//
// It is the Go rail over that corpus. The Python rail is the corpus's own record.py,
// and the rules below are that reader restated rather than imported. The consumer
// supplies the producer key and the replayed verdict; neither is read from the
// record. The first failing rule names the code, in this order: signature,
// statement, verdict-shape, policy-digest-present, input-digest, policy-digest,
// verdict.
type controlDecision struct{}

func (controlDecision) Suite() string { return "control-decision-conformance" }

const (
	cdStatementType = "https://in-toto.io/Statement/v1"
	cdPayloadType   = "application/vnd.in-toto+json"
)

var cdRuleCodes = []string{
	"signature-invalid", "statement-malformed", "verdict-malformed",
	"policy-digest-missing", "input-digest-mismatch", "policy-digest-mismatch",
	"verdict-mismatch",
}

type cdManifest struct {
	PredicateType string `json:"predicateType"`
	Keys          struct {
		Producer struct {
			PublicKey string `json:"publicKey"`
		} `json:"producer"`
	} `json:"keys"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []cdVector     `json:"vectors"`
}

type cdVector struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Expected struct {
		Verdict string  `json:"verdict"`
		Code    *string `json:"code"`
	} `json:"expected"`
}

func (controlDecision) Judge(dir string, raw []byte) (*Result, error) {
	var m cdManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	key, err := hex.DecodeString(m.Keys.Producer.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s/MANIFEST.json producer publicKey is not an Ed25519 key", dir)
	}
	result := &Result{}
	counts := map[string]int{}
	produced := map[string]bool{}
	var lines bytes.Buffer
	for _, v := range m.Vectors {
		counts[v.Expected.Verdict]++
		member := Member{ID: v.ID, Kind: v.Expected.Verdict}
		if !filepath.IsLocal(filepath.FromSlash(v.Path)) {
			member.Findings = []string{v.Path + " leaves the corpus directory"}
			result.Members = append(result.Members, member)
			continue
		}
		body, err := readIn(dir, filepath.FromSlash(v.Path))
		if err != nil {
			member.Findings = []string{v.Path + " cannot be read"}
			result.Members = append(result.Members, member)
			continue
		}
		fmt.Fprintf(&lines, "%s %s\n", v.Path, sha(body))
		verdict, code := cdDecide(&m, key, body)
		produced[code] = true
		want := ""
		if v.Expected.Code != nil {
			want = *v.Expected.Code
		}
		if verdict != v.Expected.Verdict || code != want {
			member.Findings = []string{fmt.Sprintf("derived %s/%q, the manifest declares %s/%q",
				verdict, code, v.Expected.Verdict, want)}
		}
		result.Members = append(result.Members, member)
	}
	if fmt.Sprint(counts) != fmt.Sprint(m.Counts) {
		result.Findings = append(result.Findings,
			fmt.Sprintf("counts %v disagree with the members %v", m.Counts, counts))
	}
	if got := sha(lines.Bytes()); got != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the committed bytes")
	}
	for _, code := range cdRuleCodes {
		if !produced[code] {
			result.Findings = append(result.Findings, "rule "+code+" is produced by no member")
		}
	}
	return result, nil
}

// cdDecide returns ("accept", "") or ("reject", the first failing rule's code).
func cdDecide(m *cdManifest, key, body []byte) (string, string) {
	reject := func(code string) (string, string) { return "reject", code }
	member, err := cabStrict(body)
	obj, isObj := member.(map[string]any)
	if err != nil || !isObj {
		return reject("statement-malformed")
	}
	envelope, _ := obj["envelope"].(map[string]any)
	disclosed, _ := obj["disclosed"].(map[string]any)
	payload, ok := cdVerify(envelope, key)
	if !ok {
		return reject("signature-invalid")
	}
	statement, predicate, ok := cdStatement(payload, m.PredicateType)
	if !ok {
		return reject("statement-malformed")
	}
	verdict, ok := predicate["verdict"].(map[string]any)
	if !ok || !cdKnownDecision(verdict["decision"]) {
		return reject("verdict-malformed")
	}
	if _, approval := verdict["approval"]; approval && verdict["decision"] != "deny" {
		return reject("verdict-malformed")
	}
	policy, _ := predicate["policy"].(map[string]any)
	manifestDigest, mOK := policy["manifestDigest"].(string)
	bundleDigest, bOK := policy["bundleDigest"].(string)
	if !mOK || !bOK {
		return reject("policy-digest-missing")
	}
	manifestText, mtOK := disclosed["manifest"].(string)
	contextBytes, cErr := cdCanonical(disclosed["context"], disclosed != nil && disclosed["context"] != nil)
	bundleBytes, bErr := cdCanonical(disclosed["policyBundle"], disclosed != nil && disclosed["policyBundle"] != nil)
	if !mtOK || cErr != nil || bErr != nil {
		return reject("input-digest-mismatch")
	}
	contextDigest := "sha256:" + sha(contextBytes)
	subjectDigest := "None"
	subject, _ := statement["subject"].([]any)
	if first, isMap := subject[0].(map[string]any); isMap {
		if digests, has := first["digest"].(map[string]any); has {
			if text, isText := digests["sha256"].(string); isText {
				subjectDigest = text
			}
		}
	}
	input, _ := predicate["input"].(map[string]any)
	if input["digest"] != contextDigest || "sha256:"+subjectDigest != contextDigest {
		return reject("input-digest-mismatch")
	}
	if "sha256:"+sha([]byte(manifestText)) != manifestDigest || "sha256:"+sha(bundleBytes) != bundleDigest {
		return reject("policy-digest-mismatch")
	}
	got, gErr := cdCanonical(verdict, true)
	want, wErr := cdCanonical(obj["replayedVerdict"], obj["replayedVerdict"] != nil)
	if gErr != nil || wErr != nil || !bytes.Equal(got, want) {
		return reject("verdict-mismatch")
	}
	return "accept", ""
}

func cdKnownDecision(value any) bool {
	return value == "allow" || value == "deny" || value == "transform"
}

func cdCanonical(value any, present bool) ([]byte, error) {
	if !present {
		return nil, fmt.Errorf("absent")
	}
	return rfc8785Bytes(value)
}

// cdVerify checks the DSSE envelope against the consumer's key and returns the payload.
func cdVerify(envelope map[string]any, key []byte) ([]byte, bool) {
	if envelope == nil || envelope["payloadType"] != cdPayloadType {
		return nil, false
	}
	signatures, ok := envelope["signatures"].([]any)
	if !ok || len(signatures) != 1 {
		return nil, false
	}
	entry, _ := signatures[0].(map[string]any)
	payloadText, pOK := envelope["payload"].(string)
	sigText, sOK := entry["sig"].(string)
	if !pOK || !sOK {
		return nil, false
	}
	payload, pErr := base64.StdEncoding.Strict().DecodeString(payloadText)
	sig, sErr := base64.StdEncoding.Strict().DecodeString(sigText)
	if pErr != nil || sErr != nil {
		return nil, false
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(cdPayloadType), cdPayloadType, len(payload), payload)
	if !ed25519.Verify(ed25519.PublicKey(key), []byte(pae), sig) {
		return nil, false
	}
	return payload, true
}

// cdStatement parses the signed payload and checks the Statement and predicate shape.
func cdStatement(payload []byte, predicateType string) (map[string]any, map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var statement map[string]any
	if err := dec.Decode(&statement); err != nil || statement == nil {
		return nil, nil, false
	}
	predicate, pOK := statement["predicate"].(map[string]any)
	subject, sOK := statement["subject"].([]any)
	if statement["_type"] != cdStatementType || statement["predicateType"] != predicateType ||
		!pOK || !sOK || len(subject) != 1 {
		return nil, nil, false
	}
	if _, isMap := subject[0].(map[string]any); !isMap {
		return nil, nil, false
	}
	_, inOK := predicate["input"].(map[string]any)
	_, polOK := predicate["policy"].(map[string]any)
	_, ipOK := predicate["interventionPoint"].(string)
	if !inOK || !polOK || !ipOK {
		return nil, nil, false
	}
	return statement, predicate, true
}
