package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func init() { register(agentRegistrationClassification{}) }

// agentRegistrationClassification judges corpora/vectors-agent-registration-classification/.
// Each member is a registration record and the relying party's context, and the
// verdict is whether the record earns registration credit and the first reason
// it does not. The reader re-derives both from the two files with the checks
// contract.py applies, in the same order, and compares them with the manifest:
//
//  1. strict decoding (a member twice, a non-finite constant, invalid UTF-8);
//  2. every member the rule branches on is present with its type;
//  3. event type, intake state, consent, consent scope, child agent, and a swarm
//     or an agent that is already registered;
//  4. the issued challenge: binding to the record, its window, replay, and a
//     consumption state that must be an explicit false;
//  5. the agent's key matches the challenge and its Ed25519 proof verifies;
//  6. the registry receipt binds the record's digest and verifies under the
//     relying party's trusted registry key.
//
// The corpus digest is the SHA-256 of every case's record.json and context.json
// concatenated in sorted path order (digest.py).
type agentRegistrationClassification struct{}

const (
	arcSuite             = "synthetic-agent-registration-classification/v1"
	arcRegistrationLabel = "BUDDYLISTS_TEST_REGISTRATION_V1\x00"
	arcReceiptLabel      = "BUDDYLISTS_TEST_RECEIPT_V1\x00"
	arcCredit            = "registration_evidence_sufficient_for_fixture"
	arcMalformed         = "malformed_or_missing_evidence"
	arcNotStrict         = "evidence_bytes_not_strict_json"
)

func (agentRegistrationClassification) Suite() string { return arcSuite }

type arcExpected struct {
	Reason             string `json:"reason"`
	RegistrationCredit bool   `json:"registration_credit"`
}

type arcVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected arcExpected       `json:"expected"`
}

// arcObject is a decoded JSON object.
type arcObject = map[string]any

func arcIsID(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func arcIsString(v any) bool { _, ok := v.(string); return ok }

func arcIDList(v any) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		if !arcIsID(item) {
			return false
		}
	}
	return true
}

func arcTyped(v any, spec map[string]func(any) bool) bool {
	obj, ok := v.(arcObject)
	if !ok {
		return false
	}
	for key, holds := range spec {
		value, present := obj[key]
		if !present || !holds(value) {
			return false
		}
	}
	return true
}

var arcCoreTypes = map[string]func(any) bool{
	"event_type":      arcIsString,
	"intake_state":    arcIsString,
	"agent_id":        arcIsID,
	"swarm_id":        arcIsID,
	"parent_agent_id": func(v any) bool { return v == nil || arcIsID(v) },
	"consent":         func(v any) bool { _, ok := v.(bool); return ok },
	"consent_scope":   arcIsString,
	"challenge_nonce": arcIsID,
}

var arcChallengeTypes = map[string]func(any) bool{
	"agent_id":         arcIsID,
	"swarm_id":         arcIsID,
	"challenge_nonce":  arcIsID,
	"agent_public_key": arcIsString,
	"issued_at":        arcIsString,
	"expires_at":       arcIsString,
}

func arcRequiredTypesHold(record, context any) bool {
	rec, recOK := record.(arcObject)
	ctx, ctxOK := context.(arcObject)
	if !recOK || !ctxOK {
		return false
	}
	receipt, _ := rec["registry_receipt"].(arcObject)
	_, bodyOK := receipt["body"].(arcObject)
	return arcTyped(rec["core"], arcCoreTypes) &&
		arcIsString(rec["agent_public_key"]) &&
		arcIsString(rec["agent_signature"]) &&
		receipt != nil && bodyOK && arcIsString(receipt["signature"]) &&
		arcIsString(ctx["evaluation_time"]) &&
		arcIDList(ctx["prior_registered_swarms"]) &&
		arcIDList(ctx["prior_registered_agents"]) &&
		arcIsString(ctx["trusted_registry_public_key"]) &&
		arcTyped(ctx["issued_challenge"], arcChallengeTypes)
}

// arcParseTime reads an instant the way contract.parse_time does for the forms
// the corpus uses: an RFC 3339 date and time with an offset or Z. A value
// without an offset is refused, as contract.py refuses it.
func arcParseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q is not an instant with an offset", value)
	}
	return parsed.UTC(), nil
}

// arcSigned is contract.signed: strict standard base64, a 32-byte key, and an
// Ed25519 signature over the message.
func arcSigned(message []byte, signatureB64, publicB64 string) bool {
	public, perr := arcStrictBase64(publicB64)
	signature, serr := arcStrictBase64(signatureB64)
	if perr != nil || serr != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(public), message, signature)
}

// arcStrictBase64 is base64.b64decode(validate=True): the standard alphabet,
// correct padding, and no other character. Go's decoder skips newlines, so they
// are refused first.
func arcStrictBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("a line break inside base64")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

func arcCanonical(value any) ([]byte, error) { return pythonCompactJSON(value) }

func arcDigest(value any) (string, error) {
	raw, err := arcCanonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// arcDecode is contract.decode: UTF-8, no repeated member, no non-finite number.
func arcDecode(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("not UTF-8")
	}
	return decodeJSONNumbers(data)
}

// arcCoreRefusal is the first reason the registration event itself earns no
// credit, or "".
func arcCoreRefusal(core, context arcObject) string {
	checks := []struct {
		refused bool
		reason  string
	}{
		{core["event_type"] != "registration", "not_registration_event"},
		{core["intake_state"] != "durably_committed", "not_durably_committed"},
		{core["consent"] != true, "consent_not_affirmative"},
		{core["consent_scope"] != "registration", "consent_scope_mismatch"},
		{core["parent_agent_id"] != nil, "ephemeral_or_child_agent"},
		{arcContains(context["prior_registered_swarms"], core["swarm_id"]), "swarm_already_registered"},
		{arcContains(context["prior_registered_agents"], core["agent_id"]), "agent_already_registered"},
	}
	for _, c := range checks {
		if c.refused {
			return c.reason
		}
	}
	return ""
}

func arcContains(list, want any) bool {
	items, _ := list.([]any)
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// arcChallengeRefusal is the first reason the issued challenge does not back
// the event, or "". An error is a timestamp contract.py cannot read.
func arcChallengeRefusal(core, context arcObject) (string, error) {
	challenge := context["issued_challenge"].(arcObject)
	for _, key := range []string{"agent_id", "swarm_id", "challenge_nonce"} {
		if challenge[key] != core[key] {
			return "challenge_binding_mismatch", nil
		}
	}
	now, err := arcParseTime(context["evaluation_time"].(string))
	if err != nil {
		return "", err
	}
	issued, err := arcParseTime(challenge["issued_at"].(string))
	if err != nil {
		return "", err
	}
	inWindow := !issued.After(now)
	if inWindow {
		expires, err := arcParseTime(challenge["expires_at"].(string))
		if err != nil {
			return "", err
		}
		inWindow = now.Before(expires)
	}
	if !inWindow {
		return "challenge_expired_or_not_yet_issued", nil
	}
	if challenge["consumed"] == true {
		return "challenge_replayed", nil
	}
	// Unknown and missing consumption states are NOT evidence of non-use.
	if challenge["consumed"] != false {
		return "challenge_state_unverified", nil
	}
	return "", nil
}

// arcProofRefusal is the first reason the agent proof or the durable receipt
// fails, or "". An error is a value that cannot be canonicalized.
func arcProofRefusal(record, context arcObject) (string, error) {
	core := record["core"].(arcObject)
	agentPublic := record["agent_public_key"].(string)
	if agentPublic != context["issued_challenge"].(arcObject)["agent_public_key"] {
		return "challenge_key_mismatch", nil
	}
	coreBytes, err := arcCanonical(core)
	if err != nil {
		return "", err
	}
	if !arcSigned(append([]byte(arcRegistrationLabel), coreBytes...),
		record["agent_signature"].(string), agentPublic) {
		return "agent_proof_invalid", nil
	}
	receipt := record["registry_receipt"].(arcObject)
	body := receipt["body"].(arcObject)
	coreDigest, err := arcDigest(core)
	if err != nil {
		return "", err
	}
	if body["record_digest"] != coreDigest || body["agent_id"] != core["agent_id"] ||
		body["swarm_id"] != core["swarm_id"] || body["status"] != "committed" {
		return "durable_receipt_binding_mismatch", nil
	}
	bodyBytes, err := arcCanonical(body)
	if err != nil {
		return "", err
	}
	if !arcSigned(append([]byte(arcReceiptLabel), bodyBytes...),
		receipt["signature"].(string), context["trusted_registry_public_key"].(string)) {
		return "durable_receipt_signature_invalid", nil
	}
	return "", nil
}

// arcClassify is contract.classify over decoded values. A timestamp the rule
// cannot read is the rule's own malformed-evidence refusal; a value this
// package's encoder will not spell (a float) is an error, never a guess.
func arcClassify(record, context any) (arcExpected, error) {
	refuse := func(reason string) (arcExpected, error) { return arcExpected{Reason: reason}, nil }
	if !arcRequiredTypesHold(record, context) {
		return refuse(arcMalformed)
	}
	rec, ctx := record.(arcObject), context.(arcObject)
	core := rec["core"].(arcObject)
	if reason := arcCoreRefusal(core, ctx); reason != "" {
		return refuse(reason)
	}
	reason, err := arcChallengeRefusal(core, ctx)
	if err != nil {
		return refuse(arcMalformed)
	}
	if reason != "" {
		return refuse(reason)
	}
	reason, err = arcProofRefusal(rec, ctx)
	if err != nil {
		return arcExpected{}, err
	}
	if reason != "" {
		return refuse(reason)
	}
	return arcExpected{Reason: arcCredit, RegistrationCredit: true}, nil
}

// arcClassifyBytes is contract.classify_bytes: both files are decoded strictly
// first, and a refusal there is its own reason.
func arcClassifyBytes(recordBytes, contextBytes []byte) (arcExpected, error) {
	record, rerr := arcDecode(recordBytes)
	context, cerr := arcDecode(contextBytes)
	if rerr != nil || cerr != nil {
		return arcExpected{Reason: arcNotStrict}, nil
	}
	return arcClassify(record, context)
}

func arcJudgeMember(caseDir string, v arcVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	record, rerr := readIn(caseDir, "record.json")
	context, cerr := readIn(caseDir, "context.json")
	if rerr != nil || cerr != nil {
		return append(findings, "record.json or context.json cannot be read")
	}
	got, err := arcClassifyBytes(record, context)
	if err != nil {
		return append(findings, fmt.Sprintf("the case cannot be classified: %v", err))
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived credit=%t reason=%s, the manifest declares credit=%t reason=%s",
			got.RegistrationCredit, got.Reason, v.Expected.RegistrationCredit, v.Expected.Reason))
	}
	return findings
}

// arcCorpusDigest is digest.corpus_digest: every case's two files, read back and
// concatenated in sorted path order.
func arcCorpusDigest(dir string, vectors []arcVector) (string, error) {
	var paths []string
	for _, v := range vectors {
		for _, name := range []string{"record.json", "context.json"} {
			paths = append(paths, v.Path+"/"+name)
		}
	}
	sort.Strings(paths)
	var joined bytes.Buffer
	for _, rel := range paths {
		body, err := readIn(dir, filepath.FromSlash(rel))
		if err != nil {
			return "", fmt.Errorf("%s cannot be read", rel)
		}
		joined.Write(body)
	}
	return sha(joined.Bytes()), nil
}

func (agentRegistrationClassification) Judge(dir string, raw []byte) (*Result, error) {
	var manifest struct {
		CorpusDigest string      `json:"corpusDigest"`
		Vectors      []arcVector `json:"vectors"`
	}
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, v := range manifest.Vectors {
		kind := "no_registration_credit"
		if v.Expected.RegistrationCredit {
			kind = "registration_credit"
		}
		member := Member{ID: v.ID, Kind: kind}
		member.Findings = arcJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	got, err := arcCorpusDigest(dir, manifest.Vectors)
	switch {
	case err != nil:
		result.Findings = append(result.Findings, err.Error())
	case got != manifest.CorpusDigest:
		result.Findings = append(result.Findings, fmt.Sprintf(
			"corpusDigest %s does not match the recomputed %s", short(manifest.CorpusDigest), short(got)))
	}
	return result, nil
}
