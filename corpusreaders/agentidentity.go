package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

func init() { register(agentIdentity{}) }

// agentIdentity judges corpora/vectors-agent-identity-statement/. The checks, their
// order and their codes are the ones the Python reader applies
// (packaging/agent_evidence_vectors/agentidentity.py); the reader names the first that
// fails. A member is the consumer's pins (context.json), the history (history.json, a
// list of DSSE envelopes in any order) and one past decision (decision.json).
type agentIdentity struct{}

const (
	aisSuite         = "agent-identity-statement/v1"
	aisStatementType = "https://in-toto.io/Statement/v1"
	aisPredicateType = "https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement"
	aisPayloadType   = "application/vnd.in-toto+json"
	aisPass          = "key_in_force"
	aisMaxVersion    = 1<<53 - 1
)

// aisChecks is the order the checks apply; the first that fails names the member.
var aisChecks = []string{
	"history_malformed", "statement_signature", "statement_malformed", "statement_type_wrong",
	"predicate_type_wrong", "subject_malformed", "predicate_malformed", "active_without_keys",
	"effective_after_issued", "agent_mismatch", "history_no_genesis", "history_forked",
	"history_previous_missing", "version_not_incremented", "version_gap", "history_time_reversed",
	"revoked_is_final", "history_head_mismatch", "decision_malformed", "key_unknown",
	"decision_signature", "decision_before_history", "agent_suspended", "agent_revoked",
	"key_not_in_force",
}

var aisHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

var errAIS = errors.New("malformed")

type aisEnvelope struct {
	payloadType string
	payload     []byte
	sigs        [][]byte
	keyIDs      []any // the signatures' keyid members, nil when absent
}

func (e aisEnvelope) digest() string {
	sum := sha256.Sum256(e.payload)
	return hex.EncodeToString(sum[:])
}

type aisVersion struct {
	digest    string
	version   int64
	previous  string // "" for none
	issued    time.Time
	effective time.Time
	status    string
	keys      map[string]bool
	agent     [2]string
}

func (agentIdentity) Suite() string { return aisSuite }

func (a agentIdentity) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v crVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		if !filepath.IsLocal(filepath.FromSlash(v.Path)) {
			member.Findings = []string{v.Path + " leaves the corpus directory"}
		} else {
			member.Findings = a.judgeMember(filepath.Join(dir, filepath.FromSlash(v.Path)), v)
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (a agentIdentity) judgeMember(caseDir string, v crVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	if entries, err := os.ReadDir(caseDir); err == nil {
		for _, e := range entries {
			if _, declared := v.Files[e.Name()]; !declared && !e.IsDir() {
				findings = append(findings, e.Name()+" is present and not declared")
			}
		}
	}
	got := aisDecide(caseDir)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

// aisStrict is strict I-JSON without the 2^53 integer refusal: a version past that
// bound is a predicate_malformed member, as in the Python reader, not an unreadable file.
func aisStrict(data []byte) (any, error) {
	if data == nil || !utf8.Valid(data) || a2aLoneSurrogate(data) {
		return nil, errAIS
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := cabDecode(dec)
	if err != nil {
		return nil, errAIS
	}
	if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
		return nil, errAIS
	}
	return value, nil
}

func aisObject(data []byte) (crObj, bool) {
	value, err := aisStrict(data)
	if err != nil {
		return nil, false
	}
	object, ok := value.(crObj)
	return object, ok
}

func aisHTTPS(value any) (string, bool) {
	text, ok := value.(string)
	if !ok || !crHTTPS(text) || strings.ContainsAny(text, " #") {
		return "", false
	}
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			return "", false
		}
	}
	return text, true
}

func aisPrincipal(value any) ([2]string, bool) {
	p, ok := crMembers(value, []string{"issuer", "subject"})
	if !ok {
		return [2]string{}, false
	}
	issuer, okIssuer := aisHTTPS(p["issuer"])
	subject, okSubject := p["subject"].(string)
	return [2]string{issuer, subject}, okIssuer && okSubject && subject != ""
}

func aisPublicKey(value any) ([]byte, bool) {
	text, ok := value.(string)
	if !ok || !aisHex.MatchString(text) {
		return nil, false
	}
	key, err := hex.DecodeString(text)
	return key, err == nil
}

func aisKeyID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// aisEnvelopeOf parses one DSSE envelope with at least one signature.
func aisEnvelopeOf(value any) (aisEnvelope, bool) {
	var none aisEnvelope
	env, ok := crMembers(value, []string{"payloadType", "payload", "signatures"})
	if !ok {
		return none, false
	}
	payloadType, ok := env["payloadType"].(string)
	if !ok {
		return none, false
	}
	items, ok := env["signatures"].([]any)
	if !ok || len(items) == 0 {
		return none, false
	}
	out := aisEnvelope{payloadType: payloadType}
	for _, item := range items {
		entry, ok := crMembers(item, []string{"sig"}, "keyid")
		if !ok {
			return none, false
		}
		var keyID any
		if raw, has := entry["keyid"]; has {
			if _, isText := raw.(string); !isText {
				return none, false
			}
			keyID = raw
		}
		sig, ok := crB64(entry["sig"])
		if !ok {
			return none, false
		}
		out.sigs = append(out.sigs, sig)
		out.keyIDs = append(out.keyIDs, keyID)
	}
	payload, ok := crB64(env["payload"])
	if !ok {
		return none, false
	}
	out.payload = payload
	return out, true
}

func aisHistory(raw []byte, present bool) ([]aisEnvelope, bool) {
	if !present {
		return nil, false
	}
	value, err := aisStrict(raw)
	if err != nil {
		return nil, false
	}
	list, ok := value.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	var out []aisEnvelope
	for _, item := range list {
		env, ok := aisEnvelopeOf(item)
		if !ok || env.payloadType != aisPayloadType {
			return nil, false
		}
		if !seen[env.digest()] {
			seen[env.digest()] = true
			out = append(out, env)
		}
	}
	return out, true
}

func aisSignedBy(keys [][]byte, env aisEnvelope) bool {
	message := caPAE(env.payloadType, env.payload)
	for _, key := range keys {
		for _, sig := range env.sigs {
			if len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, sig) {
				return true
			}
		}
	}
	return false
}

func aisKeySet(value any) (map[string]bool, bool) {
	list, ok := value.([]any)
	if !ok {
		return nil, false
	}
	set := map[string]bool{}
	previous := ""
	for i, item := range list {
		k, ok := crMembers(item, []string{"type", "publicKey"})
		if !ok || k["type"] != "Ed25519" {
			return nil, false
		}
		if _, ok := aisPublicKey(k["publicKey"]); !ok {
			return nil, false
		}
		text := k["publicKey"].(string)
		if i > 0 && text <= previous {
			return nil, false
		}
		previous = text
		set[text] = true
	}
	return set, true
}

// aisVersionNumber is the predicate's version: a plain integer in 1..2^53-1.
func aisVersionNumber(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, ok := new(big.Int).SetString(string(number), 10)
	if !ok || n.Sign() < 1 || n.Cmp(big.NewInt(aisMaxVersion)) > 0 {
		return 0, false
	}
	return n.Int64(), true
}

// aisPredicate parses and checks the predicate; the digest is the statement's.
func aisPredicate(value any, digest string) (aisVersion, bool) {
	var none aisVersion
	p, ok := crMembers(value, []string{"agent", "version", "issuedAt", "effectiveAt", "status", "keys"},
		"previous", "reason")
	if !ok {
		return none, false
	}
	version, ok := aisVersionNumber(p["version"])
	if !ok {
		return none, false
	}
	_, hasPrevious := p["previous"]
	if hasPrevious != (version > 1) {
		return none, false
	}
	previous := ""
	if hasPrevious {
		prev, ok := crMembers(p["previous"], []string{"sha256"})
		if !ok {
			return none, false
		}
		text, ok := prev["sha256"].(string)
		if !ok || !aisHex.MatchString(text) {
			return none, false
		}
		previous = text
	}
	status, _ := p["status"].(string)
	if status != "active" && status != "suspended" && status != "revoked" {
		return none, false
	}
	if reason, has := p["reason"]; has && !crText(reason) {
		return none, false
	}
	agent, ok := aisPrincipal(p["agent"])
	if !ok {
		return none, false
	}
	issued, okIssued := crTime(p["issuedAt"])
	effective, okEffective := crTime(p["effectiveAt"])
	keys, okKeys := aisKeySet(p["keys"])
	if !okIssued || !okEffective || !okKeys {
		return none, false
	}
	return aisVersion{digest: digest, version: version, previous: previous, issued: issued,
		effective: effective, status: status, keys: keys, agent: agent}, true
}

// aisStatement is the first Statement-level failure ("" when none) and the version.
func aisStatement(env aisEnvelope) (string, aisVersion) {
	var none aisVersion
	statement, ok := aisObject(env.payload)
	if !ok {
		return "statement_malformed", none
	}
	if _, ok := crMembers(statement, []string{"_type", "subject", "predicateType", "predicate"}); !ok {
		return "statement_malformed", none
	}
	if statement["_type"] != aisStatementType {
		return "statement_type_wrong", none
	}
	if statement["predicateType"] != aisPredicateType {
		return "predicate_type_wrong", none
	}
	subjects, ok := statement["subject"].([]any)
	if !ok || len(subjects) != 1 {
		return "subject_malformed", none
	}
	subject, ok := crMembers(subjects[0], []string{"name", "digest"})
	if !ok || !crText(subject["name"]) {
		return "subject_malformed", none
	}
	if _, ok := crSHA(subject["digest"]); !ok {
		return "subject_malformed", none
	}
	version, ok := aisPredicate(statement["predicate"], env.digest())
	if !ok {
		return "predicate_malformed", none
	}
	return "", version
}

func aisCheckIndex(code string) int {
	for i, name := range aisChecks {
		if name == code {
			return i
		}
	}
	return -1
}

// aisChain is the first chain failure over verified, well-formed versions, or "".
func aisChain(versions []aisVersion, head string) string {
	genesis := false
	for _, v := range versions {
		genesis = genesis || v.version == 1
	}
	if !genesis {
		return "history_no_genesis"
	}
	children := map[string]int{}
	byDigest := map[string]aisVersion{}
	for _, v := range versions {
		children[v.previous]++
		byDigest[v.digest] = v
	}
	for _, count := range children {
		if count > 1 {
			return "history_forked"
		}
	}
	for _, v := range versions {
		if _, ok := byDigest[v.previous]; v.previous != "" && !ok {
			return "history_previous_missing"
		}
	}
	for _, v := range versions {
		if v.previous == "" {
			continue
		}
		parent := byDigest[v.previous]
		if v.version <= parent.version {
			return "version_not_incremented"
		}
		if v.version > parent.version+1 {
			return "version_gap"
		}
	}
	for _, v := range versions {
		if v.previous == "" {
			continue
		}
		parent := byDigest[v.previous]
		if v.effective.Before(parent.effective) || v.issued.Before(parent.issued) {
			return "history_time_reversed"
		}
	}
	for _, v := range versions {
		if v.previous != "" && byDigest[v.previous].status == "revoked" {
			return "revoked_is_final"
		}
	}
	var tips []string
	for _, v := range versions {
		if _, hasChild := children[v.digest]; !hasChild {
			tips = append(tips, v.digest)
		}
	}
	if len(tips) != 1 || tips[0] != head {
		return "history_head_mismatch"
	}
	return ""
}

// aisInForce is the version in force at the instant: the highest whose effectiveAt is not after it.
func aisInForce(versions []aisVersion, at time.Time) (aisVersion, bool) {
	var best aisVersion
	found := false
	for _, v := range versions {
		if !v.effective.After(at) && (!found || v.version > best.version) {
			best, found = v, true
		}
	}
	return best, found
}

// ---------------------------------------------------------------------------
// Judging one member
// ---------------------------------------------------------------------------

type aisContext struct {
	issuerKeys [][]byte
	agent      [2]string
	head       string
}

func aisReadContext(dir string) (aisContext, bool) {
	var none aisContext
	body, ok := crRead(dir, "context.json")
	if !ok {
		return none, false
	}
	context, ok := crMembers(mustObject(aisObject(body)), []string{"issuerKeys", "agent", "head"})
	if !ok {
		return none, false
	}
	keys, ok := context["issuerKeys"].([]any)
	if !ok || len(keys) == 0 {
		return none, false
	}
	out := aisContext{}
	for _, item := range keys {
		key, ok := aisPublicKey(item)
		if !ok {
			return none, false
		}
		out.issuerKeys = append(out.issuerKeys, key)
	}
	head, ok := crMembers(context["head"], []string{"sha256"})
	if !ok {
		return none, false
	}
	text, ok := head["sha256"].(string)
	if !ok || !aisHex.MatchString(text) {
		return none, false
	}
	out.head = text
	agent, ok := aisPrincipal(context["agent"])
	if !ok {
		return none, false
	}
	out.agent = agent
	return out, true
}

// mustObject turns a failed object parse into a nil value crMembers refuses.
func mustObject(object crObj, ok bool) any {
	if !ok {
		return nil
	}
	return object
}

type aisDecision struct {
	at    time.Time
	keyID string
	env   aisEnvelope
}

func aisReadDecision(dir string) (aisDecision, bool) {
	var none aisDecision
	body, ok := crRead(dir, "decision.json")
	if !ok {
		return none, false
	}
	value, ok := crMembers(mustObject(aisObject(body)), []string{"at", "envelope"})
	if !ok {
		return none, false
	}
	env, ok := aisEnvelopeOf(value["envelope"])
	if !ok || len(env.sigs) != 1 || env.keyIDs[0] == nil {
		return none, false
	}
	keyID := env.keyIDs[0].(string)
	if !aisHex.MatchString(keyID) {
		return none, false
	}
	at, ok := crTime(value["at"])
	if !ok {
		return none, false
	}
	return aisDecision{at: at, keyID: keyID, env: env}, true
}

func aisReject(reason string) scDecision { return scDecision{"reject", reason} }

func aisDecide(dir string) scDecision {
	context, ok := aisReadContext(dir)
	if !ok {
		return aisReject(aisChecks[0])
	}
	body, present := crRead(dir, "history.json")
	envelopes, ok := aisHistory(body, present)
	if !ok {
		return aisReject("history_malformed")
	}
	for _, env := range envelopes {
		if !aisSignedBy(context.issuerKeys, env) {
			return aisReject("statement_signature")
		}
	}
	first := ""
	var versions []aisVersion
	for _, env := range envelopes {
		failure, version := aisStatement(env)
		if failure != "" {
			if first == "" || aisCheckIndex(failure) < aisCheckIndex(first) {
				first = failure
			}
			continue
		}
		versions = append(versions, version)
	}
	if first != "" {
		return aisReject(first)
	}
	for _, v := range versions {
		if v.status == "active" && len(v.keys) == 0 {
			return aisReject("active_without_keys")
		}
	}
	for _, v := range versions {
		if v.effective.After(v.issued) {
			return aisReject("effective_after_issued")
		}
	}
	for _, v := range versions {
		if v.agent != context.agent {
			return aisReject("agent_mismatch")
		}
	}
	if failure := aisChain(versions, context.head); failure != "" {
		return aisReject(failure)
	}
	decision, ok := aisReadDecision(dir)
	if !ok {
		return aisReject("decision_malformed")
	}
	known := map[string][]byte{}
	for _, v := range versions {
		for text := range v.keys {
			key, _ := hex.DecodeString(text)
			known[aisKeyID(key)] = key
		}
	}
	key, ok := known[decision.keyID]
	if !ok {
		return aisReject("key_unknown")
	}
	if !aisSignedBy([][]byte{key}, decision.env) {
		return aisReject("decision_signature")
	}
	current, ok := aisInForce(versions, decision.at)
	if !ok {
		return aisReject("decision_before_history")
	}
	switch current.status {
	case "suspended":
		return aisReject("agent_suspended")
	case "revoked":
		return aisReject("agent_revoked")
	}
	for text := range current.keys {
		raw, _ := hex.DecodeString(text)
		if aisKeyID(raw) == decision.keyID {
			return scDecision{"accept", aisPass}
		}
	}
	return aisReject("key_not_in_force")
}
