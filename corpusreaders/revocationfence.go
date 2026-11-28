package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(revocationFence{}) }

// revocationFence judges corpora/vectors-revocation-fence/. Each member is one case of a
// revocation a target enforces at its own commit: an effect permit, an epoch update, a
// target outcome, a commit under shape a, b or c, gateway propagation, the unknown-outcome
// ledger, or a CAEP or RISC Security Event Token. The reader derives the whole expected
// object of every member from its stored bytes with the checks the Python reader
// (packaging/agent_evidence_vectors/revocationfence.py) applies, in the same order, and
// reports any member whose derived object differs from the one the manifest declares.
type revocationFence struct{}

func (revocationFence) Suite() string { return "revocation-fence/v1" }

const (
	rfTypeURI       = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-fence"
	rfPermitDomain  = rfTypeURI + "#effect-permit"
	rfEpochDomain   = rfTypeURI + "#epoch-update"
	rfOutcomeDomain = rfTypeURI + "#target-outcome"
	rfCAEP          = "https://schemas.openid.net/secevent/caep/event-type/"
	rfRISC          = "https://schemas.openid.net/secevent/risc/event-type/"
)

var (
	rfPermitMembers  = []string{"v", "permit_id", "subject", "epoch", "idempotency_key", "audience", "operation_digest", "not_before_ns", "not_after_ns", "kid"}
	rfEpochMembers   = []string{"v", "subject", "epoch", "audience", "kid"}
	rfOutcomeMembers = []string{"v", "target_id", "permit_id", "subject", "epoch", "idempotency_key", "stage", "outcome", "reason", "shape", "signed_at_ns", "kid"}
	rfIntLiteral     = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	rfNSLiteral      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	errRFNotRecord   = errors.New("not a record")
)

// rfRefused is a refusal with its stable code.
type rfRefused struct{ code string }

func (r rfRefused) Error() string { return r.code }

type rfObj = map[string]any

type rfVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected json.RawMessage   `json:"expected"`
}

func (revocationFence) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v rfVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		var head struct {
			Decision string `json:"decision"`
		}
		_ = json.Unmarshal(v.Expected, &head)
		member := Member{ID: v.ID, Kind: head.Decision}
		member.Findings = rfJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func rfJudgeMember(caseDir string, v rfVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, "case.json cannot be read")
	}
	decoded, err := decodeJSONNumbers(body)
	c, ok := decoded.(rfObj)
	if err != nil || !ok {
		return append(findings, "case.json does not parse")
	}
	derived, err := rfDecide(caseDir, c)
	if err != nil {
		return append(findings, err.Error())
	}
	want, err := decodeJSONNumbers(v.Expected)
	if err != nil {
		return append(findings, "the expected object does not parse")
	}
	got, _ := json.Marshal(derived)
	declared, _ := json.Marshal(want)
	if !bytes.Equal(got, declared) {
		findings = append(findings, fmt.Sprintf("derived %s, the manifest declares %s", got, declared))
	}
	return findings
}

func rfDecide(dir string, c rfObj) (rfObj, error) {
	switch c["kind"] {
	case "permit":
		return rfPermitKind(dir, c), nil
	case "epoch-update":
		return rfUpdateKind(dir, c), nil
	case "outcome":
		return rfOutcomeKind(dir, c), nil
	case "commit":
		return rfCommitKind(dir, c), nil
	case "propagation":
		return rfPropagationKind(c), nil
	case "ledger":
		return rfLedgerKind(c)
	case "feed":
		return rfFeedKind(dir, c), nil
	}
	return nil, fmt.Errorf("unknown kind %v", c["kind"])
}

// --- values -------------------------------------------------------------------------------------

func rfInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !rfIntLiteral.MatchString(string(n)) {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func rfText(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func rfNS(v any) *big.Int {
	s, ok := v.(string)
	if !ok || !rfNSLiteral.MatchString(s) {
		return nil
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func rfStr(v any) string {
	s, _ := v.(string)
	return s
}

func rfI(v any) int64 {
	i, _ := rfInt(v)
	return i
}

func rfBig(v any) *big.Int {
	n, ok := new(big.Int).SetString(rfStr(v), 10)
	if !ok {
		return new(big.Int)
	}
	return n
}

func rfKeyID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func rfPinned(list any) map[string][]byte {
	out := map[string][]byte{}
	items, _ := list.([]any)
	for _, item := range items {
		raw, err := decodeCanonical(base64.StdEncoding, rfStr(item))
		if err == nil {
			out[rfKeyID(raw)] = raw
		}
	}
	return out
}

func rfKeys(c rfObj, role string) map[string][]byte {
	keys, _ := c["keys"].(rfObj)
	return rfPinned(keys[role])
}

func rfSigned(pins map[string][]byte, kid any, domain string, claims rfObj, sig any) bool {
	key, ok := pins[rfStr(kid)]
	if !ok || len(key) != ed25519.PublicKeySize {
		return false
	}
	s, isString := sig.(string)
	if !isString {
		return false
	}
	raw, err := decodeCanonical(base64.StdEncoding, s)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return false
	}
	canonical, err := aee.Canonicalize(encoded)
	if err != nil {
		return false
	}
	msg := append(append([]byte(domain), 0), canonical...)
	return ed25519.Verify(ed25519.PublicKey(key), msg, raw)
}

func rfRecord(dir, name string) (any, error) {
	body, err := readIn(dir, name)
	if err != nil {
		return nil, errRFNotRecord
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return nil, errRFNotRecord
	}
	return value, nil
}

// rfWire returns the claims and signature of a record with exactly the declared members and v 1.
func rfWire(raw any, members []string) (rfObj, any, error) {
	record, ok := raw.(rfObj)
	if !ok || len(record) != 2 || record["claims"] == nil || !rfHas(record, "sig") {
		return nil, nil, rfRefused{"malformed"}
	}
	claims, ok := record["claims"].(rfObj)
	if !ok || len(claims) != len(members) {
		return nil, nil, rfRefused{"malformed"}
	}
	for _, m := range members {
		if !rfHas(claims, m) {
			return nil, nil, rfRefused{"malformed"}
		}
	}
	if v, isInt := rfInt(claims["v"]); !isInt || v != 1 {
		return nil, nil, rfRefused{"malformed"}
	}
	return claims, record["sig"], nil
}

func rfHas(m rfObj, key string) bool {
	_, ok := m[key]
	return ok
}

func rfCode(err error) string {
	var r rfRefused
	if errors.As(err, &r) {
		return r.code
	}
	return "malformed"
}

// --- the three records --------------------------------------------------------------------------

func rfReadPermit(raw any, pins map[string][]byte, audience string, now *big.Int) (rfObj, error) {
	claims, sig, err := rfWire(raw, rfPermitMembers)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"permit_id", "subject", "idempotency_key", "audience", "operation_digest", "kid"} {
		if !rfText(claims[k]) {
			return nil, rfRefused{"malformed"}
		}
	}
	epoch, isInt := rfInt(claims["epoch"])
	begin, end := rfNS(claims["not_before_ns"]), rfNS(claims["not_after_ns"])
	if !isInt || begin == nil || end == nil {
		return nil, rfRefused{"malformed"}
	}
	if epoch < 0 || end.Cmp(begin) <= 0 {
		return nil, rfRefused{"malformed"}
	}
	if _, ok := pins[rfStr(claims["kid"])]; !ok {
		return nil, rfRefused{"unknown_authority"}
	}
	if !rfSigned(pins, claims["kid"], rfPermitDomain, claims, sig) {
		return nil, rfRefused{"bad_signature"}
	}
	if rfStr(claims["audience"]) != audience {
		return nil, rfRefused{"wrong_audience"}
	}
	if now.Cmp(begin) < 0 {
		return nil, rfRefused{"not_yet_valid"}
	}
	if now.Cmp(end) >= 0 {
		return nil, rfRefused{"expired"}
	}
	return claims, nil
}

func rfReadUpdate(raw any, pins map[string][]byte, audience string) (rfObj, error) {
	claims, sig, err := rfWire(raw, rfEpochMembers)
	if err != nil {
		return nil, err
	}
	epoch, isInt := rfInt(claims["epoch"])
	if !rfText(claims["subject"]) || !rfText(claims["audience"]) || !rfText(claims["kid"]) || !isInt {
		return nil, rfRefused{"malformed"}
	}
	if epoch < 0 {
		return nil, rfRefused{"malformed"}
	}
	if _, ok := pins[rfStr(claims["kid"])]; !ok {
		return nil, rfRefused{"unknown_epoch_source"}
	}
	if !rfSigned(pins, claims["kid"], rfEpochDomain, claims, sig) {
		return nil, rfRefused{"bad_signature"}
	}
	if rfStr(claims["audience"]) != audience {
		return nil, rfRefused{"wrong_audience"}
	}
	return claims, nil
}

func rfReadOutcome(raw any, pins map[string][]byte) (rfObj, error) {
	claims, sig, err := rfWire(raw, rfOutcomeMembers)
	if err != nil {
		return nil, err
	}
	stage, outcome := rfStr(claims["stage"]), rfStr(claims["outcome"])
	_, stageIsString := claims["stage"].(string)
	_, outcomeIsString := claims["outcome"].(string)
	knownStage := stage == "accept" || stage == "execute" || stage == "settle" || stage == "final"
	if !stageIsString || !outcomeIsString || !knownStage || (outcome != "committed" && outcome != "refused") {
		return nil, rfRefused{"malformed"}
	}
	kid, kidIsString := claims["kid"].(string)
	if _, ok := pins[kid]; !kidIsString || !ok {
		return nil, rfRefused{"unknown_target_key"}
	}
	if !rfSigned(pins, kid, rfOutcomeDomain, claims, sig) {
		return nil, rfRefused{"bad_signature"}
	}
	for _, k := range []string{"target_id", "permit_id", "subject", "idempotency_key", "shape", "kid"} {
		if !rfText(claims[k]) {
			return nil, rfRefused{"malformed"}
		}
	}
	_, reasonIsString := claims["reason"].(string)
	_, epochIsInt := rfInt(claims["epoch"])
	if !reasonIsString || rfNS(claims["signed_at_ns"]) == nil || !epochIsInt {
		return nil, rfRefused{"malformed"}
	}
	return claims, nil
}

// --- the kinds ----------------------------------------------------------------------------------

func rfPermitKind(dir string, c rfObj) rfObj {
	raw, err := rfRecord(dir, rfStr(c["permit"]))
	if err == nil {
		_, err = rfReadPermit(raw, rfKeys(c, "authority"), rfStr(c["audience"]), rfBig(c["now_ns"]))
	}
	if err != nil {
		return rfObj{"decision": "refused", "reason": rfCode(err)}
	}
	return rfObj{"decision": "valid", "reason": "permit_valid"}
}

func rfUpdateKind(dir string, c rfObj) rfObj {
	pins := rfKeys(c, "epoch_source")
	before := map[string]int64{}
	heldIn, _ := c["held"].(rfObj)
	for s, e := range heldIn {
		before[s] = rfI(e)
	}
	held := map[string]int64{}
	for s, e := range before {
		held[s] = e
	}
	results := []any{}
	rolledBack := false
	names, _ := c["updates"].([]any)
	for _, name := range names {
		raw, err := rfRecord(dir, rfStr(name))
		var claims rfObj
		if err == nil {
			claims, err = rfReadUpdate(raw, pins, rfStr(c["audience"]))
		}
		if err != nil {
			results = append(results, rfObj{"decision": "refused", "reason": rfCode(err)})
			continue
		}
		subject, epoch := rfStr(claims["subject"]), rfI(claims["epoch"])
		current, seen := held[subject]
		switch {
		case !seen:
			held[subject] = epoch
			results = append(results, rfObj{"decision": "installed", "reason": "epoch_installed"})
		case epoch < current:
			rolledBack = true
			results = append(results, rfObj{"decision": "refused", "reason": "epoch_rollback"})
		case epoch == current:
			results = append(results, rfObj{"decision": "unchanged", "reason": "epoch_unchanged"})
		default:
			held[subject] = epoch
			results = append(results, rfObj{"decision": "installed", "reason": "epoch_installed"})
		}
	}
	last, _ := results[len(results)-1].(rfObj)
	answer := rfObj{"decision": last["decision"], "reason": last["reason"], "results": results, "held_after": held}
	raised := false
	for s, e := range before {
		if held[s] > e {
			raised = true
		}
	}
	if raised || rolledBack {
		answer["revocation_status"] = "closed"
	}
	return answer
}

func rfOutcomeKind(dir string, c rfObj) rfObj {
	raw, err := rfRecord(dir, rfStr(c["outcome"]))
	if err == nil {
		_, err = rfReadOutcome(raw, rfKeys(c, "target"))
	}
	if err != nil {
		return rfObj{"decision": "refused", "reason": rfCode(err)}
	}
	return rfObj{"decision": "valid", "reason": "outcome_valid"}
}

func rfSameEffect(prior any, permit rfObj) (found, same bool) {
	p, ok := prior.(rfObj)
	if !ok {
		return prior != nil, false
	}
	same = len(p) == 2 && p["permit_id"] == permit["permit_id"] && p["operation_digest"] == permit["operation_digest"]
	return true, same
}

// rfFence is what the target does: commit_done, replay_done or a refusal code.
func rfFence(shape string, state rfObj, permit rfObj) string {
	effects, _ := state["effects"].(rfObj)
	if found, same := rfSameEffect(effects[rfStr(permit["idempotency_key"])], permit); found {
		if same {
			return "replay_done"
		}
		return "key_reused"
	}
	held := state["epoch"]
	epoch := rfI(permit["epoch"])
	if shape == "a" && held == "unavailable" {
		return "epoch_unavailable"
	}
	if held == nil {
		return "epoch_unknown"
	}
	if shape == "b" && state["revocation_pending"] == true {
		return "revocation_pending"
	}
	if h, isInt := rfInt(held); !isInt || h != epoch {
		return "epoch_mismatch"
	}
	if shape == "b" && state["lease_expired"] == true {
		return "lease_expired"
	}
	if shape == "c" && state["hold"] != "prepared" {
		return "revoked_before_commit"
	}
	return "commit_done"
}

func rfCommitStatus(shape string, state rfObj, permitEpoch int64) string {
	held, isInt := rfInt(state["epoch"])
	if !isInt || held < permitEpoch {
		return "unknown"
	}
	if held > permitEpoch {
		return "closed"
	}
	switch {
	case shape == "b" && state["revocation_pending"] == true:
		return "partial"
	case shape == "c" && state["hold"] == "void_pending":
		return "partial"
	case shape == "c" && state["hold"] == "voided":
		return "closed"
	}
	return "live"
}

func rfSame(a, b any) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}

func rfHonest(dir string, c rfObj, permit rfObj, reason string) bool {
	name, ok := c["outcome"].(string)
	if !ok {
		return false
	}
	raw, err := rfRecord(dir, name)
	if err != nil {
		return false
	}
	claims, err := rfReadOutcome(raw, rfKeys(c, "target"))
	if err != nil {
		return false
	}
	committed := reason == "commit_done" || reason == "replay_done"
	outcome, said := "refused", reason
	if committed {
		outcome, said = "committed", ""
	}
	want := rfObj{
		"target_id": c["audience"], "permit_id": permit["permit_id"], "subject": permit["subject"],
		"epoch": permit["epoch"], "idempotency_key": permit["idempotency_key"], "stage": c["stage"],
		"outcome": outcome, "reason": said, "shape": c["shape"],
	}
	for k, v := range want {
		if !rfSame(claims[k], v) {
			return false
		}
	}
	return true
}

func rfCommitKind(dir string, c rfObj) rfObj {
	raw, err := rfRecord(dir, rfStr(c["permit"]))
	var permit rfObj
	if err == nil {
		permit, err = rfReadPermit(raw, rfKeys(c, "authority"), rfStr(c["audience"]), rfBig(c["now_ns"]))
	}
	if err != nil {
		return rfObj{"decision": "no_outcome", "reason": rfCode(err)}
	}
	shape := rfStr(c["shape"])
	state, _ := c["state"].(rfObj)
	reason := rfFence(shape, state, permit)
	decision := "refused"
	switch reason {
	case "commit_done":
		decision = "committed"
	case "replay_done":
		decision = "replayed"
	}
	if !rfHonest(dir, c, permit, reason) {
		decision = "outcome_mismatch"
	}
	return rfObj{"decision": decision, "reason": reason, "revocation_status": rfCommitStatus(shape, state, rfI(permit["epoch"]))}
}

func rfPropagationKind(c rfObj) rfObj {
	commit, now := rfBig(c["commit_ns"]), rfBig(c["now_ns"])
	leases, _ := c["leases"].(rfObj)
	ends := map[string]*big.Int{}
	for gateway, value := range leases {
		lease, _ := value.(rfObj)
		granted, length, skew := rfBig(lease["granted_ns"]), rfBig(lease["length_ns"]), rfBig(lease["skew_ns"])
		stop := new(big.Int).Add(granted, length)
		if granted.Cmp(commit) <= 0 && commit.Cmp(stop) < 0 {
			ends[gateway] = new(big.Int).Add(stop, skew)
		}
	}
	acked := map[string]bool{}
	acks, _ := c["acks"].([]any)
	for _, ack := range acks {
		if _, live := ends[rfStr(ack)]; !live {
			return rfObj{"decision": "refused", "reason": "malformed", "revocation_status": "unknown"}
		}
		acked[rfStr(ack)] = true
	}
	waiting := []string{}
	worst := new(big.Int)
	for gateway, end := range ends {
		if !acked[gateway] && now.Cmp(end) < 0 {
			waiting = append(waiting, gateway)
			if end.Cmp(worst) > 0 {
				worst = end
			}
		}
	}
	sort.Strings(waiting)
	if len(waiting) > 0 {
		return rfObj{"decision": "pending", "label": "pending", "reason": "propagation_pending",
			"revocation_status": "partial", "waiting_on": waiting, "worst_case_ends_ns": worst.String()}
	}
	return rfObj{"decision": "revoked_for_new_admissions", "label": "revoked for new admissions",
		"reason": "propagation_done", "revocation_status": "closed", "waiting_on": waiting,
		"worst_case_ends_ns": commit.String()}
}

type rfRequest struct {
	subject     string
	reservation int64
	state       string
}

func rfLedgerKind(c rfObj) (rfObj, error) {
	requests := map[string]*rfRequest{}
	revoked := map[string]bool{}
	steps := []any{}
	list, _ := c["steps"].([]any)
	var last rfObj
	for _, item := range list {
		step, _ := item.(rfObj)
		result, err := rfLedgerStep(step, requests, revoked)
		if err != nil {
			return nil, err
		}
		steps = append(steps, result)
		last = result
	}
	if last == nil {
		return nil, errors.New("a ledger case has no steps")
	}
	var reserved int64
	states := map[string]string{}
	for id, r := range requests {
		states[id] = r.state
		if r.state != "committed" && r.state != "not committed" {
			reserved += r.reservation
		}
	}
	subjects := map[string]string{}
	status := "live"
	for s := range revoked {
		subjects[s] = "closed"
		for _, r := range requests {
			if r.subject == s && r.state != "committed" && r.state != "not committed" {
				subjects[s] = "unknown"
			}
		}
	}
	if len(revoked) > 0 {
		status = "closed"
		for _, v := range subjects {
			if v == "unknown" {
				status = "unknown"
			}
		}
	}
	return rfObj{"decision": last["decision"], "reason": last["reason"], "reserved": reserved,
		"revocation_status": status, "states": states, "steps": steps, "subjects": subjects}, nil
}

func rfLedgerStep(step rfObj, requests map[string]*rfRequest, revoked map[string]bool) (rfObj, error) {
	op := rfStr(step["op"])
	switch op {
	case "submit":
		if revoked[rfStr(step["subject"])] {
			return rfObj{"decision": "refused", "reason": "retry_after_revoke", "state": nil}, nil
		}
		requests[rfStr(step["permit_id"])] = &rfRequest{rfStr(step["subject"]), rfI(step["reservation"]), "in flight"}
		return rfObj{"decision": "done", "reason": "submitted", "state": "in flight"}, nil
	case "revoke":
		subject := rfStr(step["subject"])
		revoked[subject] = true
		for _, r := range requests {
			if r.subject == subject && r.state == "unknown" {
				r.state = "unresolved, revoked"
			}
		}
		return rfObj{"decision": "done", "reason": "revoked", "state": nil}, nil
	}
	r, ok := requests[rfStr(step["permit_id"])]
	if !ok {
		return nil, fmt.Errorf("a ledger step names an unknown request %v", step["permit_id"])
	}
	switch op {
	case "mark_unknown":
		r.state = "unknown"
		if revoked[r.subject] {
			r.state = "unresolved, revoked"
		}
		return rfObj{"decision": "done", "reason": "marked_unknown", "state": r.state}, nil
	case "retry":
		readOnly := step["read_only"] == true
		open := r.state == "unknown" || r.state == "unresolved, revoked"
		if revoked[r.subject] && open && !readOnly {
			return rfObj{"decision": "refused", "reason": "retry_after_revoke", "state": r.state}, nil
		}
		reason := "retry_allowed"
		if readOnly {
			reason = "read_only_status"
		}
		return rfObj{"decision": "done", "reason": reason, "state": r.state}, nil
	case "resolve":
		r.state = "not committed"
		if step["committed"] == true {
			r.state = "committed"
		}
		return rfObj{"decision": "done", "reason": "resolved", "state": r.state}, nil
	}
	return nil, fmt.Errorf("unknown ledger op %q", op)
}

// --- the feed -----------------------------------------------------------------------------------

func rfSetRefused(code string) rfObj {
	return rfObj{"decision": "refused", "entry": nil, "not_before_s": nil, "reason": code,
		"revocation_status": "unknown", "session_id": nil}
}

func rfIssSub(v any) (string, string, bool) {
	m, ok := v.(rfObj)
	if !ok || m["format"] != "iss_sub" || !rfText(m["iss"]) || !rfText(m["sub"]) {
		return "", "", false
	}
	return rfStr(m["iss"]), rfStr(m["sub"]), true
}

// rfSubject returns the issuer, subject and session id ("" when none) of a subject identifier.
func rfSubject(v any) (iss, sub string, session any, ok bool) {
	if iss, sub, ok = rfIssSub(v); ok {
		return iss, sub, nil, true
	}
	m, isObj := v.(rfObj)
	if !isObj || m["format"] != "complex" {
		return "", "", nil, false
	}
	if iss, sub, ok = rfIssSub(m["user"]); !ok {
		return "", "", nil, false
	}
	raw, has := m["session"]
	if !has {
		return iss, sub, nil, true
	}
	s, isObj := raw.(rfObj)
	if !isObj || s["format"] != "opaque" || !rfText(s["id"]) {
		return "", "", nil, false
	}
	return iss, sub, s["id"], true
}

func rfNumber(v any) (*big.Float, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	f, _, err := big.ParseFloat(string(n), 10, 256, big.ToNearestEven)
	return f, err == nil
}

func rfFloor(f *big.Float) int64 {
	i, acc := f.Int(nil)
	if f.Sign() < 0 && acc != big.Exact {
		i.Sub(i, big.NewInt(1))
	}
	return i.Int64()
}

func rfDecodeSet(token []byte) (head, body string, header, payload rfObj, sig []byte, ok bool) {
	for _, b := range token {
		if b >= 0x80 {
			return "", "", nil, nil, nil, false
		}
	}
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return "", "", nil, nil, nil, false
	}
	rawHeader, errH := decodeCanonical(base64.RawURLEncoding, parts[0])
	rawPayload, errP := decodeCanonical(base64.RawURLEncoding, parts[1])
	sig, errS := decodeCanonical(base64.RawURLEncoding, parts[2])
	if errH != nil || errP != nil || errS != nil {
		return "", "", nil, nil, nil, false
	}
	h, errH := decodeJSONNumbers(rawHeader)
	p, errP := decodeJSONNumbers(rawPayload)
	if errH != nil || errP != nil {
		return "", "", nil, nil, nil, false
	}
	header, okH := h.(rfObj)
	if !okH || len(header) != 3 || header["alg"] != "EdDSA" || header["typ"] != "secevent+jwt" || !rfText(header["kid"]) {
		return "", "", nil, nil, nil, false
	}
	payload, okP := p.(rfObj)
	if _, issIsString := payload["iss"].(string); !okP || !issIsString {
		return "", "", nil, nil, nil, false
	}
	return parts[0], parts[1], header, payload, sig, true
}

func rfSetShape(payload rfObj) bool {
	_, hasSub := payload["sub"]
	_, hasExp := payload["exp"]
	_, iatIsNumber := rfNumber(payload["iat"])
	events, isObj := payload["events"].(rfObj)
	if hasSub || hasExp || !rfText(payload["jti"]) || !iatIsNumber || !isObj || len(events) != 1 {
		return false
	}
	for _, body := range events {
		_, bodyIsObj := body.(rfObj)
		return bodyIsObj
	}
	return false
}

func rfFeedKind(dir string, c rfObj) rfObj {
	token, err := readIn(dir, rfStr(c["set"]))
	if err != nil {
		return rfSetRefused("set_malformed")
	}
	head, body, header, payload, sig, ok := rfDecodeSet(token)
	if !ok {
		return rfSetRefused("set_malformed")
	}
	iss := rfStr(payload["iss"])
	issuers, _ := c["issuer_keys"].(rfObj)
	pins := rfPinned(issuers[iss])
	key, pinned := pins[rfStr(header["kid"])]
	if !pinned {
		return rfSetRefused("unknown_issuer_key")
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), []byte(head+"."+body), sig) {
		return rfSetRefused("bad_signature")
	}
	if !rfAudience(payload["aud"], rfStr(c["receiver_audience"])) {
		return rfSetRefused("wrong_audience")
	}
	if !rfSetShape(payload) {
		return rfSetRefused("set_shape")
	}
	subIss, sub, session, ok := rfSubject(payload["sub_id"])
	if !ok {
		return rfSetRefused("set_shape")
	}
	if subIss != iss {
		return rfSetRefused("subject_issuer_mismatch")
	}
	digest := sha256.Sum256(token)
	journal, _ := c["journal"].([]any)
	for _, item := range journal {
		entry, _ := item.(rfObj)
		if entry["jti"] == payload["jti"] {
			if entry["sha256"] == hex.EncodeToString(digest[:]) {
				return rfObj{"decision": "delivered", "entry": nil, "not_before_s": nil, "reason": "jti_delivered", "session_id": nil}
			}
			return rfSetRefused("jti_reused")
		}
	}
	events, _ := payload["events"].(rfObj)
	for event, raw := range events {
		eventBody, _ := raw.(rfObj)
		iat, _ := rfNumber(payload["iat"])
		binding, _ := c["session_binding"].(rfObj)
		return rfApplyEvent(event, eventBody, iat, iss, sub, session, binding[iss] == true)
	}
	return rfSetRefused("set_shape")
}

func rfAudience(aud any, receiver string) bool {
	switch v := aud.(type) {
	case string:
		return v == receiver
	case []any:
		for _, a := range v {
			if a == receiver {
				return true
			}
		}
	}
	return false
}

func rfNotBefore(body rfObj, iat *big.Float) int64 {
	if stamp, ok := rfNumber(body["event_timestamp"]); ok && stamp.Cmp(iat) <= 0 {
		return rfFloor(stamp)
	}
	return rfFloor(iat)
}

func rfApplyEvent(event string, body rfObj, iat *big.Float, iss, sub string, session any, bound bool) rfObj {
	short := strings.ReplaceAll(event[strings.LastIndex(event, "/")+1:], "-", "_")
	base := rfObj{"entry": nil, "not_before_s": nil, "session_id": nil, "reason": short}
	with := func(extra rfObj) rfObj {
		out := rfObj{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	rotated := with(rfObj{"decision": "rotated", "not_before_s": rfNotBefore(body, iat), "revocation_status": "partial"})
	switch event {
	case rfCAEP + "session-revoked":
		if bound && session != nil {
			return with(rfObj{"decision": "session_ended", "revocation_status": "partial", "session_id": session})
		}
		return rotated
	case rfCAEP + "credential-change":
		switch body["change_type"] {
		case "create":
			return with(rfObj{"decision": "journalled"})
		case "revoke", "delete", "update":
			return rotated
		}
		return rfSetRefused("set_shape")
	case rfRISC + "account-disabled", rfRISC + "account-purged":
		return with(rfObj{"decision": "revoked", "entry": iss + "#" + sub, "revocation_status": "closed"})
	case rfCAEP + "risk-level-change", rfRISC + "account-enabled":
		return with(rfObj{"decision": "journalled"})
	}
	return rfSetRefused("event_unknown")
}
