package corpusreaders

// One OCSF API Activity decision record, read dimension by dimension.
//
// The record is the Praxis Policy Engine ocsf-audit sink's: an OCSF event with
// class_uid 6003 carrying the security_control ruling, the engine's decision
// facts under unmapped."aid.*" and, when chaining is on, attestation_list[0]
// with a SHA-256 fingerprint over the RFC 8785 bytes of the event, a prev_event
// link and a DSSE signature (ECDSA P-256) whose bytes ride at
// unmapped.signature_b64. The rule is the format's own, AID-EMIT-1 record
// integrity; the sink's published samples are the vectors. Every check is its
// own dimension with one status, and nothing merges them into a pass.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

const (
	ocsfVerified     = "verified"
	ocsfFailed       = "failed"
	ocsfNotChecked   = "not_checked"
	ocsfUnavailable  = "unavailable"
	ocsfNotSupported = "not_supported"

	ocsfPayloadType = "application/vnd.ocsf.event+json"
	ocsfClassUID    = 6003
)

// ocsfDim is one dimension of a report: its status and what it says.
type ocsfDim struct {
	status   string
	findings []string
	// notApplicable marks a dimension that has nothing to read, as opposed to
	// one whose reading is unavailable.
	notApplicable bool
}

func ocsfD(status string, findings ...string) ocsfDim {
	return ocsfDim{status: status, findings: findings}
}

// ocsfTally holds the findings of one dimension, worst first: failed over not
// checked over unavailable.
type ocsfTally struct{ failed, unchecked, unavailable []string }

func (t *ocsfTally) fail(format string, args ...any) {
	t.failed = append(t.failed, fmt.Sprintf(format, args...))
}
func (t *ocsfTally) skip(format string, args ...any) {
	t.unchecked = append(t.unchecked, fmt.Sprintf(format, args...))
}
func (t *ocsfTally) gone(format string, args ...any) {
	t.unavailable = append(t.unavailable, fmt.Sprintf(format, args...))
}

func (t *ocsfTally) status() string {
	switch {
	case len(t.failed) > 0:
		return ocsfFailed
	case len(t.unchecked) > 0:
		return ocsfNotChecked
	case len(t.unavailable) > 0:
		return ocsfUnavailable
	}
	return ocsfVerified
}

func (t *ocsfTally) result() ocsfDim {
	all := append(append(append([]string{}, t.failed...), t.unchecked...), t.unavailable...)
	return ocsfDim{status: t.status(), findings: all}
}

// --- the relying party's key set -------------------------------------------------------------

type ocsfKey struct {
	kid, authority string
	public         *ecdsa.PublicKey
	point          string
	notBefore      *ocsfInstant
	notAfter       *ocsfInstant
}

func (k ocsfKey) covers(at ocsfInstant) bool {
	if k.notBefore != nil && at.secs.Cmp(k.notBefore.secs) < 0 {
		return false
	}
	return !(k.notAfter != nil && at.secs.Cmp(k.notAfter.secs) > 0)
}

// ocsfTrustPolicy is the relying party's own JWKS: P-256 keys, each bound to
// the authority it belongs to.
type ocsfTrustPolicy struct {
	keys     []ocsfKey
	findings []string
}

var ocsfB64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ocsfReadPolicy reads a trust policy. A policy that lists no keys, a key that
// is not a P-256 key bound to an authority, or one key listed twice (by id or by
// public key) is a finding, and a policy with a finding is not used.
func ocsfReadPolicy(doc any) *ocsfTrustPolicy {
	p := &ocsfTrustPolicy{}
	entries, _ := ocsfGet(doc, "keys").([]any)
	if len(entries) == 0 {
		p.findings = []string{"the trust policy lists no keys"}
		return p
	}
	seenKid := map[string]bool{}
	seenPoint := map[string]string{}
	for i, entry := range entries {
		key, finding := ocsfReadKey(entry, i)
		if finding != "" {
			p.findings = append(p.findings, finding)
			continue
		}
		switch {
		case seenKid[key.kid]:
			p.findings = append(p.findings, fmt.Sprintf("keys[%d]: kid %q is listed twice", i, key.kid))
			continue
		case seenPoint[key.point] != "":
			p.findings = append(p.findings, fmt.Sprintf("keys[%d]: the public key of %q is listed again as %q",
				i, seenPoint[key.point], key.kid))
			continue
		}
		seenKid[key.kid] = true
		seenPoint[key.point] = key.kid
		p.keys = append(p.keys, key)
	}
	return p
}

// ocsfB64URLBytes is a canonical unpadded base64url value, or nil.
func ocsfB64URLBytes(v any) []byte {
	text, ok := v.(string)
	if !ok || !ocsfB64URL.MatchString(text) {
		return nil
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil
	}
	return data
}

func ocsfReadKey(entry any, i int) (ocsfKey, string) {
	where := fmt.Sprintf("keys[%d]", i)
	m, ok := ocsfObj(entry)
	if !ok {
		return ocsfKey{}, where + ": not an object"
	}
	if m["kty"] != "EC" || m["crv"] != "P-256" {
		return ocsfKey{}, where + ": not an EC P-256 key"
	}
	kid, _ := m["kid"].(string)
	authority, _ := m["authority_uid"].(string)
	if kid == "" || authority == "" {
		return ocsfKey{}, where + ": a key needs a kid and the authority_uid it belongs to"
	}
	x, y := ocsfB64URLBytes(m["x"]), ocsfB64URLBytes(m["y"])
	if len(x) != 32 || len(y) != 32 {
		return ocsfKey{}, where + ": x and y must be 32-byte base64url values"
	}
	point := append(append([]byte{4}, x...), y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return ocsfKey{}, where + ": the point is not on P-256"
	}
	key := ocsfKey{kid: kid, authority: authority, point: string(point), public: &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}}
	for _, name := range []string{"not_before", "not_after"} {
		raw, present := m[name]
		if !present {
			continue
		}
		at := ocsfInstantOf(raw)
		if !at.ok() {
			return ocsfKey{}, fmt.Sprintf("%s: %s names no instant (%s)", where, name, at.why)
		}
		if name == "not_before" {
			key.notBefore = &at
		} else {
			key.notAfter = &at
		}
	}
	return key, ""
}

func (p *ocsfTrustPolicy) report() ocsfDim {
	if len(p.findings) > 0 {
		return ocsfD(ocsfFailed, p.findings...)
	}
	return ocsfD(ocsfVerified)
}

// --- one record ------------------------------------------------------------------------------

// ocsfRecord is one line of the stream as read.
type ocsfRecord struct {
	index  int
	line   int
	doc    map[string]any
	dims   map[string]ocsfDim
	unread bool
	wide   []string
	absent []string
}

var ocsfRecordDims = []string{"structural_validity", "decision_consistency", "fingerprint", "signature", "key_binding"}

func (r *ocsfRecord) att() map[string]any {
	list, _ := ocsfGet(r.doc, "attestation_list").([]any)
	if len(list) == 0 {
		return nil
	}
	m, _ := list[0].(map[string]any)
	return m
}

// uid is metadata.uid when it is a string.
func (r *ocsfRecord) uid() (string, bool) {
	s, ok := ocsfGet(r.doc, "metadata", "uid").(string)
	return s, ok
}

func (r *ocsfRecord) fingerprint() (string, bool) {
	s, ok := ocsfGet(r.att(), "fingerprint", "value").(string)
	return s, ok
}

func ocsfSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ocsfTime is the record's time: an RFC 3339 string as emitted, or OCSF's
// millisecond integer.
func ocsfTime(v any) ocsfInstant {
	if ocsfIsInt(v) {
		return ocsfInstant{text: ocsfInt(v).String(), secs: new(big.Rat).SetFrac(ocsfInt(v), big.NewInt(1000))}
	}
	return ocsfInstantOf(v)
}

func ocsfFingerprintShape(fp any, where string, t *ocsfTally) {
	m, ok := ocsfObj(fp)
	if !ok {
		t.fail("%s is not an object", where)
		return
	}
	for _, want := range []struct {
		name string
		n    int64
	}{{"algorithm_id", 3}, {"encoding_id", 1}, {"serialization_id", 2}} {
		if !pyEqualInt(m[want.name], want.n) {
			t.fail("%s.%s is %v, not %d (SHA-256, Hex, JCS)", where, want.name, m[want.name], want.n)
		}
	}
	if value, ok := m["value"].(string); !ok || matchDollar(ocsfHex64, value) == nil {
		t.fail("%s.value is not 64 lowercase hex digits", where)
	}
}

func ocsfStructural(doc map[string]any) ocsfDim {
	t := &ocsfTally{}
	if !pyEqualInt(doc["class_uid"], ocsfClassUID) {
		t.fail("class_uid is %v, not %d (API Activity)", doc["class_uid"], ocsfClassUID)
	}
	activity := doc["activity_id"]
	if !ocsfIsInt(activity) {
		t.fail("activity_id is not an integer")
	} else if want := new(big.Int).Add(big.NewInt(ocsfClassUID*100), ocsfInt(activity)); !pyEqual(doc["type_uid"], ocsfNum{isInt: true, i: want}) {
		t.fail("type_uid is %v, not class_uid * 100 + activity_id (%s)", doc["type_uid"], want)
	}
	if !ocsfTime(doc["time"]).ok() {
		t.fail("time names no instant")
	}
	unmapped, isMap := doc["unmapped"].(map[string]any)
	if doc["unmapped"] != nil && !isMap {
		t.fail("unmapped is not an object")
	}
	if list, present := doc["attestation_list"]; present {
		items, isList := list.([]any)
		var first map[string]any
		if isList && len(items) > 0 {
			first, _ = items[0].(map[string]any)
		}
		if first == nil {
			t.fail("attestation_list is not a list whose first entry is an object")
		} else {
			ocsfAttestationShape(doc, first, unmapped, t)
			if len(items) > 1 {
				t.skip("attestation_list carries %d entries after the first; they are hashed but not read", len(items)-1)
			}
		}
	} else if len(unmapped) > 0 {
		_, sig := unmapped["signature_b64"]
		_, kid := unmapped["signature_key_id"]
		if sig || kid {
			t.fail("a signature rides on a record with no attestation to bind it")
		}
	}
	if stream := unmapped["aid.stream"]; stream != nil {
		ocsfStreamShape(stream, t)
	}
	return t.result()
}

func ocsfStreamShape(stream any, t *ocsfTally) {
	m, ok := ocsfObj(stream)
	if !ok {
		t.fail("unmapped.\"aid.stream\" is not an object")
		return
	}
	for _, name := range []string{"epoch", "stream_seq", "emission_seq"} {
		if !ocsfIsInt(m[name]) || ocsfInt(m[name]).Sign() < 0 {
			t.fail("aid.stream.%s is not a non-negative integer", name)
		}
	}
	if id, ok := m["stream_id"].(string); !ok || id == "" {
		t.fail("aid.stream.stream_id is not a string")
	}
}

func ocsfAttestationShape(doc, att, unmapped map[string]any, t *ocsfTally) {
	for _, name := range []string{"uid", "chain_uid"} {
		if s, ok := att[name].(string); !ok || s == "" {
			t.fail("attestation_list[0].%s is not a string", name)
		}
	}
	if _, ok := ocsfGet(doc, "metadata", "uid").(string); !ok {
		t.fail("metadata.uid, the uid the next record's prev_event names, is not a string")
	}
	ocsfFingerprintShape(att["fingerprint"], "attestation_list[0].fingerprint", t)
	if v, present := att["authority_uid"]; present {
		if _, ok := v.(string); !ok {
			t.fail("attestation_list[0].authority_uid is not a string")
		}
	}
	if prev := att["prev_event"]; prev != nil {
		pm, isMap := prev.(map[string]any)
		_, uidOK := pm["uid"].(string)
		if !isMap || !uidOK || !ocsfIsInt(pm["type_uid"]) {
			t.fail("attestation_list[0].prev_event needs uid and type_uid")
		} else {
			ocsfFingerprintShape(pm["fingerprint"], "attestation_list[0].prev_event.fingerprint", t)
		}
	}
	_, signed := unmapped["signature_b64"]
	if sigs := att["signatures"]; sigs != nil {
		list, isList := sigs.([]any)
		allObjects := isList && len(list) > 0
		for _, s := range list {
			if _, ok := s.(map[string]any); !ok {
				allObjects = false
			}
		}
		if !allObjects {
			t.fail("attestation_list[0].signatures is not a list of objects")
		} else {
			for _, s := range list {
				m := s.(map[string]any)
				if !pyEqualInt(m["algorithm_id"], 3) || !pyEqualInt(m["serialization_id"], 5) {
					t.fail("attestation_list[0].signatures names an algorithm other than ECDSA over DSSE")
					break
				}
			}
		}
		if !signed {
			t.fail("attestation_list[0].signatures describes a signature the record does not carry")
		}
	} else if signed {
		t.fail("unmapped.signature_b64 carries a signature its attestation does not describe")
	}
	if v, present := unmapped["signature_key_id"]; present {
		if _, ok := v.(string); !ok {
			t.fail("unmapped.signature_key_id is not a string")
		}
	}
}

// ocsfRulings are the four rulings the format writes: action_id, action,
// disposition_id, disposition.
var ocsfRulings = []struct {
	actionID      int64
	action        string
	dispositionID int64
	disposition   string
	name          string
}{
	{1, "Allowed", 1, "Allowed", "allow"},
	{4, "Modified", 1, "Allowed", "allow-modified"},
	{2, "Denied", 2, "Blocked", "deny"},
	{3, "Observed", 17, "Logged", "observed"},
}

var ocsfStepActions = map[string]bool{"allowed": true, "denied": true, "deny_ignored": true,
	"modified_payload": true, "modified_extensions": true, "aborted": true, "error": true}

func ocsfRuling(doc map[string]any) string {
	for _, r := range ocsfRulings {
		action, _ := doc["action"].(string)
		disposition, _ := doc["disposition"].(string)
		if pyEqualInt(doc["action_id"], r.actionID) && action == r.action &&
			pyEqualInt(doc["disposition_id"], r.dispositionID) && disposition == r.disposition {
			return r.name
		}
	}
	return ""
}

// ocsfConsistency reads the ruling every way the record states it: ids,
// captions, verdict, steps and status.
func ocsfConsistency(doc map[string]any) ocsfDim {
	t := &ocsfTally{}
	ruling := ocsfRuling(doc)
	if ruling == "" {
		t.fail("action and disposition [%v %v %v %v] are not one of the format's four rulings",
			doc["action_id"], doc["action"], doc["disposition_id"], doc["disposition"])
	}
	decision := ocsfGet(doc, "unmapped", "aid.decision")
	if decision == nil {
		if ruling != "" && ruling != "observed" {
			t.skip("no aid.decision: the ruling is stated only by the base-event fields")
		}
		return t.result()
	}
	dm, _ := decision.(map[string]any)
	steps, isList := dm["steps"].([]any)
	if dm == nil || !isList {
		t.fail("aid.decision has no list of steps")
		return t.result()
	}
	actions := make([]string, len(steps))
	for i, step := range steps {
		action, _ := ocsfGet(step, "action").(string)
		actions[i] = action
		if !ocsfStepActions[action] {
			t.fail("aid.decision.steps[%d].action %v is not in the format's vocabulary", i, ocsfGet(step, "action"))
		}
	}
	has := func(name string) bool {
		for _, a := range actions {
			if a == name {
				return true
			}
		}
		return false
	}
	verdict := dm["verdict"]
	deny, _ := ocsfGet(verdict, "deny").(map[string]any)
	modified := has("modified_payload") || has("modified_extensions")
	switch {
	case deny != nil:
		if ruling != "deny" {
			t.fail("aid.decision.verdict denies, and the base event records %s", ruling)
		}
		if !pyEqual(doc["status_code"], deny["code"]) {
			t.fail("status_code %v is not the verdict's code %v", doc["status_code"], deny["code"])
		}
		if !pyEqual(doc["status_detail"], deny["reason"]) {
			t.fail("status_detail is not the verdict's reason")
		}
	case verdict == "allow":
		want := "allow"
		if modified {
			want = "allow-modified"
		}
		if ruling != want {
			t.fail("aid.decision.verdict allows and the base event records %s", ruling)
		}
	case verdict == "pending":
		if ruling != "observed" {
			t.fail("aid.decision.verdict is pending and the base event records %s", ruling)
		}
	default:
		t.fail("aid.decision.verdict %v is not allow, a deny object or pending", verdict)
	}
	var flagged any = false
	if v, present := dm["deny_ignored"]; present {
		flagged = v
	}
	if truth, ok := pyTruth(flagged); !ok {
		t.fail("aid.decision.deny_ignored is not a boolean")
	} else if truth != has("deny_ignored") {
		t.fail("aid.decision.deny_ignored is %t and the steps say otherwise", truth)
	}
	return t.result()
}

// ocsfSigningInput is the published verifier rule, steps 1 to 3: the bytes the
// fingerprint and the signature cover. The record minus attestation_list[0]'s
// fingerprint and signatures and unmapped's signature_b64 and signature_key_id,
// with an unmapped left empty removed.
func ocsfSigningInput(doc map[string]any) []byte {
	event := make(map[string]any, len(doc))
	for k, v := range doc {
		event[k] = v
	}
	items := append([]any{}, doc["attestation_list"].([]any)...)
	att := make(map[string]any)
	for k, v := range items[0].(map[string]any) {
		if k != "fingerprint" && k != "signatures" {
			att[k] = v
		}
	}
	items[0] = att
	event["attestation_list"] = items
	if unmapped, ok := doc["unmapped"].(map[string]any); ok {
		kept := make(map[string]any)
		for k, v := range unmapped {
			if k != "signature_b64" && k != "signature_key_id" {
				kept[k] = v
			}
		}
		if len(kept) == 0 {
			delete(event, "unmapped")
		} else {
			event["unmapped"] = kept
		}
	}
	return []byte(ocsfCanon(event))
}

// ocsfPAE is the DSSE v1 pre-authentication encoding of payload under the
// format's payload type.
func ocsfPAE(payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(ocsfPayloadType), ocsfPayloadType, len(payload), payload))
}

func ocsfFingerprint(r *ocsfRecord) (ocsfDim, []byte) {
	if r.att() == nil {
		return ocsfD(ocsfUnavailable, "the record is not chained: it carries no attestation and no fingerprint"), nil
	}
	data := ocsfSigningInput(r.doc)
	got := ocsfSHA(data)
	if stated, _ := r.fingerprint(); got != stated {
		return ocsfD(ocsfFailed, "the bytes the rule covers hash to "+got+", not the stated fingerprint"), data
	}
	return ocsfD(ocsfVerified), data
}

var (
	ocsfB64 = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	// ocsfP256Order is the order of the P-256 group.
	ocsfP256Order, _ = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
)

type ocsfDER struct{ R, S *big.Int }

// ocsfSignatureBytes is a signature that is canonical padded base64 of canonical
// DER with r and s inside the P-256 group, or the reason it is not.
func ocsfSignatureBytes(v any) (raw []byte, r, s *big.Int, why string) {
	text, ok := v.(string)
	if !ok || text == "" || !ocsfB64.MatchString(text) {
		return nil, nil, nil, "unmapped.signature_b64 is not canonical padded base64"
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, nil, nil, "unmapped.signature_b64 is not canonical padded base64"
	}
	var sig ocsfDER
	rest, err := asn1.Unmarshal(raw, &sig)
	if err != nil || len(rest) > 0 || sig.R == nil || sig.S == nil {
		return nil, nil, nil, "the signature is not a DER-encoded ECDSA signature"
	}
	if again, err := asn1.Marshal(sig); err != nil || string(again) != string(raw) {
		return nil, nil, nil, "the signature is not in canonical DER"
	}
	if sig.R.Sign() <= 0 || sig.R.Cmp(ocsfP256Order) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(ocsfP256Order) >= 0 {
		return nil, nil, nil, "the signature's r or s is outside the P-256 group"
	}
	return raw, sig.R, sig.S, ""
}

// ocsfSignature verifies the DSSE signature against every key of the relying
// party's set; the record's key id picks none.
func ocsfSignature(r *ocsfRecord, data []byte, policy *ocsfTrustPolicy) (ocsfDim, *ocsfKey) {
	unmapped, _ := r.doc["unmapped"].(map[string]any)
	sigText, signed := unmapped["signature_b64"]
	switch {
	case !signed:
		return ocsfD(ocsfUnavailable, "unsigned: the fingerprint chain is a checksum anyone with write access to the records recomputes"), nil
	case data == nil:
		return ocsfD(ocsfNotChecked, "the record carries no attestation for the signature to cover"), nil
	case policy == nil:
		return ocsfD(ocsfNotChecked, "no trust policy is configured"), nil
	}
	_, rr, ss, why := ocsfSignatureBytes(sigText)
	if why != "" {
		return ocsfD(ocsfFailed, why), nil
	}
	digest := sha256.Sum256(ocsfPAE(data))
	for i := range policy.keys {
		key := &policy.keys[i]
		if !ecdsa.Verify(key.public, digest[:], rr, ss) {
			continue
		}
		var notes []string
		if ss.Cmp(new(big.Int).Rsh(ocsfP256Order, 1)) > 0 {
			notes = append(notes, "s is in the upper half of the group, so (r, n - s) verifies too: the signature bytes do not identify the record uniquely")
		}
		return ocsfD(ocsfVerified, notes...), key
	}
	return ocsfD(ocsfFailed, "no key in the relying party's trust policy verifies the signature"), nil
}

// ocsfKeyBinding is whether the signed bytes, read against the relying party's
// key set, name the key that signed. The record's key id is removed before
// hashing, so it is a label anyone can change; it is compared with the key that
// verified and never used to choose one.
func ocsfKeyBinding(r *ocsfRecord, sig ocsfDim, key *ocsfKey, policy *ocsfTrustPolicy) ocsfDim {
	if key == nil || policy == nil {
		return ocsfD(ocsfNotChecked, "the signature is "+sig.status)
	}
	t := &ocsfTally{}
	authority, authorityIsString := ocsfGet(r.att(), "authority_uid").(string)
	at := ocsfTime(r.doc["time"])
	kid, hasKid := ocsfGet(r.doc, "unmapped", "signature_key_id").(string)
	switch {
	case !authorityIsString:
		t.fail("the signed bytes name no authority_uid, so nothing signed names the signer")
	case key.authority != authority:
		t.fail("the key that verified, %q, belongs to %q; the signed bytes name %q", key.kid, key.authority, authority)
	}
	if at.ok() && !key.covers(at) {
		t.fail("the key that verified, %q, was not valid at the record's time %s", key.kid, at.text)
	}
	if hasKid && kid != key.kid {
		held := "which the relying party's set does not hold"
		for _, k := range policy.keys {
			if k.kid == kid {
				held = "another key of the relying party's set"
			}
		}
		t.fail("the unsigned key id names %q, %s; %q verified", kid, held, key.kid)
	}
	if len(t.failed) > 0 {
		return t.result()
	}
	var rivals []string
	for _, k := range policy.keys {
		if k.authority == authority && (!at.ok() || k.covers(at)) {
			rivals = append(rivals, k.kid)
		}
	}
	if len(rivals) > 1 {
		return ocsfD(ocsfUnavailable, fmt.Sprintf("%d keys of %q were valid at %s (%s); the signed bytes name the authority, not the key, and the key id rides outside them",
			len(rivals), authority, at.text, strings.Join(rivals, ", ")))
	}
	return ocsfD(ocsfVerified, "the signed authority_uid and the relying party's key set name one key at the record's time")
}

// ocsfCapabilityBlocks are the mapped blocks a sink without the matching read
// capability leaves out, silently.
var ocsfCapabilityBlocks = []struct {
	path       string
	capability string
	unmapped   bool
}{
	{"actor", "read_subject", false}, {"ai_agent", "read_agent", false},
	{"delegation", "read_delegation", false},
	{"cmf.security.labels", "read_labels", true}, {"cmf.workload_identity", "read_workload", true},
}

func ocsfAbsentBlocks(doc map[string]any) []string {
	var out []string
	for _, b := range ocsfCapabilityBlocks {
		var node any
		if b.unmapped {
			node = ocsfGet(doc, "unmapped", b.path)
		} else {
			node = doc[b.path]
		}
		if node == nil {
			name := b.path
			if b.unmapped {
				name = "unmapped." + name
			}
			out = append(out, fmt.Sprintf("%s (%s)", name, b.capability))
		}
	}
	return out
}

// ocsfReadOne reads one line of the stream: the strict parse first, then each
// dimension, with a dimension that cannot be read because an earlier one failed
// reported as not checked.
func ocsfReadOne(index, line int, text string, policy *ocsfTrustPolicy) *ocsfRecord {
	rec := &ocsfRecord{index: index, line: line, dims: map[string]ocsfDim{}}
	notChecked := func(why string) {
		for _, name := range ocsfRecordDims[1:] {
			rec.dims[name] = ocsfD(ocsfNotChecked, why)
		}
	}
	value, err := ocsfParse(text)
	if err != nil {
		rec.unread = true
		rec.dims["structural_validity"] = ocsfD(ocsfFailed, "not read: "+err.Error())
		notChecked("the record is not read")
		return rec
	}
	doc, _ := value.(map[string]any)
	if doc == nil {
		rec.dims["structural_validity"] = ocsfD(ocsfFailed, "a record is a JSON object")
		notChecked("the record does not have the format's shape")
		return rec
	}
	rec.dims["structural_validity"] = ocsfStructural(doc)
	if rec.dims["structural_validity"].status == ocsfFailed {
		notChecked("the record does not have the format's shape")
		return rec
	}
	rec.doc = doc
	rec.dims["decision_consistency"] = ocsfConsistency(doc)
	var data []byte
	rec.dims["fingerprint"], data = ocsfFingerprint(rec)
	sig, key := ocsfSignature(rec, data, policy)
	rec.dims["signature"] = sig
	rec.dims["key_binding"] = ocsfKeyBinding(rec, sig, key, policy)
	rec.absent = ocsfAbsentBlocks(doc)
	rec.wide = ocsfWidePaths(doc, "")
	sort.Strings(rec.wide)
	return rec
}
