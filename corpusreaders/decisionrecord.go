package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func init() { register(decisionRecord{}) }

// decisionRecord judges corpora/vectors-decision-record/, the decision-record/v1
// corpus: action-binding attachments (dps-action-binding 0.3.0) that sit beside a
// decision record, each read into separate dimensions and accepted or refused
// under the profile its member names (baseline or strict).
//
// The rules are agent_evidence_verify.decision_record at probityai/probity
// 96b302de87a32d3d4d414e7b62d41a2ece2d668f restated in Go, function by function
// (decisionrecord_read.go, decisionrecord_binding.go, and the signature, trust
// policy and strict checks below), so one binary judges this corpus beside every
// other. A member must reach the verdict, the first refusing dimension and every
// dimension status its manifest entry declares, and a member that names a
// published case must agree with that case's expected values.
type decisionRecord struct{}

func (decisionRecord) Suite() string { return "decision-record/v1" }

// --- issuer signature -----------------------------------------------------------------

// drecMemberSpan is the span of member name's value in the object opening at text[start].
func drecMemberSpan(text []byte, start int, name string) (int, int, bool) {
	i := start + 1
	next := func(at int) (any, int, bool) {
		if at >= len(text) {
			return nil, 0, false
		}
		dec := json.NewDecoder(bytes.NewReader(text[at:]))
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, 0, false
		}
		var value any
		_ = json.Unmarshal(raw, &value)
		return value, at + int(dec.InputOffset()), true
	}
	skip := func(set string) bool {
		for i < len(text) && strings.IndexByte(set, text[i]) >= 0 {
			i++
		}
		return i < len(text)
	}
	for {
		if !skip(" \t\r\n,") {
			return 0, 0, false
		}
		if text[i] == '}' {
			return 0, 0, false
		}
		key, end, ok := next(i)
		if !ok {
			return 0, 0, false
		}
		i = end
		if !skip(" \t\r\n") {
			return 0, 0, false
		}
		i++ // the colon
		if !skip(" \t\r\n") {
			return 0, 0, false
		}
		valueStart := i
		_, end, ok = next(i)
		if !ok {
			return 0, 0, false
		}
		if key == name {
			return valueStart, end, true
		}
		i = end
	}
}

// drecSealedDigest is the SHA-256 of the bytes as issued with every character of
// the signature value replaced by "A".
func drecSealedDigest(data []byte, value string) (string, bool) {
	first := bytes.IndexByte(data, '{')
	if first < 0 {
		return "", false
	}
	outerStart, _, ok := drecMemberSpan(data, first, "issuer_signature")
	if !ok {
		return "", false
	}
	start, end, ok := drecMemberSpan(data, outerStart, "value_b64")
	if !ok {
		return "", false
	}
	var out []byte
	out = append(out, data[:start+1]...)
	out = append(out, bytes.Repeat([]byte("A"), utf8.RuneCountInString(value))...)
	out = append(out, data[end-1:]...)
	return drecSHA(out), true
}

// drecSealSignedBytes is the organisation seal's signed bytes, kind attachment,
// under the shared length-prefix rule.
func drecSealSignedBytes(keyRef, decisionID string, digest []byte, sealedAt string) []byte {
	out := []byte("DPS-SIG\x00")
	for _, field := range [][]byte{[]byte("dps-signatures"), []byte("0.2.0"), []byte("organisation_seal"),
		[]byte(keyRef), []byte("attachment"), []byte(decisionID), digest, []byte(sealedAt)} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field))) // #nosec G115 -- fields are short strings and a digest
		out = append(out, field...)
	}
	return out
}

// drecTrustPolicy is a trust policy configured by the relying party, read once.
type drecTrustPolicy struct {
	keys    map[string]map[string]any // by drecKey(key_ref)
	refused string
}

// drecIterate is Python's iteration of "value or []": a list's items, an object's names, a string's characters.
func drecIterate(v any) []any {
	if !drecTruthy(v) {
		return nil
	}
	switch x := v.(type) {
	case []any:
		return x
	case map[string]any:
		var out []any
		for _, k := range drecKeys(x) {
			out = append(out, k)
		}
		return out
	case string:
		var out []any
		for _, r := range x {
			out = append(out, string(r))
		}
		return out
	}
	return nil
}

func drecReadTrustPolicy(v any) *drecTrustPolicy {
	policy, isObj := v.(map[string]any)
	if !isObj {
		return &drecTrustPolicy{refused: "the trust policy is not an object"}
	}
	if !drecEq(policy["profile"], drecPolicyProfile) || !drecEq(policy["profile_version"], drecPolicyVersion) {
		return &drecTrustPolicy{refused: "the trust policy is not " + drecPolicyProfile + " " + drecPolicyVersion}
	}
	keys := map[string]map[string]any{}
	seenKeys := map[string]string{}
	refs := map[string]bool{}
	for _, item := range drecIterate(policy["keys"]) {
		entry, isEntry := item.(map[string]any)
		if !isEntry {
			return &drecTrustPolicy{refused: "a key entry is not an object"}
		}
		ref := drecKey(entry["key_ref"])
		if refs[ref] {
			return &drecTrustPolicy{refused: fmt.Sprintf("key reference %s names two entries", drecRepr(entry["key_ref"]))}
		}
		refs[ref] = true
		if public, isStr := entry["public_key_hex"].(string); isStr {
			norm := strings.ToLower(public)
			if first, dup := seenKeys[norm]; dup {
				return &drecTrustPolicy{refused: fmt.Sprintf("one public key is listed under %s and %s", first,
					drecRepr(entry["key_ref"]))}
			}
			seenKeys[norm] = drecRepr(entry["key_ref"])
		}
		keys[ref] = entry
	}
	for _, item := range drecIterate(policy["tsas"]) {
		tsa, isTSA := item.(map[string]any)
		if !isTSA {
			continue
		}
		ref := drecKey(tsa["tsa_ref"])
		if refs[ref] {
			return &drecTrustPolicy{refused: fmt.Sprintf("reference %s names two entries", drecRepr(tsa["tsa_ref"]))}
		}
		refs[ref] = true
	}
	return &drecTrustPolicy{keys: keys}
}

// drecFromHex is bytes.fromhex: pairs of hex digits, ASCII whitespace between them ignored.
func drecFromHex(s string) ([]byte, bool) {
	var digits []byte
	for i := 0; i < len(s); {
		if strings.IndexByte(" \t\n\r\v\f", s[i]) >= 0 {
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, false
		}
		digits = append(digits, s[i], s[i+1])
		i += 2
	}
	out, err := hex.DecodeString(string(digits))
	return out, err == nil
}

func drecIssuerSignature(data []byte, doc map[string]any, policy *drecTrustPolicy, latest *drecInstant) drecDim {
	raw, has := doc["issuer_signature"]
	if !has || raw == nil {
		return drecMake(drecNotChecked, "the attachment carries no issuer signature")
	}
	if policy == nil {
		return drecMake(drecNotChecked, "no trust policy is configured, so no key is held for the signature")
	}
	sig, isObj := raw.(map[string]any)
	if !isObj || len(sig) != len(drecSignatureMembers) || !drecHas(sig, drecSignatureMembers...) {
		return drecMake(drecFailed, "the copy does not have exactly the five members of a seal copy")
	}
	keyRef := sig["key_ref"]
	if policy.refused != "" {
		return drecMake(drecFailed, "not checked: the trust policy is refused ("+policy.refused+")")
	}
	if !drecEq(sig["algorithm"], "Ed25519") || !drecEq(sig["signed_bytes_ref"], drecSignedBytesRef) {
		return drecMake(drecFailed, "the copy names another algorithm or other signed bytes")
	}
	entry, known := policy.keys[drecKey(keyRef)]
	if !known {
		return drecMake(drecFailed, fmt.Sprintf("key %s is not in the trust policy", drecRepr(keyRef)))
	}
	if !drecEq(entry["role"], "organisation") || !drecEq(entry["algorithm"], "Ed25519") {
		return drecMake(drecFailed, fmt.Sprintf("key %s is not an Ed25519 key in role organisation", drecRepr(keyRef)))
	}
	var findings []string
	signatureOK := drecSignatureVerifies(data, doc, sig, entry, &findings)
	certificate := drecCertificate(entry, &findings)
	keyState := drecKeyState(entry, sig["sealed_at"])
	findings = append(findings, keyState.Findings...)
	sealed := drecReadInstant(sig["sealed_at"])
	if latest != nil && sealed.ok() && latest.ok() && sealed.sec.Cmp(latest.sec) < 0 {
		findings = append(findings, "sealed_at is earlier than the latest stage the attachment records; both are "+
			"the issuer's times")
	}
	status := drecFailed
	if signatureOK && keyState.Status == drecVerified && certificate != drecFailed {
		status = drecVerified
	}
	if signatureOK && keyState.Status == drecUnavailable {
		status = drecUnavailable
	}
	return drecDim{Status: status, Findings: findings, Extra: map[string]any{"key_state": keyState.Status,
		"certificate": certificate}}
}

func drecSignatureVerifies(data []byte, doc, sig, entry map[string]any, findings *[]string) bool {
	value, _ := sig["value_b64"].(string)
	digest, digestOK := drecSealedDigest(data, value)
	rawSig := drecB64(sig["value_b64"])
	publicHex, isStr := entry["public_key_hex"].(string)
	if _, has := entry["public_key_hex"]; !has {
		publicHex, isStr = "", true
	}
	public, hexOK := drecFromHex(publicHex)
	if !isStr || !hexOK || len(public) != ed25519.PublicKeySize {
		*findings = append(*findings, "the policy's public key for this reference cannot be read")
		return false
	}
	if !digestOK || rawSig == nil {
		*findings = append(*findings, "the sealed digest cannot be rebuilt from the attachment")
		return false
	}
	digestBytes, _ := hex.DecodeString(digest)
	keyRef, _ := sig["key_ref"].(string)
	decisionID, _ := doc["decision_id"].(string)
	sealedAt, _ := sig["sealed_at"].(string)
	signed := drecSealSignedBytes(keyRef, decisionID, digestBytes, sealedAt)
	if !ed25519.Verify(ed25519.PublicKey(public), signed, rawSig) {
		*findings = append(*findings, "the signature does not verify over the signed bytes rebuilt from the attachment")
		return false
	}
	return true
}

func drecCertificate(entry map[string]any, findings *[]string) string {
	pinned, has := entry["certificate_b64"]
	if !has || pinned == nil {
		return drecNotChecked
	}
	der, ok := drecB64Validate(pinned)
	var cert *x509.Certificate
	var err error
	if ok {
		cert, err = x509.ParseCertificate(der)
	}
	if !ok || err != nil {
		*findings = append(*findings, "the pinned certificate cannot be read")
		return drecFailed
	}
	held, isEd := cert.PublicKey.(ed25519.PublicKey)
	if !isEd {
		*findings = append(*findings, "the pinned certificate cannot be read")
		return drecFailed
	}
	public := ""
	if v, present := entry["public_key_hex"]; present {
		public = drecStr(v)
	}
	if hex.EncodeToString(held) != strings.ToLower(public) {
		*findings = append(*findings, "the pinned certificate does not hold the key")
		return drecFailed
	}
	return drecVerified
}

// drecStr is Python's str() for the values a policy carries.
func drecStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return drecRepr(v)
}

func drecKeyState(entry map[string]any, sealedAt any) drecDim {
	stated := drecReadInstant(sealedAt)
	if !stated.ok() {
		return drecMake(drecFailed, fmt.Sprintf("sealed_at %s names no instant", drecRepr(sealedAt)))
	}
	start, end := drecReadInstant(entry["not_before"]), drecReadInstant(entry["not_after"])
	if !start.ok() || !end.ok() {
		return drecMake(drecFailed, "the policy's validity for the key names no instant")
	}
	if start.sec.Cmp(stated.sec) > 0 || stated.sec.Cmp(end.sec) > 0 {
		return drecMake(drecFailed, "signed outside the key's validity")
	}
	if revokedAt, has := entry["revoked_at"]; has {
		revoked := drecReadInstant(revokedAt)
		if !revoked.ok() {
			return drecMake(drecFailed, "the policy's revocation time names no instant")
		}
		if drecEq(entry["revocation_reason"], "compromised") {
			return drecMake(drecUnavailable, "the key was compromised: only an independent timestamp earlier than its "+
				"revocation can establish when it signed, and none is read")
		}
		if stated.sec.Cmp(revoked.sec) >= 0 {
			return drecMake(drecFailed, "signed after the key was superseded")
		}
	}
	return drecMake(drecVerified)
}

// --- the strict profile ---------------------------------------------------------------

func drecApproverIndependence(att *drecAttachment) drecDim {
	approvals := att.approvals()
	if len(approvals) == 0 {
		return drecMake(drecNotChecked, "no approval is recorded")
	}
	parties := att.parties()
	t := &drecTally{}
	for _, s := range approvals {
		if drecMember(parties, s.get("actor_ref")) {
			t.fail("%s: approved by %s, which proposed, requested or executes the action", s.id(), drecRepr(s.get("actor_ref")))
		}
	}
	return t.result()
}

func drecSingleEffect(att *drecAttachment, effects map[string]any) drecDim {
	attempts := att.ofKind("attempt")
	if len(attempts) == 0 {
		return drecMake(drecNotChecked, "no execution attempt is recorded")
	}
	t := &drecTally{}
	observed := map[string]any{}
	for _, r := range att.ofKind("result") {
		observed[drecKey(r.get("attempt_ref"))] = r.get("observed")
	}
	for _, request := range att.ofKind("request") {
		rid, _ := request.get("request_id").(string)
		var words []any
		var names []string
		for _, a := range attempts {
			if drecEq(a.get("request_ref"), request.get("stage_id")) {
				words = append(words, observed[drecKey(a.get("stage_id"))])
				names = append(names, a.id())
			}
		}
		if effect, has := effects[rid]; has {
			if !drecJSONInteger(effect) || drecIntValue(effect) > 1 {
				t.fail("%s: the target observed %s effects", request.id(), drecRepr(effect))
			}
			continue
		}
		succeeded, indeterminate := 0, false
		for i, w := range words {
			if drecEq(w, "succeeded") {
				succeeded++
			}
			if i < len(words)-1 && drecEq(w, "indeterminate") {
				indeterminate = true
			}
		}
		if succeeded > 1 {
			t.fail("%s: attempts %s were each observed to succeed; one request ran more than once", request.id(),
				strings.Join(names, ", "))
		} else if indeterminate {
			t.skip("%s: retried after an indeterminate attempt; only an observation at the target says whether "+
				"it took effect twice", request.id())
		}
	}
	return t.result()
}

func drecIdentityIndependent(att *drecAttachment, source any) drecDim {
	if source == nil {
		return drecMake(drecNotChecked, "the relying party supplied no identity source")
	}
	identities, _ := source.(map[string]any)
	t := &drecTally{}
	for _, s := range att.stages {
		if s.kindIs("proposal") {
			continue
		}
		for _, k := range []string{"reviewer_ref", "actor_ref"} {
			actor, has := s.m[k]
			if !has {
				continue
			}
			name, _ := actor.(string)
			entry, isObj := identities[name].(map[string]any)
			if !isObj {
				t.fail("%s: %s is not in the relying party's identity source", s.id(), drecRepr(actor))
			} else if !drecEq(entry["status"], drecVerified) {
				t.fail("%s: the identity source gives %s as %s", s.id(), drecRepr(actor), drecRepr(entry["status"]))
			}
		}
	}
	return t.result()
}

func drecAuthorityIndependent(att *drecAttachment, source any) drecDim {
	if source == nil {
		return drecMake(drecNotChecked, "the relying party supplied no authority source")
	}
	held := map[string]bool{}
	grants, _ := source.([]any)
	for _, g := range grants {
		if grant, isObj := g.(map[string]any); isObj {
			held[drecKey(grant["actor_ref"])+"|"+drecKey(grant["authority_ref"])] = true
		}
	}
	t := &drecTally{}
	for _, s := range append(att.approvals(), att.ofKind("change_authorisation")...) {
		authority, _ := s.get("authority").(map[string]any)
		ref := authority["authority_ref"]
		if !held[drecKey(s.get("actor_ref"))+"|"+drecKey(ref)] {
			t.fail("%s: the relying party's authority source grants %s no %s", s.id(), drecRepr(s.get("actor_ref")),
				drecRepr(ref))
		}
	}
	if len(att.approvals()) == 0 {
		t.skip("no approval is recorded")
	}
	return t.result()
}

func drecTimeIndependent(att *drecAttachment, source any) drecDim {
	if source == nil {
		return drecMake(drecNotChecked, "the relying party supplied no independent observation of the stages' times")
	}
	clock, _ := source.(map[string]any)
	tolerance := new(big.Rat)
	if v, has := clock["tolerance_seconds"]; has {
		if n, isNum := drecNumber(v); isNum {
			tolerance = n
		}
	}
	seen, _ := clock["observed"].(map[string]any)
	t := &drecTally{}
	if len(att.ofKind("attempt")) == 0 {
		t.skip("no execution attempt is recorded")
	}
	for _, s := range append(att.approvals(), att.ofKind("change_authorisation", "attempt")...) {
		mark := drecReadInstant(seen[s.id()])
		if !mark.ok() {
			t.fail("%s: no independent observation of this stage", s.id())
			continue
		}
		at := att.at(s)
		if !at.ok() || new(big.Rat).Abs(new(big.Rat).Sub(at.sec, mark.sec)).Cmp(tolerance) > 0 {
			t.fail("%s: the issuer dates it %s, observed %s", s.id(), at.text, mark.text)
		}
	}
	for _, attempt := range att.ofKind("attempt") {
		request := att.stage(attempt.get("request_ref"), "request")
		if request == nil {
			continue
		}
		basis := att.stage(request.get("authorised_by"))
		if basis == nil {
			continue
		}
		approved, ran := drecReadInstant(seen[basis.id()]), drecReadInstant(seen[attempt.id()])
		if approved.ok() && ran.ok() && approved.sec.Cmp(ran.sec) > 0 {
			t.fail("%s: observed before the approval it rests on", attempt.id())
		}
	}
	return t.result()
}

func drecLatest(decisionID any, digest string, source any) drecDim {
	latest, isObj := source.(map[string]any)
	id, _ := decisionID.(string)
	held, has := latest[id]
	if source == nil || !isObj || !has {
		return drecMake(drecNotChecked, "the relying party holds no latest attachment for this decision")
	}
	if drecEq(held, digest) {
		return drecMake(drecVerified)
	}
	return drecMake(drecFailed, "a later attachment of this decision is held; this one is not the latest")
}

// --- the report -----------------------------------------------------------------------

// drecReport is one attachment's dimensions and what the binding cases compare.
type drecReport struct {
	dims           map[string]drecDim
	strict         map[string]drecDim
	reviews        []drecReview
	standing       []drecStanding
	executed       []drecExecuted
	attempts       []drecAttemptRow
	executionState string
}

// drecInput is one attachment and what the relying party supplies beside it.
type drecInput struct {
	attachment       []byte
	record           []byte // nil: not supplied
	trustPolicy      any
	hasTrustPolicy   bool
	timestampsBeside bool
	relyingParty     map[string]any
}

func drecUnread(r *drecReport, why string) *drecReport {
	for _, name := range append(append([]string{}, drecBindingDimensions...), "issuer_signature", "time_assurance",
		"identity_assurance", "authority_assurance", "legal_signature") {
		r.dims[name] = drecMake(drecNotChecked, why)
	}
	for _, name := range drecStrictDimensions {
		r.strict[name] = drecMake(drecNotChecked, why)
	}
	return r
}

// drecRead reads one attachment's exact bytes and reports every dimension separately.
func drecRead(in drecInput) *drecReport {
	r := &drecReport{dims: map[string]drecDim{}, strict: map[string]drecDim{}}
	digest := drecSHA(in.attachment)
	var policy *drecTrustPolicy
	if in.hasTrustPolicy {
		policy = drecReadTrustPolicy(in.trustPolicy)
	}
	parsed, err := drecParse(in.attachment, drecStrict)
	if err != nil {
		r.dims["structural_validity"] = drecMake(drecFailed, "not read: "+err.Error())
		return drecUnread(r, "the attachment is not read")
	}
	r.dims["structural_validity"] = drecStructuralValidity(parsed)
	if r.dims["structural_validity"].Status != drecVerified {
		return drecUnread(r, "the attachment does not have the format's shape")
	}
	doc := parsed.(map[string]any)
	var record map[string]any
	if in.record != nil {
		recordValue, recordErr := drecParse(in.record, drecStrict)
		if recordErr != nil {
			r.dims["record"] = drecMake(drecFailed, "not read: "+recordErr.Error())
		}
		record, _ = recordValue.(map[string]any)
	}
	att := drecAttachmentFrom(doc)
	r.dims["specification_digests"], r.dims["specification_statements"] = drecSpecificationDimensions(att)
	action, binding := drecRunBinding(att)
	r.reviews, r.standing = binding.reviews, binding.standing
	r.executed = drecExecutedSpecifications(att)
	r.dims["record_statements"] = drecRecordStatements(att, record)
	r.dims["action_binding"] = action
	r.dims["stage_order"] = drecStageOrder(att)
	r.dims["authorisation_recheck"] = drecAuthorisationRecheck(att)
	r.dims["observed_results"], r.executionState, r.attempts = drecObservedResults(att)
	r.dims["rationale_provenance"] = drecRationaleProvenance(att)
	r.dims["identity_assurance"] = drecMake(drecNotChecked)
	r.dims["authority_assurance"] = drecMake(drecNotChecked)
	var latest *drecInstant
	for _, s := range att.stages {
		if at := att.at(s); at.ok() && (latest == nil || at.sec.Cmp(latest.sec) > 0) {
			latest = &at
		}
	}
	if policy == nil {
		r.dims["trust_policy"] = drecMake(drecNotChecked, "no trust policy is configured")
	} else if policy.refused != "" {
		r.dims["trust_policy"] = drecMake(drecFailed, policy.refused)
	} else {
		r.dims["trust_policy"] = drecMake(drecVerified)
	}
	r.dims["issuer_signature"] = drecIssuerSignature(in.attachment, doc, policy, latest)
	if in.timestampsBeside {
		r.dims["time_assurance"] = drecMake(drecNotSupported, "timestamps beside the attachment are not read by this reader")
	} else {
		r.dims["time_assurance"] = drecMake(drecNotChecked)
	}
	legal := "no legal signature is referenced"
	for _, s := range att.stages {
		if s.has("legal_signature_ref") {
			legal = "a legal signature is referenced; its effect is outside this format"
		}
	}
	r.dims["legal_signature"] = drecMake(drecNotChecked, legal)
	effects, _ := in.relyingParty["target_effects"].(map[string]any)
	r.strict["approver_independence"] = drecApproverIndependence(att)
	r.strict["single_effect_per_request"] = drecSingleEffect(att, effects)
	r.strict["identity_independent"] = drecIdentityIndependent(att, in.relyingParty["identities"])
	r.strict["authority_independent"] = drecAuthorityIndependent(att, in.relyingParty["authority_grants"])
	r.strict["time_independent"] = drecTimeIndependent(att, in.relyingParty["independent_times"])
	r.strict["latest_attachment"] = drecLatest(doc["decision_id"], digest, in.relyingParty["latest"])
	if r.dims["issuer_signature"].Status == drecVerified {
		r.strict["signature_required"] = drecMake(drecVerified)
	} else {
		r.strict["signature_required"] = drecMake(drecFailed, "the relying party requires a verified issuer signature")
	}
	return r
}

// drecVerdict is what one profile accepts: ("accept", "") or ("reject", "<dimension>:<status>").
func drecVerdict(r *drecReport, profile string) (string, string, error) {
	if profile != "baseline" && profile != "strict" {
		return "", "", fmt.Errorf("profile %q is not baseline or strict", profile)
	}
	names := append(append([]string{"structural_validity"}, drecBindingDimensions...), "issuer_signature")
	for _, name := range names {
		if r.dims[name].Status == drecFailed {
			return "reject", name + ":" + drecFailed, nil
		}
	}
	if profile == "baseline" {
		return "accept", "", nil
	}
	for _, name := range drecStrictDimensions {
		if status := r.strict[name].Status; status != drecVerified {
			return "reject", name + ":" + status, nil
		}
	}
	for _, name := range drecBindingDimensions {
		if status := r.dims[name].Status; status != drecVerified {
			return "reject", name + ":" + status, nil
		}
	}
	return "accept", "", nil
}

// --- the published binding cases ------------------------------------------------------

func drecNum(n int) any { return drecInt{n: big.NewInt(int64(n))} }

// drecBindingSummary is a report in the published binding cases' terms.
func drecBindingSummary(r *drecReport) map[string]any {
	out := map[string]any{"execution_state": r.executionState}
	for _, name := range drecBindingDimensions {
		out[name] = r.dims[name].Status
	}
	observed := []any{}
	for _, a := range r.attempts {
		observed = append(observed, []any{a.stageID, a.observed, a.basis})
	}
	executed := []any{}
	for _, e := range r.executed {
		executed = append(executed, []any{drecNum(e.specIndex), e.reachedBy})
	}
	reviews := []any{}
	for _, v := range r.reviews {
		var editor any
		if drecTruthy(v.editedBy) {
			editor = v.editedBy
		}
		reviews = append(reviews, []any{v.stageID, v.shown, editor})
	}
	standing := []any{}
	for _, s := range r.standing {
		standing = append(standing, []any{s.stageID, s.status, drecNum(s.requestsRecorded), s.maxRequests, s.revocation})
	}
	out["observed"], out["executed"], out["reviews"], out["standing"] = observed, executed, reviews, standing
	return out
}

// drecExpectedDifferences is where a report differs from one published case's expected values.
func drecExpectedDifferences(want map[string]any, r *drecReport) []string {
	got := drecBindingSummary(r)
	var diffs []string
	for _, name := range drecBindingDimensions {
		expected, has := want[name]
		if !has {
			expected = drecVerified
		}
		if !drecEq(got[name], expected) {
			diffs = append(diffs, fmt.Sprintf("%s: expected %v, read %v", name, expected, got[name]))
		}
	}
	state, has := want["execution_state"]
	if !has {
		state = "attempted"
	}
	if !drecEq(got["execution_state"], state) {
		diffs = append(diffs, fmt.Sprintf("execution_state: expected %v, read %v", state, got["execution_state"]))
	}
	for _, name := range []string{"observed", "executed", "reviews", "standing"} {
		if expected, named := want[name]; named && !drecEq(expected, got[name]) {
			diffs = append(diffs, fmt.Sprintf("%s: expected %s, read %s", name, drecRepr(expected), drecRepr(got[name])))
		}
	}
	return diffs
}

// --- the corpus -----------------------------------------------------------------------

type drecManifest struct {
	Source struct {
		Files map[string]struct {
			SHA256 string `json:"sha256"`
			Length int    `json:"length"`
		} `json:"files"`
	} `json:"source"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []drecVector   `json:"vectors"`
}

type drecVector struct {
	ID         string `json:"id"`
	Path       string `json:"path"`
	Profile    string `json:"profile"`
	SourceCase string `json:"sourceCase"`
	Expected   struct {
		Verdict    string                     `json:"verdict"`
		Code       *string                    `json:"code"`
		Dimensions map[string]json.RawMessage `json:"dimensions"`
	} `json:"expected"`
}

func (decisionRecord) Judge(dir string, raw []byte) (*Result, error) {
	var m drecManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, name := range sortedKeys(m.Source.Files) {
		pinned := m.Source.Files[name]
		rel := filepath.Join("source", name)
		if finding := checkVendored(dir, rel, pinned.SHA256, "published test file"); finding != "" {
			result.Findings = append(result.Findings, finding)
		} else if body, _ := readIn(dir, rel); len(body) != pinned.Length {
			result.Findings = append(result.Findings, fmt.Sprintf("the vendored %s is %d bytes, pinned at %d",
				rel, len(body), pinned.Length))
		}
	}
	cases, casesErr := drecReadCases(dir)
	if casesErr != nil {
		result.Findings = append(result.Findings, casesErr.Error())
	}
	counts := map[string]int{}
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
		member.Findings = drecJudgeMember(v, body, cases, casesErr == nil)
		result.Members = append(result.Members, member)
	}
	if fmt.Sprint(counts) != fmt.Sprint(m.Counts) {
		result.Findings = append(result.Findings, fmt.Sprintf("counts %v disagree with the members %v", m.Counts, counts))
	}
	if sha(lines.Bytes()) != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the committed bytes")
	}
	return result, nil
}

// drecReadCases reads the published binding cases by id.
func drecReadCases(dir string) (map[string]map[string]any, error) {
	body, err := readIn(dir, filepath.Join("source", "cases.json"))
	if err != nil {
		return nil, fmt.Errorf("source/cases.json cannot be read, so no member is held to its published case")
	}
	parsed, err := drecParse(body, drecLenient)
	doc, isObj := parsed.(map[string]any)
	if err != nil || !isObj {
		return nil, fmt.Errorf("source/cases.json is not a JSON object")
	}
	out := map[string]map[string]any{}
	list, _ := doc["binding_cases"].([]any)
	for _, item := range list {
		c, isCase := item.(map[string]any)
		if id, isStr := c["id"].(string); isCase && isStr {
			out[id] = c
		}
	}
	return out, nil
}

// drecMemberInput reads a member file as Python's json.loads does and lifts out what the reader takes.
func drecMemberInput(body []byte) (drecInput, string, error) {
	parsed, err := drecParse(body, drecLenient)
	if err != nil {
		return drecInput{}, "", fmt.Errorf("the member does not parse: %w", err)
	}
	member, isObj := parsed.(map[string]any)
	attachment, isStr := member["attachment"].(string)
	if !isObj || !isStr {
		return drecInput{}, "", fmt.Errorf("the member carries no attachment text")
	}
	in := drecInput{attachment: []byte(attachment), timestampsBeside: drecTruthy(member["timestamps_beside"])}
	if record, has := member["record"].(string); has {
		in.record = []byte(record)
	}
	if policy, has := member["trust_policy"]; has && policy != nil {
		in.trustPolicy, in.hasTrustPolicy = policy, true
	}
	in.relyingParty, _ = member["relying_party"].(map[string]any)
	profile := "baseline"
	if p, has := member["profile"]; has {
		profile, _ = p.(string)
	}
	return in, profile, nil
}

func drecJudgeMember(v drecVector, body []byte, cases map[string]map[string]any, haveCases bool) []string {
	in, profile, err := drecMemberInput(body)
	if err != nil {
		return []string{err.Error()}
	}
	var findings []string
	if v.Profile != profile {
		findings = append(findings, fmt.Sprintf("the manifest names profile %q, the member %q", v.Profile, profile))
	}
	report := drecRead(in)
	verdict, code, err := drecVerdict(report, profile)
	if err != nil {
		return append(findings, err.Error())
	}
	want := ""
	if v.Expected.Code != nil {
		want = *v.Expected.Code
	}
	if verdict != v.Expected.Verdict || code != want {
		findings = append(findings, fmt.Sprintf("derived %s/%q, the manifest declares %s/%q",
			verdict, code, v.Expected.Verdict, want))
	}
	findings = append(findings, drecDeclaredDifferences(report, v.Expected.Dimensions)...)
	if v.SourceCase == "" || !haveCases {
		return findings
	}
	published, found := cases[v.SourceCase]
	if !found {
		return append(findings, "names published case "+v.SourceCase+", which source/cases.json does not carry")
	}
	expected, _ := published["expected"].(map[string]any)
	if !drecDeclaresCase(v.Expected.Dimensions, expected) {
		findings = append(findings, "declared dimensions are not case "+v.SourceCase+"'s")
	}
	return append(findings, drecExpectedDifferences(expected, report)...)
}

func drecDeclaredDifferences(r *drecReport, declared map[string]json.RawMessage) []string {
	var out []string
	for _, name := range sortedKeys(declared) {
		if name == "strict" {
			var want map[string]string
			if json.Unmarshal(declared[name], &want) != nil {
				out = append(out, "strict: the declared dimensions are not a map of statuses")
				continue
			}
			for _, k := range sortedKeys(want) {
				got, known := r.strict[k]
				if !known || got.Status != want[k] {
					out = append(out, fmt.Sprintf("strict.%s: declared %s, read %s", k, want[k], got.Status))
				}
			}
			continue
		}
		var want string
		got, known := r.dims[name]
		if json.Unmarshal(declared[name], &want) != nil || !known || got.Status != want {
			out = append(out, fmt.Sprintf("%s: declared %s, read %s", name, string(declared[name]), got.Status))
		}
	}
	return out
}

// drecDeclaresCase: a member naming a published case declares exactly that case's binding dimensions.
func drecDeclaresCase(declared map[string]json.RawMessage, expected map[string]any) bool {
	if len(declared) != len(drecBindingDimensions) {
		return false
	}
	for _, name := range drecBindingDimensions {
		var want string
		raw, has := declared[name]
		if !has || json.Unmarshal(raw, &want) != nil {
			return false
		}
		published, named := expected[name]
		if !named {
			published = drecVerified
		}
		if !drecEq(published, want) {
			return false
		}
	}
	return true
}
