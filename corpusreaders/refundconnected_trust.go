package corpora

// Steps 3 and 4 of the refund-connected reader: the committed admission record
// against every retained input, and the signed handoff or resolution against
// the trust snapshots and the instant of each recorded dispatch.

import (
	"strings"
	"time"
)

// ----------------------------------------------------------------------------
// The admission state of the run.
// ----------------------------------------------------------------------------

// rcAdmissionState is Admission: the consumed approvals and the decisions of the
// run, loaded once. Either member may be any JSON value, as in the reference.
type rcAdmissionState struct{ consumed, decisions any }

func newRCAdmission(run rcRun) *rcAdmissionState {
	state := &rcAdmissionState{consumed: &rcObj{m: map[string]any{}}, decisions: &rcObj{m: map[string]any{}}}
	if raw, ok := run.json("admission/state.json").(*rcObj); ok {
		state.consumed = rcGetDefault(raw, "consumed", state.consumed)
		state.decisions = rcGetDefault(raw, "decisions", state.decisions)
	}
	return state
}

// forDecision is Admission.for_decision: the record of each decision whose key
// ends with the decision id, in the order the file lists them.
func (a *rcAdmissionState) forDecision(decisionID any) []*rcObj {
	decisions := rcObjOf(a.decisions)
	var out []*rcObj
	for _, key := range decisions.keys {
		parts := strings.Split(key, "\n")
		if !rcEqStr(decisionID, parts[len(parts)-1]) {
			continue
		}
		if entry, ok := decisions.m[key].(*rcObj); ok {
			if record, isObj := entry.get("record").(*rcObj); isObj {
				out = append(out, record)
			}
		}
	}
	return out
}

// consumedGet is consumed.get(key).
func (a *rcAdmissionState) consumedGet(key any) any {
	return rcDictGet(rcObjOf(a.consumed), key)
}

func (a *rcAdmissionState) consumedValues() []any {
	obj := rcObjOf(a.consumed)
	out := make([]any, len(obj.keys))
	for i, k := range obj.keys {
		out[i] = obj.m[k]
	}
	return out
}

// ----------------------------------------------------------------------------
// Step 3: admission and the signed records.
// ----------------------------------------------------------------------------

// admissionRecordRef is admission_record_ref: the closed shape of a committed
// record, and its admission_ref.
func (j *rcJudge) admissionRecordRef(rec *rcObj) string {
	j.needC(rcKeysAre(rec, rcAdmissionFields...), "admission-fields")
	j.needC(rcEqStr(rec.item("schema"), rcAdmission) && rcEqStr(rec.item("contract_revision"), rcRevision) &&
		rcEqStr(rec.item("state"), "committed") && rcEqStr(rec.item("tool"), "refund"), "admission-schema")
	for _, name := range append(append([]string{}, rcScope...), "decision_id", "operation_id", "approval_ref") {
		j.needC(rcASCIIID(rec.item(name)), "admission-"+name)
	}
	for _, f := range rcInputFiles {
		j.needC(rcMatch(rcRefRe, rec.item(f.field)), "admission-"+f.field)
	}
	j.needC(rcRefundArgsOK(rec.item("arguments")), "admission-arguments")
	var ordered bool
	if rcCatch(func() { ordered = rcTSs(rec.item("committed_at")).Before(rcTSs(rec.item("valid_until"))) }, "ValueError") != nil {
		j.fail(rcContra, "admission-window")
	}
	j.needC(ordered, "admission-window")
	return rcRefOf(rec)
}

// rcKeyTimes parses the three times of a trust key, raising ValueError for one
// that is malformed.
func rcKeyTimes(key any) {
	rcTSs(rcItem(key, "not_before"))
	rcTSs(rcItem(key, "not_after"))
	if revoked := rcItem(key, "revoked_at"); revoked != nil {
		rcTSs(revoked)
	}
}

// checkTrustSnapshot is check_trust_snapshot: the closed shape of a snapshot,
// and its reference.
func (j *rcJudge) checkTrustSnapshot(snapshot any) string {
	good := false
	if obj, ok := snapshot.(*rcObj); ok && rcKeysAre(obj, rcTrustFields...) && rcEqStr(obj.m["schema"], rcTrust) {
		keys, isList := rcList(obj.m["keys"])
		good = isList && len(keys) > 0
	}
	j.needC(good, "trust-fields")
	ids := &rcSet{}
	for _, key := range rcIter(rcItem(snapshot, "keys")) {
		ko, isObj := key.(*rcObj)
		j.needC(isObj && rcKeysAre(ko, rcKeyFields...) && rcIsHex64(ko.m["public_key_hex"]) && !ids.has(ko.m["key_id"]), "trust-key-fields")
		ids.add(rcItem(key, "key_id"))
		if rcCatch(func() { rcKeyTimes(key) }, "ValueError") != nil {
			j.fail(rcContra, "trust-key-time")
		}
	}
	return rcRefOf(snapshot)
}

// keyWindow is not_before <= at < not_after, evaluated left to right so a
// malformed not_after is only read when not_before has passed.
func keyWindow(key *rcObj, at time.Time) bool {
	return !rcTSs(key.item("not_before")).After(at) && at.Before(rcTSs(key.item("not_after")))
}

// signerKey is _signer_key.
func (j *rcJudge) signerKey(snapshot, keyID any, scope *rcObj, at time.Time) *rcObj {
	var matches []any
	for _, k := range rcIter(rcItem(snapshot, "keys")) {
		if rcEq(rcItem(k, "key_id"), keyID) {
			matches = append(matches, k)
		}
	}
	j.needC(len(matches) == 1, "key-unknown")
	key := rcObjOf(rcFirst(matches))
	j.needC(rcEqStr(key.item("role"), rcSignerRole), "key-role")
	j.needC(rcEq(key.item("issuer"), scope.item("admission_issuer")), "key-issuer")
	j.needC(rcEq(rcItem(snapshot, "workflow_id"), scope.item("workflow_id")), "key-workflow")
	j.needC(rcIn(scope.item("provider_namespace"), rcItem(snapshot, "provider_namespaces")), "key-provider")
	j.needC(keyWindow(key, at), "key-validity")
	revoked := key.item("revoked_at")
	j.needC(revoked == nil || at.Before(rcTSs(revoked)), "key-revoked")
	return key
}

func (j *rcJudge) handoffChecks(payload any, record *rcObj, recordRef string) {
	j.needC(rcEqStr(rcItem(payload, "admission_ref"), recordRef), "admission-ref")
	j.needC(rcEq(rcItem(payload, "not_before"), rcItem(payload, "issued_at")), "handoff-not-before")
	j.needC(!rcTSs(rcItem(payload, "valid_until")).After(rcTSs(record.item("valid_until"))), "handoff-extends-record")
	issued, until := rcTSs(rcItem(payload, "issued_at")), rcTSs(rcItem(payload, "valid_until"))
	j.needC(issued.Before(until), "handoff-window-empty")
	j.needC(until.Sub(issued) <= rcHandoffCeiling, "handoff-lifetime")
}

func (j *rcJudge) resolutionChecks(payload any, record *rcObj, recordRef string) {
	j.needC(rcEqStr(rcItem(payload, "original_admission_ref"), recordRef), "original-admission-ref")
	j.needC(rcEq(rcItem(payload, "original_approval_ref"), record.item("approval_ref")), "original-approval-ref")
	j.needC(rcEq(rcItem(payload, "decision_id"), record.item("decision_id")), "decision-id")
	j.needC(rcEqStr(rcItem(payload, "disposition"), "resolved_existing"), "disposition")
	authorized, isBool := rcItem(payload, "dispatch_authorized").(bool)
	j.needC(isBool && !authorized, "dispatch-authorized")
}

// verifyEnvelope is verify_envelope: a handoff or resolution against the type
// the caller expects, never the one the payload claims.
func (j *rcJudge) verifyEnvelope(kind string, data []byte, record *rcObj, snapshot any) *rcObj {
	fields := rcHandoffFields
	if kind == rcResolution {
		fields = rcResolutionFields
	}
	var env any
	if rcCatch(func() { env = rcParse(data) }, "ValueError") != nil {
		j.fail(rcContra, "envelope-parse")
	}
	j.needC(rcClosed(env, []string{"payload", "alg", "signature"}), "envelope-fields")
	j.needC(rcEqStr(rcItem(env, "alg"), "ed25519"), "envelope-alg")
	payload := rcItem(env, "payload")
	j.needC(rcClosed(payload, fields), "payload-fields")
	j.needC(rcEqStr(rcItem(payload, "schema"), kind) && rcEqStr(rcItem(payload, "contract_revision"), rcRevision), "payload-schema")
	recordRef := j.admissionRecordRef(record)
	j.needC(rcEqStr(rcItem(payload, "trust_snapshot_ref"), j.checkTrustSnapshot(snapshot)), "trust-snapshot-ref")
	for _, name := range append(append([]string{}, rcScope...), "operation_id") {
		j.needC(rcEq(rcItem(payload, name), record.item(name)), "scope-"+name)
	}
	key := j.envelopeKey(kind, payload, record, recordRef, snapshot)
	sig, ok := rcB64(rcStr(rcItem(env, "signature")))
	if !ok {
		j.fail(rcContra, "signature-encoding")
	}
	j.needC(len(sig) == 64 && rcEqStr(rcItem(env, "signature"), rcB64Encode(sig)), "signature-encoding")
	message := append([]byte(kind+"\x00"), rcJCS(payload)...)
	j.needC(rcEdVerify(rcBytesFromHex(key.item("public_key_hex")), message, sig), "signature-invalid")
	return rcObjOf(payload)
}

// envelopeKey runs the kind's checks and finds the signing key; a malformed
// timestamp anywhere in them is the one finding timestamp-format.
func (j *rcJudge) envelopeKey(kind string, payload any, record *rcObj, recordRef string, snapshot any) *rcObj {
	var key *rcObj
	failed := rcCatch(func() {
		if kind == rcHandoff {
			j.handoffChecks(payload, record, recordRef)
		} else {
			j.resolutionChecks(payload, record, recordRef)
		}
		key = j.signerKey(snapshot, rcItem(payload, "key_id"), record, rcTSs(rcItem(payload, "issued_at")))
	}, "ValueError")
	if failed != nil {
		j.fail(rcContra, "timestamp-format")
	}
	return key
}

// idempotencyKey is idempotency_key.
func idempotencyKey(scope *rcObj) string {
	body := &rcObj{m: map[string]any{}}
	for _, name := range append(append([]string{}, rcScope...), "operation_id") {
		body.keys = append(body.keys, name)
		body.m[name] = scope.item(name)
	}
	return "sha256:" + rcTagRef(rcIdemTag, body)
}

// checkAdmission is check_admission: the committed record against every retained
// input, or the case's reissue.
func (j *rcJudge) checkAdmission(c *rcCase, ctx *rcCtx) {
	records := j.adm.forDecision(c.decisionID)
	j.needA(len(records) > 0, "no-admission-record")
	var same []*rcObj
	for _, r := range records {
		if rcEq(r.get("approval_ref"), c.approvalID) {
			same = append(same, r)
		}
	}
	if len(same) == 0 {
		ctx.reissueOf = records[0]
		return
	}
	record := same[0]
	j.admissionRecordRef(record)
	for _, f := range rcInputFiles {
		j.needC(rcEqStr(record.item(f.field), c.rawRef(f.rel)), "admission-"+f.field+"-mismatch")
	}
	j.needC(rcTypedEq(record.item("arguments"), c.picArgs), "admission-arguments")
	payload := c.p("inputs/aps-payload.json")
	fromPayload := &rcObj{m: map[string]any{}}
	for _, name := range rcRefundArgs {
		fromPayload.keys = append(fromPayload.keys, name)
		fromPayload.m[name] = rcItem(payload, name)
	}
	j.needC(rcTypedEq(record.item("arguments"), fromPayload), "admission-arguments")
	j.needC(rcEq(j.adm.consumedGet(c.approvalID), record.item("operation_id")), "approval-not-consumed")
	uses := 0
	for _, v := range j.adm.consumedValues() {
		if rcEq(v, record.item("operation_id")) {
			uses++
		}
	}
	j.needC(uses == 1, "operation-consumed-twice")
	j.nativeWindow(c, record)
	ctx.record = record
}

// nativeWindow holds the record's commit and expiry inside the approval's native
// windows.
func (j *rcJudge) nativeWindow(c *rcCase, record *rcObj) {
	native := c.nativeBounds()
	committed := rcTSs(record.item("committed_at"))
	var latest time.Time
	for i, b := range native {
		if at := rcCeilS(rcTSms(b.low)); i == 0 || at.After(latest) {
			latest = at
		}
	}
	j.needC(!committed.Before(latest), "admission-before-native-window")
	valid := rcTSs(record.item("valid_until"))
	var earliest time.Time
	for i, b := range native {
		if at := rcFloorS(rcTSms(b.high)); i == 0 || at.Before(earliest) {
			earliest = at
		}
	}
	j.needC(!valid.After(earliest), "admission-extends-native-window")
}

// checkSnapshotFiles is check_snapshot_files.
func (j *rcJudge) checkSnapshotFiles(c *rcCase) (issuance, evaluation *rcObj) {
	rawIssuance, rawEvaluation := c.p("trust/handoff-issuance.json"), c.p("trust/handoff-evaluation.json")
	j.checkTrustSnapshot(rawIssuance)
	j.needC(rcClosed(rawEvaluation, rcEvaluationFields), "evaluation-fields")
	j.needC(rcEq(rcItem(rawEvaluation, "workflow_id"), rcItem(rawIssuance, "workflow_id")), "evaluation-workflow")
	issued := &rcDict{}
	for _, k := range rcIter(rcItem(rawIssuance, "keys")) {
		issued.set(rcItem(k, "key_id"), k)
	}
	for _, key := range rcIter(rcItem(rawEvaluation, "keys")) {
		j.needC(rcClosed(key, rcKeyFields), "evaluation-key-fields")
		if old, found := issued.get(rcItem(key, "key_id")); found {
			j.needC(sameKeyBinding(old, key), "key-rebound")
		}
	}
	return rcObjOf(rawIssuance), rcObjOf(rawEvaluation)
}

func sameKeyBinding(old, key any) bool {
	for _, field := range []string{"public_key_hex", "issuer", "role"} {
		if !rcEq(rcItem(old, field), rcItem(key, field)) {
			return false
		}
	}
	return true
}

// checkSignatureTrust is check_signature_trust: the handoff or resolution
// signature, the evaluation trust, and each recorded dispatch's authority.
func (j *rcJudge) checkSignatureTrust(c *rcCase, ctx *rcCtx) {
	issuance, evaluation := j.checkSnapshotFiles(c)
	if ctx.reissueOf != nil {
		j.verifyResolution(c, ctx, issuance)
		return
	}
	record := ctx.record
	op := record.item("operation_id")
	good := map[string]*rcObj{}
	var first *rcFinding
	for _, file := range j.run.filesIn("signer", ".handoff.json") {
		if j.otherOperation(file.data, op) {
			continue
		}
		verifyFile := file
		if found := rcTry(func() {
			good[rcFileRef(verifyFile.data)] = j.verifyEnvelope(rcHandoff, verifyFile.data, record, issuance)
		}); found != nil && first == nil {
			first = found
		}
	}
	if len(good) == 0 {
		if first != nil {
			panic(*first)
		}
		j.fail(rcAbsent, "no-handoff")
	}
	ctx.handoffs, ctx.evaluation, ctx.issuance = good, evaluation, issuance
	if trust, ok := j.run.read("trust/handoff-evaluation.json"); ok {
		ctx.evaluationRef = rcFileRef(trust)
	} else {
		ctx.evaluationRef = c.rawRef("trust/handoff-evaluation.json")
	}
	for _, attempt := range ctx.dispatches {
		j.authorizeAttempt(c, ctx, attempt)
	}
}

// otherOperation is the reference's pre-filter: a signer file whose payload
// names another operation is not this case's handoff.
func (j *rcJudge) otherOperation(data []byte, op any) bool {
	skip := false
	_ = rcCatch(func() {
		env := rcParse(data)
		if e, ok := env.(*rcObj); ok {
			if payload, isObj := e.get("payload").(*rcObj); isObj {
				skip = !rcEq(payload.get("operation_id"), op)
			}
		}
	}, "ValueError")
	return skip
}

// authorizeAttempt is _authorize_attempt.
func (j *rcJudge) authorizeAttempt(c *rcCase, ctx *rcCtx, attempt *rcObj) {
	payload, known := rcStrMapGet(ctx.handoffs, attempt.item("handoff_file_ref"))
	j.needC(known, "attempt-handoff-unknown")
	j.needC(rcEqStr(attempt.item("trust_evaluation_file_ref"), ctx.evaluationRef), "attempt-evaluation-ref")
	j.needC(rcIn(payload.item("trust_snapshot_ref"), ctx.evaluation.item("accepted_issuance_snapshots")), "issuance-snapshot-not-accepted")
	var issued, current []*rcObj
	for _, k := range rcIter(ctx.issuance.item("keys")) {
		if rcEq(rcItem(k, "key_id"), payload.item("key_id")) {
			issued = append(issued, rcObjOf(k))
		}
	}
	for _, k := range rcIter(ctx.evaluation.item("keys")) {
		if rcEq(rcItem(k, "key_id"), payload.item("key_id")) {
			current = append(current, rcObjOf(k))
		}
	}
	j.needC(len(issued) == 1 && len(current) == 1, "evaluation-key-unknown")
	j.needC(rcEqStr(current[0].item("role"), rcSignerRole), "key-role")
	atValue, found := ctx.dispatchTimes.get(attempt.item("attempt_id"))
	j.needA(found, "dispatch-time-missing")
	at, _ := atValue.(time.Time)
	keys := []*rcObj{issued[0], current[0]}
	for _, key := range keys {
		if revoked := key.item("revoked_at"); revoked != nil {
			j.needC(at.Before(rcFloorS(rcTSs(revoked))), "key-revoked-at-dispatch")
		}
	}
	lower, upper := dispatchBounds(payload, ctx.record, keys, c.nativeBounds())
	j.needC(lower.Before(upper), "dispatch-window-empty")
	j.needC(!lower.After(at), "dispatch-before-window")
	j.needC(at.Before(upper), "dispatch-after-window")
}

// dispatchBounds is _dispatch_bounds: the latest lower and earliest upper bound
// of the handoff, the record, both keys and the native windows.
func dispatchBounds(payload, record *rcObj, keys []*rcObj, native []rcBound) (lower, upper time.Time) {
	lowers := []time.Time{rcTSs(payload.item("not_before")), rcTSs(record.item("committed_at"))}
	uppers := []time.Time{rcTSs(payload.item("valid_until")), rcTSs(record.item("valid_until"))}
	for _, key := range keys {
		lowers = append(lowers, rcTSs(key.item("not_before")))
		uppers = append(uppers, rcTSs(key.item("not_after")))
	}
	for _, b := range native {
		lowers = append(lowers, rcCeilS(rcTSms(b.low)))
		uppers = append(uppers, rcFloorS(rcTSms(b.high)))
	}
	lower, upper = lowers[0], uppers[0]
	for _, t := range lowers {
		if t.After(lower) {
			lower = t
		}
	}
	for _, t := range uppers {
		if t.Before(upper) {
			upper = t
		}
	}
	return lower, upper
}

// verifyResolution is _verify_resolution: a reissue is established by a signed
// resolution of the original record.
func (j *rcJudge) verifyResolution(c *rcCase, ctx *rcCtx, issuance *rcObj) {
	original := ctx.reissueOf
	j.admissionRecordRef(original)
	var found *rcFinding
	for _, file := range j.run.filesIn("signer", ".resolution.json") {
		var payload *rcObj
		resolutionFile := file
		if failure := rcTry(func() { payload = j.verifyEnvelope(rcResolution, resolutionFile.data, original, issuance) }); failure != nil {
			if found == nil {
				found = failure
			}
			continue
		}
		if !rcEq(payload.item("presented_approval_ref"), c.approvalID) {
			continue
		}
		j.needC(rcEq(payload.item("presented_inputs"), c.inputRefs()), "presented-inputs")
		j.needC(!rcEq(payload.item("presented_approval_ref"), original.item("approval_ref")), "resolution-same-receipt")
		ctx.resolutionRef = rcFileRef(file.data)
		return
	}
	if found != nil {
		panic(*found)
	}
	j.fail(rcAbsent, "no-resolution")
}
