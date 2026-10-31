package corpora

// The first four steps of the refund-connected reader: the PIC proposal, the APS
// receipts, the committed admission record and the signed handoff or resolution.
// Each function answers what the same-named function of
// packaging/agent_evidence_vectors/refundconnected.py answers, including the
// uncaught exceptions of that reader (see refundconnected_value.go).

import (
	"math/big"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	rcSuite      = "refund-connected/v1"
	rcRevision   = "review-2026-10-23"
	rcWorker     = "did:example:refund-worker"
	rcBoundary   = "did:example:refund-approval-boundary"
	rcPrefix     = "https://payments.operator.example/v1/payments/"
	rcSuffix     = "/refunds"
	rcIdemTag    = "refund-sandbox-idempotency/0.1"
	rcHandoff    = "refund-sandbox-handoff/0.1"
	rcResolution = "refund-sandbox-resolution/0.1"
	rcAdmission  = "refund-sandbox-admission/0.1"
	rcTrust      = "refund-sandbox-trust/0.1"
	rcSignerRole = "admission-signer"
	rcPicSDK     = "330fdd817ef81d43461ea1787939e0d1cc87d589"

	rcEstablished = "ESTABLISHED"
	rcNotReached  = "NOT_REACHED"
	rcRefused     = "REFUSED"
	rcContra      = "CONTRADICTED"
	rcAbsent      = "NOT_ESTABLISHED"

	rcHandoffCeiling = 600 * time.Second
)

// rcSafeInt is 2**53 - 1, the largest integer an I-JSON number carries exactly.
var rcSafeInt = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 53), big.NewInt(1))

var (
	rcSteps = []string{"input_pic", "input_aps", "admission", "signature_trust", "execution", "observed_effect"}
	rcScope = []string{"workflow_id", "admission_issuer", "provider_namespace"}

	rcRefundArgs = []string{"payment_id", "amount_minor", "currency"}

	// rcInputFiles is INPUT_FILES: the record field and the retained file whose
	// raw bytes it names, in the order the reference lists them.
	rcInputFiles = []struct{ field, rel string }{
		{"pic_evidence_ref", "inputs/pic-proposal.json"},
		{"pic_verification_ref", "inputs/pic-verification.json"},
		{"pic_trust_file_ref", "trust/pic-keys.json"},
		{"aps_evidence_ref", "inputs/aps-approval.json"},
		{"aps_intent_file_ref", "inputs/aps-intent.json"},
		{"aps_action_file_ref", "inputs/aps-action.json"},
		{"aps_payload_file_ref", "inputs/aps-payload.json"},
		{"decision_evidence_ref", "inputs/decision-evidence.json"},
		{"aps_consumption_trust_ref", "trust/aps-consumption.json"},
	}

	rcAdmissionFields = []string{
		"schema", "contract_revision", "workflow_id", "admission_issuer", "provider_namespace",
		"decision_id", "operation_id", "approval_ref", "pic_evidence_ref", "pic_verification_ref",
		"pic_trust_file_ref", "aps_evidence_ref", "aps_intent_file_ref", "aps_action_file_ref",
		"aps_payload_file_ref", "decision_evidence_ref", "aps_consumption_trust_ref", "tool",
		"arguments", "state", "committed_at", "valid_until",
	}
	rcHandoffFields = []string{
		"schema", "contract_revision", "workflow_id", "admission_issuer", "provider_namespace",
		"operation_id", "admission_ref", "key_id", "trust_snapshot_ref", "issued_at", "not_before",
		"valid_until",
	}
	rcResolutionFields = []string{
		"schema", "contract_revision", "workflow_id", "admission_issuer", "provider_namespace",
		"decision_id", "operation_id", "original_admission_ref", "original_approval_ref",
		"presented_approval_ref", "presented_inputs", "disposition", "dispatch_authorized", "key_id",
		"trust_snapshot_ref", "issued_at",
	}
	rcTrustFields = []string{"schema", "workflow_id", "version", "provider_namespaces", "keys"}
	rcKeyFields   = []string{
		"key_id", "issuer", "role", "public_key_hex", "not_before", "not_after", "revoked_at",
	}
	rcEvaluationFields = []string{
		"schema", "contract_revision", "evaluation_id", "workflow_id", "selected_at",
		"accepted_issuance_snapshots", "keys",
	}
	rcAttestationFields = []string{
		"attestation_version", "tool", "impact", "provenance_ids", "args_digest", "claims_digest",
		"intent_digest", "expires_at",
	}
	rcPicResultFields = []string{
		"schema", "contract_revision", "run_id", "pic_sdk_commit", "proposal_file_ref",
		"pic_trust_file_ref", "evaluated_at", "result", "tool", "impact", "args_digest",
		"claims_digest", "intent_digest", "error_code",
	}
)

// ----------------------------------------------------------------------------
// The judge: one run directory, the rule-skip switch the mutation test turns.
// ----------------------------------------------------------------------------

// rcJudge carries what the reference keeps in module globals and arguments. skip
// names one rule code whose test is not applied; the differential test uses it
// as the mutant that every rule must be seen to matter against.
type rcJudge struct {
	run   rcRun
	adm   *rcAdmissionState
	st    *rcStreams
	ops   *rcObj
	skip  string
	fired map[string]int
	store map[string]*rcCtx
}

// rcCtx is the dict the reference threads through one case.
type rcCtx struct {
	operations    *rcObj
	reissueOf     *rcObj
	record        *rcObj
	handoffs      map[string]*rcObj
	evaluation    *rcObj
	issuance      *rcObj
	evaluationRef string
	resolutionRef string
	key           string
	attempts      []*rcObj
	dispatches    []*rcObj
	dispatchTimes *rcDict
}

// need raises the finding when cond is false. Every failed test is counted by
// code, so the mutation test can tell which rules a run exercised; the rule named
// by skip is counted and then not applied.
func (j *rcJudge) need(cond bool, kind, code string) {
	if cond {
		return
	}
	j.fired[code]++
	if code == j.skip {
		return
	}
	panic(rcFinding{kind: kind, code: code})
}

func (j *rcJudge) needR(cond bool, code string) { j.need(cond, rcRefused, code) }
func (j *rcJudge) needC(cond bool, code string) { j.need(cond, rcContra, code) }
func (j *rcJudge) needA(cond bool, code string) { j.need(cond, rcAbsent, code) }

// fail is a raise that no switch can skip: the reference raises it without a
// condition to test.
func (j *rcJudge) fail(kind, code string) { panic(rcFinding{kind: kind, code: code}) }

// ----------------------------------------------------------------------------
// The run directory and the case.
// ----------------------------------------------------------------------------

type rcRun struct{ root string }

type rcNamed struct {
	name string
	data []byte
}

func (r rcRun) path(rel string) string { return r.root + "/" + rel }

// read is RunDir.read: the raw bytes of a regular file, or none.
func (r rcRun) read(rel string) ([]byte, bool) {
	p := r.path(rel)
	info, err := os.Stat(p) // #nosec G304,G703 -- the run directory is the path the caller named
	if err != nil || info.IsDir() {
		return nil, false
	}
	data, err := os.ReadFile(p) // #nosec G304,G703 -- as above
	if err != nil {
		rcRaise("OSError", "%v", err)
	}
	return data, true
}

func (r rcRun) json(rel string) any {
	data, ok := r.read(rel)
	if !ok {
		return nil
	}
	return rcParse(data)
}

func (r rcRun) lines(rel string) [][]byte {
	data, ok := r.read(rel)
	if !ok || len(data) == 0 {
		return nil
	}
	return rcSplitLines(data)
}

func (r rcRun) cases() []string {
	entries, err := os.ReadDir(r.path("cases")) // #nosec G304,G703 -- as above
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if info, err := os.Stat(r.path("cases/" + e.Name())); err == nil && info.IsDir() { // #nosec G304,G703 -- as above
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func (r rcRun) filesIn(rel, suffix string) []rcNamed {
	entries, err := os.ReadDir(r.path(rel)) // #nosec G304,G703 -- as above
	if err != nil {
		return nil
	}
	var out []rcNamed
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		data, err := os.ReadFile(r.path(rel + "/" + e.Name())) // #nosec G304,G703 -- as above
		if err != nil {
			rcRaise("OSError", "%v", err)
		}
		out = append(out, rcNamed{e.Name(), data})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
}

// rcCase is Case: the retained files of one case plus the values derived while
// judging it. claim is nil until the PIC claim has been read.
type rcCase struct {
	run            rcRun
	name           string
	files          map[string][]byte
	missing, bad   []string
	parsed         map[string]any
	decisionID     any
	approvalID     any
	picArgs        any
	picArgsDigest  any
	attestation    *rcObj
	claim          *rcObj
	runID          string
	picEvaluatedAt string
}

func rcCaseFiles() []string {
	out := make([]string, 0, len(rcInputFiles)+2)
	for _, f := range rcInputFiles {
		out = append(out, f.rel)
	}
	return append(out, "trust/handoff-issuance.json", "trust/handoff-evaluation.json")
}

func newRCCase(run rcRun, name string) *rcCase {
	c := &rcCase{run: run, name: name, files: map[string][]byte{}, parsed: map[string]any{},
		attestation: &rcObj{m: map[string]any{}}}
	var present []string
	for _, rel := range rcCaseFiles() {
		data, ok := run.read("cases/" + name + "/" + rel)
		if !ok {
			c.missing = append(c.missing, rel)
			continue
		}
		c.files[rel] = data
		present = append(present, rel)
	}
	for _, rel := range present {
		var doc any
		if rcCatch(func() { doc = rcParse(c.files[rel]) }, "ValueError") != nil {
			c.bad = append(c.bad, rel)
			continue
		}
		c.parsed[rel] = doc
	}
	return c
}

func (c *rcCase) p(rel string) any {
	doc, ok := c.parsed[rel]
	if !ok {
		rcRaise("KeyError", "%q", rel)
	}
	return doc
}

func (c *rcCase) rawRef(rel string) string {
	data, ok := c.files[rel]
	if !ok {
		rcRaise("KeyError", "%q", rel)
	}
	return rcFileRef(data)
}

func (c *rcCase) inputRefs() *rcObj {
	refs := &rcObj{m: map[string]any{}}
	for _, f := range rcInputFiles {
		refs.keys = append(refs.keys, f.field)
		refs.m[f.field] = c.rawRef(f.rel)
	}
	return refs
}

func (j *rcJudge) inputsReady(c *rcCase) {
	j.needA(len(c.missing) == 0, "input-files-missing")
	j.needR(len(c.bad) == 0, "STRICT_PARSE")
}

// ----------------------------------------------------------------------------
// Small predicates shared by the steps.
// ----------------------------------------------------------------------------

func rcClosed(v any, want []string) bool {
	obj, ok := v.(*rcObj)
	return ok && rcKeysAre(obj, want...)
}

func rcList(v any) ([]any, bool) {
	list, ok := v.([]any)
	return list, ok
}

// rcRefundArgsOK is refund_args_ok.
func rcRefundArgsOK(v any) bool {
	obj, ok := v.(*rcObj)
	if !ok || !rcKeysAre(obj, rcRefundArgs...) {
		return false
	}
	id, isStr := obj.m["payment_id"].(string)
	if !isStr || !rcPaymentRe.MatchString(id) {
		return false
	}
	amount, isInt := obj.m["amount_minor"].(*big.Int)
	if !isInt || amount.Sign() <= 0 || amount.Cmp(rcSafeInt) > 0 {
		return false
	}
	return rcEqStr(obj.m["currency"], "EUR")
}

func rcTagRef(tag string, v any) string { return sha(append([]byte(tag+"\x00"), rcJCS(v)...)) }

// rcWithout is {k: v for k, v in o.items() if k not in drop}.
func rcWithout(o *rcObj, drop ...string) *rcObj {
	out := &rcObj{m: map[string]any{}}
	for _, k := range o.keys {
		skip := false
		for _, d := range drop {
			skip = skip || k == d
		}
		if !skip {
			out.keys = append(out.keys, k)
			out.m[k] = o.m[k]
		}
	}
	return out
}

func rcMake(pairs ...any) *rcObj {
	out := &rcObj{m: map[string]any{}}
	for i := 0; i < len(pairs); i += 2 {
		k := pairs[i].(string)
		out.keys = append(out.keys, k)
		out.m[k] = pairs[i+1] // #nosec G602 -- the call sites pass key and value pairs
	}
	return out
}

// ----------------------------------------------------------------------------
// Step 1: PIC.
// ----------------------------------------------------------------------------

func (j *rcJudge) checkPic(c *rcCase) {
	j.inputsReady(c)
	prop, keys, result := c.p("inputs/pic-proposal.json"), c.p("trust/pic-keys.json"), c.p("inputs/pic-verification.json")
	entry := j.picEntry(prop)
	att := j.picAttestation(entry)
	j.picSignature(entry, keys, att)
	args, claims := j.picProfile(prop, entry, att)
	inner := j.picClaim(entry, prop, claims, att)
	c.picArgs, c.picArgsDigest, c.attestation, c.claim = args, att.item("args_digest"), att, inner
	j.picResult(c, result, att)
	c.runID = rcStr(rcItem(result, "run_id"))
	c.picEvaluatedAt = rcStr(rcItem(result, "evaluated_at"))
}

func (j *rcJudge) picEntry(prop any) *rcObj {
	var evidence any
	if obj, ok := prop.(*rcObj); ok {
		evidence = obj.get("evidence")
	}
	good := false
	if list, ok := rcList(evidence); ok && len(list) == 1 {
		if e, isObj := list[0].(*rcObj); isObj {
			good = rcEqStr(e.get("type"), "sig")
		}
	}
	j.needR(good, "PIC_EVIDENCE")
	return rcObjOf(rcFirst(evidence))
}

func (j *rcJudge) picAttestation(entry *rcObj) *rcObj {
	var doc any
	caught := rcCatch(func() {
		payload := entry.item("payload")
		text, ok := payload.(string)
		if !ok {
			rcRaise("AttributeError", "payload has no encode")
		}
		doc = rcParse(rcUTF8(text))
	}, "KeyError", "AttributeError", "ValueError")
	if caught != nil {
		j.fail(rcRefused, "PIC_ATTESTATION")
	}
	att, ok := doc.(*rcObj)
	j.needR(ok && rcEqStr(att.get("attestation_version"), "PIC-ATT/1.0") && rcKeysAre(att, rcAttestationFields...), "PIC_ATTESTATION")
	return rcObjOf(doc)
}

func (j *rcJudge) picKeyring(keys any) {
	obj, ok := keys.(*rcObj)
	good := ok && rcKeysAre(obj, "trusted_keys", "revoked_keys") && rcIsObj(obj.m["trusted_keys"])
	_, revokedList := rcList(rcItemOr(keys, "revoked_keys"))
	j.needR(good && revokedList, "PIC_KEYRING")
}

// rcItemOr is v["key"] where a failure to subscript leaves the caller's test
// false: only used where the reference has already tested v is a dict.
func rcItemOr(v any, key string) any {
	if obj, ok := v.(*rcObj); ok {
		return obj.m[key]
	}
	return nil
}

func (j *rcJudge) picSignature(entry *rcObj, keys any, att *rcObj) {
	j.picKeyring(keys)
	keyID := entry.get("key_id")
	j.needR(rcEq(keyID, entry.get("signer")) && !rcIn(keyID, rcItem(keys, "revoked_keys")), "PIC_KEY")
	pub := rcDictGet(rcObjOf(rcItem(keys, "trusted_keys")), keyID)
	if inner, ok := pub.(*rcObj); ok {
		pub = inner.get("public_key")
	}
	pubHex, isStr := pub.(string)
	j.needR(isStr && rcHex64Re.MatchString(pubHex), "PIC_KEY")
	sigText := "" // entry.get("signature", "") is str() of whatever is there
	if v, present := entry.m["signature"]; present {
		sigText = rcStr(v)
	}
	sig, ok := rcB64(sigText)
	if !ok {
		j.fail(rcRefused, "PIC_SIGNATURE")
	}
	good := rcEqStr(entry.get("alg"), "ed25519") && rcEdVerify(rcBytesFromHex(pub), rcJCS(att), sig)
	j.needR(good, "PIC_SIGNATURE")
}

// rcDictGet is d.get(key) for a dict with str keys and any hashable lookup key.
func rcDictGet(d *rcObj, key any) any {
	rcHashable(key)
	if s, ok := key.(string); ok {
		return d.m[s]
	}
	return nil
}

func (j *rcJudge) picProfile(prop any, entry, att *rcObj) (args, claims any) {
	action := rcGet(prop, "action")
	if a, ok := action.(*rcObj); ok {
		args = a.get("args")
	}
	claims, intent := rcGet(prop, "claims"), rcGet(prop, "intent")
	a, isObj := action.(*rcObj)
	j.needR(isObj && rcEqStr(a.get("tool"), "refund") && rcEqStr(rcGet(prop, "impact"), "money") &&
		rcEqStr(att.item("tool"), "refund") && rcEqStr(att.item("impact"), "money") &&
		rcEq(att.item("provenance_ids"), []any{entry.get("id")}), "PIC_PROFILE")
	j.needR(rcRefundArgsOK(args), "PIC_PROFILE")
	j.needR(rcEqStr(att.item("args_digest"), sha(rcJCS(args))), "PIC_ARGS_DIGEST")
	j.needR(rcEqStr(att.item("claims_digest"), sha(rcJCS(claims))), "PIC_CLAIMS_DIGEST")
	text, isText := intent.(string)
	j.needR(isText && rcEqStr(att.item("intent_digest"), sha(rcUTF8(text))), "PIC_INTENT_DIGEST")
	return args, claims
}

func (j *rcJudge) picClaim(entry *rcObj, _, claims any, _ *rcObj) *rcObj {
	list, isList := rcList(claims)
	good := false
	if isList && len(list) == 1 {
		if first, ok := list[0].(*rcObj); ok && rcKeysAre(first, "text", "evidence") {
			_, textIsStr := first.m["text"].(string)
			good = rcEq(first.m["evidence"], []any{entry.get("id")}) && textIsStr
		}
	}
	j.needR(good, "PIC_CLAIM")
	text := rcItem(rcFirst(claims), "text")
	var doc any
	if rcCatch(func() {
		s, ok := text.(string)
		if !ok {
			rcRaise("AttributeError", "text has no encode")
		}
		doc = rcParse(rcUTF8(s))
	}, "ValueError") != nil {
		j.fail(rcRefused, "PIC_CLAIM")
	}
	inner, ok := doc.(*rcObj)
	good = ok && rcKeysAre(inner, "approval_ref", "decision_id") && rcEqStr(text, string(rcJCS(doc))) &&
		rcIsHex64(inner.m["approval_ref"]) && rcASCIIID(inner.m["decision_id"])
	j.needR(good, "PIC_CLAIM")
	return rcObjOf(doc)
}

func (j *rcJudge) picResult(c *rcCase, result any, att *rcObj) {
	r, isObj := result.(*rcObj)
	j.needC(isObj && rcKeysAre(r, rcPicResultFields...), "PIC_RESULT_SHAPE")
	j.needC(rcEqStr(r.item("result"), "allow") && r.item("error_code") == nil, "PIC_RESULT_BLOCKS")
	j.needC(rcEqStr(r.item("schema"), "refund-sandbox-pic-result/0.1") &&
		rcEqStr(r.item("contract_revision"), rcRevision) && rcEqStr(r.item("pic_sdk_commit"), rcPicSDK), "PIC_RESULT_SCHEMA")
	j.needC(rcEqStr(r.item("proposal_file_ref"), c.rawRef("inputs/pic-proposal.json")), "PIC_RESULT_PROPOSAL_REF")
	j.needC(rcEqStr(r.item("pic_trust_file_ref"), c.rawRef("trust/pic-keys.json")), "PIC_RESULT_TRUST_REF")
	j.needC(rcEq(r.item("args_digest"), att.item("args_digest")) &&
		rcEq(r.item("claims_digest"), att.item("claims_digest")) &&
		rcEq(r.item("intent_digest"), att.item("intent_digest")), "PIC_RESULT_DIGESTS")
	j.needC(rcEqStr(r.item("tool"), "refund") && rcEqStr(r.item("impact"), "money"), "PIC_RESULT_TOOL")
}

// runnerAllowedRefused is whether the runner's own result says allow for a
// proposal the reader refused.
func (j *rcJudge) runnerAllowedRefused(c *rcCase) bool {
	r, ok := c.parsed["inputs/pic-verification.json"].(*rcObj)
	return ok && rcEqStr(r.get("result"), "allow")
}
