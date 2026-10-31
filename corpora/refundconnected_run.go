package corpora

// Steps 5 and 6 of the refund-connected reader and the judgement of a case and of
// a whole run: the executor's streams, the provider's record, the report cutoff,
// the checks over the run, and the verdicts per case. Each function answers what
// the same-named function of packaging/agent_evidence_vectors/refundconnected.py
// answers, including the exceptions that reference does not catch.

import (
	"fmt"
	"strconv"
	"strings"
)

// ----------------------------------------------------------------------------
// The executor's streams and the provider's record.
// ----------------------------------------------------------------------------

type rcStreamSpec struct {
	name, schema string
	extra        []string
}

var (
	rcCommon = []string{
		"schema", "contract_revision", "run_id", "workflow_id", "admission_issuer", "provider_namespace",
		"operation_id", "recorded_at", "admission_ref", "idempotency_key",
	}
	rcStreamSpecs = []rcStreamSpec{
		{"attempts", "refund-sandbox-attempt/0.1", []string{
			"attempt_id", "kind", "handoff_file_ref", "trust_evaluation_file_ref", "tool", "arguments",
			"arguments_digest", "started_at",
		}},
		{"outcomes", "refund-sandbox-outcome/0.1", []string{
			"attempt_id", "attempt_ref", "status", "effect_ref", "observation_ref",
		}},
		{"effects", "refund-sandbox-effect/0.1", []string{
			"effect_id", "attempt_id", "attempt_ref", "arguments", "arguments_digest", "committed_at",
		}},
		{"observations", "refund-sandbox-observation/0.1", []string{
			"observation_id", "observation_kind", "attempt_id", "attempt_ref", "source_file_ref",
			"effect_refs", "observed_at",
		}},
	}
	rcReportFields = []string{
		"schema", "contract_revision", "run_id", "scenario_id", "workflow_id", "admission_issuer",
		"provider_namespace", "report_cutoff",
	}
)

// rcStreams is Streams: the four execution streams, the dispatch instants and the
// provider's record, with the first problem found reading them.
type rcStreams struct {
	records       map[string][]*rcObj
	problem       *rcFinding
	dispatchTimes *rcDict
	sim           *rcObj
}

func newRCStreams(run rcRun) *rcStreams {
	st := &rcStreams{records: map[string][]*rcObj{}, dispatchTimes: &rcDict{}}
	for _, spec := range rcStreamSpecs {
		st.records[spec.name] = st.readStream(run, spec)
	}
	st.readDispatchTimes(run)
	st.sim, _ = run.json("sim/sim.json").(*rcObj)
	return st
}

// note keeps the first problem, as `self.problem = self.problem or ...` does.
func (st *rcStreams) note(code string) {
	if st.problem == nil {
		st.problem = &rcFinding{kind: rcContra, code: code}
	}
}

func (st *rcStreams) readStream(run rcRun, spec rcStreamSpec) []*rcObj {
	fields := append(append([]string{}, rcCommon...), spec.extra...)
	var rows []*rcObj
	for _, line := range run.lines("executor/" + spec.name + ".jsonl") {
		var row any
		if rcCatch(func() { row = rcParse(line) }, "ValueError") != nil {
			st.note(spec.name + "-parse")
			continue
		}
		obj, ok := row.(*rcObj)
		if !ok || !rcKeysAre(obj, fields...) || !rcEqStr(obj.m["schema"], spec.schema) ||
			!rcEqStr(obj.m["contract_revision"], rcRevision) {
			st.note(spec.name + "-fields")
			continue
		}
		rows = append(rows, obj)
	}
	return rows
}

func (st *rcStreams) readDispatchTimes(run rcRun) {
	for _, line := range run.lines("executor/raw/dispatch-times.jsonl") {
		failed := rcCatch(func() {
			entry := rcParse(line)
			at := rcTSexact(rcItem(entry, "at"))
			st.dispatchTimes.set(rcItem(entry, "attempt_id"), at)
		}, "ValueError", "KeyError", "TypeError")
		if failed != nil {
			st.note("dispatch-times-parse")
		}
	}
}

// of is Streams.of with one match: the rows of a stream whose field equals value.
func (st *rcStreams) of(name, field string, value any) []*rcObj {
	var out []*rcObj
	for _, row := range st.records[name] {
		if rcEq(row.get(field), value) {
			out = append(out, row)
		}
	}
	return out
}

// applyCount is the number of apply requests the provider recorded under key.
func (st *rcStreams) applyCount(key string) int {
	if st.sim == nil {
		return 0
	}
	n := 0
	for _, r := range rcIter(rcGetDefault(st.sim, "requests", []any{})) {
		if rcEqStr(rcGet(r, "kind"), "apply") && rcEqStr(rcGet(r, "idempotency_key"), key) {
			n++
		}
	}
	return n
}

// rcPrefixSha is "sha256:" + digest, which raises TypeError for a digest that is
// not a str.
func rcPrefixSha(digest any) string {
	s, ok := digest.(string)
	if !ok {
		rcRaise("TypeError", "can only concatenate str to str")
	}
	return "sha256:" + s
}

// rcScopeEq is all(a[k] == b[k] for k in SCOPE).
func rcScopeEq(a any, b *rcObj) bool {
	for _, name := range rcScope {
		if !rcEq(rcItem(a, name), b.item(name)) {
			return false
		}
	}
	return true
}

// rcDigestMatches is `row["arguments_digest"] == digest == "sha256:" + pic digest`
// with digest the reference of the row's own arguments.
func rcDigestMatches(row *rcObj, c *rcCase) bool {
	digest := rcFileRef(rcJCS(row.item("arguments")))
	return rcEqStr(row.item("arguments_digest"), digest) && digest == rcPrefixSha(c.picArgsDigest)
}

// ----------------------------------------------------------------------------
// Step 5: execution.
// ----------------------------------------------------------------------------

func (j *rcJudge) checkExecution(c *rcCase, ctx *rcCtx) {
	record := ctx.record
	op := record.item("operation_id")
	key := idempotencyKey(record)
	ctx.key = key
	attempts := j.st.of("attempts", "operation_id", op)
	j.needA(len(attempts) > 0, "no-dispatch-attempt")
	var dispatches []*rcObj
	for _, a := range attempts {
		if rcEqStr(a.item("kind"), "dispatch") {
			dispatches = append(dispatches, a)
		}
	}
	j.needA(len(dispatches) > 0, "no-dispatch-attempt")
	for number, attempt := range attempts {
		j.checkAttempt(c, ctx, attempt, rcStr(op)+"-a"+strconv.Itoa(number+1))
	}
	ctx.attempts, ctx.dispatches = attempts, dispatches
	ctx.dispatchTimes = j.st.dispatchTimes
	j.checkProviderRecord(c, ctx, len(dispatches))
}

func (j *rcJudge) checkAttempt(c *rcCase, ctx *rcCtx, attempt *rcObj, wantID string) {
	record := ctx.record
	j.needC(rcEqStr(attempt.item("attempt_id"), wantID), "attempt-id-sequence")
	j.needC(rcEqStr(attempt.item("run_id"), c.runID), "attempt-run-id")
	j.needC(rcScopeEq(attempt, record), "attempt-scope")
	j.needC(rcEqStr(attempt.item("idempotency_key"), ctx.key), "idempotency-key")
	j.needC(rcEqStr(attempt.item("admission_ref"), rcRefOf(record)), "attempt-admission-ref")
	j.needC(rcStrMapHas(ctx.handoffs, attempt.item("handoff_file_ref")), "attempt-handoff-unknown")
	j.needC(rcEqStr(attempt.item("tool"), "refund") && (rcEqStr(attempt.item("kind"), "dispatch") ||
		rcEqStr(attempt.item("kind"), "reconcile_lookup")), "attempt-kind")
	j.needC(rcTypedEq(attempt.item("arguments"), record.item("arguments")), "attempt-arguments")
	j.needC(rcDigestMatches(attempt, c), "arguments-digest")
}

// checkProviderRecord holds the provider's apply count and the operations file
// against the admitted record.
func (j *rcJudge) checkProviderRecord(c *rcCase, ctx *rcCtx, dispatches int) {
	if j.st.sim == nil {
		j.fail(rcAbsent, "provider-record-missing")
		return
	}
	j.needC(j.st.applyCount(ctx.key) == dispatches, "apply-count")
	if ctx.operations == nil {
		return
	}
	record := ctx.record
	stored, isObj := ctx.operations.get(ctx.key).(*rcObj)
	j.needC(isObj && rcEq(stored.get("operation_id"), record.item("operation_id")) &&
		rcEq(stored.get("pic_args_digest"), c.picArgsDigest) &&
		rcTypedEq(stored.get("arguments"), record.item("arguments")), "operation-record")
}

// ----------------------------------------------------------------------------
// Step 6: the observed effect.
// ----------------------------------------------------------------------------

func (j *rcJudge) checkEffect(c *rcCase, ctx *rcCtx) {
	attempts := &rcDict{}
	for _, a := range ctx.attempts {
		attempts.set(a.item("attempt_id"), a)
	}
	effect := j.keyedEffect(c, ctx, attempts)
	effectRef := rcRefOf(effect)
	good := j.readBack(ctx, effect, effectRef)
	j.needC(rcEqStr(good.item("attempt_ref"), rcRefOf(rcObjOf(attempts.item(good.item("attempt_id"))))), "observation-attempt")
	var outcomes []*rcObj
	for _, o := range j.st.of("outcomes", "idempotency_key", ctx.key) {
		if rcEqStr(o.item("status"), "observed_success") && rcEqStr(o.item("effect_ref"), effectRef) &&
			rcEqStr(o.item("observation_ref"), rcRefOf(good)) {
			outcomes = append(outcomes, o)
		}
	}
	j.needA(len(outcomes) == 1, "outcome-missing")
	if len(outcomes) == 0 {
		rcRaise("IndexError", "list index out of range")
	}
	outcome := outcomes[0]
	j.needC(rcEqStr(outcome.item("attempt_ref"), rcRefOf(rcObjOf(attempts.item(outcome.item("attempt_id"))))), "outcome-attempt")
	j.checkCutoff(c, ctx.record, good, outcome)
}

// keyedEffect is the one effect recorded under the case's key, held to the
// admitted record and to the dispatch it names.
func (j *rcJudge) keyedEffect(c *rcCase, ctx *rcCtx, attempts *rcDict) *rcObj {
	record := ctx.record
	op := record.item("operation_id")
	keyed := j.st.of("effects", "idempotency_key", ctx.key)
	bound := true
	for _, e := range keyed {
		if !rcEq(e.item("operation_id"), op) {
			bound = false
			break
		}
	}
	j.needC(bound, "effect-operation-id-binding")
	j.needC(len(keyed) <= 1, "effect-count-per-key")
	j.needA(len(keyed) == 1, "effect-missing")
	if len(keyed) == 0 {
		rcRaise("IndexError", "list index out of range")
	}
	effect := keyed[0]
	j.needC(rcScopeEq(effect, record) && rcEqStr(effect.item("admission_ref"), rcRefOf(record)), "effect-scope")
	j.needC(rcTypedEq(effect.item("arguments"), record.item("arguments")), "effect-arguments")
	j.needC(rcDigestMatches(effect, c), "effect-arguments-digest")
	origin, _ := attempts.get(effect.item("attempt_id"))
	j.needC(originIsDispatch(origin, effect, ctx.dispatches), "effect-attempt")
	return effect
}

func originIsDispatch(origin any, effect *rcObj, dispatches []*rcObj) bool {
	o, ok := origin.(*rcObj)
	if !ok || !rcEqStr(o.item("kind"), "dispatch") || !rcEqStr(effect.item("attempt_ref"), rcRefOf(o)) {
		return false
	}
	for _, d := range dispatches {
		if rcEq(o, d) {
			return true
		}
	}
	return false
}

// readBack is the first observation of the effect whose retained provider
// snapshot agrees with the effect.
func (j *rcJudge) readBack(ctx *rcCtx, effect *rcObj, effectRef string) *rcObj {
	var observed []*rcObj
	for _, o := range j.st.of("observations", "idempotency_key", ctx.key) {
		if rcEqStr(o.item("observation_kind"), "effect_present") && rcIn(effectRef, o.item("effect_refs")) {
			observed = append(observed, o)
		}
	}
	j.needA(len(observed) > 0, "observation-missing")
	for _, obs := range observed {
		if j.snapshotAgrees(ctx, effect, obs) {
			return obs
		}
	}
	j.fail(rcContra, "readback-disagrees")
	return nil
}

func (j *rcJudge) snapshotAgrees(ctx *rcCtx, effect, obs *rcObj) bool {
	raw, ok := j.run.read("executor/raw/" + rcStr(obs.item("observation_id")) + ".json")
	if !ok || !rcEqStr(obs.item("source_file_ref"), rcFileRef(raw)) {
		return false
	}
	var snapshot any
	if rcCatch(func() { snapshot = rcParse(raw) }, "ValueError") != nil {
		return false
	}
	var rows []any
	for _, r := range rcIter(rcGetDefault(snapshot, "ledger", []any{})) {
		if rcEq(rcGet(r, "effect_id"), effect.item("effect_id")) {
			rows = append(rows, r)
		}
	}
	if len(rows) != 1 {
		return false
	}
	row := rows[0]
	return rcEq(rcGet(row, "operation_id"), ctx.record.item("operation_id")) &&
		rcEq(rcGet(row, "idempotency_key"), ctx.key) &&
		rcTypedEq(rcGet(row, "arguments"), ctx.record.item("arguments")) &&
		rcEq(rcGet(row, "attempt_id"), effect.item("attempt_id")) &&
		ledgerHoldsKeyOnce(snapshot, ctx.key)
}

func ledgerHoldsKeyOnce(snapshot any, key string) bool {
	n := 0
	for _, r := range rcIter(rcItem(snapshot, "ledger")) {
		if rcEq(rcGet(r, "idempotency_key"), key) {
			n++
		}
	}
	return n == 1
}

// checkCutoff is _check_cutoff: the effect's observation and outcome were recorded
// by the instant the report was cut off.
func (j *rcJudge) checkCutoff(c *rcCase, record, obs, outcome *rcObj) {
	scenario := strings.ToLower(strings.Split(c.name, "-")[0])
	raw, ok := j.run.read("executor/report-context-" + scenario + ".json")
	if !ok {
		j.fail(rcAbsent, "report-context-missing")
		return
	}
	var context any
	if rcCatch(func() { context = rcParse(raw) }, "ValueError") != nil {
		j.fail(rcContra, "report-context-fields")
		return
	}
	obj, isObj := context.(*rcObj)
	j.needC(isObj && rcKeysAre(obj, rcReportFields...), "report-context-fields")
	j.needC(rcEqStr(rcItem(context, "run_id"), c.runID) && rcScopeEq(context, record), "report-context-scope")
	var within bool
	if rcCatch(func() { within = withinCutoff(rcItem(context, "report_cutoff"), obs, outcome) }, "ValueError") != nil {
		j.fail(rcContra, "report-context-time")
		return
	}
	j.needA(within, "success-after-cutoff")
}

// withinCutoff evaluates all(ts_s(x) <= cutoff ...) lazily: it stops at the first
// instant past the cutoff, so a later malformed timestamp never raises.
func withinCutoff(cutoffValue any, obs, outcome *rcObj) bool {
	cutoff := rcTSms(cutoffValue)
	for _, x := range []any{obs.item("observed_at"), obs.item("recorded_at"), outcome.item("recorded_at")} {
		if rcTSs(x).After(cutoff) {
			return false
		}
	}
	return true
}

// ----------------------------------------------------------------------------
// Judging a case.
// ----------------------------------------------------------------------------

func rcVerdict(kind, code string) string { return rcFinding{kind: kind, code: code}.verdict() }

// attempt is the closure of judge_case: it records the step's verdict and says
// whether the step held.
func (j *rcJudge) attempt(out map[string]string, step string, fn func()) bool {
	if found := rcTry(fn); found != nil {
		out[step] = found.verdict()
		return false
	}
	out[step] = rcEstablished
	return true
}

// judgeCase is judge_case: six verdicts for one case directory.
func (j *rcJudge) judgeCase(name string) map[string]string {
	c := newRCCase(j.run, name)
	out := map[string]string{}
	for _, step := range rcSteps {
		out[step] = rcNotReached
	}
	if pic := rcTry(func() { j.checkPic(c) }); pic != nil {
		out["input_pic"] = pic.verdict()
		if pic.kind == rcRefused && j.runnerAllowedRefused(c) && name != "" {
			out["input_pic"] = rcVerdict(rcContra, "runner-allowed-"+pic.code)
		}
		j.downstream(out, c, "")
		return out
	}
	consumed := j.consumedAt(c)
	out["input_pic"] = rcEstablished
	if found := rcTry(func() { j.checkAPS(c, consumed) }); found != nil {
		out["input_aps"] = found.verdict()
		j.downstream(out, c, found.code)
		return out
	}
	out["input_aps"] = rcEstablished
	ctx := &rcCtx{operations: j.ops}
	if !j.attempt(out, "admission", func() { j.checkAdmission(c, ctx) }) {
		return out
	}
	if ctx.reissueOf != nil {
		j.reissue(out, c, ctx)
		return out
	}
	j.judgeDispatch(out, c, ctx)
	return out
}

// judgeDispatch is the tail of judge_case for a case with a committed record.
func (j *rcJudge) judgeDispatch(out map[string]string, c *rcCase, ctx *rcCtx) {
	ctx.key = idempotencyKey(ctx.record)
	for _, a := range j.st.of("attempts", "operation_id", ctx.record.item("operation_id")) {
		if rcEqStr(a.item("kind"), "dispatch") {
			ctx.dispatches = append(ctx.dispatches, a)
		}
	}
	ctx.dispatchTimes = j.st.dispatchTimes
	if !j.attempt(out, "signature_trust", func() { j.checkSignatureTrust(c, ctx) }) {
		return
	}
	if !j.attempt(out, "execution", func() { j.checkExecution(c, ctx) }) {
		return
	}
	j.attempt(out, "observed_effect", func() { j.checkEffect(c, ctx) })
	j.store[c.name] = ctx
}

// consumedAt is the instant the approval counts as consumed: the committed record's
// time when one exists, the runner's evaluation time otherwise.
func (j *rcJudge) consumedAt(c *rcCase) string {
	consumed := c.picEvaluatedAt
	var mine []*rcObj
	for _, r := range j.adm.forDecision(rcStr(c.claim.item("decision_id"))) {
		if rcEq(r.get("approval_ref"), c.claim.item("approval_ref")) {
			mine = append(mine, r)
		}
	}
	if len(mine) > 0 {
		if at, ok := mine[0].get("committed_at").(string); ok {
			consumed = strings.ReplaceAll(at, "Z", ".000Z")
		}
	}
	return consumed
}

// reissue is _reissue: a signed resolution of the original record ends the case
// without a second dispatch.
func (j *rcJudge) reissue(out map[string]string, c *rcCase, ctx *rcCtx) {
	if !j.attempt(out, "signature_trust", func() { j.checkSignatureTrust(c, ctx) }) {
		return
	}
	// A resolution authorizes nothing: no attempt may name it as its handoff.
	for _, a := range j.st.records["attempts"] {
		if rcEqStr(a.item("handoff_file_ref"), ctx.resolutionRef) {
			out["execution"] = rcVerdict(rcContra, "resolution-used-as-handoff")
			return
		}
	}
	out["execution"], out["observed_effect"], out["admission"] = rcNotReached, rcNotReached, rcEstablished
}

// downstream is _downstream_check: after a refusal at an input layer nothing
// downstream may exist for the case.
func (j *rcJudge) downstream(out map[string]string, c *rcCase, code string) {
	var decision, approval any
	if c.claim != nil {
		decision, approval = c.claim.item("decision_id"), c.claim.item("approval_ref")
	} else {
		decision = rcGet(c.claimText(), "decision_id")
		approval = rcGet(c.claimText(), "approval_ref")
	}
	var refs *rcObj
	if len(c.missing) == 0 && len(c.bad) == 0 {
		refs = c.inputRefs()
	}
	for _, r := range j.adm.forDecision(rcStr(decision)) {
		if rcEq(r.get("approval_ref"), approval) && (refs == nil || len(refs.keys) == 0 || recordCarries(r, refs)) {
			out["admission"] = rcVerdict(rcContra, "admitted-after-refusal")
			return
		}
	}
	if rcIn(approval, j.adm.consumed) && code != "APPROVAL_AFTER_CONSUMPTION" {
		out["admission"] = rcVerdict(rcContra, "consumed-after-refusal")
	}
}

// recordCarries is all(r.get(field) == ref for field, ref in refs.items()).
func recordCarries(r, refs *rcObj) bool {
	for _, field := range refs.keys {
		if !rcEq(r.get(field), refs.m[field]) {
			return false
		}
	}
	return true
}

// claimText is _claim_text: the PIC claim parsed from the proposal, or an empty
// dict when any step of reading it fails in one of the ways the reference catches.
func (c *rcCase) claimText() any {
	var doc any
	failed := rcCatch(func() {
		text := rcItem(rcFirst(rcItem(c.parsed["inputs/pic-proposal.json"], "claims")), "text")
		s, ok := text.(string)
		if !ok {
			rcRaise("AttributeError", "text has no encode")
		}
		doc = rcParse(rcUTF8(s))
	}, "TypeError", "KeyError", "IndexError", "ValueError", "AttributeError")
	if failed != nil {
		return &rcObj{m: map[string]any{}}
	}
	return doc
}

// rcCaseOK is case_ok: the case ended where a case may end.
func rcCaseOK(steps map[string]string) bool {
	for position, step := range rcSteps {
		verdict := steps[step]
		if verdict == rcEstablished {
			continue
		}
		if strings.HasPrefix(verdict, "REFUSED:") || verdict == rcNotReached {
			for _, later := range rcSteps[position+1:] {
				if steps[later] != rcNotReached {
					return false
				}
			}
			return verdict != rcNotReached || position > 0
		}
		return false
	}
	return true
}

// ----------------------------------------------------------------------------
// Checks over the whole run.
// ----------------------------------------------------------------------------

// rcAdmitted is the admitted records of the run by idempotency key, in the order
// the keys were first seen; a later case with the same key replaces the record.
type rcAdmitted struct {
	keys    []string
	records map[string]*rcObj
}

func (a *rcAdmitted) put(key string, record *rcObj) {
	if _, seen := a.records[key]; !seen {
		a.keys = append(a.keys, key)
	}
	a.records[key] = record
}

type rcCheck struct{ name, verdict string }

func (j *rcJudge) admittedRecords(names []string) *rcAdmitted {
	admitted := &rcAdmitted{records: map[string]*rcObj{}}
	for _, name := range names {
		if ctx := j.store[name]; ctx != nil && ctx.record != nil {
			admitted.put(idempotencyKey(ctx.record), ctx.record)
		}
	}
	return admitted
}

// runChecks is run_checks, in the order the reference lists the checks.
func (j *rcJudge) runChecks(names []string) []rcCheck {
	admitted := j.admittedRecords(names)
	perKey := j.effectCountPerKey()
	orphans := j.noOrphans(admitted)
	alternates := j.noAlternates(admitted)
	replay := j.replaySingle(admitted)
	count := j.effectCount(admitted)
	return []rcCheck{
		{"effect_count_per_key", perKey}, {"no_orphan_records", orphans},
		{"no_alternate_arguments", alternates}, {"replay_single_effect", replay}, {"effect_count", count},
	}
}

func (j *rcJudge) effectCountPerKey() string {
	counts := &rcDict{}
	for _, row := range j.st.records["effects"] {
		key := row.item("idempotency_key")
		n := 0
		if seen, ok := counts.get(key); ok {
			n = seen.(int)
		}
		counts.set(key, n+1)
	}
	verdict := rcEstablished
	for _, v := range counts.vals {
		if n := v.(int); n > 1 {
			verdict = rcVerdict(rcContra, fmt.Sprintf("%d-effects-for-one-key", n))
		}
	}
	return verdict
}

func (j *rcJudge) noOrphans(admitted *rcAdmitted) string {
	orphan := false
	for _, spec := range rcStreamSpecs {
		for _, r := range j.st.records[spec.name] {
			if !rcStrMapHas(admitted.records, r.item("idempotency_key")) {
				orphan = true
			}
		}
	}
	if orphan {
		return rcVerdict(rcContra, "record-without-verified-admission")
	}
	return rcEstablished
}

func (j *rcJudge) noAlternates(admitted *rcAdmitted) string {
	alternates := false
	for _, key := range admitted.keys {
		record := admitted.records[key]
		for _, stream := range []string{"attempts", "effects"} {
			for _, row := range j.st.of(stream, "idempotency_key", key) {
				alternates = alternates || !rcTypedEq(row.item("arguments"), record.item("arguments"))
			}
		}
		if j.st.sim == nil {
			continue
		}
		for _, row := range rcIter(rcGetDefault(j.st.sim, "ledger", []any{})) {
			if rcEq(rcGet(row, "idempotency_key"), key) && !rcTypedEq(rcGet(row, "arguments"), record.item("arguments")) {
				alternates = true
			}
		}
	}
	if alternates {
		return rcVerdict(rcContra, "arguments-differ-from-admission")
	}
	return rcEstablished
}

func (j *rcJudge) replaySingle(admitted *rcAdmitted) string {
	replay := rcEstablished
	for _, key := range admitted.keys {
		record := admitted.records[key]
		handoffs := 0
		for _, f := range j.run.filesIn("signer", ".handoff.json") {
			if rcEq(rcHandoffOp(f.data), record.item("operation_id")) {
				handoffs++
			}
		}
		applies := j.st.applyCount(key)
		if handoffs > 1 && (len(j.st.of("effects", "idempotency_key", key)) != 1 || applies != 1) {
			replay = rcVerdict(rcContra, "replayed-handoff-redispatched")
		}
	}
	return replay
}

// rcHandoffOp is _handoff_op: the operation a signed handoff names, or none.
func rcHandoffOp(data []byte) any {
	var op any
	failed := rcCatch(func() {
		op = rcItem(rcItem(rcParse(data), "payload"), "operation_id")
	}, "ValueError", "KeyError", "TypeError")
	if failed != nil {
		return nil
	}
	return op
}

func (j *rcJudge) effectCount(admitted *rcAdmitted) string {
	total := len(j.st.records["effects"])
	ledger := total
	if j.st.sim != nil {
		ledger = rcLen(rcGetDefault(j.st.sim, "ledger", []any{}))
	}
	if total == ledger && total == j.admittedEffects(admitted) {
		return rcEstablished
	}
	return rcVerdict(rcContra, fmt.Sprintf("effects-%d-ledger-%d", total, ledger))
}

func (j *rcJudge) admittedEffects(admitted *rcAdmitted) int {
	n := 0
	for _, e := range j.st.records["effects"] {
		if rcStrMapHas(admitted.records, e.item("idempotency_key")) {
			n++
		}
	}
	return n
}

// ----------------------------------------------------------------------------
// Judging a run.
// ----------------------------------------------------------------------------

// rcResult is what judge_run returns: the verdicts of every case and the checks
// over the run.
type rcResult struct {
	cases  []string
	steps  map[string]map[string]string
	checks []rcCheck
	ok     bool
}

// rcJudgeRun is judge_run. An exception the reference does not catch ends the run
// there, and comes back as the fault; so does any other panic, because the
// reference would end the run on it as well. fired counts the failed test of each
// rule code, and skip names one rule not to apply.
func rcJudgeRun(root, skip string) (result *rcResult, fired map[string]int, fault *rcFault) {
	fired = map[string]int{}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		result = nil
		if f, ok := r.(rcFault); ok {
			fault = &f
			return
		}
		fault = &rcFault{class: "InternalError", msg: fmt.Sprint(r)}
	}()
	run := rcRun{root: root}
	j := &rcJudge{run: run, skip: skip, fired: fired, store: map[string]*rcCtx{}}
	j.adm = newRCAdmission(run)
	j.st = newRCStreams(run)
	if data, ok := run.read("executor/operations.json"); ok && len(data) > 0 {
		j.ops, _ = rcParse(data).(*rcObj)
	}
	result = &rcResult{steps: map[string]map[string]string{}}
	result.cases = run.cases()
	for _, name := range result.cases {
		result.steps[name] = j.judgeCase(name)
	}
	if j.st.problem != nil {
		for _, steps := range result.steps {
			if steps["execution"] == rcEstablished {
				steps["execution"] = j.st.problem.verdict()
			}
		}
	}
	result.checks = j.runChecks(result.cases)
	result.ok = len(result.cases) > 0
	for _, name := range result.cases {
		result.ok = result.ok && rcCaseOK(result.steps[name])
	}
	for _, check := range result.checks {
		result.ok = result.ok && check.verdict == rcEstablished
	}
	return result, fired, nil
}
