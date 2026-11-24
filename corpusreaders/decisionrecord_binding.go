package corpusreaders

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// The binding checks of one action-binding attachment: action_binding (with the
// reviews and standing approvals the report carries beside it), stage_order,
// authorisation_recheck, observed_results, rationale_provenance and the
// executed specifications. Each restates the reference function of the same name.

type drecReview struct {
	stageID, shown string
	editedBy       any
}

type drecStanding struct {
	stageID, status  string
	requestsRecorded int
	maxRequests      any
	revocation       string
}

type drecBinding struct {
	att      *drecAttachment
	t        *drecTally
	reviews  []drecReview
	standing []drecStanding
}

func drecRunBinding(att *drecAttachment) (drecDim, *drecBinding) {
	b := &drecBinding{att: att, t: &drecTally{}}
	b.namesCarriedSpecs()
	b.readReviews()
	b.outcomes()
	b.coreFields()
	b.changes()
	b.standingApprovals()
	b.requests()
	b.attempts()
	return b.t.result(), b
}

// namesCarriedSpecs: each stage that names a specification names one the attachment carries.
func (b *drecBinding) namesCarriedSpecs() {
	for _, s := range b.att.stages {
		for _, k := range []string{"spec_digest", "shown_spec_digest", "approved_spec_digest"} {
			if s.has(k) && b.att.spec(s.get(k)) == nil {
				b.t.fail("%s: %s names a specification the attachment does not carry", s.id(), k)
			}
		}
	}
}

func (b *drecBinding) readReviews() {
	for _, review := range b.att.ofKind("review") {
		sid := review.id()
		ref := review.get("proposal_ref")
		if review.has("shown_bounds_digest") {
			if ref != nil {
				b.t.fail("%s: a review of bounds names a proposal", sid)
			}
			b.reviews = append(b.reviews, drecReview{sid, "proposal_not_named", nil})
			continue
		}
		if ref == nil {
			b.reviews = append(b.reviews, drecReview{sid, "proposal_not_named", nil})
			continue
		}
		proposal := b.att.stage(ref, "proposal")
		switch {
		case proposal == nil:
			b.t.fail("%s: proposal_ref %s names no proposal in the attachment", sid, drecRepr(ref))
			b.reviews = append(b.reviews, drecReview{sid, "proposal_not_named", nil})
		case drecEq(proposal.get("spec_digest"), review.get("shown_spec_digest")):
			b.reviews = append(b.reviews, drecReview{sid, "as_proposed", nil})
		default:
			editor := review.get("edited_by")
			if editor == nil {
				b.t.fail("%s: shown other than its proposal, with no editor named", sid)
			}
			b.reviews = append(b.reviews, drecReview{sid, "differs_from_proposal", editor})
		}
	}
}

func (b *drecBinding) outcomes() {
	counts := map[string]int{}
	var order []string
	for _, s := range b.att.ofKind("outcome", "standing_approval") {
		key := drecKey(s.get("review_ref"))
		if counts[key] == 0 {
			order = append(order, key)
		}
		counts[key]++
	}
	for _, key := range order {
		if counts[key] > 1 {
			b.t.fail("review %s has %d outcomes", strings.TrimPrefix(key, "str:"), counts[key])
		}
	}
	for _, outcome := range b.att.ofKind("outcome") {
		sid := outcome.id()
		review := b.att.stage(outcome.get("review_ref"), "review")
		if review == nil {
			b.t.fail("%s: answers no review in the attachment", sid)
			continue
		}
		if !drecEq(outcome.get("actor_ref"), review.get("reviewer_ref")) {
			b.t.fail("%s: given by %s, not by the person shown, %s", sid, drecRepr(outcome.get("actor_ref")),
				drecRepr(review.get("reviewer_ref")))
		}
		if !drecEq(outcome.get("outcome"), "approved") {
			continue
		}
		if review.has("shown_bounds_digest") {
			b.t.fail("%s: bounds approved as an outcome; an approval of bounds is a standing approval", sid)
		} else if !drecEq(outcome.get("approved_spec_digest"), review.get("shown_spec_digest")) {
			b.t.fail("%s: approves a digest other than the one its review was shown", sid)
		}
	}
}

func (b *drecBinding) coreFields() {
	seen := map[string]string{}
	for _, s := range b.att.ofKind("outcome", "standing_approval") {
		core, isObj := s.get("core_ref").(map[string]any)
		if !isObj {
			continue
		}
		key := drecKey(core["field"]) + "|" + drecKey(core["index"])
		if first, dup := seen[key]; dup {
			b.t.fail("%s: the core field %v already backs %s", s.id(), core["field"], first)
		} else {
			seen[key] = s.id()
		}
	}
}

// refusedDigests are the specifications a reviewer in the attachment rejected or escalated.
func (b *drecBinding) refusedDigests() map[string]bool {
	out := map[string]bool{}
	for _, outcome := range b.att.ofKind("outcome") {
		if !drecIn(outcome.get("outcome"), "rejected", "escalated") {
			continue
		}
		review := b.att.stage(outcome.get("review_ref"), "review")
		if review != nil && review.has("shown_spec_digest") {
			addTruthy(out, review.get("shown_spec_digest"))
		}
	}
	return out
}

// boundDigest is the specification an approval or a change binds.
func drecBoundDigest(s *drecStage) any {
	switch {
	case s == nil:
		return nil
	case s.kindIs("outcome"):
		return s.get("approved_spec_digest")
	case s.kindIs("change_authorisation"):
		return s.get("spec_digest")
	}
	return nil
}

func (b *drecBinding) changes() {
	parties := b.att.parties()
	refused := b.refusedDigests()
	for _, change := range b.att.ofKind("change_authorisation") {
		sid := change.id()
		origin := b.att.stage(change.get("from_ref"))
		switch {
		case origin == nil:
			b.t.fail("%s: from_ref names no approval or change", sid)
		case !origin.kindIs("change_authorisation") && !origin.isApprovedOutcome():
			if drecTruthy(origin.get("kind")) {
				b.t.fail("%s: a change starts from an approval or a change, not from %s", sid,
					drecRepr(origin.get("kind")))
			} else {
				b.t.fail("%s: from_ref names no approval or change", sid)
			}
		case drecEq(drecBoundDigest(origin), change.get("spec_digest")):
			b.t.fail("%s: names the specification it changes", sid)
		}
		if drecMember(parties, change.get("actor_ref")) {
			b.t.fail("%s: authorised by %s, the proposer or a service the attachment names", sid,
				drecRepr(change.get("actor_ref")))
		}
		if drecMember(refused, change.get("spec_digest")) {
			b.t.fail("%s: reaches a specification a reviewer rejected or escalated", sid)
		}
	}
}

// --- standing approvals ---

func (b *drecBinding) standingApprovals() {
	parties := b.att.parties()
	for _, approval := range b.att.ofKind("standing_approval") {
		sid := approval.id()
		review := b.att.stage(approval.get("review_ref"), "review")
		switch {
		case review == nil:
			b.t.fail("%s: answers no review in the attachment", sid)
		case !review.has("shown_bounds_digest"):
			b.t.fail("%s: answers a review shown a specification, not bounds", sid)
		case !drecEq(review.get("shown_bounds_digest"), approval.get("bounds_digest")):
			b.t.fail("%s: the review was shown other bounds than those approved", sid)
		}
		if review != nil && !drecEq(approval.get("actor_ref"), review.get("reviewer_ref")) {
			b.t.fail("%s: given by someone other than the person shown the bounds", sid)
		}
		if drecMember(parties, approval.get("actor_ref")) {
			b.t.fail("%s: given by %s, the proposer or a service the attachment names", sid,
				drecRepr(approval.get("actor_ref")))
		}
		b.standing = append(b.standing, b.standingEntry(approval))
	}
	for _, revocation := range b.att.ofKind("standing_revocation") {
		target := b.att.stage(revocation.get("revokes_ref"))
		if target == nil || !target.kindIs("standing_approval") {
			b.t.fail("%s: revokes no standing approval", revocation.id())
		}
	}
}

func (b *drecBinding) standingEntry(approval *drecStage) drecStanding {
	sid := approval.id()
	var requests, revocations []*drecStage
	for _, r := range b.att.ofKind("request") {
		if drecEq(r.get("authorised_by"), sid) {
			requests = append(requests, r)
		}
	}
	for _, r := range b.att.ofKind("standing_revocation") {
		if drecEq(r.get("revokes_ref"), sid) {
			revocations = append(revocations, r)
		}
	}
	status, bounds, why := drecReadStandingBounds(approval)
	entry := drecStanding{stageID: sid, status: status, requestsRecorded: len(requests), revocation: "none_recorded"}
	if status == drecVerified {
		entry.maxRequests = bounds["max_requests"]
	}
	if len(revocations) > 0 {
		entry.revocation = "recorded"
	}
	switch status {
	case drecFailed:
		b.t.fail("%s: %s", sid, why)
	case drecNotChecked, drecUnavailable:
		if len(requests) > 0 {
			b.t.skip("%s: %s; the requests resting on it are not checked", sid, why)
		}
	default:
		b.requestsInside(approval, bounds, requests, revocations)
	}
	return entry
}

func drecReadStandingBounds(approval *drecStage) (string, map[string]any, string) {
	content, _ := approval.get("bounds").(map[string]any)
	if !drecEq(content["availability"], "available") {
		return drecUnavailable, nil, "the bounds' bytes are unavailable"
	}
	raw := drecB64(content["bytes_b64"])
	if raw == nil {
		return drecNotChecked, nil, "the bounds' bytes cannot be decoded"
	}
	if !drecEq(drecSHA(raw), approval.get("bounds_digest")) {
		return drecFailed, nil, "the bounds' bytes are not bounds_digest's"
	}
	parsed, err := drecParse(raw, drecBounds)
	if err != nil {
		code := err.Error()
		if je, ok := err.(*drecJSONError); ok {
			code = je.Code
		}
		return drecNotChecked, nil, "the bounds cannot be read (" + code + ")"
	}
	if problem := drecBoundsProblem(parsed); problem != "" {
		return drecFailed, nil, "not well-formed bounds: " + problem
	}
	return drecVerified, parsed.(map[string]any), ""
}

func (b *drecBinding) requestsInside(approval *drecStage, bounds map[string]any, requests, revocations []*drecStage) {
	sid := approval.id()
	refused := b.refusedDigests()
	if int64(len(requests)) > drecIntValue(bounds["max_requests"]) {
		b.t.fail("%s: %d requests rest on it, max_requests is %d", sid, len(requests),
			drecIntValue(bounds["max_requests"]))
	}
	start, end := drecReadInstant(bounds["valid_from"]), drecReadInstant(bounds["valid_until"])
	for _, request := range requests {
		rid := request.id()
		at := drecReadInstant(request.get("at"))
		after, before := drecBefore(start, at), drecBefore(at, end)
		if after == nil || before == nil {
			b.t.fail("%s: its time %s cannot be placed in the period", rid, at.text)
		} else if !*after || !*before {
			b.t.fail("%s: dated outside the bounds' period", rid)
		}
		if drecMember(refused, request.get("spec_digest")) {
			b.t.fail("%s: reaches a specification a reviewer rejected or escalated", rid)
		}
		b.afterRevocation(request, revocations)
		spec := b.att.spec(request.get("spec_digest"))
		if spec == nil {
			continue // reported by namesCarriedSpecs
		}
		if spec.raw == nil {
			b.t.skip("%s: the specification's bytes are unavailable, not checked against the bounds", rid)
			continue
		}
		if problem := drecOutsideBounds(spec.raw, bounds); problem != "" {
			b.t.fail("%s: outside the bounds: %s", rid, problem)
		}
	}
}

func (b *drecBinding) afterRevocation(request *drecStage, revocations []*drecStage) {
	pos := b.att.posOf(request.get("stage_id"), -1)
	at := drecReadInstant(request.get("at"))
	for _, revocation := range revocations {
		if b.att.posOf(revocation.get("stage_id"), -1) < pos {
			b.t.fail("%s: listed after a recorded revocation", request.id())
			return
		}
		revoked := drecReadInstant(revocation.get("at"))
		order := drecBefore(revoked, at)
		if order == nil {
			b.t.fail("%s: whether it is dated after the revocation cannot be checked", request.id())
			return
		}
		if *order && revoked.sec.Cmp(at.sec) != 0 {
			b.t.fail("%s: dated after a recorded revocation", request.id())
			return
		}
	}
}

// --- requests ---

func (b *drecBinding) requests() {
	ids := map[string]string{}
	used := map[string]int{}
	perSpec := map[string]int{}
	var specOrder []string
	for _, request := range b.att.ofKind("request") {
		sid := request.id()
		rid := drecKey(request.get("request_id"))
		if first, dup := ids[rid]; dup {
			b.t.fail("%s: request_id %s is already used by %s", sid, drecRepr(request.get("request_id")), first)
		} else {
			ids[rid] = sid
		}
		basis := b.att.stage(request.get("authorised_by"))
		switch {
		case basis != nil && basis.kindIs("standing_approval"):
			continue
		case basis != nil && (basis.kindIs("change_authorisation") || basis.isApprovedOutcome()):
			if !drecEq(drecBoundDigest(basis), request.get("spec_digest")) {
				b.t.fail("%s: requests a specification other than the one %s binds", sid, basis.id())
			}
			used[basis.id()]++
			key := drecKey(request.get("spec_digest"))
			if perSpec[key] == 0 {
				specOrder = append(specOrder, key)
			}
			perSpec[key]++
		case basis != nil && basis.kindIs("outcome"):
			b.t.fail("%s: rests on an outcome that is %s, not an approval", sid, drecRepr(basis.get("outcome")))
		default:
			b.t.fail("%s: authorised_by names no approval, change or standing approval", sid)
		}
	}
	for _, change := range b.att.ofKind("change_authorisation") {
		if origin, isStr := change.get("from_ref").(string); isStr {
			used[origin]++
		}
	}
	b.limits(used, perSpec, specOrder)
}

func (b *drecBinding) limits(used, perSpec map[string]int, specOrder []string) {
	largest := map[string]int64{}
	for _, s := range b.att.stages {
		if !s.kindIs("change_authorisation") && !s.isApprovedOutcome() {
			continue
		}
		digest := drecBoundDigest(s)
		if digest == nil {
			continue
		}
		limit := int64(1)
		if v, has := s.m["request_limit"]; has && drecJSONInteger(v) {
			limit = drecIntValue(v)
		}
		key := drecKey(digest)
		if current, seen := largest[key]; !seen || limit > current {
			largest[key] = limit
		}
		if count := int64(used[s.id()]); count > limit {
			b.t.fail("%s: covers %d request(s) and %d rest on it, a change of it counting as one", s.id(), limit, count)
		}
	}
	for _, key := range specOrder {
		if limit, seen := largest[key]; seen && int64(perSpec[key]) > limit {
			name := strings.TrimPrefix(key, "str:")
			if len(name) > 12 {
				name = name[:12]
			}
			b.t.fail("specification %s: requested %d times, the largest request_limit binding it is %d",
				name, perSpec[key], limit)
		}
	}
}

func (b *drecBinding) attempts() {
	for _, attempt := range b.att.ofKind("attempt") {
		request := b.att.stage(attempt.get("request_ref"), "request")
		if request == nil {
			b.t.fail("%s: names no request", attempt.id())
		} else if !drecEq(attempt.get("spec_digest"), request.get("spec_digest")) {
			b.t.fail("%s: executes a specification other than the one requested", attempt.id())
		}
	}
}

// --- bounds ---

var drecBoundsMembers = []string{"operation", "target", "policy_version", "input_version_refs", "parameters",
	"max_requests", "valid_from", "valid_until"}

var drecSpecMembers = map[string]bool{"operation": true, "target": true, "policy_version": true,
	"input_version_refs": true, "parameters": true}

// drecBoundsProblem is why bounds are not well-formed, or the empty string.
func drecBoundsProblem(v any) string {
	bounds, isObj := v.(map[string]any)
	if !isObj {
		return "not an object"
	}
	want := map[string]bool{}
	for _, k := range drecBoundsMembers {
		want[k] = true
	}
	var differ []string
	for _, k := range drecBoundsMembers {
		if _, has := bounds[k]; !has {
			differ = append(differ, k)
		}
	}
	for k := range bounds {
		if !want[k] {
			differ = append(differ, k)
		}
	}
	if len(differ) > 0 {
		sort.Strings(differ)
		return "members are not exactly the bounds' (" + strings.Join(differ, ", ") + ")"
	}
	for _, k := range []string{"operation", "target", "policy_version"} {
		if _, isStr := bounds[k].(string); !isStr {
			return k + " is not a string"
		}
	}
	refs, isList := bounds["input_version_refs"].([]any)
	for _, x := range refs {
		if _, isStr := x.(string); !isStr {
			isList = false
		}
	}
	if !isList {
		return "input_version_refs is not a list of strings"
	}
	if !drecJSONInteger(bounds["max_requests"]) || drecIntValue(bounds["max_requests"]) < 1 {
		return "max_requests is not a JSON integer from 1"
	}
	start, end := drecReadInstant(bounds["valid_from"]), drecReadInstant(bounds["valid_until"])
	if !start.ok() || !end.ok() {
		return "the period's times name no instant"
	}
	if start.sec.Cmp(end.sec) > 0 {
		return "valid_until is before valid_from"
	}
	params, isObj := bounds["parameters"].(map[string]any)
	if !isObj {
		return "parameters is not an object"
	}
	for _, name := range drecKeys(params) {
		if problem := drecConstraintProblem(params[name]); problem != "" {
			return "parameter '" + name + "': " + problem
		}
	}
	return ""
}

func drecScalar(v any) bool {
	switch v.(type) {
	case nil, string, bool:
		return true
	}
	return drecJSONInteger(v)
}

func drecConstraintProblem(v any) string {
	c, isObj := v.(map[string]any)
	if !isObj || len(c) == 0 {
		return "a constraint is an object"
	}
	keys := drecKeys(c)
	only := func(names ...string) bool {
		if len(keys) != len(names) {
			return false
		}
		for i := range names {
			if keys[i] != names[i] {
				return false
			}
		}
		return true
	}
	switch {
	case only("exact"):
		if drecScalar(c["exact"]) {
			return ""
		}
		return "exact is not a string, integer, boolean or null"
	case only("one_of"):
		values, isList := c["one_of"].([]any)
		good := isList && len(values) > 0
		for _, x := range values {
			good = good && drecScalar(x)
		}
		if !good {
			return "one_of is not a list of values"
		}
		for i := range values {
			for _, other := range values[i+1:] {
				if drecSame(values[i], other) {
					return "one_of names a value twice"
				}
			}
		}
		return ""
	case only("max_length"):
		if drecJSONInteger(c["max_length"]) && drecIntValue(c["max_length"]) >= 0 {
			return ""
		}
		return "max_length is not a JSON integer from 0"
	case only("max"), only("min"), only("max", "min"):
		for _, k := range keys {
			if !drecJSONInteger(c[k]) {
				return "min and max are JSON integers"
			}
		}
		if len(keys) == 2 && drecIntValue(c["min"]) > drecIntValue(c["max"]) {
			return "min is above max"
		}
		return ""
	}
	return "a constraint of the kinds [" + strings.Join(keys, ", ") + "]"
}

// drecOutsideBounds is why a specification's bytes fall outside the bounds, or the empty string.
func drecOutsideBounds(raw []byte, bounds map[string]any) string {
	parsed, err := drecParse(raw, drecBounds)
	if err != nil {
		code := err.Error()
		if je, ok := err.(*drecJSONError); ok {
			code = je.Code
		}
		return "the specification cannot be read (" + code + ")"
	}
	spec, isObj := parsed.(map[string]any)
	if !isObj {
		return "the specification is not a JSON object"
	}
	var extra []string
	for k := range spec {
		if !drecSpecMembers[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return "members the bounds do not name: " + strings.Join(extra, ", ")
	}
	for _, k := range []string{"operation", "target", "policy_version"} {
		v, has := spec[k]
		if !has || !drecSame(v, bounds[k]) {
			return k + " is not the bounds'"
		}
	}
	refs, hasRefs := spec["input_version_refs"]
	if !hasRefs {
		refs = []any{}
	}
	refList, isList := refs.([]any)
	allowed, _ := bounds["input_version_refs"].([]any)
	good := isList
	for _, r := range refList {
		hit := false
		for _, a := range allowed {
			hit = hit || drecSame(r, a)
		}
		good = good && hit
	}
	if !good {
		return "an input-version reference the bounds do not allow"
	}
	paramsValue, hasParams := spec["parameters"]
	if !hasParams {
		paramsValue = map[string]any{}
	}
	params, isParams := paramsValue.(map[string]any)
	if !isParams {
		return "parameters is not an object"
	}
	constraints, _ := bounds["parameters"].(map[string]any)
	names := map[string]bool{}
	for k := range params {
		names[k] = true
	}
	for k := range constraints {
		names[k] = true
	}
	for _, name := range sortedKeys(names) {
		constraint, named := constraints[name]
		value, present := params[name]
		switch {
		case !named:
			return "parameter '" + name + "' is not named in the bounds"
		case !present:
			return "parameter '" + name + "' is named in the bounds and missing"
		case !drecSatisfies(value, constraint.(map[string]any)):
			return "parameter '" + name + "' is outside its constraint"
		}
	}
	return ""
}

func drecSatisfies(value any, c map[string]any) bool {
	if exact, has := c["exact"]; has {
		return drecSame(value, exact)
	}
	if values, has := c["one_of"]; has {
		list, _ := values.([]any)
		for _, v := range list {
			if drecSame(value, v) {
				return true
			}
		}
		return false
	}
	if n, has := c["max_length"]; has {
		s, isStr := value.(string)
		return isStr && int64(utf8.RuneCountInString(s)) <= drecIntValue(n)
	}
	if !drecJSONInteger(value) {
		return false
	}
	v := drecIntValue(value)
	if lo, has := c["min"]; has && v < drecIntValue(lo) {
		return false
	}
	if hi, has := c["max"]; has && v > drecIntValue(hi) {
		return false
	}
	return true
}

// --- order, rechecks, results, rationale ---

var drecNames = []string{"proposal_ref", "review_ref", "revokes_ref", "from_ref", "authorised_by", "request_ref",
	"recheck_ref", "attempt_ref"}

// drecStageOrder: each stage comes after the stages it names, in the listing and in the issuer's time.
func drecStageOrder(att *drecAttachment) drecDim {
	t := &drecTally{}
	for _, sid := range att.duplicateIDs {
		t.fail("stage id '%s' is used twice", sid)
	}
	for _, s := range att.stages {
		sid := s.id()
		for _, k := range drecNames {
			target := att.stage(s.get(k))
			if target == nil {
				continue
			}
			if att.position[target.id()] > att.posOf(s.get("stage_id"), -1) {
				t.fail("%s: listed before %s, which it names", sid, target.id())
			}
			order := drecBefore(att.at(target), att.at(s))
			switch {
			case order == nil:
				bad := att.at(s)
				if !att.at(target).ok() {
					bad = att.at(target)
				}
				t.fail("%s: its order against %s cannot be checked: %s names no instant", sid, target.id(), bad.text)
			case !*order:
				t.fail("%s: dated before %s, which it names", sid, target.id())
			}
		}
	}
	return t.result()
}

// drecAuthorisationRecheck: each attempt follows an authorising recheck of its own request, made for it alone.
func drecAuthorisationRecheck(att *drecAttachment) drecDim {
	attempts := att.ofKind("attempt")
	if len(attempts) == 0 && len(att.ofKind("recheck")) == 0 {
		return drecMake(drecNotChecked, "no recheck or attempt is recorded")
	}
	t := &drecTally{}
	backed := map[*drecStage]string{}
	for _, attempt := range attempts {
		drecOneAttemptRecheck(att, attempt, backed, t)
	}
	drecRechecksAfterRevocation(att, t)
	return t.result()
}

func drecOneAttemptRecheck(att *drecAttachment, attempt *drecStage, backed map[*drecStage]string, t *drecTally) {
	sid := attempt.id()
	recheck := att.stage(attempt.get("recheck_ref"), "recheck")
	if recheck == nil {
		t.fail("%s: recheck_ref names no recheck", sid)
		return
	}
	if !drecEq(recheck.get("request_ref"), attempt.get("request_ref")) {
		t.fail("%s: its recheck is of another request", sid)
	}
	if !drecEq(recheck.get("result"), "authorised") {
		t.fail("%s: attempted after a recheck that did not authorise it", sid)
	}
	if first, reused := backed[recheck]; reused {
		t.fail("%s: reuses the recheck of %s", sid, first)
	}
	backed[recheck] = sid
	order := drecBefore(att.at(recheck), att.at(attempt))
	if order == nil {
		t.fail("%s: whether its recheck precedes it cannot be checked", sid)
	} else if !*order {
		t.fail("%s: its recheck is dated after it", sid)
	}
	for _, later := range att.ofKind("recheck") {
		if later == recheck || !drecEq(later.get("request_ref"), attempt.get("request_ref")) {
			continue
		}
		listed := att.position[later.id()] < att.posOf(attempt.get("stage_id"), -1)
		after := drecBefore(att.at(recheck), att.at(later))
		beforeAttempt := drecBefore(att.at(later), att.at(attempt))
		if listed && drecTrue(after) && drecTrue(beforeAttempt) && !drecEq(later.get("result"), "authorised") {
			t.fail("%s: the latest recheck before it, %s, does not authorise it", sid, later.id())
		}
	}
}

func drecRechecksAfterRevocation(att *drecAttachment, t *drecTally) {
	for _, revocation := range att.ofKind("standing_revocation") {
		approval := revocation.get("revokes_ref")
		requests := map[string]bool{}
		for _, r := range att.ofKind("request") {
			if drecEq(r.get("authorised_by"), approval) {
				requests[r.id()] = true
			}
		}
		for _, recheck := range att.ofKind("recheck") {
			if !drecMember(requests, recheck.get("request_ref")) || !drecEq(recheck.get("result"), "authorised") {
				continue
			}
			listed := att.position[recheck.id()] > att.position[revocation.id()]
			revoked, rechecked := att.at(revocation), att.at(recheck)
			dated := drecBefore(revoked, rechecked)
			if dated == nil {
				t.fail("%s: whether it follows the revocation cannot be checked", recheck.id())
			} else if listed || (*dated && revoked.sec.Cmp(rechecked.sec) != 0) {
				t.fail("%s: authorised a request after a recorded revocation", recheck.id())
			}
		}
	}
}

type drecAttemptRow struct {
	stageID  string
	observed any
	basis    any
}

// drecObservedResults: each attempt has exactly one result, carried through as recorded.
func drecObservedResults(att *drecAttachment) (drecDim, string, []drecAttemptRow) {
	attempts := att.ofKind("attempt")
	if len(att.ofKind("request")) == 0 {
		return drecMake(drecNotChecked, "no execution attempt is recorded"), "not_requested", nil
	}
	if len(attempts) == 0 {
		return drecMake(drecNotChecked, "no execution attempt is recorded"), "requested_not_attempted", nil
	}
	t := &drecTally{}
	results := map[string][]*drecStage{}
	for _, result := range att.ofKind("result") {
		if att.stage(result.get("attempt_ref"), "attempt") == nil {
			t.fail("%s: a result naming a stage that is not an attempt", result.id())
			continue
		}
		ref := result.get("attempt_ref").(string)
		results[ref] = append(results[ref], result)
	}
	var rows []drecAttemptRow
	for _, attempt := range attempts {
		found := results[attempt.id()]
		switch len(found) {
		case 0:
			t.fail("%s: no result is recorded", attempt.id())
			rows = append(rows, drecAttemptRow{attempt.id(), "missing", nil})
		case 1:
			rows = append(rows, drecAttemptRow{attempt.id(), found[0].get("observed"), found[0].get("basis")})
		default:
			t.fail("%s: %d results are recorded", attempt.id(), len(found))
			rows = append(rows, drecAttemptRow{attempt.id(), "multiple", nil})
		}
	}
	return t.result(), "attempted", rows
}

// drecRationaleProvenance: the stated timing of each rationale against the issuer's times.
func drecRationaleProvenance(att *drecAttachment) drecDim {
	t := &drecTally{}
	for _, s := range att.stages {
		rationale, isObj := s.get("rationale").(map[string]any)
		if !isObj || drecEq(rationale["timing"], "not_recorded") {
			continue
		}
		recorded, at := drecReadInstant(rationale["recorded_at"]), att.at(s)
		switch {
		case !recorded.ok() || !at.ok():
			t.fail("%s: the rationale's timing cannot be checked: a time names no instant", s.id())
		case drecEq(rationale["timing"], "contemporaneous") && recorded.sec.Cmp(at.sec) > 0:
			t.fail("%s: presented as contemporaneous, recorded after the stage", s.id())
		case drecEq(rationale["timing"], "later_supplemented") && recorded.sec.Cmp(at.sec) <= 0:
			t.fail("%s: said to be supplemented later, dated no later than the stage", s.id())
		}
	}
	return t.result()
}

type drecExecuted struct {
	specIndex int
	reachedBy string
}

// drecExecutedSpecifications: for each executed specification, how it was reached.
func drecExecutedSpecifications(att *drecAttachment) []drecExecuted {
	paths := map[string]map[string]bool{}
	var order []string
	digests := map[string]any{}
	for _, attempt := range att.ofKind("attempt") {
		key := drecKey(attempt.get("spec_digest"))
		if _, seen := paths[key]; !seen {
			paths[key] = map[string]bool{}
			order = append(order, key)
			digests[key] = attempt.get("spec_digest")
		}
		var basis *drecStage
		if request := att.stage(attempt.get("request_ref"), "request"); request != nil {
			basis = att.stage(request.get("authorised_by"))
		}
		paths[key][drecReachedBy(att, basis)] = true
	}
	var out []drecExecuted
	for _, key := range order {
		spec := att.spec(digests[key])
		if spec == nil {
			continue
		}
		for _, word := range []string{"shown_to_reviewer", "via_change_only", "via_standing_approval", "unbound"} {
			if paths[key][word] {
				out = append(out, drecExecuted{spec.index, word})
				break
			}
		}
	}
	return out
}

func drecReachedBy(att *drecAttachment, basis *drecStage) string {
	switch {
	case basis == nil:
		return "unbound"
	case basis.kindIs("standing_approval"):
		return "via_standing_approval"
	case basis.kindIs("change_authorisation"):
		return "via_change_only"
	case basis.isApprovedOutcome():
		if review := att.stage(basis.get("review_ref"), "review"); review != nil && review.has("shown_spec_digest") {
			return "shown_to_reviewer"
		}
	}
	return "unbound"
}
