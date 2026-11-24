package corpusreaders

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// This file reads one action-binding attachment (dps-action-binding 0.3.0) into
// its dimensions. Each function restates one function of the reference reader,
// agent_evidence_verify.decision_record at probityai/probity
// 96b302de87a32d3d4d414e7b62d41a2ece2d668f, under the same name with a dr
// prefix, so a later version of the reference is ported check by check.
//
// The reference's regular expressions end in Python's "$", which also matches
// before one final newline; each pattern below says so with "\n?$".

const (
	drecProfile        = "dps-action-binding"
	drecProfileVersion = "0.3.0"
	drecPolicyProfile  = "dps-anchoring-trust-policy"
	drecPolicyVersion  = "0.2.0"
	drecSignedBytesRef = "dps-signatures 0.2.0 organisation_seal"

	drecVerified     = "verified"
	drecFailed       = "failed"
	drecNotChecked   = "not_checked"
	drecUnavailable  = "unavailable"
	drecNotSupported = "not_supported"
)

// drecBindingDimensions is the order a refusal names the first binding dimension that failed.
var drecBindingDimensions = []string{
	"specification_digests", "specification_statements", "record_statements", "action_binding",
	"stage_order", "authorisation_recheck", "observed_results", "rationale_provenance",
}

// drecStrictDimensions are the checks the strict profile adds, each its own dimension.
var drecStrictDimensions = []string{
	"approver_independence", "single_effect_per_request", "identity_independent",
	"authority_independent", "time_independent", "latest_attachment", "signature_required",
}

var (
	drecTimeRE = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?` +
		`(Z|[+-][0-9]{2}:[0-9]{2})?\n?$`)
	drecDigestRE     = regexp.MustCompile(`^[0-9a-f]{64}\n?$`)
	drecStageIDRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\n?$`)
	drecDecisionIDRE = regexp.MustCompile(`^DR-[0-9]{4}-[0-9]{3,}\n?$`)
	drecSealedAtRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\n?$`)
	// Base64 text with a newline is refused by the decoder the reference calls,
	// so this pattern ends at the end of the text.
	drecB64RE = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
	// drecB64TextRE is base64.b64decode(validate=True)'s alphabet check.
	drecB64TextRE = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)
)

// --- times ----------------------------------------------------------------------------

// drecInstant is a time as written, read as an instant when it names one.
type drecInstant struct {
	text string
	sec  *big.Rat // nil: the text names no instant
	why  string
}

func (t drecInstant) ok() bool { return t.sec != nil }

func drecMatchTime(v any) []string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return drecTimeRE.FindStringSubmatch(s)
}

// drecReadInstant reads an RFC 3339 time as seconds on one axis; a date or second
// no calendar has is no instant, and a time with no offset is none either.
func drecReadInstant(v any) drecInstant {
	s, isStr := v.(string)
	if !isStr {
		return drecInstant{text: drecRepr(v), why: "not a time"}
	}
	m := drecTimeRE.FindStringSubmatch(s)
	if m == nil {
		return drecInstant{text: s, why: "not a time"}
	}
	num := func(i int) int {
		n := 0
		for _, c := range m[i] {
			n = n*10 + int(c-'0')
		}
		return n
	}
	year, month, day, hour, minute, second := num(1), num(2), num(3), num(4), num(5), num(6)
	fraction, zone := m[7], m[8]
	if zone == "" {
		return drecInstant{text: s, why: "no offset"}
	}
	if hour > 23 || minute > 59 || second > 59 {
		return drecInstant{text: s, why: "no such time"}
	}
	if year < 1 || month < 1 || month > 12 || day < 1 ||
		day > time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return drecInstant{text: s, why: "no such date"}
	}
	offset := 0
	if zone != "Z" {
		oh := int(zone[1]-'0')*10 + int(zone[2]-'0')
		om := int(zone[4]-'0')*10 + int(zone[5]-'0')
		if oh > 23 || om > 59 {
			return drecInstant{text: s, why: "no such offset"}
		}
		offset = oh*3600 + om*60
		if zone[0] == '-' {
			offset = -offset
		}
	}
	days := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC).Unix() / 86400
	total := new(big.Rat).SetInt64(days*86400 + int64(hour*3600+minute*60+second-offset))
	if fraction != "" {
		frac, _ := new(big.Rat).SetString("0" + fraction)
		total.Add(total, frac)
	}
	return drecInstant{text: s, sec: total}
}

// drecBefore is whether earlier is at or before later; nil when either names no instant.
func drecBefore(earlier, later drecInstant) *bool {
	if !earlier.ok() || !later.ok() {
		return nil
	}
	b := earlier.sec.Cmp(later.sec) <= 0
	return &b
}

func drecTrue(b *bool) bool { return b != nil && *b }

// --- small readings -------------------------------------------------------------------

// drecB64 decodes padded base64 the way the reference reads carried bytes, or nil.
func drecB64(v any) []byte {
	s, ok := v.(string)
	if !ok || utf8.RuneCountInString(s) < 4 || !drecB64RE.MatchString(s) {
		return nil
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

// drecB64Validate is base64.b64decode(text, validate=True): only the alphabet and
// padding, the padding in its place, and the last group's spare bits not read.
func drecB64Validate(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || !drecB64TextRE.MatchString(s) {
		return nil, false
	}
	out, err := base64.StdEncoding.DecodeString(s)
	return out, err == nil
}

func drecIsRef(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= 512 && strings.IndexFunc(s, func(r rune) bool { return !pyIsSpace(r) }) >= 0
}

func drecMatches(re *regexp.Regexp, v any) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

// drecIn is Python's "value in (words...)".
func drecIn(v any, words ...string) bool {
	for _, w := range words {
		if drecEq(v, w) {
			return true
		}
	}
	return false
}

func drecHas(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func drecAny(m map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// drecTruthy is Python's bool() of a JSON value.
func drecTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case drecInt:
		return x.n.Sign() != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func drecSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// --- dimensions -----------------------------------------------------------------------

// drecDim is one dimension: its status, what it carries, and its findings.
type drecDim struct {
	Status   string
	Findings []string
	Extra    map[string]any
}

func drecMake(status string, findings ...string) drecDim {
	return drecDim{Status: status, Findings: findings}
}

// drecTally collects one dimension's findings, worst first: failed over not
// checked over unavailable.
type drecTally struct {
	failed, unchecked, unavailable []string
}

func (t *drecTally) fail(format string, a ...any) {
	t.failed = append(t.failed, fmt.Sprintf(format, a...))
}
func (t *drecTally) skip(format string, a ...any) {
	t.unchecked = append(t.unchecked, fmt.Sprintf(format, a...))
}
func (t *drecTally) gone(format string, a ...any) {
	t.unavailable = append(t.unavailable, fmt.Sprintf(format, a...))
}

func (t *drecTally) status() string {
	switch {
	case len(t.failed) > 0:
		return drecFailed
	case len(t.unchecked) > 0:
		return drecNotChecked
	case len(t.unavailable) > 0:
		return drecUnavailable
	}
	return drecVerified
}

func (t *drecTally) result() drecDim {
	all := append(append(append([]string{}, t.failed...), t.unchecked...), t.unavailable...)
	return drecDim{Status: t.status(), Findings: all}
}

// --- structure ------------------------------------------------------------------------

type drecShape struct{ required, optional []string }

var drecStageShapes = map[string]drecShape{
	"proposal": {[]string{"stage_id", "kind", "at", "origin", "spec_digest"},
		[]string{"deployer_role_pointer", "system_name", "version", "actor_ref"}},
	"review": {[]string{"stage_id", "kind", "at", "reviewer_ref"},
		[]string{"shown_spec_digest", "shown_bounds_digest", "proposal_ref", "edited_by",
			"shown_view_ref", "shown_view_digest"}},
	"outcome": {[]string{"stage_id", "kind", "at", "review_ref", "outcome", "actor_ref", "method", "rationale"},
		[]string{"approved_spec_digest", "authority", "request_limit", "escalated_to_ref",
			"identity_evidence_ref", "legal_signature_ref", "core_ref"}},
	"standing_approval": {[]string{"stage_id", "kind", "at", "review_ref", "actor_ref", "method", "authority",
		"rationale", "bounds_digest", "bounds"},
		[]string{"identity_evidence_ref", "legal_signature_ref", "core_ref"}},
	"standing_revocation": {[]string{"stage_id", "kind", "at", "revokes_ref", "actor_ref", "method",
		"rationale"}, []string{"authority"}},
	"change_authorisation": {[]string{"stage_id", "kind", "at", "from_ref", "spec_digest", "actor_ref",
		"method", "authority", "rationale"},
		[]string{"request_limit", "identity_evidence_ref", "legal_signature_ref"}},
	"request": {[]string{"stage_id", "kind", "at", "request_id", "authorised_by", "spec_digest",
		"requested_by"}, nil},
	"recheck": {[]string{"stage_id", "kind", "at", "request_ref", "result", "authority_source_ref"},
		[]string{"detail"}},
	"attempt": {[]string{"stage_id", "kind", "at", "request_ref", "recheck_ref", "spec_digest",
		"executor_ref"}, []string{"trace_refs"}},
	"result": {[]string{"stage_id", "kind", "at", "attempt_ref", "observed", "basis"},
		[]string{"evidence_ref", "trace_refs"}},
}

var (
	drecDigestMembers = []string{"spec_digest", "shown_spec_digest", "shown_bounds_digest", "approved_spec_digest",
		"bounds_digest", "shown_view_digest"}
	drecIDMembers = []string{"stage_id", "proposal_ref", "review_ref", "revokes_ref", "from_ref", "authorised_by",
		"request_ref", "recheck_ref", "attempt_ref"}
	drecRefMembers = []string{"deployer_role_pointer", "system_name", "version", "actor_ref", "reviewer_ref",
		"edited_by", "shown_view_ref", "method", "escalated_to_ref", "identity_evidence_ref",
		"legal_signature_ref", "request_id", "requested_by", "authority_source_ref",
		"executor_ref", "evidence_ref"}
	drecEnumNames = []string{"origin", "outcome", "result", "observed", "basis"}
	drecEnums     = map[string][]string{
		"origin":   {"ai", "human"},
		"outcome":  {"approved", "rejected", "escalated"},
		"result":   {"authorised", "not_authorised", "unavailable"},
		"observed": {"succeeded", "failed", "indeterminate"},
		"basis":    {"target_response", "independent_observation", "executor_observation"},
	}
	drecOutcomeWords = []string{"approved", "rejected", "escalated"}
)

// drecCheckMembers holds obj to exactly the required members plus any optional ones.
func drecCheckMembers(obj any, required, optional []string, where string, t *drecTally) bool {
	m, ok := obj.(map[string]any)
	if !ok {
		t.fail("%s: not an object", where)
		return false
	}
	allowed := map[string]bool{}
	var missing, extra []string
	for _, k := range required {
		allowed[k] = true
		if _, has := m[k]; !has {
			missing = append(missing, k)
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.fail("%s: missing %s", where, strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.fail("%s: members the format does not have: %s", where, strings.Join(extra, ", "))
	}
	return len(missing) == 0 && len(extra) == 0
}

func drecCheckRationale(value any, where string, t *drecTally) {
	if !drecCheckMembers(value, []string{"timing"}, []string{"ai_assisted", "recorded_at", "text_ref"}, where, t) {
		return
	}
	m := value.(map[string]any)
	timing := m["timing"]
	switch {
	case !drecIn(timing, "contemporaneous", "later_supplemented", "not_recorded"):
		t.fail("%s: timing %s is not one the format names", where, drecRepr(timing))
	case drecEq(timing, "not_recorded"):
		if len(drecAny(m, "ai_assisted", "recorded_at", "text_ref")) > 0 {
			t.fail("%s: a rationale not recorded states when or how it was recorded", where)
		}
	case !drecHas(m, "ai_assisted", "recorded_at"):
		t.fail("%s: a recorded rationale states ai_assisted and recorded_at", where)
	}
	if v, has := m["ai_assisted"]; has {
		if _, isBool := v.(bool); !isBool {
			t.fail("%s: ai_assisted is not a boolean", where)
		}
	}
	if v, has := m["recorded_at"]; has && drecMatchTime(v) == nil {
		t.fail("%s: recorded_at is not a time with an offset", where)
	}
}

func drecCheckCoreRef(value any, where string, t *drecTally) {
	m, ok := value.(map[string]any)
	if !ok || !drecIn(m["field"], "affirmation_record", "review_log") {
		t.fail("%s: core_ref names no core field the format reads", where)
		return
	}
	if drecEq(m["field"], "affirmation_record") {
		drecCheckMembers(m, []string{"field"}, nil, where, t)
		return
	}
	if !drecCheckMembers(m, []string{"field", "index"}, nil, where, t) {
		return
	}
	index := m["index"]
	integral := drecJSONInteger(index)
	negative := integral && drecIntValue(index) < 0
	if f, isFloat := index.(float64); isFloat && f == math.Trunc(f) {
		integral, negative = true, f < 0
	}
	if !integral || negative {
		t.fail("%s: review_log index is not an integer from 0", where)
	}
}

func drecCheckStageKind(stage map[string]any, where string, t *drecTally) {
	switch stage["kind"] {
	case "proposal":
		ai := drecEq(stage["origin"], "ai")
		if ai && (!drecHas(stage, "deployer_role_pointer") || drecHas(stage, "actor_ref")) {
			t.fail("%s: an AI proposal names its deployer role and no person", where)
		}
		if !ai && (!drecHas(stage, "actor_ref") ||
			len(drecAny(stage, "deployer_role_pointer", "system_name", "version")) > 0) {
			t.fail("%s: a human proposal names its person and no AI system", where)
		}
	case "review":
		if drecHas(stage, "shown_spec_digest") == drecHas(stage, "shown_bounds_digest") {
			t.fail("%s: a review is shown exactly one of a specification and bounds", where)
		}
	case "outcome":
		approved := drecEq(stage["outcome"], "approved")
		carries := drecAny(stage, "approved_spec_digest", "authority", "request_limit")
		if approved && !drecHas(stage, "approved_spec_digest", "authority") {
			t.fail("%s: an approval carries its approved digest and its authority", where)
		}
		if !approved && len(carries) > 0 {
			t.fail("%s: a rejection or an escalation carries %s", where, strings.Join(carries, ", "))
		}
	}
	if v, has := stage["rationale"]; has {
		drecCheckRationale(v, where+".rationale", t)
	}
	if v, has := stage["authority"]; has {
		drecCheckMembers(v, []string{"authority_ref"}, nil, where+".authority", t)
	}
	if v, has := stage["core_ref"]; has {
		drecCheckCoreRef(v, where+".core_ref", t)
	}
	if v, has := stage["request_limit"]; has && (!drecJSONInteger(v) || drecIntValue(v) < 1) {
		t.fail("%s: request_limit is not an integer from 1", where)
	}
	if stage["kind"] == "standing_approval" {
		drecCheckContent(stage["bounds"], where+".bounds", t)
	}
}

func drecCheckValues(stage map[string]any, where string, t *drecTally) {
	for _, k := range drecDigestMembers {
		if v, has := stage[k]; has && !drecMatches(drecDigestRE, v) {
			t.fail("%s: %s is not a SHA-256 in lowercase hex", where, k)
		}
	}
	for _, k := range drecIDMembers {
		if v, has := stage[k]; has && !drecMatches(drecStageIDRE, v) {
			t.fail("%s: %s is not a stage id", where, k)
		}
	}
	for _, k := range drecRefMembers {
		if v, has := stage[k]; has && !drecIsRef(v) {
			t.fail("%s: %s is not a reference", where, k)
		}
	}
	for _, k := range drecEnumNames {
		if v, has := stage[k]; has && !drecIn(v, drecEnums[k]...) {
			t.fail("%s: %s %s is not one the format names", where, k, drecRepr(v))
		}
	}
	if m := drecMatchTime(stage["at"]); m == nil || m[8] == "" {
		t.fail("%s: at is not a time with an offset", where)
	}
	if v, has := stage["trace_refs"]; has {
		list, isList := v.([]any)
		good := isList
		for _, x := range list {
			good = good && drecIsRef(x)
		}
		if !good {
			t.fail("%s: trace_refs is not a list of references", where)
		}
	}
}

func drecCheckContent(content any, where string, t *drecTally) {
	m, isObj := content.(map[string]any)
	switch {
	case isObj && drecEq(m["availability"], "available"):
		if drecCheckMembers(m, []string{"availability", "bytes_b64"}, nil, where, t) && drecB64(m["bytes_b64"]) == nil {
			t.fail("%s: bytes_b64 is not padded base64", where)
		}
	case isObj && drecEq(m["availability"], "unavailable"):
		if drecCheckMembers(m, []string{"availability", "reason"}, []string{"reason_ref"}, where, t) &&
			!drecIn(m["reason"], "withheld", "retention_disposition", "redaction_event", "other") {
			t.fail("%s: reason %s is not one the format names", where, drecRepr(m["reason"]))
		}
	default:
		t.fail("%s: content is neither available nor unavailable", where)
	}
}

func drecCheckSpecification(spec any, where string, t *drecTally) {
	if !drecCheckMembers(spec, []string{"spec_digest", "representation", "content", "summary"}, nil, where, t) {
		return
	}
	m := spec.(map[string]any)
	if !drecMatches(drecDigestRE, m["spec_digest"]) {
		t.fail("%s: spec_digest is not a SHA-256 in lowercase hex", where)
	}
	rep, isObj := m["representation"].(map[string]any)
	switch {
	case isObj && drecEq(rep["kind"], "original_bytes"):
		drecCheckMembers(rep, []string{"kind", "media_type"}, nil, where+".representation", t)
	case isObj && drecEq(rep["kind"], "canonical_form"):
		drecCheckMembers(rep, []string{"kind", "media_type", "canonicalisation", "specification_ref"}, nil,
			where+".representation", t)
	default:
		t.fail("%s: representation is neither original bytes nor a canonical form", where)
	}
	drecCheckContent(m["content"], where+".content", t)
	if drecCheckMembers(m["summary"], []string{"operation", "target", "policy_version", "input_version_refs"}, nil,
		where+".summary", t) {
		refs, isList := m["summary"].(map[string]any)["input_version_refs"].([]any)
		good := isList
		for _, x := range refs {
			good = good && drecIsRef(x)
		}
		if !good {
			t.fail("%s.summary: input_version_refs is not a list of references", where)
		}
	}
}

var drecSignatureMembers = []string{"algorithm", "key_ref", "signed_bytes_ref", "sealed_at", "value_b64"}

func drecCheckSignatureShape(sig any, t *drecTally) {
	if !drecCheckMembers(sig, drecSignatureMembers, nil, "issuer_signature", t) {
		return
	}
	m := sig.(map[string]any)
	if !drecEq(m["algorithm"], "Ed25519") {
		t.fail("issuer_signature: algorithm %s is not Ed25519", drecRepr(m["algorithm"]))
	}
	if !drecEq(m["signed_bytes_ref"], drecSignedBytesRef) {
		t.fail("issuer_signature: signed_bytes_ref names other signed bytes")
	}
	if key, ok := m["key_ref"].(string); !ok || utf8.RuneCountInString(key) < 1 || utf8.RuneCountInString(key) > 256 {
		t.fail("issuer_signature: key_ref is not a key reference")
	}
	if !drecMatches(drecSealedAtRE, m["sealed_at"]) {
		t.fail("issuer_signature: sealed_at is not written YYYY-MM-DDTHH:MM:SSZ")
	}
	if drecB64(m["value_b64"]) == nil {
		t.fail("issuer_signature: value_b64 is not padded base64")
	}
}

// drecStructuralValidity holds the attachment to the shape its schema publishes.
func drecStructuralValidity(doc any) drecDim {
	t := &drecTally{}
	if !drecCheckMembers(doc, []string{"profile", "profile_version", "decision_id", "action_specifications",
		"stages"}, []string{"issuer_signature"}, "attachment", t) {
		return t.result()
	}
	m := doc.(map[string]any)
	if !drecEq(m["profile"], drecProfile) || !drecEq(m["profile_version"], drecProfileVersion) {
		t.fail("attachment: profile %s %s is not %s %s", drecRepr(m["profile"]), drecRepr(m["profile_version"]),
			drecProfile, drecProfileVersion)
	}
	if !drecMatches(drecDecisionIDRE, m["decision_id"]) {
		t.fail("attachment: decision_id is not a decision record id")
	}
	if specs, isList := m["action_specifications"].([]any); !isList || len(specs) == 0 {
		t.fail("attachment: action_specifications is not a non-empty list")
	} else {
		for i, spec := range specs {
			drecCheckSpecification(spec, fmt.Sprintf("action_specifications[%d]", i), t)
		}
	}
	stages, isList := m["stages"].([]any)
	if !isList {
		t.fail("attachment: stages is not a list")
		return t.result()
	}
	kinds := map[string]bool{}
	for _, s := range stages {
		if sm, isObj := s.(map[string]any); isObj {
			if k, isStr := sm["kind"].(string); isStr {
				kinds[k] = true
			}
		}
	}
	if !kinds["review"] || (!kinds["outcome"] && !kinds["standing_approval"]) {
		t.fail("attachment: no review, or neither an outcome nor a standing approval")
	}
	for i, s := range stages {
		where := fmt.Sprintf("stages[%d]", i)
		sm, isObj := s.(map[string]any)
		var kind any
		if isObj {
			kind = sm["kind"]
		}
		name, isStr := kind.(string)
		shape, known := drecStageShapes[name]
		if !isStr || !known {
			t.fail("%s: kind %s is not a stage the format names", where, drecRepr(kind))
			continue
		}
		if drecCheckMembers(sm, shape.required, shape.optional, where, t) {
			drecCheckValues(sm, where, t)
			drecCheckStageKind(sm, where, t)
		}
	}
	if sig, has := m["issuer_signature"]; has {
		drecCheckSignatureShape(sig, t)
	}
	return t.result()
}

// --- the attachment as read -----------------------------------------------------------

type drecSpec struct {
	index     int
	digest    any
	raw       []byte // nil: unavailable
	mediaType any
	summary   map[string]any
}

// drecStage is one stage; its pointer is its identity.
type drecStage struct {
	pos int
	m   map[string]any
}

func (s *drecStage) get(key string) any { return s.m[key] }
func (s *drecStage) has(key string) bool {
	_, ok := s.m[key]
	return ok
}
func (s *drecStage) id() string {
	id, _ := s.m["stage_id"].(string)
	return id
}
func (s *drecStage) kindIs(kinds ...string) bool { return drecIn(s.m["kind"], kinds...) }

// drecAttachment is the parts of one structurally valid attachment the binding checks read.
type drecAttachment struct {
	doc          map[string]any
	specs        []drecSpec
	stages       []*drecStage
	byID         map[string]*drecStage
	position     map[string]int
	duplicateIDs []string
}

func drecAttachmentFrom(doc map[string]any) *drecAttachment {
	att := &drecAttachment{doc: doc, byID: map[string]*drecStage{}, position: map[string]int{}}
	specs, _ := doc["action_specifications"].([]any)
	for i, s := range specs {
		spec, _ := s.(map[string]any)
		content, _ := spec["content"].(map[string]any)
		var raw []byte
		if drecEq(content["availability"], "available") {
			raw = drecB64(content["bytes_b64"])
		}
		rep, _ := spec["representation"].(map[string]any)
		media, hasMedia := rep["media_type"]
		if !hasMedia {
			media = ""
		}
		summary, _ := spec["summary"].(map[string]any)
		att.specs = append(att.specs, drecSpec{index: i, digest: spec["spec_digest"], raw: raw, mediaType: media,
			summary: summary})
	}
	stages, _ := doc["stages"].([]any)
	for _, s := range stages {
		if m, isObj := s.(map[string]any); isObj {
			att.stages = append(att.stages, &drecStage{pos: len(att.stages), m: m})
		}
	}
	for _, st := range att.stages {
		sid := st.id()
		if _, seen := att.byID[sid]; seen {
			att.duplicateIDs = append(att.duplicateIDs, sid)
			continue
		}
		att.byID[sid] = st
		att.position[sid] = st.pos
	}
	return att
}

func (a *drecAttachment) ofKind(kinds ...string) []*drecStage {
	var out []*drecStage
	for _, s := range a.stages {
		if s.kindIs(kinds...) {
			out = append(out, s)
		}
	}
	return out
}

func (a *drecAttachment) spec(digest any) *drecSpec {
	for i := range a.specs {
		if drecEq(a.specs[i].digest, digest) {
			return &a.specs[i]
		}
	}
	return nil
}

// stage is the stage ref names, when it is of one of kinds (any kind when none given).
func (a *drecAttachment) stage(ref any, kinds ...string) *drecStage {
	id, ok := ref.(string)
	if !ok {
		return nil
	}
	found := a.byID[id]
	if found != nil && len(kinds) > 0 && !found.kindIs(kinds...) {
		return nil
	}
	return found
}

func (a *drecAttachment) posOf(ref any, fallback int) int {
	if id, ok := ref.(string); ok {
		if p, has := a.position[id]; has {
			return p
		}
	}
	return fallback
}

func (a *drecAttachment) at(s *drecStage) drecInstant { return drecReadInstant(s.get("at")) }

func addTruthy(set map[string]bool, v any) {
	if s, ok := v.(string); ok && s != "" {
		set[s] = true
	}
}

// parties is every machine party the attachment names (the AI drafter, the
// requester, the executor) together with every proposer.
func (a *drecAttachment) parties() map[string]bool {
	named := map[string]bool{}
	for _, s := range a.ofKind("proposal") {
		// The reference's services() names an AI proposal's role and system and
		// proposers() names every proposal's role, system and person; every
		// caller reads the two together.
		addTruthy(named, s.get("deployer_role_pointer"))
		addTruthy(named, s.get("system_name"))
		addTruthy(named, s.get("actor_ref"))
	}
	for _, s := range a.ofKind("request") {
		addTruthy(named, s.get("requested_by"))
	}
	for _, s := range a.ofKind("attempt") {
		addTruthy(named, s.get("executor_ref"))
	}
	return named
}

func drecMember(set map[string]bool, v any) bool {
	s, ok := v.(string)
	return ok && set[s]
}

func (s *drecStage) isApprovedOutcome() bool {
	return s.kindIs("outcome") && drecEq(s.get("outcome"), "approved")
}

// approvals are the approved outcomes and standing approvals: every act a request can rest on.
func (a *drecAttachment) approvals() []*drecStage {
	var out []*drecStage
	for _, s := range a.stages {
		if s.kindIs("standing_approval") || s.isApprovedOutcome() {
			out = append(out, s)
		}
	}
	return out
}

// --- specifications -------------------------------------------------------------------

func drecSpecificationDimensions(att *drecAttachment) (drecDim, drecDim) {
	digests, statements := &drecTally{}, &drecTally{}
	for _, spec := range att.specs {
		if spec.raw == nil {
			digests.gone("specification %d: bytes unavailable", spec.index)
			statements.skip("specification %d: bytes unavailable, summary not checked", spec.index)
			continue
		}
		if !drecEq(drecSHA(spec.raw), spec.digest) {
			digests.fail("specification %d: its bytes are not its digest's", spec.index)
		}
		drecStatements(spec, statements)
	}
	return digests.result(), statements.result()
}

func drecStatements(spec drecSpec, t *drecTally) {
	if !drecEq(spec.mediaType, "application/json") {
		t.skip("specification %d: media type %s is not read", spec.index, drecRepr(spec.mediaType))
		return
	}
	body, err := drecParse(spec.raw, drecStrict)
	if err != nil {
		t.skip("specification %d: not read: %v", spec.index, err)
		return
	}
	m, isObj := body.(map[string]any)
	if !isObj {
		t.skip("specification %d: the bytes are not a JSON object", spec.index)
		return
	}
	var wrong []string
	for _, k := range []string{"operation", "target", "policy_version", "input_version_refs"} {
		v, has := m[k]
		if !has || !drecSame(v, spec.summary[k]) {
			wrong = append(wrong, k)
		}
	}
	if len(wrong) > 0 {
		t.fail("specification %d: the summary's %s is not the bytes'", spec.index, strings.Join(wrong, ", "))
	}
}

// --- record statements ----------------------------------------------------------------

func drecRecordStatements(att *drecAttachment, record map[string]any) drecDim {
	if record == nil {
		return drecMake(drecNotChecked, "the decision record is not supplied")
	}
	t := &drecTally{}
	if !drecEq(record["decision_id"], att.doc["decision_id"]) {
		t.fail("the attachment names %s, the record %s", drecRepr(att.doc["decision_id"]), drecRepr(record["decision_id"]))
	}
	authority := record["drafting_authority"]
	for _, s := range att.ofKind("proposal") {
		if !drecEq(s.get("origin"), "ai") {
			continue
		}
		da, isObj := authority.(map[string]any)
		if !isObj {
			t.fail("%s: an AI proposer, and the record has no drafting_authority", s.id())
			continue
		}
		for _, k := range []string{"deployer_role_pointer", "system_name", "version"} {
			if !drecEq(s.get(k), da[k]) {
				t.fail("%s: %s is not the record's drafting_authority's", s.id(), k)
			}
		}
	}
	for _, s := range att.stages {
		if !s.kindIs("outcome", "standing_approval") {
			continue
		}
		approval := s.kindIs("standing_approval") || drecEq(s.get("outcome"), "approved")
		core, has := s.m["core_ref"]
		if !has || core == nil {
			if approval {
				t.skip("%s: no core field backs this approval", s.id())
			}
			continue
		}
		coreMap, _ := core.(map[string]any)
		drecCoreStatement(s, coreMap, record, t)
	}
	return t.result()
}

func drecCoreStatement(s *drecStage, core, record map[string]any, t *drecTally) {
	sid := s.id()
	word := s.get("outcome")
	if s.kindIs("standing_approval") {
		word = "approved"
	}
	var actor, when any
	if drecEq(core["field"], "affirmation_record") {
		entry, isObj := record["affirmation_record"].(map[string]any)
		if !isObj {
			t.fail("%s: the record has no affirmation_record", sid)
			return
		}
		if !drecEq(word, "approved") {
			t.fail("%s: an affirmation backs an outcome that is not an approval", sid)
		}
		actor, when = entry["actor_identity"], entry["timestamp"]
		if !drecEq(entry["method"], s.get("method")) {
			t.fail("%s: method is not the affirmation_record's", sid)
		}
	} else {
		index := core["index"]
		if !drecJSONInteger(index) {
			t.skip("%s: review_log index %s is not written as an integer", sid, drecRepr(index))
			return
		}
		log, isList := record["review_log"].([]any)
		i := drecIntValue(index)
		if !isList || i < 0 || i >= int64(len(log)) {
			t.fail("%s: review_log has no entry %d", sid, i)
			return
		}
		entry, isObj := log[i].(map[string]any)
		if !isObj {
			t.fail("%s: review_log has no entry %d", sid, i)
			return
		}
		actor, when = entry["reviewer"], entry["reviewed_at"]
		switch {
		case !drecIn(entry["outcome"], drecOutcomeWords...):
			t.skip("%s: review_log outcome %s is not a word this check knows", sid, drecRepr(entry["outcome"]))
		case !drecEq(entry["outcome"], word):
			t.fail("%s: the record's review_log says %v, the stage %v", sid, entry["outcome"], word)
		}
	}
	if !drecEq(actor, s.get("actor_ref")) {
		t.fail("%s: actor %s is not the record's %s", sid, drecRepr(s.get("actor_ref")), drecRepr(actor))
	}
	coreTime, stageTime := drecReadInstant(when), drecReadInstant(s.get("at"))
	switch {
	case !coreTime.ok():
		t.skip("%s: the record's time %s cannot be compared (%s)", sid, drecRepr(when), coreTime.why)
	case !stageTime.ok():
		t.fail("%s: the stage's time %s names no instant", sid, stageTime.text)
	case coreTime.sec.Cmp(stageTime.sec) != 0:
		t.fail("%s: the stage's time is not the record's", sid)
	}
}
