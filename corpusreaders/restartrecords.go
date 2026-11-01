package corpusreaders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

func init() { register(restartRecords{}) }

// restartRecords judges corpora/vectors-restart-records/. Each member is one decoded
// in-toto Statement v1 of a restoration-evidence/v1 predicate, or a bundle of
// them in one directory. The rules, their order and the reason codes are those
// of the Python checker beside the corpus (corpora/vectors-restart-records/check_vectors.py):
// every rule of the five predicate documents in table order, then the bundle
// rules B1 to B7 of profiles/restoration-evidence.md, the first failing rule
// being the reason. corpusreaders/testdata/restart-records.json.gz holds what the
// Python checker answers on tens of thousands of variants, and the tests hold
// this reader to it.
type restartRecords struct{}

func (restartRecords) Suite() string { return "restart-records/v1" }

const (
	rrHost          = "https://probityai.github.io/agent-evidence-vectors"
	rrStatementType = "https://in-toto.io/Statement/v1"
	rrR1            = "incident-action-authorization"
	rrR2            = "revocation-sweep"
	rrR3            = "re-enable-decision"
	rrR4            = "joint-authority"
	rrRB            = "revocation-boundary"
	rrProfile       = "profiles/restoration-evidence.md"
	rrBundleOK      = "bundle-consistent"
	// rrMaxIntDigits is CPython's int-from-text limit: json.loads refuses an
	// integer literal of more digits, so the Python checker reads it as malformed.
	rrMaxIntDigits = 4300
)

var (
	rrNames      = []string{rrR1, rrR2, rrR3, rrR4, rrRB}
	rrNameOfType = func() map[string]string {
		out := map[string]string{}
		for _, name := range rrNames {
			out[rrHost+"/predicate/v1/"+name] = name
		}
		return out
	}()
	rrAccepted = map[string]string{rrR1: "authorization-recorded", rrR2: "sweep-recorded",
		rrR3: "decision-recorded", rrR4: "assignment-recorded", rrRB: "boundary-recorded"}

	rrRegistry = map[string]map[string]bool{
		"response_function": rrSet("monitoring_increase", "restriction", "isolation", "pause",
			"remediation", "restoration"),
		"pause_hold": rrSet("held", "in_flight_unknown", "effect_after_pause",
			"residual_state_remains", "not_established"),
		"restoration_decision": rrSet("resume_full", "resume_staged", "remain_restricted",
			"not_established"),
		"revocation_state": rrSet("issued", "enforced_observed", "use_after_revocation",
			"not_established"),
		"intent_binding":     rrSet("committed_before_execution", "asserted_after_execution"),
		"independence_basis": rrSet("independent_sources", "subject_supplied", "undeclared"),
		"set_sufficiency":    rrSet("sufficient", "insufficient", "not_assessed"),
	}
	rrRoles     = rrSet("advised", "authorized", "executed", "accountable")
	rrAuthority = rrSet("role_grant", "policy_preauthorized", "contract_third_party",
		"executive_approval", "unknown")
	rrPartStates = rrSet("revoked", "retained", "unassessed")
	rrCoverage   = rrSet("complete_verified", "issued_after_only", "partial", "unknown")
	rrSinkKinds  = rrSet("database", "filesystem", "http_endpoint", "subprocess", "queue", "other")
	rrVantages   = rrSet("sink_side", "agent_side")
	rrResults    = rrSet("no_post_revocation_commit_observed", "post_revocation_commit_observed",
		"not_established")
	rrSlots = rrSet("actorObjective", "persistence", "rootCause", "affectedScope", "assetIntegrity",
		"restoredAssetsClean", "containmentReproof", "incidentReplay", "restoreOrder",
		"postRestartMonitoring", "exclusiveControl", "controlsNotDegraded", "residualRisk",
		"seniorApproval", "multiPartyAuthorization", "ownerConfirmation")
	rrScopeKeys = []string{"agents", "tools", "routes", "credentials"}
	rrCountKeys = []string{"attempts", "inFlightAtRevocation", "postRevocationCommits",
		"replaysAttempted", "replaysCommitted"}
	rrCommon = []string{"incident", "producer", "issuedAt", "registryDigest", "doesNotAssert"}

	// rrURLExcluded is the ECMAScript \s set that the JSON Schemas' URL pattern
	// excludes, which the Python checker spells out the same way.
	rrURLExcluded = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006" +
		"\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"

	// rrDigest names a bundle file by its bytes. Only a test replaces it, to
	// assign digests and so build the predecessor cycle no real digest can.
	rrDigest = sha

	// rrSkipped switches rules off by key ("<predicate>/<code>" or "bundle/<code>").
	// Only the test that proves each rule is load-bearing sets it.
	rrSkipped = map[string]bool{}
)

func rrSet(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		out[v] = true
	}
	return out
}

// --- strict JSON ------------------------------------------------------------------------

// rrStrict parses what the Python checker's strict_json accepts: UTF-8, no
// duplicate member at any depth, no NaN or Infinity, no lone surrogate, and no
// integer literal past CPython's digit limit.
func rrStrict(data []byte) (any, error) {
	if !utf8.Valid(data) || a2aLoneSurrogate(data) {
		return nil, errors.New("not UTF-8 text")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := cabDecode(dec)
	if err != nil {
		return nil, err
	}
	if _, extra := dec.Token(); !errors.Is(extra, io.EOF) {
		return nil, errors.New("trailing data")
	}
	if !rrDigitsWithinLimit(value) {
		return nil, errors.New("an integer past the digit limit")
	}
	return value, nil
}

func rrDigitsWithinLimit(value any) bool {
	switch v := value.(type) {
	case json.Number:
		text := strings.TrimPrefix(string(v), "-")
		return strings.ContainsAny(text, ".eE") || len(text) <= rrMaxIntDigits
	case []any:
		for _, item := range v {
			if !rrDigitsWithinLimit(item) {
				return false
			}
		}
	case map[string]any:
		for _, item := range v {
			if !rrDigitsWithinLimit(item) {
				return false
			}
		}
	}
	return true
}

// --- value shapes -----------------------------------------------------------------------

type rrObj = map[string]any

func rrExact(value any, required []string, optional ...string) bool {
	object, ok := value.(rrObj)
	if !ok {
		return false
	}
	for _, key := range required {
		if _, has := object[key]; !has {
			return false
		}
	}
	allowed := rrSet(append(append([]string{}, required...), optional...)...)
	for key := range object {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func rrHas(object rrObj, key string) bool {
	_, has := object[key]
	return has
}

func rrString(value any) bool {
	_, ok := value.(string)
	return ok
}

func rrText(value any) bool {
	s, ok := value.(string)
	return ok && s != ""
}

func rrOneOf(value any, allowed map[string]bool) bool {
	s, ok := value.(string)
	return ok && allowed[s]
}

func rrURL(value any) bool {
	s, ok := value.(string)
	if !ok || !strings.HasPrefix(s, "https://") || len(s) == len("https://") {
		return false
	}
	return !strings.ContainsAny(s[len("https://"):], rrURLExcluded)
}

// rrTime is an RFC 3339 UTC time to whole seconds in ASCII digits that names a
// real instant: what TIME_RE and datetime.strptime accept together.
func rrTime(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) != 20 {
		return false
	}
	for i := 0; i < 20; i++ {
		c := s[i]
		switch i {
		case 4, 7:
			if c != '-' {
				return false
			}
		case 10:
			if c != 'T' {
				return false
			}
		case 13, 16:
			if c != ':' {
				return false
			}
		case 19:
			if c != 'Z' {
				return false
			}
		default:
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	num := func(a, b int) int {
		n := 0
		for _, c := range s[a:b] {
			n = n*10 + int(c-'0')
		}
		return n
	}
	year, month, day := num(0, 4), num(5, 7), num(8, 10)
	if year < 1 || month < 1 || month > 12 || day < 1 || day > rrDaysIn(year, month) {
		return false
	}
	return num(11, 13) < 24 && num(14, 16) < 60 && num(17, 19) < 60
}

func rrDaysIn(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 31
}

func rrSha(value any) bool {
	if !rrExact(value, []string{"sha256"}) {
		return false
	}
	s, ok := value.(rrObj)["sha256"].(string)
	if !ok || len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// rrInt is the value of a JSON integer token, or nil for anything else: a token
// with a fraction or an exponent is a Python float, and a bool is never a count.
func rrInt(value any) *big.Int {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		return nil
	}
	out, ok := new(big.Int).SetString(string(n), 10)
	if !ok {
		return nil
	}
	return out
}

func rrCount(value any) bool {
	n := rrInt(value)
	return n != nil && n.Sign() >= 0
}

func rrList(value any, item func(any) bool, minItems int) bool {
	list, ok := value.([]any)
	if !ok || len(list) < minItems {
		return false
	}
	for _, v := range list {
		if !item(v) {
			return false
		}
	}
	return true
}

func rrStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// rrSortedUniqueTexts is a list of non-empty strings in strictly increasing
// code-point order, which is what value == sorted(value) with no repeat asks.
func rrSortedUniqueTexts(value any, minItems int) bool {
	if !rrList(value, rrText, minItems) {
		return false
	}
	items := rrStrings(value)
	for i := 1; i < len(items); i++ {
		if items[i-1] >= items[i] {
			return false
		}
	}
	return true
}

func rrRolesOK(value any) bool {
	return rrSortedUniqueTexts(value, 1) && rrList(value, func(r any) bool { return rrOneOf(r, rrRoles) }, 0)
}

func rrDescriptor(value any) bool {
	if !rrExact(value, []string{"digest"}, "uri", "mediaType") {
		return false
	}
	object := value.(rrObj)
	for _, key := range []string{"uri", "mediaType"} {
		if rrHas(object, key) && !rrText(object[key]) {
			return false
		}
	}
	return rrSha(object["digest"])
}

func rrRef(value any) bool {
	return rrExact(value, []string{"issuer", "id"}) && rrURL(value.(rrObj)["issuer"]) &&
		rrText(value.(rrObj)["id"])
}

func rrSameStrings(a, b []string) bool {
	x, y := sortedStrings(a), sortedStrings(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// --- rule 1 and the common members -----------------------------------------------------

func rrSubject(value any) bool {
	if !rrExact(value, []string{"digest"}, "name") {
		return false
	}
	object := value.(rrObj)
	return rrSha(object["digest"]) && (!rrHas(object, "name") || rrText(object["name"]))
}

// rrStatementName is rule 1 of every document: the predicate name, or "" when
// the statement is malformed.
func rrStatementName(statement any) string {
	object, isObject := statement.(rrObj)
	predicateType, _ := object["predicateType"].(string)
	name := rrNameOfType[predicateType]
	if rrSkipped["statement/statement-malformed"] {
		_, predicateOK := object["predicate"].(rrObj)
		if predicateOK {
			return name
		}
		return ""
	}
	if !isObject || !rrExact(statement, []string{"_type", "subject", "predicateType", "predicate"}) {
		return ""
	}
	if object["_type"] != rrStatementType || name == "" || !rrList(object["subject"], rrSubject, 1) {
		return ""
	}
	if _, ok := object["predicate"].(rrObj); !ok {
		return ""
	}
	return name
}

func rrCommonOK(p rrObj) bool {
	incident, _ := p["incident"].(rrObj)
	producer, _ := p["producer"].(rrObj)
	return rrExact(p["incident"], []string{"issuer", "id"}, "related") &&
		rrURL(incident["issuer"]) && rrText(incident["id"]) &&
		(!rrHas(incident, "related") || rrList(incident["related"], rrRef, 0)) &&
		rrExact(p["producer"], []string{"id"}) && rrURL(producer["id"]) &&
		rrTime(p["issuedAt"]) && rrSha(p["registryDigest"]) &&
		rrList(p["doesNotAssert"], rrText, 0)
}

func rrPredecessors(value any, needs string) bool {
	entry := func(r any) bool {
		return rrExact(r, []string{"predicateType", "digest"}) &&
			rrOneOf(r.(rrObj)["predicateType"], rrTypeSet) && rrSha(r.(rrObj)["digest"])
	}
	if !rrList(value, entry, 1) {
		return false
	}
	if needs == "" {
		return true
	}
	for _, r := range value.([]any) {
		if r.(rrObj)["predicateType"] == rrHost+"/predicate/v1/"+needs {
			return true
		}
	}
	return false
}

var rrTypeSet = func() map[string]bool {
	out := map[string]bool{}
	for uri := range rrNameOfType {
		out[uri] = true
	}
	return out
}()

func rrKeys(extra ...string) []string { return append(append([]string{}, rrCommon...), extra...) }

func rrObjAt(p rrObj, keys ...string) rrObj {
	var cur any = p
	for _, k := range keys {
		object, _ := cur.(rrObj)
		cur = object[k]
	}
	object, _ := cur.(rrObj)
	return object
}

func rrListAt(p rrObj, key string) []any {
	list, _ := p[key].([]any)
	return list
}

// rrBefore compares two valid times; fixed-width UTC text orders as instants.
func rrBefore(a, b any) bool { return a.(string) <= b.(string) }

// --- the rules ----------------------------------------------------------------------------

type rrRule struct {
	code string
	ok   func(p rrObj) bool
}

// rrRules is each document's Rules table from rule 2 on, in order. Rule 1 is
// rrStatementName. The tests hold the codes equal to the tables in the documents.
var rrRules = map[string][]rrRule{
	rrR1: {
		{"predicate-malformed", rrR1Shape},
		{"closed-vocabulary-violation", rrR1Vocabulary},
		{"no-authorizer", func(p rrObj) bool { return len(rrHolders(p, "authorized")) > 0 }},
		{"no-accountable-party", func(p rrObj) bool { return len(rrHolders(p, "accountable")) > 0 }},
		{"authority-basis-missing", func(p rrObj) bool {
			for _, party := range rrHolders(p, "authorized") {
				if !rrHas(party, "authorityBasis") {
					return false
				}
			}
			return true
		}},
		{"authorization-window-inverted", func(p rrObj) bool { return rrBefore(p["authorizedAt"], p["notAfter"]) }},
		{"intent-not-committed-before", func(p rrObj) bool {
			if p["intentBinding"] != "committed_before_execution" || !rrHas(p, "executedAt") {
				return true
			}
			return rrBefore(p["authorizedAt"], p["executedAt"])
		}},
		{"authorization-expired", func(p rrObj) bool {
			return !rrHas(p, "executedAt") || rrBefore(p["executedAt"], p["notAfter"])
		}},
		{"induced-effects-unobserved", func(p rrObj) bool {
			effects := rrObjAt(p, "action", "inducedEffects")
			return effects["declared"] != "none_observed" || rrHas(effects, "observation")
		}},
	},
	rrR2: {
		{"predicate-malformed", rrR2Shape},
		{"closed-vocabulary-violation", func(p rrObj) bool {
			for _, entry := range rrListAt(p, "revocations") {
				for _, rp := range rrListAt(entry.(rrObj), "relyingParties") {
					if !rrOneOf(rp.(rrObj)["state"], rrRegistry["revocation_state"]) {
						return false
					}
				}
			}
			return true
		}},
		{"denominator-union-mismatch", func(p rrObj) bool {
			return rrSameStrings(rrPartMembers(p, ""), rrPopulation(p))
		}},
		{"revocation-entries-mismatch", func(p rrObj) bool {
			var revoked []string
			for _, entry := range rrListAt(p, "revocations") {
				revoked = append(revoked, entry.(rrObj)["credential"].(string))
			}
			return rrSameStrings(revoked, rrPartMembers(p, "revoked"))
		}},
		{"coverage-claim-exceeds-proof", func(p rrObj) bool {
			return rrObjAt(p, "coverage")["claim"] != "complete_verified" ||
				rrSameStrings(rrPartMembers(p, "revoked"), rrPopulation(p))
		}},
		{"coverage-claim-incomplete", func(p rrObj) bool {
			coverage := rrObjAt(p, "coverage")
			return coverage["claim"] != "issued_after_only" || rrHas(coverage, "issuedAfter")
		}},
	},
	rrR3: {
		{"predicate-malformed", rrR3Shape},
		{"closed-vocabulary-violation", func(p rrObj) bool {
			if !rrOneOf(rrObjAt(p, "restoration")["decision"], rrRegistry["restoration_decision"]) ||
				!rrOneOf(p["setSufficiency"], rrRegistry["set_sufficiency"]) {
				return false
			}
			for _, a := range rrListAt(p, "approvers") {
				if !rrOneOf(a.(rrObj)["independenceBasis"], rrRegistry["independence_basis"]) {
					return false
				}
			}
			return true
		}},
		{"evidence-slot-missing", func(p rrObj) bool {
			evidence := rrObjAt(p, "evidence")
			if len(evidence) != len(rrSlots) {
				return false
			}
			for slot := range evidence {
				if !rrSlots[slot] {
					return false
				}
			}
			return true
		}},
		{"evidence-slot-unexplained", func(p rrObj) bool {
			for _, v := range rrObjAt(p, "evidence") {
				if reason, has := v.(rrObj)["notAddressed"]; has && reason == "" {
					return false
				}
			}
			return true
		}},
		{"no-approver", func(p rrObj) bool {
			for _, a := range rrListAt(p, "approvers") {
				for _, role := range rrStrings(a.(rrObj)["roles"]) {
					if role == "authorized" {
						return true
					}
				}
			}
			return false
		}},
		{"partial-without-scope", func(p rrObj) bool {
			restoration := rrObjAt(p, "restoration")
			return restoration["decision"] != "resume_staged" || rrScopeSize(restoration) > 0
		}},
		{"full-with-scope", func(p rrObj) bool {
			restoration := rrObjAt(p, "restoration")
			return restoration["decision"] != "resume_full" || !rrHas(restoration, "restoredScope")
		}},
	},
	rrR4: {
		{"predicate-malformed", rrR4Shape},
		// No member of this predicate takes a registry-defined value.
		{"closed-vocabulary-violation", func(rrObj) bool { return true }},
		{"authority-basis-missing", func(p rrObj) bool {
			for _, party := range rrListAt(p, "parties") {
				if !rrHas(party.(rrObj), "authorityBasis") {
					return false
				}
			}
			return true
		}},
		{"single-organization", func(p rrObj) bool {
			orgs := map[string]bool{}
			for _, party := range rrListAt(p, "parties") {
				orgs[party.(rrObj)["organization"].(string)] = true
			}
			return len(orgs) >= 2
		}},
		{"party-acts-outside-assignment", func(p rrObj) bool {
			for _, a := range rrListAt(p, "actions") {
				if !rrAssigned(p, a.(rrObj)) {
					return false
				}
			}
			return true
		}},
	},
	rrRB: {
		{"predicate-malformed", rrRBShape},
		// No member of this predicate takes a registry-defined value.
		{"closed-vocabulary-violation", func(rrObj) bool { return true }},
		{"revocation-outside-window", func(p rrObj) bool {
			window, at := rrObjAt(p, "window"), rrObjAt(p, "revocation")["effectiveAt"]
			return rrBefore(window["start"], at) && rrBefore(at, window["end"])
		}},
		{"counts-inconsistent", func(p rrObj) bool {
			c := rrObjAt(p, "counts")
			n := func(k string) *big.Int { return rrInt(c[k]) }
			return n("inFlightAtRevocation").Cmp(n("attempts")) <= 0 &&
				n("postRevocationCommits").Cmp(n("inFlightAtRevocation")) <= 0 &&
				n("replaysCommitted").Cmp(n("replaysAttempted")) <= 0
		}},
		{"result-contradicts-counts", func(p rrObj) bool {
			if p["result"] == "not_established" {
				return true
			}
			c := rrObjAt(p, "counts")
			committed := rrInt(c["postRevocationCommits"]).Sign() > 0 || rrInt(c["replaysCommitted"]).Sign() > 0
			return (p["result"] == "post_revocation_commit_observed") == committed
		}},
		{"observer-not-at-sink", func(p rrObj) bool {
			return p["result"] != "no_post_revocation_commit_observed" ||
				rrObjAt(p, "observer")["vantage"] == "sink_side"
		}},
	},
}

func rrHolders(p rrObj, role string) []rrObj {
	var out []rrObj
	for _, party := range rrListAt(p, "parties") {
		object := party.(rrObj)
		for _, r := range rrStrings(object["roles"]) {
			if r == role {
				out = append(out, object)
				break
			}
		}
	}
	return out
}

func rrPopulation(p rrObj) []string { return rrStrings(rrObjAt(p, "population")["credentials"]) }

func rrPartMembers(p rrObj, state string) []string {
	var out []string
	for _, part := range rrListAt(p, "partition") {
		object := part.(rrObj)
		if state == "" || object["state"] == state {
			out = append(out, rrStrings(object["credentials"])...)
		}
	}
	return out
}

func rrScopeSize(restoration rrObj) int {
	scope, _ := restoration["restoredScope"].(rrObj)
	total := 0
	for _, key := range rrScopeKeys {
		total += len(rrStrings(scope[key]))
	}
	return total
}

func rrAssigned(p rrObj, action rrObj) bool {
	for _, party := range rrListAt(p, "parties") {
		object := party.(rrObj)
		if object["id"] != action["party"] {
			continue
		}
		for _, asset := range rrStrings(object["assets"]) {
			if asset == action["asset"] {
				return true
			}
		}
	}
	return false
}

func rrR1Effects(value any) bool {
	object, ok := value.(rrObj)
	if !ok || !rrString(object["declared"]) {
		return false
	}
	switch object["declared"] {
	case "listed":
		if !rrExact(value, []string{"declared", "items"}) || !rrList(object["items"], rrText, 1) {
			return false
		}
		items := rrStrings(object["items"])
		return len(rrSet(items...)) == len(items)
	case "none_observed":
		return rrExact(value, []string{"declared"}, "observation") &&
			(!rrHas(object, "observation") || rrSha(object["observation"]))
	case "unknown":
		return rrExact(value, []string{"declared"})
	}
	return false
}

func rrR1Party(value any) bool {
	if !rrExact(value, []string{"id", "roles"}, "authorityBasis", "independenceBasis") {
		return false
	}
	object := value.(rrObj)
	return rrText(object["id"]) && rrRolesOK(object["roles"]) &&
		(!rrHas(object, "authorityBasis") || rrOneOf(object["authorityBasis"], rrAuthority)) &&
		(!rrHas(object, "independenceBasis") || rrString(object["independenceBasis"]))
}

func rrR1Shape(p rrObj) bool {
	if !rrExact(p, rrKeys("action", "parties", "authorizedAt", "notAfter", "intentBinding"),
		"executedAt", "pause") || !rrCommonOK(p) {
		return false
	}
	action := rrObjAt(p, "action")
	target := func(t any) bool { return rrExact(t, []string{"id"}) && rrText(t.(rrObj)["id"]) }
	pauseOK := !rrHas(p, "pause") || (rrExact(p["pause"], []string{"hold", "holdProof"}) &&
		rrString(rrObjAt(p, "pause")["hold"]) && rrSha(rrObjAt(p, "pause")["holdProof"]))
	return rrExact(p["action"], []string{"functions", "targets", "inducedEffects"}) &&
		rrSortedUniqueTexts(action["functions"], 1) && rrList(action["targets"], target, 1) &&
		rrR1Effects(action["inducedEffects"]) && rrList(p["parties"], rrR1Party, 1) &&
		rrTime(p["authorizedAt"]) && rrTime(p["notAfter"]) &&
		(!rrHas(p, "executedAt") || rrTime(p["executedAt"])) &&
		rrString(p["intentBinding"]) && pauseOK
}

func rrR1Vocabulary(p rrObj) bool {
	for _, f := range rrStrings(rrObjAt(p, "action")["functions"]) {
		if !rrRegistry["response_function"][f] {
			return false
		}
	}
	if !rrOneOf(p["intentBinding"], rrRegistry["intent_binding"]) {
		return false
	}
	if rrHas(p, "pause") && !rrOneOf(rrObjAt(p, "pause")["hold"], rrRegistry["pause_hold"]) {
		return false
	}
	for _, party := range rrListAt(p, "parties") {
		object := party.(rrObj)
		if rrHas(object, "independenceBasis") &&
			!rrOneOf(object["independenceBasis"], rrRegistry["independence_basis"]) {
			return false
		}
	}
	return true
}

func rrR2Revocation(value any) bool {
	if !rrExact(value, []string{"credential", "revokedAt", "evidence", "relyingParties"}) {
		return false
	}
	object := value.(rrObj)
	rp := func(r any) bool {
		return rrExact(r, []string{"id", "state"}) && rrText(r.(rrObj)["id"]) && rrString(r.(rrObj)["state"])
	}
	return rrText(object["credential"]) && rrTime(object["revokedAt"]) &&
		rrDescriptor(object["evidence"]) && rrList(object["relyingParties"], rp, 0)
}

func rrR2Shape(p rrObj) bool {
	if !rrExact(p, rrKeys("predecessors", "population", "partition", "revocations", "coverage")) ||
		!rrCommonOK(p) {
		return false
	}
	part := func(v any) bool {
		return rrExact(v, []string{"state", "credentials"}) &&
			rrOneOf(v.(rrObj)["state"], rrPartStates) && rrList(v.(rrObj)["credentials"], rrText, 1)
	}
	coverage := rrObjAt(p, "coverage")
	return rrPredecessors(p["predecessors"], rrR1) &&
		rrExact(p["population"], []string{"credentials"}) &&
		rrSortedUniqueTexts(rrObjAt(p, "population")["credentials"], 1) &&
		rrList(p["partition"], part, 1) && rrList(p["revocations"], rrR2Revocation, 0) &&
		rrExact(p["coverage"], []string{"claim"}, "issuedAfter") && rrOneOf(coverage["claim"], rrCoverage) &&
		(!rrHas(coverage, "issuedAfter") || rrTime(coverage["issuedAfter"]))
}

func rrR3Slot(value any) bool {
	if object, ok := value.(rrObj); ok && rrHas(object, "notAddressed") {
		return rrExact(value, []string{"notAddressed"}) && rrString(object["notAddressed"])
	}
	return rrDescriptor(value)
}

func rrR3Shape(p rrObj) bool {
	if !rrExact(p, rrKeys("predecessors", "restoration", "approvers", "setSufficiency", "evidence")) ||
		!rrCommonOK(p) {
		return false
	}
	restoration := rrObjAt(p, "restoration")
	scopeOK := !rrHas(restoration, "restoredScope")
	if !scopeOK && rrExact(restoration["restoredScope"], rrScopeKeys) {
		scopeOK = true
		for _, key := range rrScopeKeys {
			scopeOK = scopeOK && rrSortedUniqueTexts(rrObjAt(restoration, "restoredScope")[key], 0)
		}
	}
	approver := func(a any) bool {
		return rrExact(a, []string{"id", "roles", "independenceBasis"}) && rrText(a.(rrObj)["id"]) &&
			rrRolesOK(a.(rrObj)["roles"]) && rrString(a.(rrObj)["independenceBasis"])
	}
	evidence, ok := p["evidence"].(rrObj)
	if !ok {
		return false
	}
	for _, v := range evidence {
		if !rrR3Slot(v) {
			return false
		}
	}
	return rrPredecessors(p["predecessors"], "") &&
		rrExact(p["restoration"], []string{"decision"}, "restoredScope") &&
		rrString(restoration["decision"]) && scopeOK &&
		rrList(p["approvers"], approver, 0) && rrString(p["setSufficiency"])
}

func rrR4Party(value any) bool {
	if !rrExact(value, []string{"id", "organization", "correlationId", "assets"}, "authorityBasis") {
		return false
	}
	object := value.(rrObj)
	return rrText(object["id"]) && rrText(object["organization"]) && rrText(object["correlationId"]) &&
		(!rrHas(object, "authorityBasis") || rrOneOf(object["authorityBasis"], rrAuthority)) &&
		rrSortedUniqueTexts(object["assets"], 0)
}

func rrR4Shape(p rrObj) bool {
	if !rrExact(p, rrKeys("sharedIndicators", "parties"), "actions") || !rrCommonOK(p) {
		return false
	}
	if !rrList(p["sharedIndicators"], rrSha, 1) {
		return false
	}
	indicators := rrListAt(p, "sharedIndicators")
	for i := 1; i < len(indicators); i++ {
		if indicators[i-1].(rrObj)["sha256"].(string) > indicators[i].(rrObj)["sha256"].(string) {
			return false
		}
	}
	action := func(a any) bool {
		return rrExact(a, []string{"party", "asset", "record"}) && rrText(a.(rrObj)["party"]) &&
			rrText(a.(rrObj)["asset"]) && rrSha(a.(rrObj)["record"])
	}
	return rrList(p["parties"], rrR4Party, 2) && (!rrHas(p, "actions") || rrList(p["actions"], action, 0))
}

func rrRBShape(p rrObj) bool {
	if !rrExact(p, rrKeys("sink", "observer", "revocation", "window", "counts", "exclusions", "result"),
		"predecessors") || !rrCommonOK(p) {
		return false
	}
	sink, observer, revocation := rrObjAt(p, "sink"), rrObjAt(p, "observer"), rrObjAt(p, "revocation")
	window, counts := rrObjAt(p, "window"), rrObjAt(p, "counts")
	countsOK := rrExact(p["counts"], rrCountKeys)
	for _, key := range rrCountKeys {
		countsOK = countsOK && rrCount(counts[key])
	}
	exclusion := func(e any) bool {
		return rrExact(e, []string{"count", "reason"}) && rrCount(e.(rrObj)["count"]) && rrText(e.(rrObj)["reason"])
	}
	return rrExact(p["sink"], []string{"id", "kind", "commitBoundary"}) && rrText(sink["id"]) &&
		rrOneOf(sink["kind"], rrSinkKinds) && rrText(sink["commitBoundary"]) &&
		rrExact(p["observer"], []string{"id", "vantage"}) && rrText(observer["id"]) &&
		rrOneOf(observer["vantage"], rrVantages) &&
		rrExact(p["revocation"], []string{"credential", "effectiveAt", "timeSource"}) &&
		rrText(revocation["credential"]) && rrTime(revocation["effectiveAt"]) && rrText(revocation["timeSource"]) &&
		rrExact(p["window"], []string{"start", "end"}) && rrTime(window["start"]) && rrTime(window["end"]) &&
		countsOK && rrList(p["exclusions"], exclusion, 0) && rrOneOf(p["result"], rrResults) &&
		(!rrHas(p, "predecessors") || rrPredecessors(p["predecessors"], ""))
}

// --- one record ---------------------------------------------------------------------------

// rrCheckStatement applies the document the statement's predicateType names.
func rrCheckStatement(statement any) (string, string) {
	name := rrStatementName(statement)
	if name == "" {
		return "reject", "statement-malformed"
	}
	predicate := statement.(rrObj)["predicate"].(rrObj)
	for _, rule := range rrRules[name] {
		if rrSkipped[name+"/"+rule.code] {
			continue
		}
		if !rule.ok(predicate) {
			return "reject", rule.code
		}
	}
	return "accept", rrAccepted[name]
}

// rrCheckRecord checks one statement's bytes: strict JSON first, then its document.
func rrCheckRecord(data []byte) (string, string) {
	statement, err := rrStrict(data)
	if err != nil {
		return "reject", "statement-malformed"
	}
	return rrCheckStatement(statement)
}

// --- a bundle ------------------------------------------------------------------------------

// errRRUnreadable is a bundle that carries no verdict at all: one that does not
// carry exactly one re-enable-decision record, or a directory with no statement.
var errRRUnreadable = errors.New("not a restoration-evidence bundle")

type rrBundle struct {
	names      []string
	predicates map[string]rrObj
	types      map[string]string
	digest     map[string]string
	refs       map[string][]rrObj
	resolved   map[string][]string
	decision   string
}

type rrBundleRule struct {
	code string
	ok   func(b *rrBundle) bool
}

var rrBundleRules = []rrBundleRule{
	{"predecessor-not-carried", (*rrBundle).carried},
	{"predecessor-type-mismatch", (*rrBundle).typesMatch},
	{"predecessor-cycle", func(b *rrBundle) bool { return !rrFindCycle(b.resolved) }},
	{"incident-mismatch", (*rrBundle).sameIncident},
	{"predecessor-issued-later", (*rrBundle).ordered},
	{"restored-credential-unswept", (*rrBundle).swept},
}

func (b *rrBundle) carried() bool {
	for _, name := range b.names {
		b.resolved[name] = nil
		for _, ref := range b.refs[name] {
			want := rrObjAt(ref, "digest")["sha256"]
			var hits []string
			for _, other := range b.names {
				if b.digest[other] == want {
					hits = append(hits, other)
				}
			}
			if len(hits) != 1 {
				return false
			}
			b.resolved[name] = append(b.resolved[name], hits[0])
		}
	}
	return true
}

func (b *rrBundle) typesMatch() bool {
	for _, name := range b.names {
		for i, ref := range b.refs[name] {
			if i >= len(b.resolved[name]) || b.types[b.resolved[name][i]] != ref["predicateType"] {
				return false
			}
		}
	}
	return true
}

func rrIncidentKeys(p rrObj) map[[2]string]bool {
	incident := rrObjAt(p, "incident")
	key := func(o rrObj) [2]string {
		issuer, _ := o["issuer"].(string)
		id, _ := o["id"].(string)
		return [2]string{issuer, id}
	}
	keys := map[[2]string]bool{key(incident): true}
	for _, r := range rrListAt(incident, "related") {
		keys[key(r.(rrObj))] = true
	}
	return keys
}

func (b *rrBundle) sameIncident() bool {
	anchor := rrIncidentKeys(b.predicates[b.decision])
	for _, name := range b.names {
		shared := false
		for k := range rrIncidentKeys(b.predicates[name]) {
			shared = shared || anchor[k]
		}
		if !shared {
			return false
		}
	}
	return true
}

func (b *rrBundle) ordered() bool {
	for _, name := range b.names {
		for _, target := range b.resolved[name] {
			if !rrBefore(b.predicates[target]["issuedAt"], b.predicates[name]["issuedAt"]) {
				return false
			}
		}
	}
	return true
}

func (b *rrBundle) swept() bool {
	swept := map[string]bool{}
	for _, name := range b.names {
		if b.types[name] == rrHost+"/predicate/v1/"+rrR2 {
			for _, c := range rrPopulation(b.predicates[name]) {
				swept[c] = true
			}
		}
	}
	scope, ok := rrObjAt(b.predicates[b.decision], "restoration")["restoredScope"].(rrObj)
	if !ok {
		return true
	}
	for _, c := range rrStrings(scope["credentials"]) {
		if !swept[c] {
			return false
		}
	}
	return true
}

// rrFindCycle is true when the predecessor graph (record -> records it names)
// has a cycle.
func rrFindCycle(edges map[string][]string) bool {
	state := map[string]int{}
	var visit func(node string) bool
	visit = func(node string) bool {
		state[node] = 1
		for _, next := range edges[node] {
			if state[next] == 1 || (state[next] == 0 && visit(next)) {
				return true
			}
		}
		state[node] = 2
		return false
	}
	for _, node := range sortedKeys(edges) {
		if state[node] == 0 && visit(node) {
			return true
		}
	}
	return false
}

// rrCheckBundle checks a bundle given as file name -> statement bytes.
func rrCheckBundle(files map[string][]byte) (string, string, error) {
	names := sortedKeys(files)
	if !rrSkipped["bundle/B1"] {
		for _, name := range names {
			if verdict, reason := rrCheckRecord(files[name]); verdict != "accept" {
				return "reject", reason, nil
			}
		}
	}
	b := &rrBundle{names: names, predicates: map[string]rrObj{}, types: map[string]string{},
		digest: map[string]string{}, refs: map[string][]rrObj{}, resolved: map[string][]string{}}
	var decisions []string
	for _, name := range names {
		value, _ := rrStrict(files[name])
		statement, _ := value.(rrObj)
		b.predicates[name], _ = statement["predicate"].(rrObj)
		b.types[name], _ = statement["predicateType"].(string)
		b.digest[name] = rrDigest(files[name])
		for _, ref := range rrListAt(b.predicates[name], "predecessors") {
			object, _ := ref.(rrObj)
			b.refs[name] = append(b.refs[name], object)
		}
		if rrNameOfType[b.types[name]] == rrR3 {
			decisions = append(decisions, name)
		}
	}
	if len(decisions) != 1 {
		return "", "", fmt.Errorf("%w: a bundle carries exactly one %s record; this one carries %d",
			errRRUnreadable, rrR3, len(decisions))
	}
	b.decision = decisions[0]
	for _, rule := range rrBundleRules {
		if rrSkipped["bundle/"+rule.code] {
			continue
		}
		if !rule.ok(b) {
			return "reject", rule.code, nil
		}
	}
	return "accept", rrBundleOK, nil
}

// rrBundleDir reads every regular *.json file in a directory, skipping hidden
// names as Python's glob does.
func rrBundleDir(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		// name is an entry of the corpus directory listing, never caller input.
		info, err := os.Stat(filepath.Join(dir, name)) //nolint:gosec // G703: name comes from os.ReadDir(dir)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		body, err := readIn(dir, name)
		if err != nil {
			return nil, err
		}
		files[name] = body
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: %s holds no *.json statement", errRRUnreadable, dir)
	}
	return files, nil
}

// --- the corpus ------------------------------------------------------------------------------

type rrVector struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Path     string            `json:"path"`
	Shape    string            `json:"shape"`
	Files    map[string]string `json:"files"`
	Expected struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	} `json:"expected"`
}

type rrManifest struct {
	Counts       map[string]int    `json:"counts"`
	CorpusDigest string            `json:"corpusDigest"`
	SpecDigests  map[string]string `json:"specDigests"`
	Vectors      []rrVector        `json:"vectors"`
}

func (restartRecords) Judge(dir string, raw []byte) (*Result, error) {
	var manifest rrManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	measured := map[string]int{}
	for _, v := range manifest.Vectors {
		measured[v.Kind]++
		result.Members = append(result.Members, Member{ID: v.ID, Kind: v.Kind, Findings: rrJudgeMember(dir, v)})
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	if bad := rrCorpusDigest(raw, manifest.CorpusDigest); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	for _, rel := range sortedKeys(manifest.SpecDigests) {
		if bad := checkVendored(filepath.Join(dir, ".."), rel, manifest.SpecDigests[rel], "document"); bad != "" {
			result.Findings = append(result.Findings, bad)
		}
	}
	return result, nil
}

func rrJudgeMember(dir string, v rrVector) []string {
	var findings []string
	caseDir := filepath.Join(dir, v.Path)
	if v.Kind != v.Expected.Verdict {
		findings = append(findings, fmt.Sprintf("kind %s, expected verdict %s", v.Kind, v.Expected.Verdict))
	}
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return append(findings, v.Path+" cannot be read")
	}
	for _, entry := range entries {
		if _, listed := v.Files[entry.Name()]; !listed && !entry.IsDir() {
			findings = append(findings, entry.Name()+" is in the member's directory and not in its manifest row")
		}
	}
	for _, name := range sortedKeys(v.Files) {
		body, err := readIn(caseDir, name)
		if err != nil {
			findings = append(findings, name+" is missing")
		} else if sha(body) != v.Files[name] {
			findings = append(findings, name+" does not match its manifest digest")
		}
	}
	var verdict, reason string
	if v.Shape == "bundle" {
		files, err := rrBundleDir(caseDir)
		if err == nil {
			verdict, reason, err = rrCheckBundle(files)
		}
		if err != nil {
			return append(findings, err.Error())
		}
	} else {
		body, err := readIn(caseDir, "statement.json")
		if err != nil {
			return append(findings, "statement.json cannot be read")
		}
		verdict, reason = rrCheckRecord(body)
	}
	if verdict != v.Expected.Verdict || reason != v.Expected.Reason {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			verdict, reason, v.Expected.Verdict, v.Expected.Reason))
	}
	return findings
}

// rrCorpusDigest recomputes corpusDigest: SHA-256 over the vectors array as
// json.dumps(indent=2, sort_keys=True, ensure_ascii=True) plus a newline writes
// it. The member file digests are checked against the files per member, so the
// array is the one the generator hashed exactly when every member is intact.
func rrCorpusDigest(raw []byte, declared string) string {
	value, err := decodeJSONNumbers(raw)
	if err != nil {
		return "MANIFEST.json does not parse: " + err.Error()
	}
	vectors := value.(map[string]any)["vectors"]
	var buf bytes.Buffer
	if err := rrPretty(&buf, vectors, 0); err != nil {
		return "corpusDigest cannot be recomputed: " + err.Error()
	}
	buf.WriteByte('\n')
	if got := sha(buf.Bytes()); got != declared {
		return fmt.Sprintf("corpusDigest is %s, the vectors hash to %s", short(declared), short(got))
	}
	return ""
}

// rrPretty writes what CPython's json.dumps(value, indent=2, sort_keys=True,
// ensure_ascii=True) writes. A float refuses, as pythonCompactJSON does.
func rrPretty(buf *bytes.Buffer, value any, depth int) error {
	indent := func(d int) { buf.WriteString("\n" + strings.Repeat("  ", d)) }
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writePythonString(buf, v, true)
	case json.Number:
		n := rrInt(v)
		if n == nil {
			return fmt.Errorf("a float (%s) has no agreed spelling", v)
		}
		buf.WriteString(n.String())
	case []any:
		if len(v) == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			indent(depth + 1)
			if err := rrPretty(buf, item, depth+1); err != nil {
				return err
			}
		}
		indent(depth)
		buf.WriteByte(']')
	case map[string]any:
		if len(v) == 0 {
			buf.WriteString("{}")
			return nil
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			indent(depth + 1)
			writePythonString(buf, k, true)
			buf.WriteString(": ")
			if err := rrPretty(buf, v[k], depth+1); err != nil {
				return err
			}
		}
		indent(depth)
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unexpected %T", value)
	}
	return nil
}
