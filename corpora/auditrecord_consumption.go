package corpora

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// Consumption binding (Section 5.4, revision 01), restated from the draft for
// the Go rail, mirroring packaging/agent_evidence_vectors/auditrecord.py. A
// consumption-state entry of evaluation.inputs may carry a consumption member,
// and decision.operationKey is the agent's identifier for one intended
// operation and the identity of a retry. Members CS1 to CS40 exercise it, and
// consumption.supersedes names the limit document a record's limitDigest
// replaced. CS7, CS8, CS17, CS18 to CS22 and CS25 are files of several records judged
// one by one and then as a set, under one ledger: the limitDigest values that
// supersedes links.

// arInt reads a JSON integer as the decoder's json.Number.
func arInt(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return parsed, err == nil
}

func arIsCount(value any) bool {
	parsed, ok := arInt(value)
	return ok && parsed >= 0
}

// arConsumptionOf returns the consumption member of the consumption-state
// entry, or nil when no entry carries one.
func arConsumptionOf(pred map[string]any) map[string]any {
	for _, item := range arList(pred, "evaluation.inputs") {
		entry, ok := item.(map[string]any)
		if ok && entry["input"] == arConsumptionInput {
			found, _ := entry["consumption"].(map[string]any)
			return found
		}
	}
	return nil
}

// arHeldFor returns the held entry this call is a retry of, or nil.
func arHeldFor(consumption, decision map[string]any) map[string]any {
	held, _ := consumption["held"].([]any)
	for _, item := range held {
		entry, _ := item.(map[string]any)
		if arRetryOf(entry, decision) {
			return entry
		}
	}
	return nil
}

// arWithinLimit is the value a verifier derives for a record that carries
// consumption: the amount already consumed, plus the amount held for earlier
// permits, plus this call's amount unless it is a retry of a held permit, is at
// most the limit. It is nil for a record that carries no consumption.
func arWithinLimit(pred map[string]any) *bool {
	consumption := arConsumptionOf(pred)
	if consumption == nil {
		return nil
	}
	consumed, _ := arInt(consumption["consumed"])
	reserved, _ := arInt(consumption["reserved"])
	limit, _ := arInt(consumption["limit"])
	counted := consumed + reserved
	if arHeldFor(consumption, arObj(pred, "decision")) == nil {
		requested, _ := arInt(consumption["requested"])
		counted += requested
	}
	within := counted <= limit
	return &within
}

// arHeldShape holds one held entry to exactly operationKey, requestDigest and
// amount.
func arHeldShape(item any) error {
	entry, ok := item.(map[string]any)
	if !ok {
		return arRefuse("consumption-malformed")
	}
	if !arHasAll(entry, arHeldMembers) {
		return arRefuse("member-missing")
	}
	for name := range entry {
		if !arContains(arHeldMembers, name) {
			return arRefuse("consumption-malformed")
		}
	}
	key, isText := entry["operationKey"].(string)
	digest, _ := entry["requestDigest"].(string)
	if !isText || key == "" || !arIsDigest(digest) || !arIsCount(entry["amount"]) {
		return arRefuse("consumption-value-invalid")
	}
	return nil
}

func arConsumptionShape(consumption map[string]any) error {
	if err := arConsumptionMembership(consumption); err != nil {
		return err
	}
	_, hasAsset := consumption["asset"]
	_, hasUnit := consumption["unit"]
	if arConsumptionChecks["asset-exclusive"] && hasAsset && hasUnit {
		return arRefuse("consumption-unit-ambiguous")
	}
	digest, _ := consumption["limitDigest"].(string)
	unit, isText := consumption["unit"].(string)
	if !hasUnit {
		unit, isText = "-", true
	}
	if !arIsDigest(digest) || !isText || unit == "" {
		return arRefuse("consumption-value-invalid")
	}
	if hasAsset {
		if err := arAssetShape(consumption["asset"]); err != nil {
			return err
		}
	}
	if err := arConsumptionSupersedes(consumption, digest); err != nil {
		return err
	}
	if err := arConsumptionCountValues(consumption); err != nil {
		return err
	}
	held, ok := consumption["held"].([]any)
	if !ok {
		return arRefuse("consumption-malformed")
	}
	for _, item := range held {
		if err := arHeldShape(item); err != nil {
			return err
		}
	}
	return nil
}

// arAssetShape: the optional asset carries exactly id and decimals, the id a
// CAIP-19 asset id (CS35) and decimals a count no larger than
// arAssetDecimalsMax (CS36).
func arAssetShape(raw any) error {
	asset, ok := raw.(map[string]any)
	if !ok {
		return arRefuse("consumption-malformed")
	}
	if !arHasAll(asset, arAssetMembers) {
		return arRefuse("member-missing")
	}
	for name := range asset {
		if !arContains(arAssetMembers, name) {
			return arRefuse("consumption-malformed")
		}
	}
	id, isText := asset["id"].(string)
	if arConsumptionChecks["asset-id"] && (!isText || !arCAIP19.MatchString(id)) {
		return arRefuse("consumption-value-invalid")
	}
	decimals, isInt := arInt(asset["decimals"])
	if arConsumptionChecks["asset-decimals"] && (!isInt || decimals < 0 || decimals > arAssetDecimalsMax) {
		return arRefuse("consumption-value-invalid")
	}
	return nil
}

// arConsumptionMembership: every required member is present and no member is
// outside the required and optional sets. unit is not required beside asset.
func arConsumptionMembership(consumption map[string]any) error {
	_, hasAsset := consumption["asset"]
	for _, name := range arConsumptionMembers {
		if name == "stateRevision" && !arConsumptionChecks["state-revision"] {
			continue
		}
		if name == "unit" && hasAsset {
			continue
		}
		if _, ok := consumption[name]; !ok {
			return arRefuse("member-missing")
		}
	}
	for name := range consumption {
		if !arContains(arConsumptionMembers, name) && !arContains(arConsumptionOptional, name) {
			return arRefuse("consumption-malformed")
		}
	}
	return nil
}

// arConsumptionSupersedes: a supersedes member is a digest and names a limit
// other than the one this set is held under.
func arConsumptionSupersedes(consumption map[string]any, digest string) error {
	raw, present := consumption["supersedes"]
	if !present {
		return nil
	}
	replaced, isDigest := raw.(string)
	if arConsumptionChecks["supersedes-digest"] && (!isDigest || !arIsDigest(replaced)) {
		return arRefuse("consumption-value-invalid")
	}
	if arConsumptionChecks["supersedes-self"] && replaced == digest {
		return arRefuse("consumption-supersedes-self")
	}
	return nil
}

// arConsumptionCountValues: each declared count member is a count.
func arConsumptionCountValues(consumption map[string]any) error {
	if !arConsumptionChecks["counts"] {
		return nil
	}
	for _, name := range arConsumptionCounts {
		if value, ok := consumption[name]; ok && !arIsCount(value) {
			return arRefuse("consumption-value-invalid")
		}
	}
	return nil
}

// arRuleConsumption: consumption sits only on a consumption-state entry.
// reserved is the sum of the held amounts and the held operation keys are
// distinct. A record that carries consumption carries decision.operationKey. A
// call whose key is held is a retry: its request digest and amount are the held
// entry's (CS10), and it is not counted twice (CS4); a call whose key is not
// held is a new operation even when its request digest is a held entry's (CS11,
// CS12).
func arRuleConsumption(s *arState) error {
	if arConsumptionMisplaced(s.pred) {
		return arRefuse("consumption-misplaced")
	}
	decision := arObj(s.pred, "decision")
	if raw, present := decision["operationKey"]; present {
		if key, ok := raw.(string); !ok || key == "" {
			return arRefuse("operation-key-invalid")
		}
	}
	consumption := arConsumptionOf(s.pred)
	if consumption == nil {
		return nil
	}
	if err := arConsumptionShape(consumption); err != nil {
		return err
	}
	sum, repeated := arHeldTotals(consumption)
	if arConsumptionChecks["distinct-keys"] && repeated {
		return arRefuse("consumption-held-key-repeated")
	}
	if reserved, _ := arInt(consumption["reserved"]); arConsumptionChecks["reserved"] && sum != reserved {
		return arRefuse("consumption-reserved-mismatch")
	}
	if _, has := decision["operationKey"]; arConsumptionChecks["operation-key"] && !has {
		return arRefuse("member-missing")
	}
	if retried := arHeldFor(consumption, decision); arConsumptionChecks["key-reuse"] && retried != nil {
		requested, _ := arInt(consumption["requested"])
		amount, _ := arInt(retried["amount"])
		if retried["requestDigest"] != decision["requestDigest"] || amount != requested {
			return arRefuse("consumption-key-reused")
		}
	}
	return nil
}

// arConsumptionMisplaced reports an input other than the consumption input that
// carries a consumption block.
func arConsumptionMisplaced(pred map[string]any) bool {
	for _, item := range arList(pred, "evaluation.inputs") {
		entry, _ := item.(map[string]any)
		if _, carries := entry["consumption"]; arConsumptionChecks["misplaced"] && carries &&
			entry["input"] != arConsumptionInput {
			return true
		}
	}
	return false
}

// arHeldTotals returns the sum of the held amounts and whether any held
// operation key appears twice.
func arHeldTotals(consumption map[string]any) (int64, bool) {
	held, _ := consumption["held"].([]any)
	seen := map[string]bool{}
	var sum int64
	repeated := false
	for _, item := range held {
		entry, _ := item.(map[string]any)
		key, _ := entry["operationKey"].(string)
		repeated = repeated || seen[key]
		seen[key] = true
		amount, _ := arInt(entry["amount"])
		sum += amount
	}
	return sum, repeated
}

// --------------------------------------------------------------------------
// Records retained together: the set checks.
// --------------------------------------------------------------------------

// arSetReport is the verdict of a set of records judged together.
type arSetReport struct {
	verdict string
	codes   []string
	missing []arSeqPoint
}

type arSetRule struct {
	name  string
	code  string
	check func(group []map[string]any) bool
}

// arSetRules are the checks across the records of one ledger, in the
// order a set is refused. It is a variable so a test can drop one.
var arSetRules = []arSetRule{
	{"stale-revision", "consumption-set-stale-revision", arSetStaleRevision},
	{"release-unshown", "consumption-set-release-unshown", arSetReleaseUnshown},
	{"asset-mismatch", "consumption-set-asset-mismatch", arSetAssetMismatch},
}

// arAssetMatchDecimals: an asset is its id with its decimals. A test drops the
// decimals (CS39).
var arAssetMatchDecimals = true

// arDenomination is what a record's consumption counts in.
func arDenomination(pred map[string]any) string {
	consumption := arConsumptionOf(pred)
	asset, has := consumption["asset"].(map[string]any)
	if !has {
		unit, _ := consumption["unit"].(string)
		return "unit\x00" + unit
	}
	id, _ := asset["id"].(string)
	decimals := ""
	if arAssetMatchDecimals {
		number, _ := asset["decimals"].(json.Number)
		decimals = number.String()
	}
	return "asset\x00" + id + "\x00" + decimals
}

// arSetAssetMismatch: one ledger counts one denomination, every record naming
// the same ISO 4217 unit or the same CAIP-19 asset with the same decimals. USDC
// on Base and USDC on Solana are two assets (CS38), and one asset id under two
// decimals values reads one amount at two scales (CS39).
func arSetAssetMismatch(group []map[string]any) bool {
	seen := map[string]bool{}
	for _, pred := range group {
		seen[arDenomination(pred)] = true
	}
	return len(seen) > 1
}

// arClaimReading is how the claim check reads a set: check turns it on; ledger
// confines it to one ledger, as if the claim were keyed by the limit document
// (CS32); scope reads the claim under the principal and the agent key (CS33);
// release lets a record of the operation showing none end its claim (CS28).
var arClaimReading = map[string]bool{"check": true, "ledger": false, "scope": true, "release": true}

// arClaimScope is the principal (delegation.subject) and the agent key
// (agent.signers). A rotated agent key is a new scope.
func arClaimScope(pred map[string]any) string {
	if !arClaimReading["scope"] {
		return ""
	}
	signers := []string{}
	for _, item := range arList(pred, "agent.signers") {
		text, _ := item.(string)
		signers = append(signers, text)
	}
	return arStr(pred, "delegation.subject") + "\x00" + strings.Join(signers, "\x00")
}

// arSetRetryAsNew: a held claim is keyed by the principal, the agent key and the
// operation key, never by the limit document. A permit whose operation key a
// record of the same scope holds, which does not itself hold that key, presents
// a retry as a new operation (CS31, CS32), unless it is the original call (a
// lower stateRevision in the same ledger) or a record of that operation shows
// none, which leaves no claim (CS28).
func arSetRetryAsNew(predicates []map[string]any, ledgerOf map[int]int) bool {
	for i, perm := range predicates {
		key, _ := arObj(perm, "decision")["operationKey"].(string)
		if !arPermitted(perm) || arHeldKeys(perm)[key] {
			continue
		}
		for j, hold := range predicates {
			if i == j || arClaimScope(hold) != arClaimScope(perm) || !arHeldKeys(hold)[key] {
				continue
			}
			sameLedger := ledgerOf[i] == ledgerOf[j]
			if arClaimReading["ledger"] && !sameLedger {
				continue
			}
			if sameLedger && arRevision(perm) < arRevision(hold) {
				continue
			}
			if !arClaimReleased(predicates, i, key) {
				return true
			}
		}
	}
	return false
}

// arClaimReleased: a record other than the permit at index perm, of the same
// operation key and scope, shows none.
func arClaimReleased(predicates []map[string]any, perm int, key string) bool {
	if !arClaimReading["release"] {
		return false
	}
	for k, other := range predicates {
		otherKey, _ := arObj(other, "decision")["operationKey"].(string)
		if k != perm && otherKey == key && arClaimScope(other) == arClaimScope(predicates[perm]) &&
			arStr(other, "effect.observed") == "none" {
			return true
		}
	}
	return false
}

func arHeldKeys(pred map[string]any) map[string]bool {
	keys := map[string]bool{}
	held, _ := arConsumptionOf(pred)["held"].([]any)
	for _, item := range held {
		entry, _ := item.(map[string]any)
		key, _ := entry["operationKey"].(string)
		keys[key] = true
	}
	return keys
}

func arRevision(pred map[string]any) int64 {
	revision, _ := arInt(arConsumptionOf(pred)["stateRevision"])
	return revision
}

func arPermitted(pred map[string]any) bool {
	reported := arStr(pred, "decision.reported")
	return reported == "permit" || reported == "permit-with-conditions"
}

// arSetStaleRevision: a permit that read a stateRevision older than a record
// already holding an unsettled permit, and omits that permit's operationKey
// from held, read a state that had not counted it: one limit spent twice (CS7,
// CS17). The key is the operation key; a request digest cannot tell two
// identical intended payments apart (CS17).
func arSetStaleRevision(group []map[string]any) bool {
	for i, later := range group {
		for j, earlier := range group {
			if i == j || arRevision(later) >= arRevision(earlier) || !arPermitted(later) {
				continue
			}
			seen := arHeldKeys(later)
			if key, ok := arObj(later, "decision")["operationKey"].(string); ok {
				seen[key] = true
			}
			for key := range arHeldKeys(earlier) {
				if !seen[key] {
					return true
				}
			}
		}
	}
	return false
}

// arSetReleaseUnshown: a held permit absent from a record that read a later
// state must be explained by the record of that operation: showing none
// (released) or occurred (moved to consumed). A lost response leaves it held
// (CS8).
func arSetReleaseUnshown(group []map[string]any) bool {
	shown := map[string]string{}
	for _, pred := range group {
		key, _ := arObj(pred, "decision")["operationKey"].(string)
		shown[key] = arStr(pred, "effect.observed")
	}
	for i, later := range group {
		for j, earlier := range group {
			if i == j || arRevision(later) <= arRevision(earlier) {
				continue
			}
			kept := arHeldKeys(later)
			for key := range arHeldKeys(earlier) {
				if !kept[key] && shown[key] != "none" && shown[key] != "occurred" {
					return true
				}
			}
		}
	}
	return false
}

// arSetChainJoin is the one way records are grouped: a replacement links two
// limit documents into one ledger. A test drops it to read the groups as one
// limitDigest each. arSetJoinAll reads every record as one ledger whatever its
// limit (CS25).
var (
	arSetChainJoin = true
	arSetJoinAll   = false
)

// arConsumptionGroups groups the records that carry consumption by ledger. Two
// limitDigest values belong to one ledger when any record names one as the
// other's supersedes, transitively (CS18 to CS22): a permit held under a limit
// that was then replaced is still held under the replacement, so its retry is
// the same operation and its release has to be shown. Records whose limitDigest
// values no supersedes links stay in separate groups (CS25). A retry is identified by
// its operation key and never by the limit, and stateRevision orders the whole
// ledger, so a replacement does not restart it.
func arConsumptionGroups(predicates []map[string]any) [][]map[string]any {
	parent := map[string]string{}
	var find func(digest string) string
	find = func(digest string) string {
		if _, known := parent[digest]; !known {
			parent[digest] = digest
		}
		if parent[digest] != digest {
			parent[digest] = find(parent[digest])
		}
		return parent[digest]
	}
	type carrier struct {
		digest string
		pred   map[string]any
	}
	var carrying []carrier
	for _, pred := range predicates {
		consumption := arConsumptionOf(pred)
		if consumption == nil {
			continue
		}
		digest, _ := consumption["limitDigest"].(string)
		if replaced, has := consumption["supersedes"].(string); arSetChainJoin && has {
			parent[find(replaced)] = find(digest)
		}
		carrying = append(carrying, carrier{digest, pred})
	}
	grouped := map[string][]map[string]any{}
	var order []string
	for _, item := range carrying {
		root := find(item.digest)
		if arSetJoinAll {
			root = ""
		}
		if _, seen := grouped[root]; !seen {
			order = append(order, root)
		}
		grouped[root] = append(grouped[root], item.pred)
	}
	groups := make([][]map[string]any, 0, len(order))
	for _, root := range order {
		groups = append(groups, grouped[root])
	}
	return groups
}

// arConsumptionSetFindings judges the records that carry consumption, grouped
// by ledger (arConsumptionGroups). A set is malformed on the first check, in
// arSetRules order, that any group fails. disabled names one check to skip.
func arConsumptionSetFindings(predicates []map[string]any, disabled string) arSetReport {
	groups := arConsumptionGroups(predicates)
	for _, rule := range arSetRules {
		if rule.name == disabled {
			continue
		}
		for _, group := range groups {
			if rule.check(group) {
				return arSetReport{verdict: "malformed", codes: []string{rule.code}}
			}
		}
	}
	var carrying []map[string]any
	ledgerOf := map[int]int{}
	for index, group := range groups {
		for _, pred := range group {
			ledgerOf[len(carrying)] = index
			carrying = append(carrying, pred)
		}
	}
	if arClaimReading["check"] && disabled != "retry-as-new" && arSetRetryAsNew(carrying, ledgerOf) {
		return arSetReport{verdict: "malformed", codes: []string{"consumption-set-retry-as-new"}}
	}
	return arSetReport{verdict: "valid"}
}

// arSetRecords returns the envelopes a set member carries.
func arSetRecords(raw []byte) ([][]byte, error) {
	if err := aee.CheckIJSON(raw); err != nil {
		return nil, err
	}
	var bundle struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil || bundle.Records == nil {
		return nil, arRefuse("set-unreadable")
	}
	envelopes := make([][]byte, 0, len(bundle.Records))
	for _, record := range bundle.Records {
		envelopes = append(envelopes, []byte(record))
	}
	return envelopes, nil
}

// arEnvelopePayload decodes the payload of an envelope.
func arEnvelopePayload(envelope []byte) ([]byte, error) {
	var parsed struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(parsed.Payload)
}

// arEnvelopePredicate reads the predicate of an envelope already judged valid.
func arEnvelopePredicate(envelope []byte) (map[string]any, error) {
	payload, err := arEnvelopePayload(envelope)
	if err != nil {
		return nil, err
	}
	_, statement, err := arParse(payload)
	if err != nil {
		return nil, err
	}
	pred, ok := statement["predicate"].(map[string]any)
	if !ok {
		return nil, arRefuse("statement-shape")
	}
	return pred, nil
}

type arSetResult struct {
	reports    []arReport
	joint      arSetReport
	predicates []map[string]any
}

// arVerifySet judges a set member: every record on its own, then the records
// together. A record that is itself malformed leaves the set unjudged.
func arVerifySet(raw []byte, predicateType, observerKey, disabled string) arSetResult {
	envelopes, err := arSetRecords(raw)
	if err != nil {
		return arSetResult{joint: arSetReport{verdict: "malformed", codes: []string{"set-unreadable"}}}
	}
	var result arSetResult
	for _, envelope := range envelopes {
		result.reports = append(result.reports, arVerify(envelope, predicateType, observerKey, disabled))
	}
	for _, report := range result.reports {
		if report.verdict != "valid" {
			result.joint = arSetReport{verdict: "malformed", codes: []string{"set-record-malformed"}}
			return result
		}
	}
	for _, envelope := range envelopes {
		pred, err := arEnvelopePredicate(envelope)
		if err != nil {
			result.joint = arSetReport{verdict: "malformed", codes: []string{"set-record-malformed"}}
			return result
		}
		result.predicates = append(result.predicates, pred)
	}
	result.joint = arConsumptionSetFindings(result.predicates, disabled)
	if result.joint.verdict == "valid" {
		result.joint = arSequenceSetFindings(result.predicates, envelopes)
	}
	return result
}

// --------------------------------------------------------------------------
// The corpus judge's two additions.
// --------------------------------------------------------------------------

// arLimitFindings: a member whose record carries consumption declares the
// withinLimit a verifier derives; a member that carries none declares none.
func arLimitFindings(label string, v arVector, body []byte) []string {
	var got *bool
	if pred, err := arEnvelopePredicate(body); err == nil {
		got = arWithinLimit(pred)
	}
	want := v.Expected.WithinLimit
	if (got == nil) != (want == nil) || (got != nil && *got != *want) {
		return []string{fmt.Sprintf("%s: expected withinLimit %s, got %s", label, arBoolText(want), arBoolText(got))}
	}
	return nil
}

func arBoolText(value *bool) string {
	if value == nil {
		return "none"
	}
	return strconv.FormatBool(*value)
}

func arLimitsText(values []*bool) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, arBoolText(value))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// arSetFindings: each record of a set member reaches the member's verdict, tier
// and withinLimit, and the records together reach expected.set.
func arSetFindings(label string, manifest *arManifest, v arVector, body []byte) []string {
	result := arVerifySet(body, manifest.PredicateType, manifest.Keys.Observer.PublicKey, "")
	var findings []string
	for index, report := range result.reports {
		for _, found := range arDeclaredFindings(label, v, report) {
			findings = append(findings,
				strings.Replace(found, label+": ", fmt.Sprintf("%s: record %d: ", label, index+1), 1))
		}
	}
	var limits []*bool
	for _, pred := range result.predicates {
		limits = append(limits, arWithinLimit(pred))
	}
	declared := v.Expected.Set
	wantLimits := declared.WithinLimit
	if wantLimits == nil {
		wantLimits = make([]*bool, len(limits))
	}
	if arSeqText(result.joint.missing) != arSeqText(declared.Missing) {
		findings = append(findings, fmt.Sprintf("%s: expected missing %s, got %s",
			label, arSeqText(declared.Missing), arSeqText(result.joint.missing)))
	}
	if len(result.predicates) > 0 && arLimitsText(limits) != arLimitsText(wantLimits) {
		findings = append(findings, fmt.Sprintf("%s: expected withinLimit %s, got %s",
			label, arLimitsText(wantLimits), arLimitsText(limits)))
	}
	if result.joint.verdict != declared.Verdict ||
		strings.Join(result.joint.codes, ",") != strings.Join(declared.Codes, ",") {
		findings = append(findings, fmt.Sprintf("%s: expected set %s [%s], got %s [%s]", label,
			declared.Verdict, strings.Join(declared.Codes, ","),
			result.joint.verdict, strings.Join(result.joint.codes, ",")))
	}
	return findings
}
