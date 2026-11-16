package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() { register(capabilityRequirement{}) }

// capabilityRequirement judges corpora/vectors-capability-requirement/. Each
// member is one record: a signed capability requirement, a report on a hosted
// endpoint, or a drift comparison of two runs. The reader derives each member's
// decision from the record alone, with the checks the Python reader applies in
// the same order, and names the first one that fails:
//
//  1. contract_id_missing; 2. contract_id_unknown; 3. kind_unknown;
//  4. requirement_signature_invalid; 5. capability_names_a_model;
//  6. thresholds_invalid; 7. evaluation_set_digest_mismatch;
//  8. held_out_commitment_not_attested; 9. requirement_invalid;
//  10. run_against_other_requirement; 11. runs_on_different_endpoints;
//  12. run_signature_invalid; 13. held_out_not_assessor_signed;
//  14. findings_merged; 15. model_identity_overclaimed; 16. behaviour_mismatch;
//  17. runs_not_distinct; 18. runs_out_of_order; 19. comparison_wrong.
//
// A check that does not apply to the record's kind passes, and a record whose
// shape a check cannot read fails that check, as in the Python reader. Every
// signature is verified against the key the record itself names; which keys a
// deployment trusts is a separate decision this reader does not make.
type capabilityRequirement struct{}

const (
	capreqContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/capability-requirement"
	capreqAllowed    = "record_consistent"
	capreqUnproven   = "unproven"
)

func (capabilityRequirement) Suite() string { return "capability-requirement/v1" }

var capreqChecks = []string{
	"contract_id_missing",
	"contract_id_unknown",
	"kind_unknown",
	"requirement_signature_invalid",
	"capability_names_a_model",
	"thresholds_invalid",
	"evaluation_set_digest_mismatch",
	"held_out_commitment_not_attested",
	"requirement_invalid",
	"run_against_other_requirement",
	"runs_on_different_endpoints",
	"run_signature_invalid",
	"held_out_not_assessor_signed",
	"findings_merged",
	"model_identity_overclaimed",
	"behaviour_mismatch",
	"runs_not_distinct",
	"runs_out_of_order",
	"comparison_wrong",
}

// capreqShape is the panic value of a record whose shape a check cannot read: a
// missing member, a member of the wrong type. capreqRun turns it into "this check
// fails", which is what the Python reader does with a KeyError or TypeError.
type capreqShape struct{}

type capreqVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained json.RawMessage   `json:"retained"`
}

func (capabilityRequirement) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v capreqVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = capreqJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func capreqJudgeMember(caseDir string, v capreqVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read: "+err.Error())
	}
	record, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "record.json does not parse: "+err.Error())
	}
	declared, err := decodeJSONNumbers(v.Retained)
	if err != nil {
		return append(findings, "the manifest's retained fields do not parse: "+err.Error())
	}
	if !capreqSame(capreqRetained(record), declared) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := capreqDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func capreqDecide(record any) scDecision {
	if failure := capreqFirstFailure(record); failure != "" {
		return scDecision{Decision: "deny", Reason: failure}
	}
	return scDecision{Decision: "allow", Reason: capreqAllowed}
}

// capreqRun runs one check. A record whose shape the check cannot read fails it.
func capreqRun(check func() bool) (failed bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(capreqShape); !ok {
				panic(r)
			}
			failed = true
		}
	}()
	return check()
}

// capreqSafe is the Python reader's _safe: the value, or nil when the shape is wrong.
func capreqSafe(read func() any) (value any) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(capreqShape); !ok {
				panic(r)
			}
			value = nil
		}
	}()
	return read()
}

func capreqFirstFailure(record any) string {
	rec, ok := record.(map[string]any)
	if !ok {
		return "contract_id_missing"
	}
	table := capreqTable(rec)
	for _, name := range capreqChecks {
		if capreqRun(table[name]) {
			return name
		}
	}
	return ""
}

func capreqKindIs(kind any, names ...string) bool {
	text, ok := kind.(string)
	if !ok {
		return false
	}
	for _, name := range names {
		if text == name {
			return true
		}
	}
	return false
}

func capreqTable(rec map[string]any) map[string]func() bool {
	kind := rec["kind"]
	runsKind := capreqKindIs(kind, "endpoint-report", "drift")
	isDrift := capreqKindIs(kind, "drift")
	isReport := capreqKindIs(kind, "endpoint-report")
	table := map[string]func() bool{
		"contract_id_missing": func() bool { _, has := rec["contractId"]; return !has },
		"contract_id_unknown": func() bool {
			id, has := rec["contractId"]
			return has && !capreqSame(id, capreqContractID)
		},
		"kind_unknown": func() bool { return !capreqKindIs(kind, "requirement", "endpoint-report", "drift") },
		"requirement_invalid": func() bool {
			return runsKind && capreqRequirementFailure(capreqRR(rec)) != ""
		},
		"run_against_other_requirement": func() bool {
			if !runsKind {
				return false
			}
			for _, run := range capreqRuns(rec) {
				want := capreqRequirementDigest(capreqRequirement(capreqRR(rec)))
				if !capreqSame(capreqGet(capreqGet(run, "body"), "requirementDigest"), want) {
					return true
				}
			}
			return false
		},
		"runs_on_different_endpoints": func() bool {
			return isDrift && !capreqSame(capreqGet(capreqGet(capreqGet(rec, "baseline"), "body"), "endpoint"),
				capreqGet(capreqGet(capreqGet(rec, "current"), "body"), "endpoint"))
		},
		"run_signature_invalid": func() bool {
			if !runsKind {
				return false
			}
			for _, run := range capreqRuns(rec) {
				if !capreqVerified(capreqOpt(run, "verifierSignature"), capreqCanon(capreqGet(run, "body"))) {
					return true
				}
			}
			return false
		},
		"held_out_not_assessor_signed": func() bool {
			if !runsKind {
				return false
			}
			for _, run := range capreqRuns(rec) {
				if !capreqHeldOutValid(capreqRR(rec), run) {
					return true
				}
			}
			return false
		},
		"findings_merged": func() bool {
			if !isReport {
				return false
			}
			_, verdict := rec["verdict"]
			_, identity := rec["modelIdentity"]
			_, behaviour := rec["behaviour"]
			return verdict || !identity || !behaviour
		},
		"model_identity_overclaimed": func() bool { return isReport && capreqIdentityOverclaimed(rec) },
		"behaviour_mismatch": func() bool {
			return isReport && !capreqSame(capreqGet(rec, "behaviour"), capreqBehaviour(capreqRR(rec), capreqGet(rec, "run")))
		},
		"runs_not_distinct": func() bool {
			if !isDrift {
				return false
			}
			before, after := capreqGet(capreqGet(rec, "baseline"), "body"), capreqGet(capreqGet(rec, "current"), "body")
			return capreqSame(capreqGet(before, "runId"), capreqGet(after, "runId")) || capreqSame(before, after)
		},
		"runs_out_of_order": func() bool {
			if !isDrift {
				return false
			}
			current := capreqAt(capreqGet(capreqGet(capreqGet(rec, "current"), "body"), "observedAt"))
			baseline := capreqAt(capreqGet(capreqGet(capreqGet(rec, "baseline"), "body"), "observedAt"))
			return !current.after(baseline)
		},
		"comparison_wrong": func() bool {
			return isDrift && !capreqSame(capreqGet(rec, "comparison"),
				capreqCompare(capreqRR(rec), capreqGet(rec, "baseline"), capreqGet(rec, "current")))
		},
	}
	for _, check := range capreqRequirementChecks {
		failing := check.failing
		table[check.name] = func() bool { return capreqKindIs(kind, "requirement") && failing(rec) }
	}
	return table
}

// capreqRR is the record that carries the requirement: the record itself for a
// requirement, its requirementRecord for a report or a drift comparison.
func capreqRR(rec map[string]any) any {
	if capreqSame(capreqGet(rec, "kind"), "requirement") {
		return rec
	}
	return capreqGet(rec, "requirementRecord")
}

func capreqRuns(rec map[string]any) []any {
	if capreqSame(capreqGet(rec, "kind"), "endpoint-report") {
		return []any{capreqGet(rec, "run")}
	}
	return []any{capreqGet(rec, "baseline"), capreqGet(rec, "current")}
}

type capreqRequirementCheck struct {
	name    string
	failing func(rr any) bool
}

var capreqRequirementChecks = []capreqRequirementCheck{
	{"requirement_signature_invalid", func(rr any) bool {
		signature := capreqOpt(rr, "requirerSignature")
		return !capreqVerified(signature, capreqCanon(capreqRequirement(rr)))
	}},
	{"capability_names_a_model", capreqCapabilityNamesAModel},
	{"thresholds_invalid", capreqThresholdsInvalid},
	{"evaluation_set_digest_mismatch", capreqDigestMismatch},
	{"held_out_commitment_not_attested", capreqNotAttested},
}

// capreqRequirementFailure is the first requirement check the record's requirement
// fails, or "".
func capreqRequirementFailure(rr any) string {
	for _, check := range capreqRequirementChecks {
		failing := check.failing
		if capreqRun(func() bool { return failing(rr) }) {
			return check.name
		}
	}
	return ""
}

func capreqCapabilityNamesAModel(rr any) bool {
	capability, ok := capreqGet(capreqRequirement(rr), "capability").(map[string]any)
	if !ok || len(capability) != 2 {
		return true
	}
	id, hasID := capability["id"]
	statement, hasStatement := capability["statement"]
	if !hasID || !hasStatement {
		return true
	}
	_, idText := id.(string)
	_, statementText := statement.(string)
	return !idText || !statementText
}

func capreqThresholdsInvalid(rr any) bool {
	list, ok := capreqGet(capreqRequirement(rr), "thresholds").([]any)
	if !ok || len(list) == 0 {
		return true
	}
	seen := map[string]bool{}
	for _, item := range list {
		threshold, ok := item.(map[string]any)
		if !ok || len(threshold) != 5 {
			return true
		}
		for _, key := range []string{"metric", "set", "comparator", "value", "maxDrift"} {
			if _, has := threshold[key]; !has {
				return true
			}
		}
		metric, ok := threshold["metric"].(string)
		if !ok || metric == "" {
			return true
		}
		if !capreqOneOf(threshold["set"], "public", "heldOut") || !capreqOneOf(threshold["comparator"], "gte", "lte") {
			return true
		}
		if !capreqIsInt(threshold["value"]) || !capreqIsInt(threshold["maxDrift"]) || capreqInt(threshold["maxDrift"]).Sign() < 0 {
			return true
		}
		if seen[metric] {
			return true
		}
		seen[metric] = true
	}
	return false
}

func capreqDigestMismatch(rr any) bool {
	evaluation := capreqGet(capreqRequirement(rr), "evaluationSet")
	items, ok := capreqGet(evaluation, "items").([]any)
	if !ok || len(items) == 0 {
		return true
	}
	texts := make([]string, 0, len(items))
	for _, item := range items {
		if !capreqIsDigest(item) {
			return true
		}
		texts = append(texts, item.(string))
	}
	return !capreqSame(capreqGet(evaluation, "digest"), capreqItemsDigest(texts))
}

func capreqNotAttested(rr any) bool {
	requirement := capreqRequirement(rr)
	held, ok := capreqOpt(capreqGet(requirement, "evaluationSet"), "heldOut").(map[string]any)
	if !ok || !capreqIsDigest(held["commitment"]) {
		return true
	}
	attestation, ok := capreqOpt(rr, "assessorAttestation").(map[string]any)
	if !ok || !capreqSame(attestation["publicKey"], held["assessorKey"]) {
		return true
	}
	return !capreqVerified(attestation, capreqAttestationBytes(requirement))
}

func capreqRequirement(rr any) any { return capreqGet(rr, "requirement") }

func capreqRequirementDigest(requirement any) string { return sha(capreqCanon(requirement)) }

func capreqItemsDigest(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	list := make([]any, len(sorted))
	for i, item := range sorted {
		list[i] = item
	}
	return sha(capreqCanon(list))
}

func capreqAttestationBytes(requirement any) []byte {
	return capreqCanon(map[string]any{
		"capabilityId": capreqGet(capreqGet(requirement, "capability"), "id"),
		"commitment":   capreqGet(capreqGet(capreqGet(requirement, "evaluationSet"), "heldOut"), "commitment"),
	})
}

func capreqAssessorRunBytes(run any) []byte {
	body := capreqGet(run, "body")
	return capreqCanon(map[string]any{
		"requirementDigest": capreqGet(body, "requirementDigest"),
		"results":           capreqGet(capreqGet(body, "heldOut"), "results"),
		"runId":             capreqGet(body, "runId"),
	})
}

// capreqVerified reports whether signature is a key and a signature that verify
// over data.
func capreqVerified(signature any, data []byte) bool {
	fields, ok := signature.(map[string]any)
	if !ok {
		return false
	}
	keyText, ok := fields["publicKey"].(string)
	sigText, ok2 := fields["signature"].(string)
	if !ok || !ok2 {
		return false
	}
	key, okKey := capreqBase64(keyText)
	sig, okSig := capreqBase64(sigText)
	if !okKey || !okSig || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), data, sig)
}

// capreqBase64 decodes the way Python's b64decode(validate=True) does: the standard
// alphabet, padded, and nothing else, not even a line break.
func capreqBase64(text string) ([]byte, bool) {
	if strings.ContainsAny(text, "\r\n") {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	return decoded, err == nil
}

func capreqHeldOutValid(rr, run any) bool {
	if capreqOpt(capreqGet(run, "body"), "heldOut") == nil {
		return true
	}
	signature := capreqOpt(run, "assessorSignature")
	named := capreqGet(capreqGet(capreqGet(capreqRequirement(rr), "evaluationSet"), "heldOut"), "assessorKey")
	fields, ok := signature.(map[string]any)
	return ok && capreqSame(fields["publicKey"], named) && capreqVerified(signature, capreqAssessorRunBytes(run))
}

func capreqIdentityOverclaimed(rec map[string]any) bool {
	claim := capreqGet(rec, "modelIdentity")
	if capreqSame(claim, capreqUnproven) {
		return false
	}
	endpoint := capreqGet(rec, "endpoint")
	proof, _ := capreqOpt(rec, "identityProof").(map[string]any)
	if !capreqSame(claim, "proven") || !capreqSame(capreqGet(endpoint, "access"), "weights-held") ||
		proof == nil || !capreqIsDigest(proof["weightsDigest"]) {
		return true
	}
	return !capreqSame(proof["weightsDigest"], capreqGet(endpoint, "claimedWeightsDigest"))
}

// capreqValue is the run's usable value for a threshold's metric, or nil.
func capreqValue(rr, run, threshold any) *big.Int {
	var values any
	if capreqSame(capreqGet(threshold, "set"), "public") {
		values = capreqGet(capreqGet(run, "body"), "public")
	} else {
		held := capreqOpt(capreqGet(run, "body"), "heldOut")
		if held == nil || !capreqHeldOutValid(rr, run) {
			return nil
		}
		values = capreqGet(held, "results")
	}
	found := capreqOpt(values, capreqText(capreqGet(threshold, "metric")))
	if !capreqIsInt(found) {
		return nil
	}
	return capreqInt(found)
}

func capreqMeets(threshold any, value *big.Int) bool {
	limit := capreqInt(capreqGet(threshold, "value"))
	if capreqSame(capreqGet(threshold, "comparator"), "gte") {
		return value.Cmp(limit) >= 0
	}
	return value.Cmp(limit) <= 0
}

func capreqThresholds(rr any) []any {
	list, ok := capreqGet(capreqRequirement(rr), "thresholds").([]any)
	if !ok {
		panic(capreqShape{})
	}
	return list
}

// capreqBehaviour is the behaviour on the pinned set: contradicted, else not
// established, else supported.
func capreqBehaviour(rr, run any) string {
	thresholds := capreqThresholds(rr)
	values := make([]*big.Int, len(thresholds))
	for i, threshold := range thresholds {
		values[i] = capreqValue(rr, run, threshold)
	}
	missing := false
	for i, threshold := range thresholds {
		if values[i] == nil {
			missing = true
		} else if !capreqMeets(threshold, values[i]) {
			return "contradicted"
		}
	}
	if missing {
		return "not_established"
	}
	return "supported"
}

// capreqCompare is the comparison two runs of one requirement give.
func capreqCompare(rr, baseline, current any) map[string]any {
	changes := []any{}
	unmatched := []string{}
	drifted := false
	for _, threshold := range capreqThresholds(rr) {
		before, after := capreqValue(rr, baseline, threshold), capreqValue(rr, current, threshold)
		metric := capreqText(capreqGet(threshold, "metric"))
		if before == nil || after == nil {
			unmatched = append(unmatched, metric)
			continue
		}
		worse := new(big.Int).Sub(before, after)
		if !capreqSame(capreqGet(threshold, "comparator"), "gte") {
			worse.Neg(worse)
		}
		meetsBefore, meetsAfter := capreqMeets(threshold, before), capreqMeets(threshold, after)
		changes = append(changes, map[string]any{
			"baseline": json.Number(before.String()), "baselineMeets": meetsBefore,
			"current": json.Number(after.String()), "currentMeets": meetsAfter,
			"metric": metric, "worsenedBy": json.Number(worse.String()),
		})
		if worse.Cmp(capreqInt(capreqGet(threshold, "maxDrift"))) > 0 || (meetsBefore && !meetsAfter) {
			drifted = true
		}
	}
	outcome := "stable"
	if drifted {
		outcome = "drifted"
	} else if len(unmatched) > 0 {
		outcome = "not_established"
	}
	sort.Strings(unmatched)
	names := make([]any, len(unmatched))
	for i, name := range unmatched {
		names[i] = name
	}
	return map[string]any{
		"baselineRunId": capreqGet(capreqGet(baseline, "body"), "runId"),
		"changes":       changes,
		"currentRunId":  capreqGet(capreqGet(current, "body"), "runId"),
		"outcome":       outcome,
		"unmatched":     names,
	}
}

// capreqRetained is the facts a verifier keeps from a record: its kind and what it
// found.
func capreqRetained(record any) map[string]any {
	rec, _ := record.(map[string]any)
	kind := rec["kind"]
	kept := map[string]any{"kind": kind}
	switch {
	case capreqKindIs(kind, "requirement"):
		kept["requirementDigest"] = capreqSafe(func() any { return capreqRequirementDigest(capreqRequirement(rec)) })
		kept["thresholds"] = capreqSafe(func() any {
			switch list := capreqGet(capreqRequirement(rec), "thresholds").(type) {
			case []any:
				return json.Number(strconv.Itoa(len(list)))
			case map[string]any:
				return json.Number(strconv.Itoa(len(list)))
			case string:
				return json.Number(strconv.Itoa(len([]rune(list))))
			}
			panic(capreqShape{})
		})
	case capreqKindIs(kind, "endpoint-report"):
		kept["behaviour"] = rec["behaviour"]
		kept["modelIdentity"] = rec["modelIdentity"]
		kept["runId"] = capreqSafe(func() any { return capreqGet(capreqGet(capreqGet(rec, "run"), "body"), "runId") })
	case capreqKindIs(kind, "drift"):
		kept["outcome"] = capreqSafe(func() any { return capreqGet(capreqGet(rec, "comparison"), "outcome") })
		kept["runIds"] = capreqSafe(func() any {
			return []any{capreqGet(capreqGet(capreqGet(rec, "baseline"), "body"), "runId"),
				capreqGet(capreqGet(capreqGet(rec, "current"), "body"), "runId")}
		})
	}
	return kept
}

// capreqInstant is a timestamp as Python's datetime.fromisoformat reads it: aware
// when it carries an offset, naive when it does not. Python refuses to order an
// aware instant against a naive one, and so does this.
type capreqInstant struct {
	at    time.Time
	aware bool
}

func (a capreqInstant) after(b capreqInstant) bool {
	if a.aware != b.aware {
		panic(capreqShape{})
	}
	return a.at.After(b.at)
}

func capreqAt(value any) capreqInstant {
	text, ok := value.(string)
	if !ok {
		panic(capreqShape{})
	}
	text = strings.ReplaceAll(text, "Z", "+00:00")
	if at, err := time.Parse("2006-01-02T15:04:05-07:00", text); err == nil {
		return capreqInstant{at: at, aware: true}
	}
	if at, err := time.Parse("2006-01-02T15:04:05", text); err == nil {
		return capreqInstant{at: at}
	}
	panic(capreqShape{})
}

// capreqGet reads member key of an object. A value that is not an object, or an
// object without the member, is a shape error: Python's KeyError and TypeError.
func capreqGet(object any, key string) any {
	fields, ok := object.(map[string]any)
	if !ok {
		panic(capreqShape{})
	}
	value, has := fields[key]
	if !has {
		panic(capreqShape{})
	}
	return value
}

// capreqOpt is Python's dict.get: nil for a missing member, a shape error for a
// value that is not an object.
func capreqOpt(object any, key string) any {
	fields, ok := object.(map[string]any)
	if !ok {
		panic(capreqShape{})
	}
	return fields[key]
}

func capreqText(value any) string {
	text, ok := value.(string)
	if !ok {
		panic(capreqShape{})
	}
	return text
}

func capreqOneOf(value any, names ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, name := range names {
		if text == name {
			return true
		}
	}
	return false
}

func capreqIsInt(value any) bool {
	number, ok := value.(json.Number)
	return ok && !strings.ContainsAny(number.String(), ".eE")
}

func capreqInt(value any) *big.Int {
	number, ok := value.(json.Number)
	if !ok {
		panic(capreqShape{})
	}
	integer, ok := new(big.Int).SetString(number.String(), 10)
	if !ok {
		panic(capreqShape{})
	}
	return integer
}

func capreqIsDigest(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != 64 {
		return false
	}
	for _, c := range text {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// capreqSame is Python's ==, over decoded JSON: two values are the same when they
// write the same canonical bytes.
func capreqSame(a, b any) bool {
	left, errLeft := capreqCanonOrErr(a)
	right, errRight := capreqCanonOrErr(b)
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

func capreqCanonOrErr(value any) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(capreqShape); !ok {
				panic(r)
			}
			err = fmt.Errorf("a value this encoder cannot write")
		}
	}()
	return capreqCanon(value), nil
}

// capreqCanon is the byte string every signature in this contract covers: compact
// JSON with sorted keys and no ASCII escaping, as json.dumps writes it with
// sort_keys=True, separators=(",", ":"), ensure_ascii=False.
func capreqCanon(value any) []byte {
	var out bytes.Buffer
	capreqEncode(&out, value)
	return out.Bytes()
}

func capreqEncode(out *bytes.Buffer, value any) {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case string:
		writePythonString(out, v, false)
	case json.Number:
		out.WriteString(capreqNumber(v))
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			capreqEncode(out, item)
		}
		out.WriteByte(']')
	case map[string]any:
		out.WriteByte('{')
		for i, key := range sortedKeys(v) {
			if i > 0 {
				out.WriteByte(',')
			}
			writePythonString(out, key, false)
			out.WriteByte(':')
			capreqEncode(out, v[key])
		}
		out.WriteByte('}')
	default:
		panic(capreqShape{})
	}
}

func capreqNumber(number json.Number) string {
	text := number.String()
	if !strings.ContainsAny(text, ".eE") {
		integer, ok := new(big.Int).SetString(text, 10)
		if !ok {
			panic(capreqShape{})
		}
		return integer.String()
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil && !math.IsInf(parsed, 0) {
		panic(capreqShape{})
	}
	return capreqFloat(parsed)
}

// capreqFloat spells a float the way CPython's repr does.
func capreqFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	text := strconv.FormatFloat(f, 'e', -1, 64)
	sign := ""
	if strings.HasPrefix(text, "-") {
		sign, text = "-", text[1:]
	}
	mantissa, exponent, _ := strings.Cut(text, "e")
	power, _ := strconv.Atoi(exponent)
	digits := strings.Replace(mantissa, ".", "", 1)
	point := power + 1
	if point > -4 && point <= 16 {
		switch {
		case point <= 0:
			return sign + "0." + strings.Repeat("0", -point) + digits
		case point >= len(digits):
			return sign + digits + strings.Repeat("0", point-len(digits)) + ".0"
		default:
			return sign + digits[:point] + "." + digits[point:]
		}
	}
	rest := ""
	if len(digits) > 1 {
		rest = "." + digits[1:]
	}
	shift := point - 1
	marker := "+"
	if shift < 0 {
		marker, shift = "-", -shift
	}
	return fmt.Sprintf("%s%s%se%s%02d", sign, digits[:1], rest, marker, shift)
}
