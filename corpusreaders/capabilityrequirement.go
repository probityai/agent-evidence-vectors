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
	crContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/capability-requirement"
	crAllowed    = "record_consistent"
	crUnproven   = "unproven"
)

func (capabilityRequirement) Suite() string { return "capability-requirement/v1" }

var crChecks = []string{
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

// crShape is the panic value of a record whose shape a check cannot read: a
// missing member, a member of the wrong type. crRun turns it into "this check
// fails", which is what the Python reader does with a KeyError or TypeError.
type crShape struct{}

type crVector struct {
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
		var v crVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = crJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func crJudgeMember(caseDir string, v crVector) []string {
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
	if !crSame(crRetained(record), declared) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := crDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func crDecide(record any) scDecision {
	if failure := crFirstFailure(record); failure != "" {
		return scDecision{Decision: "deny", Reason: failure}
	}
	return scDecision{Decision: "allow", Reason: crAllowed}
}

// crRun runs one check. A record whose shape the check cannot read fails it.
func crRun(check func() bool) (failed bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crShape); !ok {
				panic(r)
			}
			failed = true
		}
	}()
	return check()
}

// crSafe is the Python reader's _safe: the value, or nil when the shape is wrong.
func crSafe(read func() any) (value any) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crShape); !ok {
				panic(r)
			}
			value = nil
		}
	}()
	return read()
}

func crFirstFailure(record any) string {
	rec, ok := record.(map[string]any)
	if !ok {
		return "contract_id_missing"
	}
	table := crTable(rec)
	for _, name := range crChecks {
		if crRun(table[name]) {
			return name
		}
	}
	return ""
}

func crKindIs(kind any, names ...string) bool {
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

func crTable(rec map[string]any) map[string]func() bool {
	kind := rec["kind"]
	runsKind := crKindIs(kind, "endpoint-report", "drift")
	isDrift := crKindIs(kind, "drift")
	isReport := crKindIs(kind, "endpoint-report")
	table := map[string]func() bool{
		"contract_id_missing": func() bool { _, has := rec["contractId"]; return !has },
		"contract_id_unknown": func() bool {
			id, has := rec["contractId"]
			return has && !crSame(id, crContractID)
		},
		"kind_unknown": func() bool { return !crKindIs(kind, "requirement", "endpoint-report", "drift") },
		"requirement_invalid": func() bool {
			return runsKind && crRequirementFailure(crRR(rec)) != ""
		},
		"run_against_other_requirement": func() bool {
			if !runsKind {
				return false
			}
			for _, run := range crRuns(rec) {
				want := crRequirementDigest(crRequirement(crRR(rec)))
				if !crSame(crGet(crGet(run, "body"), "requirementDigest"), want) {
					return true
				}
			}
			return false
		},
		"runs_on_different_endpoints": func() bool {
			return isDrift && !crSame(crGet(crGet(crGet(rec, "baseline"), "body"), "endpoint"),
				crGet(crGet(crGet(rec, "current"), "body"), "endpoint"))
		},
		"run_signature_invalid": func() bool {
			if !runsKind {
				return false
			}
			for _, run := range crRuns(rec) {
				if !crVerified(crOpt(run, "verifierSignature"), crCanon(crGet(run, "body"))) {
					return true
				}
			}
			return false
		},
		"held_out_not_assessor_signed": func() bool {
			if !runsKind {
				return false
			}
			for _, run := range crRuns(rec) {
				if !crHeldOutValid(crRR(rec), run) {
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
		"model_identity_overclaimed": func() bool { return isReport && crIdentityOverclaimed(rec) },
		"behaviour_mismatch": func() bool {
			return isReport && !crSame(crGet(rec, "behaviour"), crBehaviour(crRR(rec), crGet(rec, "run")))
		},
		"runs_not_distinct": func() bool {
			if !isDrift {
				return false
			}
			before, after := crGet(crGet(rec, "baseline"), "body"), crGet(crGet(rec, "current"), "body")
			return crSame(crGet(before, "runId"), crGet(after, "runId")) || crSame(before, after)
		},
		"runs_out_of_order": func() bool {
			if !isDrift {
				return false
			}
			current := crAt(crGet(crGet(crGet(rec, "current"), "body"), "observedAt"))
			baseline := crAt(crGet(crGet(crGet(rec, "baseline"), "body"), "observedAt"))
			return !current.after(baseline)
		},
		"comparison_wrong": func() bool {
			return isDrift && !crSame(crGet(rec, "comparison"),
				crCompare(crRR(rec), crGet(rec, "baseline"), crGet(rec, "current")))
		},
	}
	for _, check := range crRequirementChecks {
		failing := check.failing
		table[check.name] = func() bool { return crKindIs(kind, "requirement") && failing(rec) }
	}
	return table
}

// crRR is the record that carries the requirement: the record itself for a
// requirement, its requirementRecord for a report or a drift comparison.
func crRR(rec map[string]any) any {
	if crSame(crGet(rec, "kind"), "requirement") {
		return rec
	}
	return crGet(rec, "requirementRecord")
}

func crRuns(rec map[string]any) []any {
	if crSame(crGet(rec, "kind"), "endpoint-report") {
		return []any{crGet(rec, "run")}
	}
	return []any{crGet(rec, "baseline"), crGet(rec, "current")}
}

type crRequirementCheck struct {
	name    string
	failing func(rr any) bool
}

var crRequirementChecks = []crRequirementCheck{
	{"requirement_signature_invalid", func(rr any) bool {
		signature := crOpt(rr, "requirerSignature")
		return !crVerified(signature, crCanon(crRequirement(rr)))
	}},
	{"capability_names_a_model", crCapabilityNamesAModel},
	{"thresholds_invalid", crThresholdsInvalid},
	{"evaluation_set_digest_mismatch", crDigestMismatch},
	{"held_out_commitment_not_attested", crNotAttested},
}

// crRequirementFailure is the first requirement check the record's requirement
// fails, or "".
func crRequirementFailure(rr any) string {
	for _, check := range crRequirementChecks {
		failing := check.failing
		if crRun(func() bool { return failing(rr) }) {
			return check.name
		}
	}
	return ""
}

func crCapabilityNamesAModel(rr any) bool {
	capability, ok := crGet(crRequirement(rr), "capability").(map[string]any)
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

func crThresholdsInvalid(rr any) bool {
	list, ok := crGet(crRequirement(rr), "thresholds").([]any)
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
		if !crOneOf(threshold["set"], "public", "heldOut") || !crOneOf(threshold["comparator"], "gte", "lte") {
			return true
		}
		if !crIsInt(threshold["value"]) || !crIsInt(threshold["maxDrift"]) || crInt(threshold["maxDrift"]).Sign() < 0 {
			return true
		}
		if seen[metric] {
			return true
		}
		seen[metric] = true
	}
	return false
}

func crDigestMismatch(rr any) bool {
	evaluation := crGet(crRequirement(rr), "evaluationSet")
	items, ok := crGet(evaluation, "items").([]any)
	if !ok || len(items) == 0 {
		return true
	}
	texts := make([]string, 0, len(items))
	for _, item := range items {
		if !crIsDigest(item) {
			return true
		}
		texts = append(texts, item.(string))
	}
	return !crSame(crGet(evaluation, "digest"), crItemsDigest(texts))
}

func crNotAttested(rr any) bool {
	requirement := crRequirement(rr)
	held, ok := crOpt(crGet(requirement, "evaluationSet"), "heldOut").(map[string]any)
	if !ok || !crIsDigest(held["commitment"]) {
		return true
	}
	attestation, ok := crOpt(rr, "assessorAttestation").(map[string]any)
	if !ok || !crSame(attestation["publicKey"], held["assessorKey"]) {
		return true
	}
	return !crVerified(attestation, crAttestationBytes(requirement))
}

func crRequirement(rr any) any { return crGet(rr, "requirement") }

func crRequirementDigest(requirement any) string { return sha(crCanon(requirement)) }

func crItemsDigest(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	list := make([]any, len(sorted))
	for i, item := range sorted {
		list[i] = item
	}
	return sha(crCanon(list))
}

func crAttestationBytes(requirement any) []byte {
	return crCanon(map[string]any{
		"capabilityId": crGet(crGet(requirement, "capability"), "id"),
		"commitment":   crGet(crGet(crGet(requirement, "evaluationSet"), "heldOut"), "commitment"),
	})
}

func crAssessorRunBytes(run any) []byte {
	body := crGet(run, "body")
	return crCanon(map[string]any{
		"requirementDigest": crGet(body, "requirementDigest"),
		"results":           crGet(crGet(body, "heldOut"), "results"),
		"runId":             crGet(body, "runId"),
	})
}

// crVerified reports whether signature is a key and a signature that verify
// over data.
func crVerified(signature any, data []byte) bool {
	fields, ok := signature.(map[string]any)
	if !ok {
		return false
	}
	keyText, ok := fields["publicKey"].(string)
	sigText, ok2 := fields["signature"].(string)
	if !ok || !ok2 {
		return false
	}
	key, okKey := crBase64(keyText)
	sig, okSig := crBase64(sigText)
	if !okKey || !okSig || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), data, sig)
}

// crBase64 decodes the way Python's b64decode(validate=True) does: the standard
// alphabet, padded, and nothing else, not even a line break.
func crBase64(text string) ([]byte, bool) {
	if strings.ContainsAny(text, "\r\n") {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(text)
	return decoded, err == nil
}

func crHeldOutValid(rr, run any) bool {
	if crOpt(crGet(run, "body"), "heldOut") == nil {
		return true
	}
	signature := crOpt(run, "assessorSignature")
	named := crGet(crGet(crGet(crRequirement(rr), "evaluationSet"), "heldOut"), "assessorKey")
	fields, ok := signature.(map[string]any)
	return ok && crSame(fields["publicKey"], named) && crVerified(signature, crAssessorRunBytes(run))
}

func crIdentityOverclaimed(rec map[string]any) bool {
	claim := crGet(rec, "modelIdentity")
	if crSame(claim, crUnproven) {
		return false
	}
	endpoint := crGet(rec, "endpoint")
	proof, _ := crOpt(rec, "identityProof").(map[string]any)
	if !crSame(claim, "proven") || !crSame(crGet(endpoint, "access"), "weights-held") ||
		proof == nil || !crIsDigest(proof["weightsDigest"]) {
		return true
	}
	return !crSame(proof["weightsDigest"], crGet(endpoint, "claimedWeightsDigest"))
}

// crValue is the run's usable value for a threshold's metric, or nil.
func crValue(rr, run, threshold any) *big.Int {
	var values any
	if crSame(crGet(threshold, "set"), "public") {
		values = crGet(crGet(run, "body"), "public")
	} else {
		held := crOpt(crGet(run, "body"), "heldOut")
		if held == nil || !crHeldOutValid(rr, run) {
			return nil
		}
		values = crGet(held, "results")
	}
	found := crOpt(values, crText(crGet(threshold, "metric")))
	if !crIsInt(found) {
		return nil
	}
	return crInt(found)
}

func crMeets(threshold any, value *big.Int) bool {
	limit := crInt(crGet(threshold, "value"))
	if crSame(crGet(threshold, "comparator"), "gte") {
		return value.Cmp(limit) >= 0
	}
	return value.Cmp(limit) <= 0
}

func crThresholds(rr any) []any {
	list, ok := crGet(crRequirement(rr), "thresholds").([]any)
	if !ok {
		panic(crShape{})
	}
	return list
}

// crBehaviour is the behaviour on the pinned set: contradicted, else not
// established, else supported.
func crBehaviour(rr, run any) string {
	thresholds := crThresholds(rr)
	values := make([]*big.Int, len(thresholds))
	for i, threshold := range thresholds {
		values[i] = crValue(rr, run, threshold)
	}
	missing := false
	for i, threshold := range thresholds {
		if values[i] == nil {
			missing = true
		} else if !crMeets(threshold, values[i]) {
			return "contradicted"
		}
	}
	if missing {
		return "not_established"
	}
	return "supported"
}

// crCompare is the comparison two runs of one requirement give.
func crCompare(rr, baseline, current any) map[string]any {
	changes := []any{}
	unmatched := []string{}
	drifted := false
	for _, threshold := range crThresholds(rr) {
		before, after := crValue(rr, baseline, threshold), crValue(rr, current, threshold)
		metric := crText(crGet(threshold, "metric"))
		if before == nil || after == nil {
			unmatched = append(unmatched, metric)
			continue
		}
		worse := new(big.Int).Sub(before, after)
		if !crSame(crGet(threshold, "comparator"), "gte") {
			worse.Neg(worse)
		}
		meetsBefore, meetsAfter := crMeets(threshold, before), crMeets(threshold, after)
		changes = append(changes, map[string]any{
			"baseline": json.Number(before.String()), "baselineMeets": meetsBefore,
			"current": json.Number(after.String()), "currentMeets": meetsAfter,
			"metric": metric, "worsenedBy": json.Number(worse.String()),
		})
		if worse.Cmp(crInt(crGet(threshold, "maxDrift"))) > 0 || (meetsBefore && !meetsAfter) {
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
		"baselineRunId": crGet(crGet(baseline, "body"), "runId"),
		"changes":       changes,
		"currentRunId":  crGet(crGet(current, "body"), "runId"),
		"outcome":       outcome,
		"unmatched":     names,
	}
}

// crRetained is the facts a verifier keeps from a record: its kind and what it
// found.
func crRetained(record any) map[string]any {
	rec, _ := record.(map[string]any)
	kind := rec["kind"]
	kept := map[string]any{"kind": kind}
	switch {
	case crKindIs(kind, "requirement"):
		kept["requirementDigest"] = crSafe(func() any { return crRequirementDigest(crRequirement(rec)) })
		kept["thresholds"] = crSafe(func() any {
			switch list := crGet(crRequirement(rec), "thresholds").(type) {
			case []any:
				return json.Number(strconv.Itoa(len(list)))
			case map[string]any:
				return json.Number(strconv.Itoa(len(list)))
			case string:
				return json.Number(strconv.Itoa(len([]rune(list))))
			}
			panic(crShape{})
		})
	case crKindIs(kind, "endpoint-report"):
		kept["behaviour"] = rec["behaviour"]
		kept["modelIdentity"] = rec["modelIdentity"]
		kept["runId"] = crSafe(func() any { return crGet(crGet(crGet(rec, "run"), "body"), "runId") })
	case crKindIs(kind, "drift"):
		kept["outcome"] = crSafe(func() any { return crGet(crGet(rec, "comparison"), "outcome") })
		kept["runIds"] = crSafe(func() any {
			return []any{crGet(crGet(crGet(rec, "baseline"), "body"), "runId"),
				crGet(crGet(crGet(rec, "current"), "body"), "runId")}
		})
	}
	return kept
}

// crInstant is a timestamp as Python's datetime.fromisoformat reads it: aware
// when it carries an offset, naive when it does not. Python refuses to order an
// aware instant against a naive one, and so does this.
type crInstant struct {
	at    time.Time
	aware bool
}

func (a crInstant) after(b crInstant) bool {
	if a.aware != b.aware {
		panic(crShape{})
	}
	return a.at.After(b.at)
}

func crAt(value any) crInstant {
	text, ok := value.(string)
	if !ok {
		panic(crShape{})
	}
	text = strings.ReplaceAll(text, "Z", "+00:00")
	if at, err := time.Parse("2006-01-02T15:04:05-07:00", text); err == nil {
		return crInstant{at: at, aware: true}
	}
	if at, err := time.Parse("2006-01-02T15:04:05", text); err == nil {
		return crInstant{at: at}
	}
	panic(crShape{})
}

// crGet reads member key of an object. A value that is not an object, or an
// object without the member, is a shape error: Python's KeyError and TypeError.
func crGet(object any, key string) any {
	fields, ok := object.(map[string]any)
	if !ok {
		panic(crShape{})
	}
	value, has := fields[key]
	if !has {
		panic(crShape{})
	}
	return value
}

// crOpt is Python's dict.get: nil for a missing member, a shape error for a
// value that is not an object.
func crOpt(object any, key string) any {
	fields, ok := object.(map[string]any)
	if !ok {
		panic(crShape{})
	}
	return fields[key]
}

func crText(value any) string {
	text, ok := value.(string)
	if !ok {
		panic(crShape{})
	}
	return text
}

func crOneOf(value any, names ...string) bool {
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

func crIsInt(value any) bool {
	number, ok := value.(json.Number)
	return ok && !strings.ContainsAny(number.String(), ".eE")
}

func crInt(value any) *big.Int {
	number, ok := value.(json.Number)
	if !ok {
		panic(crShape{})
	}
	integer, ok := new(big.Int).SetString(number.String(), 10)
	if !ok {
		panic(crShape{})
	}
	return integer
}

func crIsDigest(value any) bool {
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

// crSame is Python's ==, over decoded JSON: two values are the same when they
// write the same canonical bytes.
func crSame(a, b any) bool {
	left, errLeft := crCanonOrErr(a)
	right, errRight := crCanonOrErr(b)
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

func crCanonOrErr(value any) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crShape); !ok {
				panic(r)
			}
			err = fmt.Errorf("a value this encoder cannot write")
		}
	}()
	return crCanon(value), nil
}

// crCanon is the byte string every signature in this contract covers: compact
// JSON with sorted keys and no ASCII escaping, as json.dumps writes it with
// sort_keys=True, separators=(",", ":"), ensure_ascii=False.
func crCanon(value any) []byte {
	var out bytes.Buffer
	crEncode(&out, value)
	return out.Bytes()
}

func crEncode(out *bytes.Buffer, value any) {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case string:
		writePythonString(out, v, false)
	case json.Number:
		out.WriteString(crNumber(v))
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			crEncode(out, item)
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
			crEncode(out, v[key])
		}
		out.WriteByte('}')
	default:
		panic(crShape{})
	}
}

func crNumber(number json.Number) string {
	text := number.String()
	if !strings.ContainsAny(text, ".eE") {
		integer, ok := new(big.Int).SetString(text, 10)
		if !ok {
			panic(crShape{})
		}
		return integer.String()
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil && !math.IsInf(parsed, 0) {
		panic(crShape{})
	}
	return crFloat(parsed)
}

// crFloat spells a float the way CPython's repr does.
func crFloat(f float64) string {
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
