package corpusreaders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
)

func init() { register(priorSealSeams{}) }

// priorSealSeams judges corpora/vectors-priorseal-exact-call-seams/. Each member
// is one case of the exact-call envelope matrix in imokokok/PriorSeal (input
// contract 1.0.1): a signed authorization and an observed execution envelope.
// The reader implements the contract's section 4 mismatch rules and takes one
// named reading for each of the three questions the text leaves open (a missing
// observed time, a non-numeric observed time, the representation of chainId).
// A case whose answer is the same under every combination of readings is
// decided by the text; a case whose answer moves with a question is open, and
// the reader derives the answer under each reading of that question. It
// applies the checks the Python reader applies:
//
//  1. the manifest's expected answer is the one the text gives;
//  2. a decided member declares no readings;
//  3. an open member declares exactly the answers its one open question gives
//     under each of its readings.
type priorSealSeams struct{}

func (priorSealSeams) Suite() string { return "priorseal-exact-call-seams/v1" }

// pssQuestions lists each question the 1.0.1 text leaves open and its readings.
var pssQuestions = map[string][]string{
	"missing-time":            {"skip", "zero", "outside"},
	"non-numeric-time":        {"comparison-false", "outside"},
	"chain-id-representation": {"decimal-string", "json-type"},
}

type pssAnswer struct {
	Decision    string   `json:"decision"`
	ReasonCodes []string `json:"reasonCodes"`
	Question    string   `json:"question"`
}

func (a pssAnswer) equal(b pssAnswer) bool {
	return a.Decision == b.Decision && a.Question == b.Question &&
		slices.Equal(pssSorted(a.ReasonCodes), pssSorted(b.ReasonCodes))
}

func pssSorted(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}

type pssReading struct {
	Reading string    `json:"reading"`
	Answer  pssAnswer `json:"answer"`
}

type pssVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected pssAnswer         `json:"expected"`
	Readings []pssReading      `json:"readings"`
}

type pssCase struct {
	Source struct {
		Authorization map[string]any `json:"authorization"`
	} `json:"source"`
	Observed map[string]any `json:"observed"`
}

func (priorSealSeams) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v pssVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = pssJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func pssJudgeMember(caseDir string, v pssVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, fmt.Sprintf("case.json cannot be read: %v", err))
	}
	var c pssCase
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&c); err != nil {
		return append(findings, fmt.Sprintf("case.json does not parse: %v", err))
	}
	authorization := c.Source.Authorization
	intent, ok := authorization["intent"].(map[string]any)
	if !ok {
		return append(findings, "case.json carries no source.authorization.intent")
	}
	if got := pssJudge(authorization, intent, c.Observed); !got.equal(v.Expected) {
		return append(findings, "the answer the text gives is not the one the manifest declares")
	}
	if v.Expected.Decision != "open" {
		if len(v.Readings) > 0 {
			findings = append(findings, "a decided case declares readings")
		}
		return findings
	}
	choices, known := pssQuestions[v.Expected.Question]
	if !known || len(v.Readings) != len(choices) {
		return append(findings, "declared readings do not hold")
	}
	base := pssEveryReading()[0]
	for _, row := range v.Readings {
		readings := maps.Clone(base)
		readings[v.Expected.Question] = row.Reading
		if !slices.Contains(choices, row.Reading) || !row.Answer.equal(pssBind(authorization, intent, c.Observed, readings)) {
			return append(findings, "declared readings do not hold")
		}
	}
	return findings
}

func pssQuestionNames() []string {
	names := make([]string, 0, len(pssQuestions))
	for name := range pssQuestions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// pssEveryReading is every combination of one reading per question; the first
// is each question's first reading.
func pssEveryReading() []map[string]string {
	combos := []map[string]string{{}}
	for _, name := range pssQuestionNames() {
		var next []map[string]string
		for _, combo := range combos {
			for _, choice := range pssQuestions[name] {
				extended := maps.Clone(combo)
				extended[name] = choice
				next = append(next, extended)
			}
		}
		combos = next
	}
	return combos
}

// pssJudge answers a case: the decided answer, or open naming each question
// whose reading changes the answer with the others held fixed.
func pssJudge(authorization, intent, observed map[string]any) pssAnswer {
	var moving []string
	for _, name := range pssQuestionNames() {
		if pssMoves(authorization, intent, observed, name) {
			moving = append(moving, name)
		}
	}
	if len(moving) > 0 {
		return pssAnswer{Decision: "open", Question: strings.Join(moving, ",")}
	}
	return pssBind(authorization, intent, observed, pssEveryReading()[0])
}

func pssMoves(authorization, intent, observed map[string]any, question string) bool {
	for _, base := range pssEveryReading() {
		var first pssAnswer
		for i, choice := range pssQuestions[question] {
			readings := maps.Clone(base)
			readings[question] = choice
			answer := pssBind(authorization, intent, observed, readings)
			if i == 0 {
				first = answer
			} else if !answer.equal(first) {
				return true
			}
		}
	}
	return false
}

// pssString is the 1.0.1 String() coercion: null and missing to the empty
// string, an integer to its decimal.
func pssString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case bool:
		if v {
			return "true"
		}
		return "false"
	case json.Number:
		return v.String()
	case string:
		return v
	}
	return fmt.Sprint(value)
}

func pssSame(left, right any) bool {
	return strings.EqualFold(pssString(left), pssString(right))
}

func pssTime(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := number.Int64()
	return n, err == nil
}

func pssChainMismatch(signed, observed any, reading string) bool {
	if reading == "decimal-string" {
		return pssString(signed) != pssString(observed)
	}
	return !reflect.DeepEqual(signed, observed)
}

// pssWindowCodes applies the two window rows over executedAt, falling back to
// observedAt.
func pssWindowCodes(authorization, intent, observed map[string]any, readings map[string]string) []string {
	both := []string{"OUTSIDE_AUTHORIZATION_WINDOW", "OUTSIDE_TIME_WINDOW"}
	when := observed["executedAt"]
	if when == nil {
		when = observed["observedAt"]
	}
	if when == nil && readings["missing-time"] == "zero" {
		when = json.Number("0")
	}
	if when == nil {
		if readings["missing-time"] == "outside" {
			return both
		}
		return nil
	}
	at, isTime := pssTime(when)
	if !isTime {
		if readings["non-numeric-time"] == "outside" {
			return both
		}
		return nil
	}
	validUntil, _ := pssTime(intent["validUntil"])
	notBefore, _ := pssTime(authorization["notBefore"])
	expiresAt, _ := pssTime(authorization["expiresAt"])
	var codes []string
	if at > validUntil {
		codes = append(codes, "OUTSIDE_TIME_WINDOW")
	}
	if at < notBefore || at > expiresAt {
		codes = append(codes, "OUTSIDE_AUTHORIZATION_WINDOW")
	}
	return codes
}

// pssBind is the section 4 mismatch set of one case under one reading of each
// open question.
func pssBind(authorization, intent, observed map[string]any, readings map[string]string) pssAnswer {
	var codes []string
	if pssChainMismatch(intent["chainId"], observed["chainId"], readings["chain-id-representation"]) {
		codes = append(codes, "CHAIN_MISMATCH")
	}
	if !pssSame(observed["action"], intent["action"]) {
		codes = append(codes, "ACTION_MISMATCH")
	}
	if !pssSame(observed["sender"], intent["sender"]) {
		codes = append(codes, "SENDER_MISMATCH")
	}
	if pssNonce(observed) != pssNonce(intent) {
		codes = append(codes, "NONCE_MISMATCH")
	}
	for _, pair := range [][3]string{
		{"callTarget", "target", "CALL_TARGET_MISMATCH"},
		{"calldataHash", "calldataHash", "CALLDATA_MISMATCH"},
	} {
		if intent[pair[0]] != nil && !pssSame(observed[pair[1]], intent[pair[0]]) {
			codes = append(codes, pair[2])
		}
	}
	if value := intent["transactionValue"]; value != nil && pssString(observed["nativeValue"]) != pssString(value) {
		codes = append(codes, "TRANSACTION_VALUE_MISMATCH")
	}
	codes = append(codes, pssWindowCodes(authorization, intent, observed, readings)...)
	reasons := pssSorted(slices.Compact(pssSorted(codes)))
	if reasons == nil {
		reasons = []string{}
	}
	if len(reasons) > 0 {
		return pssAnswer{Decision: "not_bound", ReasonCodes: reasons}
	}
	return pssAnswer{Decision: "bound", ReasonCodes: reasons}
}

// pssNonce reads a nonce: missing is "0", null is the empty string.
func pssNonce(m map[string]any) string {
	value, present := m["nonce"]
	if !present {
		return "0"
	}
	return pssString(value)
}
