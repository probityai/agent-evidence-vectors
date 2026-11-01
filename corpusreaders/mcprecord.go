package corpora

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

func init() { register(mcpRecordContract{}) }

// mcpRecordContract judges vectors-mcp-record-contract/. Two jobs, and the
// second is the one that matters: the ordinary corpus check, and then the
// criterion RUN against every member, so the rule is measured against the
// corpus rather than asserted beside it.
//
// A criterion stated only in prose is satisfied by whatever a reader takes it
// to mean, and the two readings that matter here differ on a record that is
// fully re-checkable and carries a figure nobody should quote.
type mcpRecordContract struct{}

func (mcpRecordContract) Suite() string { return "cross-run-record-contract" }

// mcpAxes are the three answers the criterion returns, separate on purpose.
var mcpAxes = []string{"recheckable", "figureMeansWhatItSays", "independence"}

// mcpFourInputs are the four conditions a re-run needs; mcpMeaning are the two
// that decide what a result means. Held here as well as in the generator on
// purpose: this is the thing that would catch the generator agreeing with itself.
var (
	mcpFourInputs = map[string]bool{"mrc-c-1": true, "mrc-c-2": true, "mrc-c-3": true, "mrc-c-4": true}
	mcpMeaning    = map[string]string{"mrc-c-5": "figureMeansWhatItSays", "mrc-c-6": "independence"}
)

type mcpManifest struct {
	Criterion    string                     `json:"criterion"`
	Conditions   map[string]json.RawMessage `json:"conditions"`
	Counts       map[string]int             `json:"counts"`
	CorpusDigest string                     `json:"corpusDigest"`
	Vectors      []mcpVector                `json:"vectors"`
}

type mcpVector struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Record     string          `json:"record"`
	Conditions []string        `json:"conditions"`
	Expected   json.RawMessage `json:"expected"`
}

// mcpExpected is the declaration a member makes about the three answers. Each
// field is a pointer so "declares no expectation on this axis" is a different
// state from "declares false", which is a finding the corpus makes.
type mcpExpected struct {
	Recheckable           *bool   `json:"recheckable"`
	FigureMeansWhatItSays *bool   `json:"figureMeansWhatItSays"`
	Independence          *string `json:"independence"`
}

func (m mcpRecordContract) Judge(dir string, raw []byte) (*Result, error) {
	var manifest mcpManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	accepted, rejected, used := map[string]bool{}, map[string]bool{}, map[string]bool{}
	ids, files := make([]string, 0, len(manifest.Vectors)), make([]string, 0, len(manifest.Vectors))

	for _, v := range manifest.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.Record)
		for _, c := range v.Conditions {
			used[c] = true
			switch v.Kind {
			case "accept":
				accepted[c] = true
			case "reject":
				rejected[c] = true
			}
		}
		m.judgeMember(dir, &manifest, v, &member)
		result.Members = append(result.Members, member)
	}

	if orphan := orphanTwins(accepted, rejected); len(orphan) > 0 {
		result.Findings = append(result.Findings, fmt.Sprintf(
			"conditions that reject and never accept: %v. A checker that refuses every "+
				"record would score full marks on them.", orphan))
	}
	if idle := declaredMinusUsed(manifest.Conditions, used); len(idle) > 0 {
		result.Findings = append(result.Findings,
			fmt.Sprintf("conditions declared and carried by no member: %v", idle))
	}
	// The criterion sits above the corpus directory, so it is resolved against
	// the parent rather than the corpus.
	if !existsIn(corpusParent(dir), manifest.Criterion) {
		result.Findings = append(result.Findings, fmt.Sprintf(
			"the manifest names the criterion at %s and no such file is there, so the "+
				"corpus measures a rule nobody can read", manifest.Criterion))
	}
	measured := map[string]int{"accept": 0, "reject": 0}
	for _, v := range manifest.Vectors {
		if _, k := measured[v.Kind]; k {
			measured[v.Kind]++
		}
	}
	if bad := countsDisagree(manifest.Counts, measured); bad != "" {
		result.Findings = append(result.Findings, bad)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		return nil, err
	}
	if digest != manifest.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the record files on disk")
	}
	return result, nil
}

func (m mcpRecordContract) judgeMember(dir string, manifest *mcpManifest, v mcpVector, out *Member) {
	if v.Kind != "accept" && v.Kind != "reject" {
		out.Findings = append(out.Findings, fmt.Sprintf("declares kind %q", v.Kind))
	}
	if len(v.Conditions) == 0 {
		out.Findings = append(out.Findings, "cites no condition")
		return
	}
	for _, condition := range v.Conditions {
		if _, defined := manifest.Conditions[condition]; !defined {
			out.Findings = append(out.Findings, "cites condition "+condition+" the manifest does not define")
		}
	}
	if !existsIn(dir, v.Record) {
		out.Findings = append(out.Findings, "the manifest names a record file that does not exist")
		return
	}
	var declared map[string]json.RawMessage
	if err := json.Unmarshal(v.Expected, &declared); err != nil {
		out.Findings = append(out.Findings, "the expected block does not parse: "+err.Error())
		return
	}
	incomplete := false
	for _, axis := range mcpAxes {
		if _, present := declared[axis]; !present {
			out.Findings = append(out.Findings, "declares no expectation on "+axis)
			incomplete = true
		}
	}
	if incomplete {
		return
	}
	var expected mcpExpected
	if err := json.Unmarshal(v.Expected, &expected); err != nil {
		out.Findings = append(out.Findings, "the expected block does not parse: "+err.Error())
		return
	}
	m.checkDeclaredAxes(v, expected, out)
	m.checkAgainstCriterion(dir, v, expected, out)
}

// checkDeclaredAxes asserts a reject member fails exactly one axis and that its
// condition says which. One member failing two axes cannot tell you which rule
// caught it, which is the property the whole reason column exists for.
func (mcpRecordContract) checkDeclaredAxes(v mcpVector, expected mcpExpected, out *Member) {
	var failing []string
	if expected.Recheckable != nil && !*expected.Recheckable {
		failing = append(failing, "recheckable")
	}
	if expected.FigureMeansWhatItSays != nil && !*expected.FigureMeansWhatItSays {
		failing = append(failing, "figureMeansWhatItSays")
	}
	if expected.Independence != nil && *expected.Independence == "undeclared" {
		failing = append(failing, "independence")
	}
	if v.Kind == "accept" {
		if len(failing) > 0 {
			out.Findings = append(out.Findings, fmt.Sprintf("is an accept member declaring a failure on %v", failing))
		}
		return
	}
	if len(failing) != 1 {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"is a reject member declaring failures on %v. One member failing two axes cannot "+
				"tell you which rule caught it, which is the property the whole reason column "+
				"exists for.", failing))
		return
	}
	condition := v.Conditions[0]
	wanted := mcpMeaning[condition]
	if mcpFourInputs[condition] {
		wanted = "recheckable"
	}
	if failing[0] != wanted {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"cites %s and declares its failure on %s, not on %s", condition, failing[0], wanted))
	}
}

// checkAgainstCriterion runs the criterion. This is the check the prose cannot do.
func (mcpRecordContract) checkAgainstCriterion(dir string, v mcpVector, expected mcpExpected, out *Member) {
	body, err := readIn(dir, v.Record)
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		out.Findings = append(out.Findings, "the record does not parse: "+err.Error())
		return
	}
	// The identifier is a digest over the member's kind, its conditions and the
	// record itself, so an edit to the record without regenerating leaves a
	// name describing bytes that are no longer there.
	checkRunRecordIdentity(body, v, out)

	observed := checkRunRecord(record)
	reason := strings.Join(append(append([]string{}, observed.Missing...), observed.Notes...), "; ")
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if reason == "" {
		reason = "the checker gave no reason, which is its own defect"
	}
	if expected.Recheckable != nil && observed.Recheckable != *expected.Recheckable {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares recheckable=%t and the checker answers %t. %s",
			*expected.Recheckable, observed.Recheckable, reason))
	}
	if expected.FigureMeansWhatItSays != nil && observed.FigureMeansWhatItSays != *expected.FigureMeansWhatItSays {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares figureMeansWhatItSays=%t and the checker answers %t. %s",
			*expected.FigureMeansWhatItSays, observed.FigureMeansWhatItSays, reason))
	}
	if expected.Independence != nil && observed.Independence != *expected.Independence {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"declares independence=%s and the checker answers %s. %s",
			*expected.Independence, observed.Independence, reason))
	}
	if v.Kind == "reject" && len(observed.Missing) == 0 && len(observed.Notes) == 0 {
		out.Findings = append(out.Findings, "is a reject member the checker had nothing at all to say about")
	}
}

// checkRunRecordIdentity recomputes the member's name from its kind, its
// conditions and the record's own value.
func checkRunRecordIdentity(body []byte, v mcpVector, out *Member) {
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return
	}
	conditions := make([]any, 0, len(v.Conditions))
	for _, c := range v.Conditions {
		conditions = append(conditions, c)
	}
	payload, err := pythonCompactJSON(map[string]any{
		"kind": v.Kind, "conditions": conditions, "payload": value,
	})
	if err != nil {
		out.Findings = append(out.Findings, err.Error())
		return
	}
	if idFromBytes(payload) != v.ID {
		out.Findings = append(out.Findings, "identifier does not recompute from the member's own bytes")
	}
}

// ---------------------------------------------------------------------------
// The interoperability-evidence criterion, restated in Go from
// vectors-mcp-record-contract/check_run_record.py.
//
// A cross-run claim is evidence when a third party can obtain the same result
// from what is published and compare it byte for byte. That reduces to four
// inputs. Two further declarations do not decide whether a result can be
// obtained, they decide what it means, so they are reported separately rather
// than folded into the verdict.
// ---------------------------------------------------------------------------

// immutableRef: a reference is immutable when nothing can move it. A full
// commit identifier and a digest qualify. A branch name, a tag name and a bare
// version string do not: a tag is a name its owner can re-point.
var immutableRef = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})$`)

// runRecordVerdict is the criterion's three answers plus what it had to say.
type runRecordVerdict struct {
	Recheckable           bool
	FigureMeansWhatItSays bool
	Independence          string
	Missing               []string
	Notes                 []string
}

func isImmutableRef(value any) bool {
	s, ok := value.(string)
	return ok && immutableRef.MatchString(strings.TrimSpace(s))
}

func objectAt(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func checkRunRecord(record map[string]any) runRecordVerdict {
	sides, _ := record["sides"].([]any)
	var missing, notes []string
	if len(sides) == 0 {
		missing = append(missing, "the record names no side that ran anything")
	}
	for index, item := range sides {
		side := objectAt(item)
		label, _ := side["label"].(string)
		if label == "" {
			label = fmt.Sprintf("side %d", index+1)
		}
		missing = append(missing, checkRunRecordSide(side, label)...)
	}
	honestFigure := checkRunRecordFigure(objectAt(record["figure"]), &notes)
	stance := checkRunRecordIndependence(objectAt(record["independence"]), &notes)
	for _, item := range sides {
		side := objectAt(item)
		if environment, present := side["environment"]; !present || isFalsy(environment) {
			label, _ := side["label"].(string)
			if label == "" {
				label = "a side"
			}
			notes = append(notes, label+": no environment is recorded. A result that turns out "+
				"not to depend on the runtime is a stronger result, and nobody can establish "+
				"that from a record that never named one.")
		}
	}
	return runRecordVerdict{
		Recheckable:           len(missing) == 0,
		FigureMeansWhatItSays: honestFigure,
		Independence:          stance,
		Missing:               missing,
		Notes:                 notes,
	}
}

// isFalsy is Python's truthiness for the values a JSON document can hold. It is
// spelled out because the criterion's own tests turn on it: an empty object, an
// empty string and a zero are each "not recorded".
func isFalsy(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return v == ""
	case float64:
		return v == 0
	case json.Number:
		return jsonNumberIsZero(v)
	case []any:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	}
	return false
}

// checkRunRecordSide is one direction of a cross-run: what a third party would
// need to redo it.
func checkRunRecordSide(side map[string]any, label string) []string {
	var missing []string
	inputs, runner, output := objectAt(side["inputs"]), objectAt(side["runner"]), objectAt(side["output"])
	if !isImmutableRef(inputs["ref"]) {
		missing = append(missing, label+": the inputs carry no immutable reference. A repository "+
			"name and a version string name a thing that can change under the claim; a commit "+
			"identifier or a digest names bytes.")
	}
	if !isImmutableRef(runner["ref"]) && !isImmutableRef(runner["digest"]) {
		missing = append(missing, label+": the runner carries no immutable reference and no digest. "+
			"Naming the library the runner was built on is not naming the runner: the driver that "+
			"loaded the inputs and emitted the result is the part a third party has to have.")
	}
	invocation, ok := side["invocation"].(string)
	if !ok || strings.TrimSpace(invocation) == "" {
		missing = append(missing, label+": no invocation is published, so a third party cannot know "+
			"what was asked of the runner, only what the runner is.")
	}
	switch {
	case !isImmutableRef(output["digest"]):
		missing = append(missing, label+": the result carries no digest, so a third party who "+
			"re-runs it has nothing to compare against.")
	case isFalsy(output["published"]):
		missing = append(missing, label+": the result carries a digest and is not published, so the "+
			"digest is a claim about a file nobody else can hold.")
	}
	return missing
}

// checkRunRecordFigure asks whether the headline agrees with its own counting rule.
func checkRunRecordFigure(figure map[string]any, notes *[]string) bool {
	if len(figure) > 0 && isFalsy(figure["countingRule"]) {
		*notes = append(*notes, "the headline figure states no counting rule. A figure written as "+
			"N of N is read as N passes; when some members were deliberately not scored, the same "+
			"run is also honestly describable as N members with no failures, and those are "+
			"different claims.")
		return false
	}
	if len(figure) == 0 {
		return true
	}
	honest := true
	// Each unscored entry says how many members it covers, because a reason
	// covering four members and a reason covering one are one entry each and
	// the count is the only thing that reconciles with the total.
	withheld := 0
	if entries, ok := figure["notScored"].([]any); ok {
		for _, item := range entries {
			if count, ok := numberOf(objectAt(item)["count"]); ok {
				withheld += count
			}
		}
	}
	scored, scoredOK := numberOf(figure["scored"])
	total, totalOK := numberOf(figure["total"])
	if scoredOK && totalOK {
		if scored+withheld != total {
			honest = false
			*notes = append(*notes, fmt.Sprintf(
				"the figure says %d scored of %d and its unscored entries account for %d, "+
					"which do not add up.", scored, total, withheld))
		}
		if headline, _ := figure["headline"].(string); scored != total &&
			headline == fmt.Sprintf("%d of %d", total, total) {
			honest = false
			*notes = append(*notes, fmt.Sprintf(
				"the headline reads %d of %d and %d members were scored. The unscored members "+
					"are enumerated, which is the honest half; the headline is the half that is read.",
				total, total, scored))
		}
	}
	return honest
}

// numberOf reads a JSON number as an integer, reporting whether the value was
// an integer at all. A float is not an integer here and is not counted as one.
func numberOf(value any) (int, bool) {
	switch v := value.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}

// checkRunRecordIndependence returns three answers, not two. "Undeclared" is a
// defect in the record; "self-report" is a fact about the run that the record
// states, and the second is worth publishing while the first leaves a reader
// guessing.
func checkRunRecordIndependence(independence map[string]any, notes *[]string) string {
	if isFalsy(independence["declared"]) {
		*notes = append(*notes, "independence is not declared. Whether the party that ran the "+
			"inputs authored them decides whether the result is independent evidence or a "+
			"self-report, and a reader cannot infer it.")
		return "undeclared"
	}
	if !isFalsy(independence["runnerAuthoredInputs"]) {
		*notes = append(*notes, "the party that ran the inputs authored them, so the result is a "+
			"self-report. That is worth publishing and it is not independent evidence, and the "+
			"record says so, which is the point.")
		return "self-report"
	}
	return "independent"
}
