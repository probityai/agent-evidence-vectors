package corpora

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

func init() { register(aciCorpus{}) }

// aciCorpus judges vectors-aci/. It carries nineteen checks, one per normative
// sentence of ACI Draft Specification v0.9, and each corpus member is one ACI
// deployment declaring the codes those checks must emit against it.
//
// A member here is a whole deployment rather than a single statement: an
// organization publishes several manifests plus a discovery chain, and half the
// requirements are about how those files agree with each other. The deployment
// is serialised into one file so the identifier stays a digest of the member's
// own bytes, which is what makes a flipped byte name its member.
//
// Four of the six deployments the specification itself ships do not satisfy the
// text they illustrate. They are corpus members with an expected reject and the
// finding they demonstrate, rather than corrected copies: a corpus that fixed
// the specification's examples would certify against a document nobody
// published.
type aciCorpus struct{}

func (aciCorpus) Suite() string { return "aci" }

// aciChecks is the reader's own copy of the requirement table. The manifest
// carries the same table and checkCorpus asserts the two agree: a check in one
// and not the other is a requirement that nothing forces.
var aciChecks = map[string]string{
	"ACI-SER-001": "13.1",
	"ACI-LVL-001": "3.1-3.3",
	"ACI-LVL-002": "3.3",
	"ACI-REQ-001": "5.2, 6.2, 7.2, 8.2, 9.2",
	"ACI-IDF-001": "5.2",
	"ACI-IDF-002": "10.1",
	"ACI-IDF-003": "10.1",
	"ACI-TS-001":  "5.2, 16",
	"ACI-CON-001": "17.2",
	"ACI-CON-002": "17.2",
	"ACI-DIS-001": "4.1",
	"ACI-DIS-002": "4.2",
	"ACI-DIS-003": "4.2",
	"ACI-EXT-001": "12.2",
	"ACI-EXT-002": "12.2",
	"ACI-AGT-001": "9.4",
	"ACI-BLK-001": "6.4, 7.4, 8.4, 9.4",
	"ACI-LIF-001": "11.1",
	"ACI-LIF-002": "11.3",
}

// The five manifest kinds of SPEC.md section 2, and the file each is published
// under per sections 4.1, 4.2 and appendix A.1.
var (
	aciKinds = []string{"identity", "capability", "knowledge", "trust", "agent"}
	aciFile  = map[string]string{
		"identity":   "identity.json",
		"capability": "capabilities.json",
		"knowledge":  "knowledge.json",
		"trust":      "trust.json",
		"agent":      "agents.json",
	}
	// Sections 3.1 to 3.3: which manifests each conformance level requires.
	aciLevelManifests = map[int][]string{
		1: {"identity", "capability"},
		2: {"identity", "capability", "knowledge", "trust"},
		3: {"identity", "capability", "knowledge", "trust", "agent"},
	}
	// Sections 5.2, 6.2, 7.2, 8.2 and 9.2.
	aciRequired = map[string][]string{
		"identity":   {"manifest_version", "last_updated", "publisher", "identifiers"},
		"capability": {"manifest_version", "last_updated", "publisher"},
		"knowledge":  {"manifest_version", "last_updated", "publisher"},
		"trust":      {"manifest_version", "last_updated", "publisher"},
		"agent":      {"manifest_version", "last_updated", "publisher"},
	}
	// Sections 5.3, 6.3, 7.3, 8.3 and 9.3.
	aciOptional = map[string][]string{
		"identity":   {"jurisdiction", "registration_number", "website", "contact", "social", "brand", "description"},
		"capability": {"industries", "pricing_model", "documentation"},
		"knowledge":  {"domain", "domain_label"},
		"trust":      {"certifications", "patents", "compliance", "signatures", "history"},
		"agent":      {"authentication"},
	}
	// Sections 6.4, 7.4, 8.4 and 9.4.
	aciBlocks = map[string][]string{
		"capability": {"products", "services", "solutions"},
		"knowledge":  {"concepts"},
		"trust":      {"assertions"},
		"agent":      {"agents"},
	}
	// schema_version is named in section 14.3 and discovery in section 4.5, for
	// every manifest. Appendix A is marked INFORMATIVE by the specification at
	// line 755, so a field appearing only there is not normative vocabulary --
	// which is what makes the section 12.2 extension rule checkable at all.
	aciUniversal    = []string{"manifest_version", "last_updated", "publisher", "schema_version", "discovery"}
	aciLifecycle    = map[string]bool{"active": true, "deprecated": true, "superseded": true, "withdrawn": true}
	aciIdentifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)*$`)
)

// aciMaxIdentifier is the ceiling set by section 10.1: "An identifier SHALL NOT
// exceed 128 characters."
const aciMaxIdentifier = 128

// Severities. A MUST that is not met is a violation and decides accept from
// reject. A SHOULD that is not met is a warning, and a place the specification
// leaves undecided is a note. Collapsing the three would make every example the
// specification ships a reject, which reports more than the text supports.
const (
	aciViolation = "violation"
	aciWarning   = "warning"
	aciNote      = "note"
)

type aciManifest struct {
	SpecVersion  string            `json:"specVersion"`
	SpecCommit   string            `json:"specCommit"`
	Checks       map[string]string `json:"checks"`
	Counts       map[string]int    `json:"counts"`
	CorpusDigest string            `json:"corpusDigest"`
	Vectors      []aciVector       `json:"vectors"`
}

type aciVector struct {
	ID          string      `json:"id"`
	Kind        string      `json:"kind"`
	File        string      `json:"file"`
	Level       int         `json:"level"`
	Expected    aciExpected `json:"expected"`
	SpecFinding string      `json:"specFinding"`
	Note        string      `json:"note"`
}

type aciExpected struct {
	Codes []string `json:"codes"`
}

// aciDeployment is a member's own bytes: the files an organization publishes,
// keyed by the path each is served at.
type aciDeployment struct {
	ACIVersion string            `json:"aciVersion"`
	Files      map[string]string `json:"files"`
}

func (a aciCorpus) Judge(dir string, raw []byte) (*Result, error) {
	var m aciManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	seen := map[string]bool{}
	ids, files := make([]string, 0, len(m.Vectors)), make([]string, 0, len(m.Vectors))
	emitted := map[string]bool{}
	for _, v := range m.Vectors {
		member := Member{ID: v.ID, Kind: v.Kind}
		if seen[v.ID] {
			member.Findings = append(member.Findings, "duplicate identifier")
		}
		seen[v.ID] = true
		ids, files = append(ids, v.ID), append(files, v.File)
		for _, code := range v.Expected.Codes {
			emitted[code] = true
		}
		a.judgeMember(dir, v, &member)
		result.Members = append(result.Members, member)
	}
	result.Findings = append(result.Findings, a.checkCorpus(dir, &m, emitted, ids, files)...)
	return result, nil
}

// judgeMember replays one deployment through the nineteen checks and compares
// the codes they emit with the codes the member declares.
func (a aciCorpus) judgeMember(dir string, v aciVector, member *Member) {
	if v.Kind != "accept" && v.Kind != "reject" && v.Kind != "indeterminate" {
		member.Findings = append(member.Findings,
			fmt.Sprintf("kind %q is not one this corpus judges", v.Kind))
		return
	}
	if v.Level < 1 || v.Level > 3 {
		member.Findings = append(member.Findings,
			fmt.Sprintf("level %d is outside the three the specification defines", v.Level))
		return
	}
	deployment, ok := a.loadMember(dir, v, member)
	if !ok {
		return
	}
	got := aciRun(deployment.Files, v.Level)
	member.Findings = append(member.Findings, aciCompareCodes(v, got)...)
	member.Findings = append(member.Findings, aciCompareVerdict(v, got)...)
}

// loadMember reads a member's own bytes, asserts the identifier still names
// them, and decodes the deployment they carry.
func (aciCorpus) loadMember(dir string, v aciVector, member *Member) (aciDeployment, bool) {
	var deployment aciDeployment
	body, err := readIn(dir, v.File)
	if err != nil {
		member.Findings = append(member.Findings,
			fmt.Sprintf("member file %s is unreadable: %v", v.File, err))
		return deployment, false
	}
	if got := idFromBytes(body); got != v.ID {
		member.Findings = append(member.Findings,
			fmt.Sprintf("identifier does not recompute from the member's own bytes (declared %s, computed %s)",
				v.ID, got))
	}
	if err := json.Unmarshal(body, &deployment); err != nil {
		member.Findings = append(member.Findings,
			fmt.Sprintf("member file %s does not parse as a deployment: %v", v.File, err))
		return deployment, false
	}
	return deployment, true
}

// aciCompareCodes reports each direction of the disagreement separately: a code
// declared that no check emits is a stale expectation, and a code emitted that
// nothing declares is a member whose behaviour nobody wrote down.
func aciCompareCodes(v aciVector, got map[string]string) []string {
	var findings []string
	want := map[string]bool{}
	for _, code := range v.Expected.Codes {
		if _, known := aciChecks[code]; !known {
			findings = append(findings,
				fmt.Sprintf("expects code %s, which is not one of the nineteen checks", code))
			continue
		}
		want[code] = true
	}
	for _, code := range sortedKeys(want) {
		if _, fired := got[code]; !fired {
			findings = append(findings,
				fmt.Sprintf("declares %s and the checks do not emit it at level %d", code, v.Level))
		}
	}
	for _, code := range sortedKeys(got) {
		if !want[code] {
			findings = append(findings,
				fmt.Sprintf("the checks emit %s (%s) at level %d and the member does not declare it",
					code, got[code], v.Level))
		}
	}
	return findings
}

// aciCompareVerdict decides accept, indeterminate or reject from severity. Two
// verdicts would force a deployment that meets every MUST and misses a SHOULD
// into the wrong box in both directions: reject reports more than the
// specification says, and accept discards the finding.
func aciCompareVerdict(v aciVector, got map[string]string) []string {
	var violations []string
	for _, code := range sortedKeys(got) {
		if got[code] == aciViolation {
			violations = append(violations, code)
		}
	}
	verdict := "accept"
	switch {
	case len(violations) > 0:
		verdict = "reject"
	case len(got) > 0:
		verdict = "indeterminate"
	}
	if v.Kind == verdict {
		return nil
	}
	switch verdict {
	case "reject":
		return []string{fmt.Sprintf("is declared %s and the checks refuse it on %v", v.Kind, violations)}
	case "indeterminate":
		return []string{fmt.Sprintf("is declared %s and the checks meet every MUST while reporting %v",
			v.Kind, sortedKeys(got))}
	default:
		return []string{fmt.Sprintf("is declared %s and no check reports anything against it", v.Kind)}
	}
}

// checkCorpus carries the claims that belong to no single member.
func (a aciCorpus) checkCorpus(dir string, m *aciManifest, emitted map[string]bool, ids, files []string) []string {
	var findings []string
	if m.SpecVersion == "" {
		findings = append(findings, "the manifest declares no specVersion, so nothing records which text this corpus certifies against")
	}
	if m.SpecCommit == "" {
		findings = append(findings, "the manifest declares no specCommit, so the vendored example deployments are pinned to nothing")
	}
	// The reader's table and the manifest's must agree in both directions.
	for _, code := range sortedKeys(aciChecks) {
		if _, ok := m.Checks[code]; !ok {
			findings = append(findings,
				fmt.Sprintf("the reader carries check %s and the manifest does not declare it", code))
			continue
		}
		if m.Checks[code] != aciChecks[code] {
			findings = append(findings,
				fmt.Sprintf("check %s cites section %q in the manifest and %q in the reader",
					code, m.Checks[code], aciChecks[code]))
		}
	}
	for _, code := range sortedKeys(m.Checks) {
		if _, ok := aciChecks[code]; !ok {
			findings = append(findings,
				fmt.Sprintf("the manifest declares check %s and no reader here carries it", code))
		}
	}
	// Every check needs a member that forces it. Without this a corpus of
	// nineteen checks and one member scores full marks.
	for _, code := range sortedKeys(aciChecks) {
		if !emitted[code] {
			findings = append(findings,
				fmt.Sprintf("no member declares %s, so that check is named and never forced", code))
		}
	}
	measured := map[string]int{}
	for i := range ids {
		_ = i
	}
	for _, v := range m.Vectors {
		measured[v.Kind]++
	}
	if disagreement := countsDisagree(m.Counts, measured); disagreement != "" {
		findings = append(findings, disagreement)
	}
	digest, err := orderedCorpusDigest(dir, ids, files)
	if err != nil {
		findings = append(findings, fmt.Sprintf("the corpus digest could not be computed: %v", err))
	} else if digest != m.CorpusDigest {
		findings = append(findings,
			fmt.Sprintf("corpusDigest does not match the members on disk (manifest %s, on disk %s)",
				short(m.CorpusDigest), short(digest)))
	}
	return findings
}

// aciRun is the nineteen checks. It returns every code that fires against one
// deployment at one claimed conformance level, mapped to the highest severity
// at which it fired.
func aciRun(files map[string]string, level int) map[string]string {
	codes := map[string]string{}
	rank := map[string]int{aciNote: 0, aciWarning: 1, aciViolation: 2}
	fire := func(code, severity string) {
		if seen, ok := codes[code]; !ok || rank[severity] > rank[seen] {
			codes[code] = severity
		}
	}

	decoded := map[string]map[string]any{}
	present := map[string]bool{}
	for _, kind := range aciKinds {
		text, ok := files[aciFile[kind]]
		if !ok {
			continue
		}
		present[kind] = true
		var fields map[string]any
		if err := json.Unmarshal([]byte(text), &fields); err != nil {
			fire("ACI-SER-001", aciViolation) // section 13.1: manifests SHALL be valid JSON
			continue
		}
		decoded[kind] = fields
	}

	required := aciLevelManifests[level]
	for _, kind := range required {
		if !present[kind] {
			fire("ACI-LVL-001", aciViolation) // sections 3.1 to 3.3
		}
	}

	for _, kind := range required {
		fields, ok := decoded[kind]
		if !ok {
			continue
		}
		for _, field := range aciRequired[kind] {
			if _, ok := fields[field]; !ok {
				fire("ACI-REQ-001", aciViolation)
			}
		}
		aciCheckTimestamp(fields, fire)
		aciCheckExtensions(kind, fields, fire)
	}

	aciCheckIdentifiers(decoded, required, fire)
	aciCheckConsistency(decoded, required, fire)
	aciCheckDiscovery(files, level, fire)
	aciCheckBlocks(decoded, level, fire)
	aciCheckLifecycle(decoded, required, fire)
	if level >= 3 {
		aciCheckAgents(decoded, fire)
	}
	return codes
}

// aciCheckTimestamp is ACI-TS-001, sections 5.2 and 16: last_updated MUST be an
// ISO 8601 timestamp. A date-only value fires too, and the finding is the same
// one the specification's own examples carry.
func aciCheckTimestamp(fields map[string]any, fire func(string, string)) {
	value, ok := fields["last_updated"]
	if !ok {
		return
	}
	text, ok := value.(string)
	if !ok {
		fire("ACI-TS-001", aciViolation)
		return
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05"} {
		if _, err := time.Parse(layout, text); err == nil {
			return
		}
	}
	// A date is a valid ISO 8601 date and is not a timestamp. Sections 5.2 and
	// 16 ask for a timestamp and do not say whether a date satisfies them, so
	// this is a warning rather than a refusal, and 18 of the 18 manifest files
	// the specification ships carry it.
	if _, err := time.Parse("2006-01-02", text); err == nil {
		fire("ACI-TS-001", aciWarning)
		return
	}
	fire("ACI-TS-001", aciViolation)
}

// aciCheckExtensions is ACI-EXT-001 and ACI-EXT-002, section 12.2: extension
// fields MUST start with x-, and MUST NOT redefine a normative field.
func aciCheckExtensions(kind string, fields map[string]any, fire func(string, string)) {
	known := map[string]bool{}
	for _, field := range aciUniversal {
		known[field] = true
	}
	for _, group := range [][]string{aciRequired[kind], aciOptional[kind], aciBlocks[kind]} {
		for _, field := range group {
			known[field] = true
		}
	}
	for _, name := range sortedKeys(fields) {
		if strings.HasPrefix(name, "x-") {
			if known[strings.TrimPrefix(name, "x-")] {
				fire("ACI-EXT-002", aciViolation)
			}
			continue
		}
		if !known[name] {
			fire("ACI-EXT-001", aciViolation)
		}
	}
}

// aciCheckIdentifiers is ACI-IDF-001, ACI-IDF-002 and ACI-IDF-003: the
// identifiers array carries at least one identifier (section 5.2), each matches
// the section 10.1 grammar, and none exceeds 128 characters.
func aciCheckIdentifiers(decoded map[string]map[string]any, required []string, fire func(string, string)) {
	identity, ok := decoded["identity"]
	if ok {
		if raw, present := identity["identifiers"]; present {
			array, isArray := raw.([]any)
			switch {
			case !isArray:
				fire("ACI-IDF-001", aciViolation)
			case len(array) == 0:
				fire("ACI-IDF-001", aciViolation)
			}
		}
	}
	for _, value := range aciIdentifierValues(decoded, required) {
		if !aciIdentifierRE.MatchString(value) {
			fire("ACI-IDF-002", aciViolation)
		}
		if len(value) > aciMaxIdentifier {
			fire("ACI-IDF-003", aciViolation)
		}
	}
}

// aciIdentifierValues gathers every string the specification treats as an ACI
// identifier: the ids in the identifiers array, and the id of every product,
// service, solution, concept, assertion and agent.
func aciIdentifierValues(decoded map[string]map[string]any, required []string) []string {
	var out []string
	if identity, ok := decoded["identity"]; ok {
		if array, isArray := identity["identifiers"].([]any); isArray {
			for _, item := range array {
				switch value := item.(type) {
				case string:
					out = append(out, value)
				case map[string]any:
					if id, isString := value["id"].(string); isString {
						out = append(out, id)
					}
				}
			}
		}
	}
	for _, entity := range aciEntities(decoded, required) {
		if id, ok := entity["id"].(string); ok {
			out = append(out, id)
		}
	}
	return out
}

// aciEntities is every named entity section 11 asks to declare a lifecycle
// state for.
func aciEntities(decoded map[string]map[string]any, required []string) []map[string]any {
	inLevel := map[string]bool{}
	for _, kind := range required {
		inLevel[kind] = true
	}
	var out []map[string]any
	for _, kind := range aciKinds {
		if !inLevel[kind] {
			continue
		}
		fields, ok := decoded[kind]
		if !ok {
			continue
		}
		for _, block := range aciBlocks[kind] {
			array, isArray := fields[block].([]any)
			if !isArray {
				continue
			}
			for _, item := range array {
				if entity, isObject := item.(map[string]any); isObject {
					out = append(out, entity)
				}
			}
		}
	}
	return out
}

// aciCheckConsistency is ACI-CON-001 and ACI-CON-002, section 17.2: every
// manifest uses one manifest_version and names one publisher.
func aciCheckConsistency(decoded map[string]map[string]any, required []string, fire func(string, string)) {
	for field, code := range map[string]string{"manifest_version": "ACI-CON-001", "publisher": "ACI-CON-002"} {
		values := map[string]bool{}
		for _, kind := range required {
			fields, ok := decoded[kind]
			if !ok {
				continue
			}
			if value, isString := fields[field].(string); isString {
				values[value] = true
			}
		}
		if len(values) > 1 {
			fire(code, aciViolation)
		}
	}
}

// aciCheckDiscovery is ACI-DIS-001, ACI-DIS-002 and ACI-DIS-003, sections 4.1
// and 4.2. Whether a RELATIVE llms.txt target satisfies section 4.1 is a
// question the specification does not answer, so a relative link that names the
// right file is accepted here and the ambiguity is reported in the corpus
// README rather than decided silently in a check.
func aciCheckDiscovery(files map[string]string, level int, fire func(string, string)) {
	llms, ok := files["llms.txt"]
	if !ok {
		fire("ACI-DIS-001", aciViolation)
	} else {
		linked := map[string]bool{}
		for _, target := range aciMarkdownTargets(llms) {
			for _, kind := range aciKinds {
				if path.Base(target) == aciFile[kind] {
					linked[kind] = true
				}
			}
		}
		for _, kind := range aciLevelManifests[level] {
			if !linked[kind] {
				fire("ACI-DIS-001", aciViolation)
			}
		}
	}

	wellKnown, present := files[".well-known/aci"]
	if !present {
		// Section 4.2 makes the discovery file a SHOULD while section 4.4 puts
		// it first in resolution order, and no deployment the specification
		// ships publishes one.
		fire("ACI-DIS-002", aciWarning)
		// Section 4.2 is a SHOULD, so an absent discovery file is not a
		// violation. Section 4.4 puts it first in resolution order, which is
		// why the corpus carries members both ways.
		return
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(wellKnown), &fields); err != nil {
		fire("ACI-DIS-002", aciViolation)
		return
	}
	for _, field := range []string{"aci_version", "last_updated", "manifests"} {
		if _, ok := fields[field]; !ok {
			fire("ACI-DIS-002", aciViolation)
		}
	}
	manifests, isObject := fields["manifests"].(map[string]any)
	if !isObject {
		if _, declared := fields["manifests"]; declared {
			fire("ACI-DIS-003", aciViolation)
		}
		return
	}
	for _, kind := range aciLevelManifests[level] {
		if _, ok := manifests[kind]; !ok {
			fire("ACI-DIS-003", aciViolation)
		}
	}
}

// aciMarkdownTargets extracts every markdown inline link target from llms.txt.
// Relative targets are kept: a parser that drops them reports a deployment as
// having no links at all, which is how the reference validator reads every
// example the specification ships.
func aciMarkdownTargets(text string) []string {
	var targets []string
	for _, line := range strings.Split(text, "\n") {
		rest := line
		for {
			open := strings.Index(rest, "](")
			if open < 0 {
				break
			}
			end := strings.Index(rest[open+2:], ")")
			if end < 0 {
				break
			}
			target := strings.TrimSpace(rest[open+2 : open+2+end])
			if space := strings.IndexAny(target, " \t"); space >= 0 {
				target = target[:space]
			}
			targets = append(targets, target)
			rest = rest[open+2+end+1:]
		}
	}
	return targets
}

// aciCheckBlocks is ACI-BLK-001, sections 6.4, 7.4, 8.4 and 9.4: the content
// blocks each level expects are populated.
func aciCheckBlocks(decoded map[string]map[string]any, level int, fire func(string, string)) {
	expect := map[string][]string{"capability": aciBlocks["capability"]}
	if level >= 2 {
		expect["knowledge"] = aciBlocks["knowledge"]
		expect["trust"] = aciBlocks["trust"]
	}
	if level >= 3 {
		expect["agent"] = aciBlocks["agent"]
	}
	for _, kind := range aciKinds {
		blocks, wanted := expect[kind]
		if !wanted {
			continue
		}
		fields, ok := decoded[kind]
		if !ok {
			continue
		}
		populated := false
		for _, block := range blocks {
			if array, isArray := fields[block].([]any); isArray && len(array) > 0 {
				populated = true
			}
		}
		if !populated {
			fire("ACI-BLK-001", aciWarning)
		}
	}
}

// aciCheckLifecycle is ACI-LIF-001 and ACI-LIF-002, sections 11.1 and 11.3: a
// declared state is one of the four defined, and a superseded entity names its
// replacement.
func aciCheckLifecycle(decoded map[string]map[string]any, required []string, fire func(string, string)) {
	for _, entity := range aciEntities(decoded, required) {
		status, ok := entity["status"].(string)
		if !ok || status == "" {
			continue
		}
		if !aciLifecycle[status] {
			fire("ACI-LIF-001", aciWarning)
		}
		if status == "superseded" {
			if replacement, named := entity["superseded_by"].(string); !named || replacement == "" {
				fire("ACI-LIF-002", aciWarning)
			}
		}
	}
}

// aciCheckAgents is ACI-AGT-001 and ACI-LVL-002, sections 9.4 and 3.3: each
// agent declaration carries a unique id, and at least one declares an
// operational interaction method.
func aciCheckAgents(decoded map[string]map[string]any, fire func(string, string)) {
	fields, ok := decoded["agent"]
	if !ok {
		return
	}
	array, isArray := fields["agents"].([]any)
	if !isArray || len(array) == 0 {
		fire("ACI-LVL-002", aciViolation)
		return
	}
	seen := map[string]bool{}
	operational := false
	for _, item := range array {
		agent, isObject := item.(map[string]any)
		if !isObject {
			fire("ACI-AGT-001", aciViolation)
			continue
		}
		id, named := agent["id"].(string)
		if !named || id == "" {
			fire("ACI-AGT-001", aciViolation)
		} else if seen[id] {
			fire("ACI-AGT-001", aciViolation)
		}
		seen[id] = true
		if iface, declared := agent["interface"].(map[string]any); declared && len(iface) > 0 {
			operational = true
		}
	}
	if !operational {
		fire("ACI-LVL-002", aciViolation)
	}
}
