package corpora

import (
	"fmt"
	"strconv"
	"strings"
)

// The chain-break conditions, the deployment profiles and the per-member basis
// of the AI Agent Action suite.
//
// Everything in this file exists because the reader above checked a
// chain-break member only through the chain hash of its last sidecar line. A
// corpus whose profile-scoped accept member carried a priorHead-null break
// under the profile that forbids one, and whose "pre-break identifier" named no
// chain at all, printed the same clean verdict as the correct corpus, byte for
// byte. These checks recompute what those members claim: which record roots the
// chain, which digest every statement in it therefore carries, which profile a
// verdict holds under, and which lines of the vendored text a rejection rests
// on.

const (
	breakRootedCondition = "aia-c-17"
	prohibitionCondition = "aia-c-18"
	knownHeadCondition   = "aia-c-19"
	nullPriorHeadAllowed = "permitted"
	nullPriorHeadBanned  = "forbidden"
)

// agentActionBasis is what a reject member rests on: lines of the vendored
// specification and a quotation found in them, or a section of the proposed
// text for a rule the specification does not carry.
type agentActionBasis struct {
	Source  string            `json:"source"`
	Lines   string            `json:"lines"`
	Quote   string            `json:"quote"`
	Section string            `json:"section"`
	Against *agentActionBasis `json:"against"`
}

type agentActionProfile struct {
	NullPriorHead string            `json:"nullPriorHead"`
	Cites         *agentActionBasis `json:"cites"`
}

// agentActionContext is what every member check reads beyond the member itself.
type agentActionContext struct {
	specLines    []string
	specSource   string
	proposedText string
	profiles     map[string]agentActionProfile
	genesisIDs   map[string]bool
}

// sidecarRecord is one parsed record line with the chain hash of its bytes.
type sidecarRecord struct {
	fields map[string]any
	hash   string
}

func (r sidecarRecord) isBreak() bool { return r.fields["type"] == "chain_break" }

func (r sidecarRecord) nullPriorHead() bool {
	head, present := r.fields["priorHead"]
	return r.isBreak() && present && head == nil
}

func (r sidecarRecord) isGenesis() bool { return r.fields["previousHash"] == "genesis" }

func (r sidecarRecord) isRoot() bool { return r.isGenesis() || r.nullPriorHead() }

func parseSidecar(lines [][]byte) []sidecarRecord {
	records := make([]sidecarRecord, 0, len(lines))
	for _, line := range lines {
		value, err := decodeJSONNumbers(line)
		fields, _ := value.(map[string]any)
		if err != nil || fields == nil {
			fields = map[string]any{}
		}
		records = append(records, sidecarRecord{fields: fields, hash: sha(line)})
	}
	return records
}

// newAgentActionContext loads the vendored text and the genesis identifiers
// the corpus carries. A genesis identifier is the chain hash of a sidecar's
// first record when that record is the literal genesis, which is what makes a
// declared "pre-break identifier" an identifier of some chain rather than a
// digest of nothing.
func newAgentActionContext(dir string, m *agentActionManifest) *agentActionContext {
	ctx := &agentActionContext{
		proposedText: m.ProposedText,
		profiles:     m.Profiles,
		genesisIDs:   map[string]bool{},
	}
	if len(m.SpecUpstreamCommit) >= 7 {
		ctx.specSource = m.TracksUpstream + "@" + m.SpecUpstreamCommit[:7]
	}
	if body, err := readIn(dir, m.SpecVendored); err == nil {
		ctx.specLines = strings.Split(string(body), "\n")
	}
	for _, v := range m.Vectors {
		if v.Records == "" {
			continue
		}
		body, err := readIn(dir, v.Records)
		if err != nil {
			continue
		}
		first, _, _ := strings.Cut(string(body), "\n")
		if records := parseSidecar([][]byte{[]byte(first)}); records[0].isGenesis() {
			ctx.genesisIDs[records[0].hash] = true
		}
	}
	return ctx
}

// checkProfiles asserts every profile the manifest defines states its rule and
// cites the text it comes from.
func (ctx *agentActionContext) checkProfiles() []string {
	var findings []string
	for _, name := range sortedKeys(ctx.profiles) {
		profile := ctx.profiles[name]
		if profile.NullPriorHead != nullPriorHeadAllowed && profile.NullPriorHead != nullPriorHeadBanned {
			findings = append(findings, fmt.Sprintf(
				"profile %q: nullPriorHead must be permitted or forbidden, and it is %q",
				name, profile.NullPriorHead))
		}
		if profile.Cites == nil {
			findings = append(findings, fmt.Sprintf("profile %q cites no text", name))
			continue
		}
		for _, bad := range ctx.checkSpecCitation(*profile.Cites) {
			findings = append(findings, fmt.Sprintf("profile %q: %s", name, bad))
		}
	}
	return findings
}

// twinKey is the condition a twin is matched under. A member whose verdict is
// scoped to a profile is twinned only with a member scoped to the same one,
// because a rejection under one profile and an acceptance under another are
// not the same boundary seen from both sides.
func twinKey(condition, profile string) string {
	if profile == "" {
		return condition
	}
	return condition + "@" + profile
}

// checkBasis asserts a reject member names the text it rests on and that the
// text still says it. An accept member rests on nothing to reject, so a basis
// on one is a misfiled row.
func (ctx *agentActionContext) checkBasis(v agentActionVector, out *Member) {
	if v.Kind == "accept" {
		if v.Basis != nil {
			out.Findings = append(out.Findings, "an accept member declares a basis, which only a rejection has")
		}
		return
	}
	if v.Basis == nil {
		out.Findings = append(out.Findings,
			"declares no basis, so nothing says which text makes this member rejectable")
		return
	}
	switch v.Basis.Source {
	case ctx.specSource:
		out.Findings = append(out.Findings, ctx.checkSpecCitation(*v.Basis)...)
	case ctx.proposedText:
		if strings.TrimSpace(v.Basis.Section) == "" {
			out.Findings = append(out.Findings, "rests on proposedText and names no section of proposedText")
		}
		if v.Basis.Against != nil {
			for _, bad := range ctx.checkSpecCitation(*v.Basis.Against) {
				out.Findings = append(out.Findings, "its against citation: "+bad)
			}
		}
	default:
		out.Findings = append(out.Findings, fmt.Sprintf(
			"basis source %q is neither the vendored specification (%s) nor proposedText (%s)",
			v.Basis.Source, ctx.specSource, ctx.proposedText))
	}
}

// checkSpecCitation resolves a line range in the vendored text and finds the
// quotation in it once hard wrapping is flattened. A range alone survives an
// upstream edit that moved the text it pointed at; a range and the words it
// is supposed to hold do not.
func (ctx *agentActionContext) checkSpecCitation(c agentActionBasis) []string {
	if c.Source != ctx.specSource {
		return []string{fmt.Sprintf("cites %q, and the vendored specification is %s", c.Source, ctx.specSource)}
	}
	text, bad := ctx.specSpan(c.Lines)
	if bad != "" {
		return []string{bad}
	}
	quote := flatten(c.Quote)
	if quote == "" || !strings.Contains(text, quote) {
		return []string{fmt.Sprintf("the quotation %q does not occur in lines %s of the vendored specification",
			c.Quote, c.Lines)}
	}
	return nil
}

// specSpan returns the flattened text of comma-separated inclusive line ranges.
func (ctx *agentActionContext) specSpan(ranges string) (string, string) {
	var parts []string
	for _, part := range strings.Split(ranges, ",") {
		first, last, isRange := strings.Cut(strings.TrimSpace(part), "-")
		if !isRange {
			last = first
		}
		lo, err1 := strconv.Atoi(first)
		hi, err2 := strconv.Atoi(last)
		if err1 != nil || err2 != nil || lo < 1 || hi < lo {
			return "", fmt.Sprintf("line range %q does not parse", part)
		}
		if hi > len(ctx.specLines) {
			return "", fmt.Sprintf("lines %s fall outside the vendored specification, which has %d lines",
				part, len(ctx.specLines))
		}
		parts = append(parts, strings.Join(ctx.specLines[lo-1:hi], " "))
	}
	return flatten(strings.Join(parts, " ")), ""
}

func flatten(text string) string { return strings.Join(strings.Fields(text), " ") }

// checkChainBreaks runs every chain-shape check a member's declarations call
// for. Dispatch reads the declared conditions and expectations, never the
// identifier, for the reason dispatchDeclaredChecks gives.
func (ctx *agentActionContext) checkChainBreaks(v agentActionVector, statement map[string]any,
	lines [][]byte, out *Member) {
	records := parseSidecar(lines)
	checkBreakMembers(records, out)
	ctx.checkProfile(v, statement, records, out)
	subject := subjectDigest(statement)
	if v.Expected.ChainRoot != nil {
		checkChainRoot(v, subject, records, out)
	}
	conditions := map[string]bool{}
	for _, c := range v.Conditions {
		conditions[c] = true
	}
	if conditions[breakRootedCondition] {
		ctx.checkBreakRooted(v, subject, records, out)
	}
	if conditions[prohibitionCondition] {
		ctx.checkProhibition(v, records, out)
	}
	if conditions[knownHeadCondition] {
		checkKnownHead(v, subject, records, out)
	}
}

// checkBreakMembers asserts every chain_break record carries all three prior*
// members, null or not. #588 requires it so that two producers with identical
// knowledge cannot disagree about whether a member appears, and a corpus break
// missing one is a member with a second fault it does not declare.
func checkBreakMembers(records []sidecarRecord, out *Member) {
	for i, r := range records {
		if !r.isBreak() {
			continue
		}
		for _, member := range []string{"priorHead", "priorSequence", "priorRecordCount"} {
			if _, present := r.fields[member]; !present {
				out.Findings = append(out.Findings, fmt.Sprintf(
					"sidecar record %d is a chain_break that omits %s, which #588 requires even when null",
					i+1, member))
			}
		}
	}
}

func statementHasNullBreak(statement map[string]any) bool {
	predicate, _ := statement["predicate"].(map[string]any)
	chainBreak, isBreak := predicate["chainBreak"].(map[string]any)
	if !isBreak {
		return false
	}
	head, present := chainBreak["priorHead"]
	return present && head == nil
}

// checkProfile asserts a verdict that depends on the deployment choice names
// the choice, and that an accept member does not carry what its own profile
// forbids.
func (ctx *agentActionContext) checkProfile(v agentActionVector, statement map[string]any,
	records []sidecarRecord, out *Member) {
	hasNull := statementHasNullBreak(statement)
	for _, r := range records {
		hasNull = hasNull || r.nullPriorHead()
	}
	if v.Profile == "" {
		if hasNull {
			out.Findings = append(out.Findings,
				"carries a chain_break with priorHead null and declares no profile, so its verdict "+
					"depends on a deployment choice it does not name")
		}
		return
	}
	profile, defined := ctx.profiles[v.Profile]
	if !defined {
		out.Findings = append(out.Findings, fmt.Sprintf("profile %q is not defined in the manifest", v.Profile))
		return
	}
	if v.Kind == "accept" && hasNull && profile.NullPriorHead == nullPriorHeadBanned {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"an accept member under profile %q carries a chain_break with priorHead null, which that "+
				"profile forbids", v.Profile))
	}
}

func subjectDigest(statement map[string]any) string {
	subjects, _ := statement["subject"].([]any)
	if len(subjects) == 0 {
		return ""
	}
	subject, _ := subjects[0].(map[string]any)
	digest, _ := subject["digest"].(map[string]any)
	value, _ := digest["sha256"].(string)
	return value
}

// checkChainRoot asserts the declared root is the first sidecar record, that
// the record is one #588 lets root a chain, and that an accept member carries
// it as its subject digest.
func checkChainRoot(v agentActionVector, subject string, records []sidecarRecord, out *Member) {
	if len(records) == 0 {
		out.Findings = append(out.Findings, "declares a chainRoot with no record sidecar to recompute it from")
		return
	}
	if !records[0].isRoot() {
		out.Findings = append(out.Findings,
			"the first sidecar record is not a root: neither a genesis record nor a chain_break with "+
				"priorHead null")
	}
	if records[0].hash != *v.Expected.ChainRoot {
		out.Findings = append(out.Findings, "chainRoot does not recompute from the first sidecar record")
	}
	if v.Kind == "accept" && subject != *v.Expected.ChainRoot {
		out.Findings = append(out.Findings, "an accept member's subject digest is not its chain root")
	}
}

// checkBreakRooted: a segment rooted at a priorHead-null break is identified by
// the break's own chain hash, and a reject member claims instead the genesis
// identifier of a chain the corpus actually carries.
func (ctx *agentActionContext) checkBreakRooted(v agentActionVector, subject string,
	records []sidecarRecord, out *Member) {
	if len(records) == 0 || !records[0].nullPriorHead() {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"cites %s and its segment is not rooted at a chain_break with priorHead null", breakRootedCondition))
		return
	}
	if v.Kind != "reject" {
		return
	}
	claimed := v.Expected.PreBreakIdentifier
	if claimed == nil {
		out.Findings = append(out.Findings, "declares no preBreakIdentifier, so nothing says what it claims")
		return
	}
	if subject != *claimed {
		out.Findings = append(out.Findings, "its subject digest is not the declared preBreakIdentifier")
	}
	if *claimed == records[0].hash {
		out.Findings = append(out.Findings,
			"preBreakIdentifier is the segment's own root, so the member carries the digest it should "+
				"and nothing is being caught")
	}
	for _, r := range records {
		if r.hash == *claimed {
			out.Findings = append(out.Findings, "preBreakIdentifier is the chain hash of a record inside the segment")
			break
		}
	}
	if !ctx.genesisIDs[*claimed] {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"preBreakIdentifier %s is not the genesis identifier of any chain this corpus carries", short(*claimed)))
	}
}

// checkProhibition: the prohibition condition is judged under a profile that
// forbids priorHead null, and its reject member carries such a break.
func (ctx *agentActionContext) checkProhibition(v agentActionVector, records []sidecarRecord, out *Member) {
	if profile, ok := ctx.profiles[v.Profile]; !ok || profile.NullPriorHead != nullPriorHeadBanned {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"cites %s under profile %q, which does not forbid priorHead null", prohibitionCondition, v.Profile))
	}
	if v.Kind != "reject" {
		return
	}
	for _, r := range records {
		if r.nullPriorHead() {
			return
		}
	}
	out.Findings = append(out.Findings,
		"is the rejection a forbidding profile owes, and its sidecar carries no chain_break with priorHead null")
}

// checkKnownHead: a break whose prior head is known links to the record before
// it and does not root a chain, so a reject member claiming it did carries the
// break's own chain hash.
func checkKnownHead(v agentActionVector, subject string, records []sidecarRecord, out *Member) {
	if len(records) == 0 || !records[0].isGenesis() {
		out.Findings = append(out.Findings, fmt.Sprintf(
			"cites %s and its chain does not start at a genesis record", knownHeadCondition))
		return
	}
	link := -1
	for i := 1; i < len(records); i++ {
		head, _ := records[i].fields["priorHead"].(string)
		if records[i].isBreak() && head == records[i-1].hash {
			link = i
			break
		}
	}
	if link < 0 {
		out.Findings = append(out.Findings,
			"carries no chain_break whose priorHead is the chain hash of the record before it")
		return
	}
	if v.Kind == "reject" && subject != records[link].hash {
		out.Findings = append(out.Findings, "its subject digest does not carry the chain hash of the break it re-roots at")
	}
}
