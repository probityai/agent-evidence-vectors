package corpusreaders

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

func init() { register(grantUse{}) }

// grantUse judges corpora/vectors-grant-use/. Each member is one record of an
// effect judged as a use of a grant: the grant chain from root to leaf, the
// trusted root, authority and worker keys, the permits minted on the leaf grant,
// the other effects recorded against them, the effect being judged with the call
// it applied, and the witness log. The reader recomputes every digest it relies
// on and applies the checks the Python reader applies, in the same order,
// naming the first one that fails:
//
//  1. contract_id_missing, 2. contract_id_unknown, 3. malformed_record;
//  4. grant_chain_broken: the root has no parent and a trusted issuer, and each
//     grant sits one level down, names its parent's recomputed digest, and was
//     issued by its parent's holder;
//  5. grant_widened: no grant admits more than its parent;
//  6. grant_not_in_force: the effect was observed while every grant was in force;
//  7. tool_not_granted; 8. call_args_unbound; 9. argument_outside_constraint;
//  10. permit_missing; 11. uses_exhausted; 12. permit_not_for_grant;
//  13. permit_not_from_holder; 14. permit_authority_unknown;
//  15. authority_key_in_worker; 16. permit_not_in_force; 17. permit_reused;
//  18. permit_identity_mismatch; 19. effect_args_mismatch;
//  20. effect_grant_unlinked; 21. effect_unwitnessed.
type grantUse struct{}

const guContractID = "https://probityai.github.io/agent-evidence-vectors/contract/grant-use/v1"

// guSafe is the largest integer every JSON reader holds exactly.
const guSafe = 1<<53 - 1

var guInstant = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

func (grantUse) Suite() string { return "grant-use/v1" }

func (grantUse) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v drVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = guJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func guJudgeMember(caseDir string, v drVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "record.json")
	if err != nil {
		return append(findings, "record.json cannot be read: "+err.Error())
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, "record.json does not parse: "+err.Error())
	}
	record, isMap := value.(map[string]any)
	if !isMap {
		return append(findings, "record.json is not an object")
	}
	if got := guDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type guObj = map[string]any

// guDecide mirrors the Python reader check by check.
func guDecide(record guObj) scDecision {
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != guContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	if guMalformed(record) {
		return scDecision{"deny", "malformed_record"}
	}
	r := guRecord{record}
	steps := []struct {
		reason string
		fails  func() bool
	}{
		{"grant_chain_broken", r.chainBroken},
		{"grant_widened", r.widened},
		{"grant_not_in_force", r.grantNotInForce},
		{"tool_not_granted", func() bool { return !slices.Contains(guTexts(r.leaf()["tools"]), r.callTool()) }},
		{"call_args_unbound", func() bool { return guDigest(r.callArgs()) != r.effect()["argsDigest"] }},
		{"argument_outside_constraint", r.outsideConstraint},
		{"permit_missing", func() bool { return r.permit() == nil }},
		{"uses_exhausted", r.usesExhausted},
		{"permit_not_for_grant", func() bool { return r.permit()["grantDigest"] != guDigest(r.leaf()) }},
		{"permit_not_from_holder", func() bool { return r.permit()["authorityKeyId"] != r.leaf()["holder"] }},
		{"permit_authority_unknown", func() bool {
			return !slices.Contains(guTexts(record["authorityKeys"]), r.authority())
		}},
		{"authority_key_in_worker", func() bool { return slices.Contains(guTexts(record["workerKeys"]), r.authority()) }},
		{"permit_not_in_force", r.permitNotInForce},
		{"permit_reused", r.reused},
		{"permit_identity_mismatch", r.identityMismatch},
		{"effect_args_mismatch", func() bool { return r.effect()["argsDigest"] != r.permit()["argsDigest"] }},
		{"effect_grant_unlinked", func() bool { return r.effect()["grantDigest"] != r.permit()["grantDigest"] }},
		{"effect_unwitnessed", r.unwitnessed},
	}
	for _, step := range steps {
		if step.fails() {
			return scDecision{"deny", step.reason}
		}
	}
	return scDecision{"allow", "authorized_use"}
}

// guDigest is "sha256:" and the hex SHA-256 of json.dumps(value, sort_keys=True,
// separators=(",", ":"), ensure_ascii=False), which is RFC 8785 for strings and
// integers. A value the encoder refuses digests to the empty string, which no
// recorded digest equals.
func guDigest(value any) string {
	data, err := pythonCompactJSONOpts(value, pyEncodeOpts{EnsureASCII: false})
	if err != nil {
		return ""
	}
	return "sha256:" + sha(data)
}

func guTime(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !guInstant.MatchString(text) {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", text)
	return parsed, err == nil
}

func guMust(value any) time.Time {
	parsed, _ := guTime(value)
	return parsed
}

// guInt reads a safe JSON integer. A boolean, a float token or a number past
// the safe bound is not one.
func guInt(value any) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	parsed, ok := new(big.Int).SetString(n.String(), 10)
	if !ok || !parsed.IsInt64() {
		return 0, false
	}
	i := parsed.Int64()
	return i, i >= -guSafe && i <= guSafe
}

func guTexts(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func guIsTexts(value any, nonempty bool) bool {
	list, ok := value.([]any)
	if !ok || (nonempty && len(list) == 0) {
		return false
	}
	seen := map[string]bool{}
	for _, item := range list {
		text, ok := item.(string)
		if !ok || seen[text] {
			return false
		}
		seen[text] = true
	}
	return true
}

func guHasTexts(value any, names ...string) bool {
	m, ok := value.(guObj)
	if !ok {
		return false
	}
	for _, name := range names {
		if _, ok := m[name].(string); !ok {
			return false
		}
	}
	return true
}

func guHasFloat(value any) bool {
	switch v := value.(type) {
	case json.Number:
		return strings.ContainsAny(v.String(), ".eE")
	case guObj:
		for _, item := range v {
			if guHasFloat(item) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, guHasFloat)
	}
	return false
}

// guScalarKey names a constraint value by type and value, so 1 and "1" differ.
func guScalarKey(value any) (string, bool) {
	if text, ok := value.(string); ok {
		return "s:" + text, true
	}
	if i, ok := guInt(value); ok {
		return fmt.Sprintf("n:%d", i), true
	}
	return "", false
}

func guConstraintOK(value any) bool {
	c, ok := value.(guObj)
	if !ok || len(c) != 1 {
		return false
	}
	for kind, bound := range c {
		switch kind {
		case "exact":
			_, ok := guScalarKey(bound)
			return ok
		case "oneOf":
			list, ok := bound.([]any)
			if !ok || len(list) == 0 {
				return false
			}
			seen := map[string]bool{}
			for _, item := range list {
				key, ok := guScalarKey(item)
				if !ok || seen[key] {
					return false
				}
				seen[key] = true
			}
			return true
		case "range":
			list, ok := bound.([]any)
			if !ok || len(list) != 2 {
				return false
			}
			lo, okLo := guInt(list[0])
			hi, okHi := guInt(list[1])
			return okLo && okHi && lo <= hi
		case "prefix":
			_, ok := bound.(string)
			return ok
		}
	}
	return false
}

func guGrantOK(value any) bool {
	if !guHasTexts(value, "grantId", "issuer", "holder", "notBefore", "expiresAt") {
		return false
	}
	g := value.(guObj)
	parent, present := g["parentDigest"]
	if _, isText := parent.(string); !present || (parent != nil && !isText) {
		return false
	}
	if !guIsTexts(g["tools"], true) || !guIsTexts(g["hopKinds"], false) || !guIsTexts(g["caveats"], false) {
		return false
	}
	counts := map[string]int64{}
	for _, name := range []string{"maxUses", "depth", "maxDepth"} {
		n, ok := guInt(g[name])
		if !ok || n < 0 {
			return false
		}
		counts[name] = n
	}
	if counts["depth"] > counts["maxDepth"] {
		return false
	}
	if _, ok := g["closedWorld"].(bool); !ok {
		return false
	}
	constraints, ok := g["constraints"].(guObj)
	if !ok {
		return false
	}
	tools := guTexts(g["tools"])
	for tool, named := range constraints {
		args, ok := named.(guObj)
		if !ok || !slices.Contains(tools, tool) {
			return false
		}
		for _, c := range args {
			if !guConstraintOK(c) {
				return false
			}
		}
	}
	return true
}

func guPermitOK(value any) bool {
	if !guHasTexts(value, "permitId", "grantDigest", "workflowId", "runId", "callId", "tool",
		"argsDigest", "issuedAt", "expiresAt", "authorityKeyId") {
		return false
	}
	p := value.(guObj)
	if ids, present := p["approvalIds"]; present && !guIsTexts(ids, false) {
		return false
	}
	if srl, present := p["srl"]; present {
		if _, ok := srl.(guObj); !ok {
			return false
		}
	}
	return true
}

func guEffectOK(value any) bool {
	if !guHasTexts(value, "effectId", "permitId", "grantDigest", "workflowId", "runId", "callId",
		"argsDigest", "observedAt", "observerKeyId", "outcome") {
		return false
	}
	e := value.(guObj)
	if !slices.Contains([]string{"applied", "not-applied", "uncertain"}, e["outcome"].(string)) {
		return false
	}
	if srl, present := e["srl"]; present {
		if _, ok := srl.(guObj); !ok {
			return false
		}
	}
	return true
}

func guEntryOK(value any) bool {
	if !guHasTexts(value, "kind", "digest", "at") {
		return false
	}
	w := value.(guObj)
	if _, ok := guInt(w["seq"]); !ok {
		return false
	}
	return slices.Contains([]string{"grant", "permit", "effect", "srl", "approval"}, w["kind"].(string))
}

func guAll(value any, ok func(any) bool) bool {
	list, isList := value.([]any)
	return isList && !slices.ContainsFunc(list, func(item any) bool { return !ok(item) })
}

func guShape(record guObj) bool {
	if _, ok := record["decisionTime"].(string); !ok {
		return false
	}
	if !guIsTexts(record["roots"], true) || !guIsTexts(record["authorityKeys"], true) ||
		!guIsTexts(record["workerKeys"], false) {
		return false
	}
	grants, _ := record["grants"].([]any)
	if len(grants) == 0 || !guAll(record["grants"], guGrantOK) || !guAll(record["permits"], guPermitOK) ||
		!guAll(record["effects"], guEffectOK) || !guEffectOK(record["effect"]) ||
		!guAll(record["witness"], guEntryOK) {
		return false
	}
	call, ok := record["call"].(guObj)
	if !ok {
		return false
	}
	if _, ok := call["tool"].(string); !ok {
		return false
	}
	_, ok = call["args"].(guObj)
	return ok
}

func guMalformed(record guObj) bool {
	if guHasFloat(record) || !guShape(record) {
		return true
	}
	decided, ok := guTime(record["decisionTime"])
	if !ok {
		return true
	}
	for _, item := range record["grants"].([]any) {
		g := item.(guObj)
		from, okFrom := guTime(g["notBefore"])
		until, okUntil := guTime(g["expiresAt"])
		if !okFrom || !okUntil || !from.Before(until) {
			return true
		}
	}
	var evidence []any
	for _, item := range record["permits"].([]any) {
		evidence = append(evidence, item.(guObj)["issuedAt"])
		if _, ok := guTime(item.(guObj)["expiresAt"]); !ok {
			return true
		}
	}
	for _, item := range append(slices.Clone(record["effects"].([]any)), record["effect"]) {
		evidence = append(evidence, item.(guObj)["observedAt"])
	}
	for _, item := range record["witness"].([]any) {
		evidence = append(evidence, item.(guObj)["at"])
	}
	for _, instant := range evidence {
		parsed, ok := guTime(instant)
		if !ok || parsed.After(decided) {
			return true
		}
	}
	return guDuplicates(record["permits"], "permitId") || guDuplicates(record["effects"], "effectId")
}

func guDuplicates(list any, key string) bool {
	seen := map[string]bool{}
	for _, item := range list.([]any) {
		id := item.(guObj)[key].(string)
		if seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

// guRecord reads a record that has passed guMalformed.
type guRecord struct{ m guObj }

func (r guRecord) grants() []guObj {
	var out []guObj
	for _, item := range r.m["grants"].([]any) {
		out = append(out, item.(guObj))
	}
	return out
}

func (r guRecord) list(name string) []guObj {
	var out []guObj
	for _, item := range r.m[name].([]any) {
		out = append(out, item.(guObj))
	}
	return out
}

func (r guRecord) leaf() guObj      { g := r.grants(); return g[len(g)-1] }
func (r guRecord) effect() guObj    { return r.m["effect"].(guObj) }
func (r guRecord) call() guObj      { return r.m["call"].(guObj) }
func (r guRecord) callTool() string { return r.call()["tool"].(string) }
func (r guRecord) callArgs() guObj  { return r.call()["args"].(guObj) }
func (r guRecord) authority() string {
	return r.permit()["authorityKeyId"].(string)
}

func (r guRecord) permit() guObj {
	for _, p := range r.list("permits") {
		if p["permitId"] == r.effect()["permitId"] {
			return p
		}
	}
	return nil
}

func (r guRecord) chainBroken() bool {
	grants := r.grants()
	if grants[0]["parentDigest"] != nil || !slices.Contains(guTexts(r.m["roots"]), grants[0]["issuer"].(string)) {
		return true
	}
	for i, g := range grants {
		if depth, _ := guInt(g["depth"]); depth != int64(i) {
			return true
		}
		if i > 0 && (g["parentDigest"] != guDigest(grants[i-1]) || g["issuer"] != grants[i-1]["holder"]) {
			return true
		}
	}
	return false
}

// guSame is JSON value equality between an argument and a constraint value.
func guSame(a, b any) bool {
	if sa, ok := a.(string); ok {
		sb, ok := b.(string)
		return ok && sa == sb
	}
	ia, okA := guInt(a)
	ib, okB := guInt(b)
	return okA && okB && ia == ib
}

func guOnly(c guObj) (string, any) {
	for kind, bound := range c {
		return kind, bound
	}
	return "", nil
}

func guAdmits(c guObj, value any) bool {
	kind, bound := guOnly(c)
	switch kind {
	case "exact":
		return guSame(value, bound)
	case "oneOf":
		return slices.ContainsFunc(bound.([]any), func(v any) bool { return guSame(value, v) })
	case "range":
		n, ok := guInt(value)
		lo, _ := guInt(bound.([]any)[0])
		hi, _ := guInt(bound.([]any)[1])
		return ok && lo <= n && n <= hi
	}
	text, ok := value.(string)
	return ok && strings.HasPrefix(text, bound.(string))
}

// guNarrows reports whether every value child admits, parent admits.
func guNarrows(child, parent guObj) bool {
	kind, bound := guOnly(child)
	switch kind {
	case "exact":
		return guAdmits(parent, bound)
	case "oneOf":
		return !slices.ContainsFunc(bound.([]any), func(v any) bool { return !guAdmits(parent, v) })
	case "range":
		lo, _ := guInt(bound.([]any)[0])
		hi, _ := guInt(bound.([]any)[1])
		pkind, pbound := guOnly(parent)
		switch pkind {
		case "range":
			plo, _ := guInt(pbound.([]any)[0])
			phi, _ := guInt(pbound.([]any)[1])
			return plo <= lo && hi <= phi
		case "exact", "oneOf":
			values := []any{pbound}
			if pkind == "oneOf" {
				values = pbound.([]any)
			}
			members := map[int64]bool{}
			for _, v := range values {
				if n, ok := guInt(v); ok {
					members[n] = true
				}
			}
			if hi-lo+1 > int64(len(members)) {
				return false
			}
			for n := lo; n <= hi; n++ {
				if !members[n] {
					return false
				}
			}
			return true
		}
		return false
	}
	pkind, pbound := guOnly(parent)
	return pkind == "prefix" && strings.HasPrefix(bound.(string), pbound.(string))
}

func guArgs(g guObj, tool string) guObj {
	named, _ := g["constraints"].(guObj)[tool].(guObj)
	if named == nil {
		return guObj{}
	}
	return named
}

func guToolWidened(child, parent guObj, tool string) bool {
	mine, theirs := guArgs(child, tool), guArgs(parent, tool)
	for arg, c := range theirs {
		own, present := mine[arg]
		if !present || !guNarrows(own.(guObj), c.(guObj)) {
			return true
		}
	}
	if parent["closedWorld"].(bool) {
		for arg := range mine {
			if _, named := theirs[arg]; !named {
				return true
			}
		}
	}
	return false
}

func guSubset(small, large any) bool {
	wide := guTexts(large)
	return !slices.ContainsFunc(guTexts(small), func(s string) bool { return !slices.Contains(wide, s) })
}

func guWidenedPair(child, parent guObj) bool {
	if !guSubset(child["tools"], parent["tools"]) {
		return true
	}
	if parent["closedWorld"].(bool) && !child["closedWorld"].(bool) {
		return true
	}
	for _, tool := range guTexts(child["tools"]) {
		if guToolWidened(child, parent, tool) {
			return true
		}
	}
	n := func(g guObj, name string) int64 { v, _ := guInt(g[name]); return v }
	if n(child, "maxUses") > n(parent, "maxUses") || n(child, "maxDepth") > n(parent, "maxDepth") ||
		n(child, "depth") > n(parent, "maxDepth") {
		return true
	}
	if guMust(child["notBefore"]).Before(guMust(parent["notBefore"])) ||
		guMust(child["expiresAt"]).After(guMust(parent["expiresAt"])) {
		return true
	}
	return !guSubset(child["hopKinds"], parent["hopKinds"]) || !guSubset(parent["caveats"], child["caveats"])
}

func (r guRecord) widened() bool {
	grants := r.grants()
	for i := 1; i < len(grants); i++ {
		if guWidenedPair(grants[i], grants[i-1]) {
			return true
		}
	}
	return false
}

func guInForce(from, until, instant any) bool {
	at := guMust(instant)
	return !at.Before(guMust(from)) && at.Before(guMust(until))
}

func (r guRecord) grantNotInForce() bool {
	return slices.ContainsFunc(r.grants(), func(g guObj) bool {
		return !guInForce(g["notBefore"], g["expiresAt"], r.effect()["observedAt"])
	})
}

func (r guRecord) outsideConstraint() bool {
	named, args := guArgs(r.leaf(), r.callTool()), r.callArgs()
	for arg, c := range named {
		value, present := args[arg]
		if !present || !guAdmits(c.(guObj), value) {
			return true
		}
	}
	if r.leaf()["closedWorld"].(bool) {
		for arg := range args {
			if _, ok := named[arg]; !ok {
				return true
			}
		}
	}
	return false
}

// seq is the witness position of a digest under a kind, or +Inf when the log
// does not hold it.
func (r guRecord) seq(kind string, value string) float64 {
	for _, w := range r.list("witness") {
		if w["kind"] == kind && w["digest"] == value {
			n, _ := guInt(w["seq"])
			return float64(n)
		}
	}
	return math.Inf(1)
}

func (r guRecord) usesExhausted() bool {
	leafDigest := guDigest(r.leaf())
	mine := r.seq("permit", guDigest(r.permit()))
	spent := int64(0)
	for _, p := range r.list("permits") {
		at := r.seq("permit", guDigest(p))
		if p["grantDigest"] == leafDigest && (at <= mine || math.IsInf(at, 1)) {
			spent++
		}
	}
	limit, _ := guInt(r.leaf()["maxUses"])
	return spent > limit
}

func (r guRecord) permitNotInForce() bool {
	p := r.permit()
	if slices.ContainsFunc(r.grants(), func(g guObj) bool {
		return !guInForce(g["notBefore"], g["expiresAt"], p["issuedAt"])
	}) {
		return true
	}
	return !guInForce(p["issuedAt"], p["expiresAt"], r.effect()["observedAt"])
}

func (r guRecord) reused() bool {
	e := r.effect()
	mine := r.seq("effect", guDigest(e))
	return slices.ContainsFunc(r.list("effects"), func(other guObj) bool {
		return other["permitId"] == e["permitId"] && other["effectId"] != e["effectId"] &&
			r.seq("effect", guDigest(other)) < mine
	})
}

func (r guRecord) identityMismatch() bool {
	p, e := r.permit(), r.effect()
	for _, name := range []string{"workflowId", "runId", "callId"} {
		if e[name] != p[name] {
			return true
		}
	}
	return r.callTool() != p["tool"]
}

func (r guRecord) unwitnessed() bool {
	for i, w := range r.list("witness") {
		if n, _ := guInt(w["seq"]); n != int64(i+1) {
			return true
		}
	}
	permitAt := r.seq("permit", guDigest(r.permit()))
	effectAt := r.seq("effect", guDigest(r.effect()))
	return !(permitAt < effectAt && !math.IsInf(effectAt, 1))
}

