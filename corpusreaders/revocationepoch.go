package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

func init() { register(revocationEpoch{}) }

// revocationEpoch judges corpora/vectors-revocation-epoch/. Each member is one
// record: the grant a permit rests on, the trusted revocation-list issuers, the
// freshness limit, every signed revocation list, the permit and the effect with
// the list each was checked against, and the witness log that orders them. The
// reader recomputes every digest it relies on and applies the checks the Python
// reader applies, in the same order, naming the first one that fails:
//
//  1. contract_id_missing; 2. contract_id_unknown; 3. malformed_record;
//  4. srl_issuer_untrusted: a list from a key the record does not trust;
//  5. grant_binding_mismatch: the permit or effect names another grant, or the
//     effect another permit;
//  6. srl_epoch_not_monotonic: one epoch with two contents, a later epoch issued
//     no later, or an epoch going back in the witness log;
//  7. srl_absent: the permit or effect carries no srl member;
//  8. srl_digest_mismatch: the named epoch and digest match no list;
//  9. srl_stale_at_permit: the permit's list was not in force at issue;
//  10. revoked_at_permit: the permit's list covers the work;
//  11. effect_after_revocation: a list witnessed before an effect that was not
//     refused covers the work;
//  12. revocation_order_ambiguous: the witness log does not order the work;
//  13. effect_epoch_behind: the effect names an older list than one witnessed
//     before it;
//  14. srl_stale_at_effect: the effect's list was not in force where it landed.
type revocationEpoch struct{}

const reContractID = "https://probityai.github.io/agent-evidence-vectors/contract/revocation-epoch/v1"

func (revocationEpoch) Suite() string { return "revocation-epoch/v1" }

func (revocationEpoch) Judge(dir string, raw []byte) (*Result, error) {
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
		member.Findings = reJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func reJudgeMember(caseDir string, v drVector) []string {
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
		return append(findings, "record.json is not a JSON object")
	}
	if got := reDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

type reEntry struct {
	seq          int64
	kind, digest string
	at           time.Time
}

type reList struct {
	epoch   int64
	issued  time.Time
	issuer  string
	revoked []string
}

type reRef struct {
	present bool
	epoch   int64
	digest  string
}

type reView struct {
	trusted     []string
	fresh       time.Duration
	grantDigest string
	holder      string
	parent      string
	lists       map[string]reList
	witness     []reEntry
	permitID    string
	permitGrant string
	authority   string
	permitAt    time.Time
	permitRef   reRef
	permitSeq   int64
	effectPerm  string
	effectGrant string
	effectAt    time.Time
	outcome     string
	effectRef   reRef
	effectSeq   int64
	covered     map[string]bool
}

// reDecide mirrors the Python reader: the contract checks, the structural
// check, then the eleven revocation checks in order.
func reDecide(record map[string]any) scDecision {
	id, present := record["contractId"]
	if !present {
		return scDecision{"deny", "contract_id_missing"}
	}
	if id != reContractID {
		return scDecision{"deny", "contract_id_unknown"}
	}
	v, ok := reParse(record)
	if !ok {
		return scDecision{"deny", "malformed_record"}
	}
	checks := []struct {
		reason string
		fails  func(*reView) bool
	}{
		{"srl_issuer_untrusted", reUntrusted},
		{"grant_binding_mismatch", reBinding},
		{"srl_epoch_not_monotonic", reNotMonotonic},
		{"srl_absent", func(v *reView) bool { return !v.permitRef.present || !v.effectRef.present }},
		{"srl_digest_mismatch", reDigestMismatch},
		{"srl_stale_at_permit", reStaleAtPermit},
		{"revoked_at_permit", func(v *reView) bool { return v.covers(v.lists[v.permitRef.digest]) }},
		{"effect_after_revocation", func(v *reView) bool { return v.outcome != "not-applied" && v.revokedBeforeEffect() }},
		{"revocation_order_ambiguous", reAmbiguous},
		{"effect_epoch_behind", reEpochBehind},
		{"srl_stale_at_effect", func(v *reView) bool {
			return v.tooOld(v.lists[v.effectRef.digest], v.effectAt, v.effectSeq)
		}},
	}
	for _, check := range checks {
		if check.fails(&v) {
			return scDecision{"deny", check.reason}
		}
	}
	if v.outcome == "not-applied" && v.revokedBeforeEffect() {
		return scDecision{"allow", "revocation_enforced_at_effect"}
	}
	return scDecision{"allow", "not_revoked"}
}

func reInt(value any) (int64, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// reHasFraction reports a number anywhere in the record that is not an integer.
func reHasFraction(value any) bool {
	switch v := value.(type) {
	case json.Number:
		_, ok := reInt(v)
		return !ok
	case map[string]any:
		for _, item := range v {
			if reHasFraction(item) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, reHasFraction)
	}
	return false
}

func reDigest(value any) (string, bool) {
	body, err := pythonCompactJSONOpts(value, pyEncodeOpts{})
	if err != nil {
		return "", false
	}
	return "sha256:" + sha(body), true
}

func reTexts(value any, empty bool) ([]string, bool) {
	list, ok := value.([]any)
	if !ok || (!empty && len(list) == 0) {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func reHasTexts(m map[string]any, names ...string) bool {
	for _, name := range names {
		if _, ok := m[name].(string); !ok {
			return false
		}
	}
	return true
}

func reRefOf(m map[string]any) (reRef, bool) {
	raw, present := m["srl"]
	if !present {
		return reRef{}, true
	}
	ref, isMap := raw.(map[string]any)
	if !isMap {
		return reRef{}, false
	}
	epoch, ok := reInt(ref["epoch"])
	digest, isText := ref["digest"].(string)
	if !ok || epoch < 0 || !isText {
		return reRef{}, false
	}
	return reRef{present: true, epoch: epoch, digest: digest}, true
}

func reParse(record map[string]any) (reView, bool) {
	var v reView
	if reHasFraction(record) {
		return v, false
	}
	var ok bool
	if v.trusted, ok = reTexts(record["trustedSrlIssuers"], false); !ok {
		return v, false
	}
	fresh, ok := reInt(record["freshnessSeconds"])
	if !ok || fresh < 1 {
		return v, false
	}
	v.fresh = time.Duration(fresh) * time.Second
	if !reParseLists(record["srls"], &v) || !reParseGrant(record["grant"], &v) {
		return v, false
	}
	permit, isMap := record["permit"].(map[string]any)
	if !isMap || !reParsePermit(permit, &v) {
		return v, false
	}
	effect, isMap := record["effect"].(map[string]any)
	if !isMap || !reParseEffect(effect, &v) {
		return v, false
	}
	if !reParseWitness(record["witness"], &v) {
		return v, false
	}
	permitDigest, ok1 := reDigest(permit)
	effectDigest, ok2 := reDigest(effect)
	if !ok1 || !ok2 {
		return v, false
	}
	v.permitSeq = v.seq("permit", permitDigest)
	v.effectSeq = v.seq("effect", effectDigest)
	v.covered = map[string]bool{v.grantDigest: true, v.holder: true, v.authority: true}
	if v.parent != "" {
		v.covered[v.parent] = true
	}
	return v, true
}

func reParseLists(raw any, v *reView) bool {
	list, isList := raw.([]any)
	if !isList {
		return false
	}
	v.lists = map[string]reList{}
	for _, item := range list {
		m, isMap := item.(map[string]any)
		if !isMap || !reHasTexts(m, "issuedAt", "issuerKeyId") {
			return false
		}
		epoch, ok := reInt(m["epoch"])
		revoked, isTexts := reTexts(m["revoked"], true)
		issued, err := time.Parse(time.RFC3339, m["issuedAt"].(string))
		digest, digested := reDigest(m)
		if !ok || epoch < 0 || !isTexts || err != nil || !digested {
			return false
		}
		v.lists[digest] = reList{epoch: epoch, issued: issued, issuer: m["issuerKeyId"].(string), revoked: revoked}
	}
	return true
}

func reParseGrant(raw any, v *reView) bool {
	grant, isMap := raw.(map[string]any)
	if !isMap || !reHasTexts(grant, "grantId", "issuer", "holder") {
		return false
	}
	switch parent := grant["parentDigest"].(type) {
	case nil:
	case string:
		v.parent = parent
	default:
		return false
	}
	v.holder = grant["holder"].(string)
	digest, ok := reDigest(grant)
	v.grantDigest = digest
	return ok
}

func reParsePermit(m map[string]any, v *reView) bool {
	if !reHasTexts(m, "permitId", "grantDigest", "authorityKeyId", "issuedAt") {
		return false
	}
	var ok bool
	if v.permitRef, ok = reRefOf(m); !ok {
		return false
	}
	at, err := time.Parse(time.RFC3339, m["issuedAt"].(string))
	v.permitID, v.permitGrant, v.authority, v.permitAt = m["permitId"].(string),
		m["grantDigest"].(string), m["authorityKeyId"].(string), at
	return err == nil
}

func reParseEffect(m map[string]any, v *reView) bool {
	if !reHasTexts(m, "effectId", "permitId", "grantDigest", "observerKeyId", "observedAt", "outcome") {
		return false
	}
	v.outcome = m["outcome"].(string)
	if !slices.Contains([]string{"applied", "not-applied", "uncertain"}, v.outcome) {
		return false
	}
	var ok bool
	if v.effectRef, ok = reRefOf(m); !ok {
		return false
	}
	at, err := time.Parse(time.RFC3339, m["observedAt"].(string))
	v.effectPerm, v.effectGrant, v.effectAt = m["permitId"].(string), m["grantDigest"].(string), at
	return err == nil
}

func reParseWitness(raw any, v *reView) bool {
	list, isList := raw.([]any)
	if !isList {
		return false
	}
	kinds := []string{"grant", "permit", "effect", "srl", "approval"}
	for _, item := range list {
		m, isMap := item.(map[string]any)
		if !isMap || !reHasTexts(m, "kind", "digest", "at") {
			return false
		}
		seq, ok := reInt(m["seq"])
		at, err := time.Parse(time.RFC3339, m["at"].(string))
		if !ok || err != nil || !slices.Contains(kinds, m["kind"].(string)) {
			return false
		}
		if n := len(v.witness); n > 0 && (seq <= v.witness[n-1].seq || at.Before(v.witness[n-1].at)) {
			return false
		}
		if len(v.witness) == 0 && seq < 1 {
			return false
		}
		v.witness = append(v.witness, reEntry{seq: seq, kind: m["kind"].(string), digest: m["digest"].(string), at: at})
	}
	return true
}

// seq is the first witness sequence number of kind and digest, or 0.
func (v *reView) seq(kind, digest string) int64 {
	for _, e := range v.witness {
		if e.kind == kind && e.digest == digest {
			return e.seq
		}
	}
	return 0
}

func (v *reView) at(seq int64) (time.Time, bool) {
	for _, e := range v.witness {
		if e.seq == seq && seq != 0 {
			return e.at, true
		}
	}
	return time.Time{}, false
}

// witnessedLists is every witnessed list the record carries, in witness order.
func (v *reView) witnessedLists() []reEntry {
	var out []reEntry
	for _, e := range v.witness {
		if _, known := v.lists[e.digest]; e.kind == "srl" && known {
			out = append(out, e)
		}
	}
	return out
}

func (v *reView) before(seq int64) []reList {
	var out []reList
	if seq == 0 {
		return out
	}
	for _, e := range v.witnessedLists() {
		if e.seq < seq {
			out = append(out, v.lists[e.digest])
		}
	}
	return out
}

func (v *reView) covers(l reList) bool {
	return slices.ContainsFunc(l.revoked, func(entry string) bool { return v.covered[entry] })
}

func (v *reView) revokedBeforeEffect() bool {
	return slices.ContainsFunc(v.before(v.effectSeq), v.covers)
}

func (v *reView) named(ref reRef) bool {
	l, known := v.lists[ref.digest]
	return known && l.epoch == ref.epoch
}

func (v *reView) tooOld(l reList, claimed time.Time, seq int64) bool {
	moment := claimed
	if witnessed, ok := v.at(seq); ok && witnessed.After(moment) {
		moment = witnessed
	}
	age := moment.Sub(l.issued)
	return age < 0 || age >= v.fresh
}

func reUntrusted(v *reView) bool {
	for _, l := range v.lists {
		if !slices.Contains(v.trusted, l.issuer) {
			return true
		}
	}
	return false
}

func reBinding(v *reView) bool {
	return v.permitGrant != v.grantDigest || v.effectGrant != v.grantDigest || v.effectPerm != v.permitID
}

func reNotMonotonic(v *reView) bool {
	epochs := map[int64]bool{}
	ordered := make([]reList, 0, len(v.lists))
	for _, l := range v.lists {
		if epochs[l.epoch] {
			return true
		}
		epochs[l.epoch] = true
		ordered = append(ordered, l)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].epoch < ordered[j].epoch })
	for i := 1; i < len(ordered); i++ {
		if !ordered[i].issued.After(ordered[i-1].issued) {
			return true
		}
	}
	seen := v.witnessedLists()
	for i := 1; i < len(seen); i++ {
		if v.lists[seen[i].digest].epoch < v.lists[seen[i-1].digest].epoch {
			return true
		}
	}
	return false
}

func reDigestMismatch(v *reView) bool {
	return !v.named(v.permitRef) || !v.named(v.effectRef)
}

func reStaleAtPermit(v *reView) bool {
	l := v.lists[v.permitRef.digest]
	if v.tooOld(l, v.permitAt, v.permitSeq) {
		return true
	}
	if v.permitSeq == 0 {
		return false
	}
	if listed := v.seq("srl", v.permitRef.digest); listed != 0 && listed > v.permitSeq {
		return true
	}
	return slices.ContainsFunc(v.before(v.permitSeq), func(o reList) bool { return o.epoch > l.epoch })
}

func reAmbiguous(v *reView) bool {
	for i, e := range v.witness {
		if e.seq != int64(i+1) {
			return true
		}
	}
	if v.permitSeq == 0 || v.effectSeq == 0 || v.effectSeq < v.permitSeq {
		return true
	}
	for digest := range v.lists {
		if v.seq("srl", digest) == 0 {
			return true
		}
	}
	for _, e := range v.witness {
		if _, known := v.lists[e.digest]; e.kind == "srl" && !known {
			return true
		}
	}
	own := v.seq("srl", v.effectRef.digest)
	return own == 0 || own > v.effectSeq
}

func reEpochBehind(v *reView) bool {
	return slices.ContainsFunc(v.before(v.effectSeq), func(l reList) bool { return l.epoch > v.effectRef.epoch })
}
