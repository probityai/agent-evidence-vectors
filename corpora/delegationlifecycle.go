package corpora

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

func init() { register(delegationLifecycle{}) }

// delegationLifecycle judges vectors-delegation-lifecycle/. A member is one
// question a relying party asks about an AI agent: does this presenter hold this
// delegated authority at the time the relying party observed the presentation?
// The member is a set of signed records (identifier registrations, grants,
// revocations, disputes, resolutions, identifier links, retirements) plus one
// signed presentation, under a policy pinning the payload type, the registry's
// key, the relying party's key and the trusted roots. Every record is a DSSE v1
// envelope signed with Ed25519.
//
// The reader names the first check that fails, in this order:
//
//  1. every record parses as a DSSE envelope over a JSON object of a known type
//     (else no verdict, malformed_record);
//  2. the presentation carries the presenter's signature and the relying
//     party's (signature_invalid:presentation);
//  3. each grant on the presented chain verifies under its issuer's registered
//     key (signature_invalid:grant), links to the grant before it, and the first
//     is issued by a trusted root (chain_broken);
//  4. the registry had not retired or revoked the presenter at observed_at
//     (presenter_inactive), and, for a sub-agent whose registration names a
//     parent, had not retired or revoked that parent or any parent above it
//     (parent_inactive); a parent's recovery or succession does not carry its
//     sub-agents to the successor;
//  5. the presenter is the last grant's delegate, or reaches it through links
//     that are one to one (link_conflict), signed by both identifiers and the
//     registry (signature_invalid:link), and made while the old identifier was
//     active (link_old_inactive); otherwise presenter_not_delegate;
//  6. no grant on the chain carries a revocation, signed by a principal with
//     standing, whose effective_at is at or before observed_at
//     (revocation_incomplete when it states no grounds,
//     grant_revoked_dispute_open while an affected principal's dispute has no
//     resolution with standing, grant_revoked otherwise);
//  7. every recovery record that names the presenter as its new identifier is
//     signed by the registry and the Responsible entity
//     (signature_invalid:recovery), and the registry registered both identifiers
//     to that entity, or to its predecessor under a recorded responsible
//     succession, with one software attestation digest (recovery_mismatch);
//     the registry's own succession records are followed the same way;
//  8. no retired or revoked agent of the presenter's Responsible entity and
//     software is left unjoined to the presenter by a succession or recovery
//     record (succession_unrecorded).
//
// Neither a recovery nor a succession record carries a grant. An accepted
// presenter whose predecessors, or whose parent's predecessors, left adverse
// records is accepted with authority_valid_with_history, or with
// authority_valid_with_history_contested when the Responsible entity asserted
// that the presenter is a new agent.
//
// A record whose signature does not verify counts as absent. The README states
// each rule and which of them are proposals.
type delegationLifecycle struct{}

func (delegationLifecycle) Suite() string { return "delegation-lifecycle/v1" }

type dlVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Twin     string            `json:"twin"`
}

type dlKey struct {
	KeyID     string `json:"keyid"`
	PublicKey string `json:"public_key"`
}

type dlPolicy struct {
	PayloadType     string   `json:"payload_type"`
	RegistryKey     dlKey    `json:"registry_key"`
	RelyingPartyKey dlKey    `json:"relying_party_key"`
	Roots           []string `json:"roots"`
}

type dlCase struct {
	Policy       dlPolicy `json:"policy"`
	Records      []string `json:"records"`
	Presentation string   `json:"presentation"`
}

// dlRecord is one parsed envelope. Times are parsed once, here, so that a
// record whose time does not parse is a malformed record and never a
// comparison against the zero time.
type dlRecord struct {
	kind     string
	fields   map[string]any
	payload  []byte
	sigs     []caSig
	times    map[string]time.Time
	verified bool
}

func (r *dlRecord) str(name string) string {
	s, _ := r.fields[name].(string)
	return s
}

// dlRequired is every field a record of each type must carry, and which of
// them are times. A field outside these lists is ignored.
var dlRequired = map[string]struct{ text, times []string }{
	"registration":           {[]string{"identifier", "keyid", "public_key"}, []string{"registered_at"}},
	"retirement":             {[]string{"identifier"}, []string{"retired_at"}},
	"identifier-revocation":  {[]string{"identifier"}, []string{"revoked_at"}},
	"grant":                  {[]string{"grant_id", "issuer", "delegate"}, []string{"issued_at"}},
	"revocation":             {[]string{"revocation_id", "grant_id", "initiator"}, []string{"effective_at", "issued_at"}},
	"dispute":                {[]string{"dispute_id", "revocation_id", "filed_by"}, []string{"filed_at"}},
	"resolution":             {[]string{"dispute_id", "revocation_id", "decided_by", "outcome"}, []string{"decided_at"}},
	"link":                   {[]string{"link_id", "old", "new"}, []string{"linked_at"}},
	"recovery":               {[]string{"recovery_id", "old", "new", "responsible"}, []string{"recovered_at"}},
	"succession":             {[]string{"succession_id", "old", "new", "responsible"}, []string{"recorded_at"}},
	"new-agent-assertion":    {[]string{"assertion_id", "identifier", "succession_id", "responsible", "grounds"}, []string{"asserted_at"}},
	"responsible-succession": {[]string{"record_id", "old_responsible", "new_responsible"}, []string{"succeeded_at"}},
	"presentation":           {[]string{"presenter"}, []string{"observed_at"}},
}

// dlRules are the rules the mutation sweep switches off one at a time.
var dlRules = []string{
	"signature", "relying_party_attestation", "link_registry_attestation", "chain",
	"presenter_active", "links", "link_conflict", "link_old_active", "revocation",
	"revocation_time", "standing", "revocation_complete", "dispute", "resolution",
	"resolution_standing", "recovery_no_authority", "recovery_signature", "recovery_match",
	"recovery_history", "succession_recorded", "new_agent_assertion", "responsible_succession",
	"parent_lifespan", "parent_not_carried", "succession_no_authority", "parent_history",
}

func (delegationLifecycle) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	accepted := map[string]bool{}
	var vectors []dlVector
	for _, entry := range manifest.Vectors {
		var v dlVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		accepted[v.ID] = v.Expected.Decision == "accept"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = dlJudgeMember(filepath.Join(dir, v.Path), v)
		if v.Expected.Decision != "accept" && !accepted[v.Twin] {
			member.Findings = append(member.Findings, "a refused member must name an accepted twin")
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func dlJudgeMember(caseDir string, v dlVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	got, err := dlDecideDir(caseDir, nil)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// dlDecideDir reads one case directory and decides it with the named rules
// switched off. An error means case.json itself could not be read.
func dlDecideDir(caseDir string, skip map[string]bool) (scDecision, error) {
	var c dlCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return scDecision{}, err
	}
	s := &dlState{policy: c.Policy, skip: skip}
	for _, name := range c.Records {
		r, ok := s.parse(caseDir, name)
		if !ok {
			return dlNoVerdict, nil
		}
		s.records = append(s.records, r)
	}
	presentation, ok := s.parse(caseDir, c.Presentation)
	if !ok || presentation.kind != "presentation" {
		return dlNoVerdict, nil
	}
	return s.decide(presentation), nil
}

var dlNoVerdict = scDecision{Decision: "no_verdict", Reason: "malformed_record"}

func dlReject(reason string) scDecision { return scDecision{Decision: "reject", Reason: reason} }

type dlState struct {
	policy  dlPolicy
	skip    map[string]bool
	records []*dlRecord
	keys    map[string][]ed25519.PublicKey
}

func (s *dlState) off(rule string) bool { return s.skip[rule] }

func (s *dlState) parse(caseDir, name string) (*dlRecord, bool) {
	raw, err := readIn(caseDir, name)
	if err != nil {
		return nil, false
	}
	payloadType, body, sigs, ok := apParse(raw)
	if !ok || payloadType != s.policy.PayloadType {
		return nil, false
	}
	var fields map[string]any
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return nil, false
	}
	r := &dlRecord{fields: fields, payload: body, sigs: sigs, times: map[string]time.Time{}}
	r.kind = r.str("type")
	required, known := dlRequired[r.kind]
	if !known {
		return nil, false
	}
	for _, field := range required.text {
		if r.str(field) == "" {
			return nil, false
		}
	}
	for _, field := range required.times {
		t, err := time.Parse(time.RFC3339, r.str(field))
		if err != nil {
			return nil, false
		}
		r.times[field] = t
	}
	return r, true
}

func dlPublicKey(k dlKey) (ed25519.PublicKey, bool) {
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || sha(raw) != k.KeyID {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// signedBy reports whether some signature on r names one of keys by its keyid
// and verifies over the DSSE pre-authentication encoding.
func (s *dlState) signedBy(r *dlRecord, keys []ed25519.PublicKey) bool {
	message := caPAE(s.policy.PayloadType, r.payload)
	for _, k := range keys {
		kid := sha(k)
		for _, sig := range r.sigs {
			if sig.keyid == kid && ed25519.Verify(k, message, sig.sig) {
				return true
			}
		}
	}
	return false
}

func (s *dlState) registryKeys() []ed25519.PublicKey {
	k, ok := dlPublicKey(s.policy.RegistryKey)
	if !ok {
		return nil
	}
	return []ed25519.PublicKey{k}
}

// bindKeys reads the registrations the registry signed into the key table.
func (s *dlState) bindKeys() {
	s.keys = map[string][]ed25519.PublicKey{}
	registry := s.registryKeys()
	for _, r := range s.records {
		if r.kind != "registration" {
			continue
		}
		k, ok := dlPublicKey(dlKey{KeyID: r.str("keyid"), PublicKey: r.str("public_key")})
		if ok && (s.off("signature") || s.signedBy(r, registry)) {
			s.keys[r.str("identifier")] = append(s.keys[r.str("identifier")], k)
		}
	}
}

// dlSelfSigned names, for each record type its own principal signs, the field
// holding that principal.
var dlSelfSigned = map[string]string{
	"grant": "issuer", "revocation": "initiator", "dispute": "filed_by",
	"resolution": "decided_by", "new-agent-assertion": "responsible",
}

// verify reports whether a record carries the signatures its type needs: the
// registry's for what the registry records, the signer's own registered key for
// what a principal asserts, and several for a link, a recovery or a hand-over.
func (s *dlState) verify(r *dlRecord) bool {
	if s.off("signature") {
		return true
	}
	if field, ok := dlSelfSigned[r.kind]; ok {
		return s.signedBy(r, s.keys[r.str(field)])
	}
	registry := s.signedBy(r, s.registryKeys())
	switch r.kind {
	case "registration", "retirement", "identifier-revocation", "succession":
		return registry
	case "link":
		registered := s.off("link_registry_attestation") || registry
		return registered && s.signedBy(r, s.keys[r.str("old")]) && s.signedBy(r, s.keys[r.str("new")])
	case "recovery":
		return registry && (s.off("recovery_signature") || s.signedBy(r, s.keys[r.str("responsible")]))
	case "responsible-succession":
		return registry && s.signedBy(r, s.keys[r.str("old_responsible")])
	}
	return false
}

func (s *dlState) decide(p *dlRecord) scDecision {
	s.bindKeys()
	for _, r := range s.records {
		r.verified = s.verify(r)
	}
	if !s.presentationAttested(p) {
		return dlReject("signature_invalid:presentation")
	}
	chain, reason := s.chain(p)
	if reason != "" {
		return dlReject(reason)
	}
	observed := p.times["observed_at"]
	if !s.off("presenter_active") && s.inactive(p.str("presenter"), observed) {
		return dlReject("presenter_inactive")
	}
	if s.parentEnded(p.str("presenter"), observed, map[string]bool{}) {
		return dlReject("parent_inactive")
	}
	viaLink, reason := s.holder(chain[len(chain)-1].str("delegate"), p.str("presenter"))
	if reason != "" {
		return dlReject(reason)
	}
	if reason := s.revoked(chain, p.str("presenter"), observed); reason != "" {
		return dlReject(reason)
	}
	history, contested, reason := s.recovered(p.str("presenter"))
	if reason != "" {
		return dlReject(reason)
	}
	inherited, reason := s.parentHistory(p.str("presenter"))
	if reason != "" {
		return dlReject(reason)
	}
	history = history || inherited
	if !s.off("succession_recorded") && s.unjoined(p.str("presenter")) {
		return dlReject("succession_unrecorded")
	}
	switch {
	case viaLink:
		return scDecision{Decision: "accept", Reason: "authority_valid_via_link"}
	case contested:
		return scDecision{Decision: "accept", Reason: "authority_valid_with_history_contested"}
	case history:
		return scDecision{Decision: "accept", Reason: "authority_valid_with_history"}
	}
	return scDecision{Decision: "accept", Reason: "authority_valid"}
}

// recovered follows the recovery and succession records that end at presenter
// back to every predecessor. It refuses a recovery that does not verify or whose
// two registrations do not match, ignores a succession record the registry did
// not sign, and reports whether any predecessor left an adverse record and
// whether the Responsible entity contested a succession on the path.
func (s *dlState) recovered(presenter string) (history, contested bool, reason string) {
	visited := map[string]bool{}
	for queue := []string{presenter}; len(queue) > 0; queue = queue[1:] {
		at := queue[0]
		if visited[at] {
			continue
		}
		visited[at] = true
		for _, r := range s.records {
			if !s.joins(r) || r.str("new") != at {
				continue
			}
			if !r.verified {
				return false, false, "signature_invalid:recovery"
			}
			if !s.off("recovery_match") && !s.recoveryMatches(r) {
				return false, false, "recovery_mismatch"
			}
			old := r.str("old")
			history = history || (!s.off("recovery_history") && s.adverse(old))
			contested = contested || s.assertedNew(r)
			queue = append(queue, old)
		}
	}
	return history, contested, ""
}

// joins reports whether r carries history from an old identifier to a new one:
// any recovery record, and a succession record only when the registry signed it.
func (s *dlState) joins(r *dlRecord) bool {
	return r.kind == "recovery" || (r.kind == "succession" && r.verified)
}

// assertedNew reports whether the Responsible entity of succession r signed an
// assertion that r's new identifier is a new agent.
func (s *dlState) assertedNew(r *dlRecord) bool {
	if r.kind != "succession" || s.off("new_agent_assertion") {
		return false
	}
	for _, a := range s.records {
		if a.kind == "new-agent-assertion" && a.verified && a.str("succession_id") == r.str("succession_id") &&
			a.str("identifier") == r.str("new") && a.str("responsible") == r.str("responsible") {
			return true
		}
	}
	return false
}

// unjoined reports whether the registry registered presenter with the
// Responsible entity and software of an agent it had already retired or revoked,
// and no succession or recovery record joins that agent to presenter.
func (s *dlState) unjoined(presenter string) bool {
	next := s.registration(presenter)
	if next == nil || next.str("software") == "" {
		return false
	}
	registered := next.times["registered_at"]
	for _, old := range s.records {
		if old.kind != "registration" || !old.verified || old.str("identifier") == presenter ||
			old.str("software") != next.str("software") ||
			!s.covers(old.str("responsible"), next.str("responsible"), registered) ||
			!s.ended(old.str("identifier"), registered) {
			continue
		}
		if !s.joined(old.str("identifier"), presenter) {
			return true
		}
	}
	return false
}

func (s *dlState) joined(old, next string) bool {
	for _, r := range s.records {
		if s.joins(r) && r.verified && r.str("old") == old && r.str("new") == next {
			return true
		}
	}
	return false
}

// covers reports whether successor is the Responsible entity from, or took over
// from's agents through verified responsible-succession records made at or
// before t.
func (s *dlState) covers(from, successor string, t time.Time) bool {
	if from == "" || successor == "" {
		return false
	}
	reached := map[string]bool{from: true}
	for grew := true; grew && !s.off("responsible_succession"); {
		grew = false
		for _, r := range s.records {
			if r.kind == "responsible-succession" && r.verified && reached[r.str("old_responsible")] &&
				!reached[r.str("new_responsible")] && !r.times["succeeded_at"].After(t) {
				reached[r.str("new_responsible")] = true
				grew = true
			}
		}
	}
	return reached[successor]
}

func (s *dlState) registration(identifier string) *dlRecord {
	for _, r := range s.records {
		if r.kind == "registration" && r.verified && r.str("identifier") == identifier {
			return r
		}
	}
	return nil
}

// recoveryMatches reports whether the registry registered the new identifier to
// the record's Responsible entity, and the old one to that entity or to a
// predecessor it took over from before the record, with one software digest.
func (s *dlState) recoveryMatches(r *dlRecord) bool {
	old, next := s.registration(r.str("old")), s.registration(r.str("new"))
	if old == nil || next == nil {
		return false
	}
	responsible := r.str("responsible")
	return s.covers(old.str("responsible"), responsible, dlLinkedAt(r)) &&
		next.str("responsible") == responsible &&
		old.str("software") != "" && old.str("software") == next.str("software")
}

// adverse reports whether identifier left a record a relying party must see: an
// identifier revocation, a revocation of a grant made to it, or a dispute it
// filed.
func (s *dlState) adverse(identifier string) bool {
	delegated := map[string]bool{}
	for _, r := range s.records {
		if r.kind == "grant" && r.verified && r.str("delegate") == identifier {
			delegated[r.str("grant_id")] = true
		}
	}
	for _, r := range s.records {
		if !r.verified {
			continue
		}
		switch {
		case r.kind == "identifier-revocation" && r.str("identifier") == identifier,
			r.kind == "revocation" && delegated[r.str("grant_id")],
			r.kind == "dispute" && r.str("filed_by") == identifier:
			return true
		}
	}
	return false
}

func (s *dlState) presentationAttested(p *dlRecord) bool {
	if !s.off("signature") && !s.signedBy(p, s.keys[p.str("presenter")]) {
		return false
	}
	if s.off("relying_party_attestation") {
		return true
	}
	k, ok := dlPublicKey(s.policy.RelyingPartyKey)
	return ok && s.signedBy(p, []ed25519.PublicKey{k})
}

// chain resolves the presented grant identifiers to verified grants, in order.
func (s *dlState) chain(p *dlRecord) ([]*dlRecord, string) {
	ids, ok := p.fields["chain"].([]any)
	if !ok || len(ids) == 0 {
		return nil, "chain_broken"
	}
	var chain []*dlRecord
	for _, raw := range ids {
		id, _ := raw.(string)
		grant, reason := s.grant(id)
		if reason != "" {
			return nil, reason
		}
		chain = append(chain, grant)
	}
	if !s.off("chain") && !s.linked(chain) {
		return nil, "chain_broken"
	}
	return chain, ""
}

func (s *dlState) grant(id string) (*dlRecord, string) {
	seen := false
	for _, r := range s.records {
		if r.kind != "grant" || r.str("grant_id") != id {
			continue
		}
		seen = true
		if r.verified {
			return r, ""
		}
	}
	if seen {
		return nil, "signature_invalid:grant"
	}
	return nil, "chain_broken"
}

func (s *dlState) linked(chain []*dlRecord) bool {
	root := false
	for _, r := range s.policy.Roots {
		root = root || r == chain[0].str("issuer")
	}
	if !root || chain[0].fields["parent"] != nil {
		return false
	}
	for i := 1; i < len(chain); i++ {
		parent, _ := chain[i].fields["parent"].(string)
		if parent != chain[i-1].str("grant_id") || chain[i].str("issuer") != chain[i-1].str("delegate") {
			return false
		}
	}
	return true
}

// inactive reports whether the registry retired or revoked an identifier at or
// before t. A presenter is inactive at the instant of its retirement; a link
// made at the instant of retirement is made by an inactive identifier too.
func (s *dlState) inactive(identifier string, t time.Time) bool {
	for _, r := range s.records {
		if !r.verified || r.str("identifier") != identifier {
			continue
		}
		var when time.Time
		switch r.kind {
		case "retirement":
			when = r.times["retired_at"]
		case "identifier-revocation":
			when = r.times["revoked_at"]
		default:
			continue
		}
		if !when.After(t) {
			return true
		}
	}
	return false
}

// ended reports whether identifier had ended at t: the registry retired or
// revoked it, or it is a sub-agent whose parent had ended.
func (s *dlState) ended(identifier string, t time.Time) bool {
	return s.inactive(identifier, t) || s.parentEnded(identifier, t, map[string]bool{})
}

// parentEnded reports whether the registry registered identifier as a sub-agent
// of a parent that had ended at t. A sub-agent's lifespan is bound to the one
// parent identifier its registration names: a recovery or succession record
// that joins that parent to a successor carries history, and neither the
// parent's grants nor its sub-agents.
func (s *dlState) parentEnded(identifier string, t time.Time, seen map[string]bool) bool {
	if s.off("parent_lifespan") {
		return false
	}
	reg := s.registration(identifier)
	if reg == nil {
		return false
	}
	parent := reg.str("parent")
	if parent == "" || seen[parent] {
		return false
	}
	seen[parent] = true
	if !s.inactive(parent, t) && !s.parentEnded(parent, t, seen) {
		return false
	}
	if s.off("parent_not_carried") {
		for _, r := range s.records {
			if s.joins(r) && r.verified && r.str("old") == parent && !s.ended(r.str("new"), t) {
				return false
			}
		}
	}
	return true
}

// parentHistory reports whether a parent of presenter, or a parent above it,
// carries history from a predecessor that left an adverse record, and refuses
// when that history cannot be resolved.
func (s *dlState) parentHistory(presenter string) (bool, string) {
	if s.off("parent_history") {
		return false, ""
	}
	seen := map[string]bool{presenter: true}
	for at := presenter; ; {
		reg := s.registration(at)
		if reg == nil || reg.str("parent") == "" || seen[reg.str("parent")] {
			return false, ""
		}
		at = reg.str("parent")
		seen[at] = true
		history, _, reason := s.recovered(at)
		if reason != "" || history {
			return history, reason
		}
	}
}

// holder reports whether presenter holds a grant made to delegate: directly,
// or through a path of links followed one hop at a time.
func (s *dlState) holder(delegate, presenter string) (bool, string) {
	if delegate == presenter {
		return false, ""
	}
	if s.off("links") {
		return false, "presenter_not_delegate"
	}
	visited := map[string]bool{}
	for at := delegate; !visited[at]; {
		visited[at] = true
		next, reason := s.hop(at)
		if reason != "" {
			return false, reason
		}
		if next == "" {
			break
		}
		if next == presenter {
			return true, ""
		}
		at = next
	}
	if s.unverifiedLinkFrom(visited) {
		return false, "signature_invalid:link"
	}
	return false, "presenter_not_delegate"
}

// hop returns the one successor of old, or "" when it has none.
func (s *dlState) hop(old string) (string, string) {
	var links []*dlRecord
	for _, r := range s.records {
		if s.carries(r) && r.verified && r.str("old") == old {
			links = append(links, r)
		}
	}
	if len(links) == 0 {
		return "", ""
	}
	link := links[0]
	if !s.off("link_conflict") && (len(links) > 1 || s.predecessors(link.str("new")) > 1) {
		return "", "link_conflict"
	}
	if !s.off("link_old_active") && s.ended(old, dlLinkedAt(link)) {
		return "", "link_old_inactive"
	}
	return link.str("new"), ""
}

// carries reports whether r passes a grant on: a link always, a recovery record
// only when the recovery_no_authority rule is switched off, and a succession
// record only when the succession_no_authority rule is.
func (s *dlState) carries(r *dlRecord) bool {
	return r.kind == "link" || (r.kind == "recovery" && s.off("recovery_no_authority")) ||
		(r.kind == "succession" && s.off("succession_no_authority"))
}

func dlLinkedAt(r *dlRecord) time.Time {
	switch r.kind {
	case "recovery":
		return r.times["recovered_at"]
	case "succession":
		return r.times["recorded_at"]
	}
	return r.times["linked_at"]
}

func (s *dlState) predecessors(identifier string) int {
	n := 0
	for _, r := range s.records {
		if r.kind == "link" && r.verified && r.str("new") == identifier {
			n++
		}
	}
	return n
}

func (s *dlState) unverifiedLinkFrom(visited map[string]bool) bool {
	for _, r := range s.records {
		if r.kind == "link" && !r.verified && visited[r.str("old")] {
			return true
		}
	}
	return false
}

// revoked returns the refusal for the first grant on the chain that carries a
// revocation in force at observed, or "" when none does.
func (s *dlState) revoked(chain []*dlRecord, presenter string, observed time.Time) string {
	if s.off("revocation") {
		return ""
	}
	for i := range chain {
		standing := map[string]bool{}
		for _, g := range chain[:i+1] {
			standing[g.str("issuer")] = true
		}
		affected := map[string]bool{presenter: true}
		for _, g := range chain[i:] {
			affected[g.str("delegate")] = true
		}
		if r := s.inForce(chain[i].str("grant_id"), standing, observed); r != nil {
			return s.refusal(r, standing, affected, observed)
		}
	}
	return ""
}

// inForce returns the revocation of grantID with the earliest effective_at at
// or before observed, among those signed by a principal with standing.
func (s *dlState) inForce(grantID string, standing map[string]bool, observed time.Time) *dlRecord {
	var first *dlRecord
	for _, r := range s.records {
		if r.kind != "revocation" || !r.verified || r.str("grant_id") != grantID {
			continue
		}
		if !s.off("standing") && !standing[r.str("initiator")] {
			continue
		}
		effective := r.times["effective_at"]
		if !s.off("revocation_time") && effective.After(observed) {
			continue
		}
		if first == nil || effective.Before(first.times["effective_at"]) {
			first = r
		}
	}
	return first
}

func (s *dlState) refusal(r *dlRecord, standing, affected map[string]bool, observed time.Time) string {
	if !s.off("revocation_complete") && r.str("grounds") == "" {
		return "revocation_incomplete"
	}
	if !s.off("dispute") && s.disputeOpen(r.str("revocation_id"), standing, affected, observed) {
		return "grant_revoked_dispute_open"
	}
	return "grant_revoked"
}

// disputeOpen reports whether an affected principal filed a dispute of the
// revocation by observed that no resolution with standing had closed by then.
func (s *dlState) disputeOpen(revocationID string, standing, affected map[string]bool, observed time.Time) bool {
	for _, d := range s.records {
		if d.kind != "dispute" || !d.verified || d.str("revocation_id") != revocationID ||
			!affected[d.str("filed_by")] || d.times["filed_at"].After(observed) {
			continue
		}
		if !s.resolved(d, standing, observed) {
			return true
		}
	}
	return false
}

func (s *dlState) resolved(d *dlRecord, standing map[string]bool, observed time.Time) bool {
	if s.off("resolution") {
		return false
	}
	for _, r := range s.records {
		if r.kind != "resolution" || !r.verified || r.str("dispute_id") != d.str("dispute_id") ||
			r.str("revocation_id") != d.str("revocation_id") || r.times["decided_at"].After(observed) {
			continue
		}
		if s.off("resolution_standing") || standing[r.str("decided_by")] {
			return true
		}
	}
	return false
}
