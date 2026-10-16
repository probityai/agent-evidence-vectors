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
//     (presenter_inactive);
//  5. the presenter is the last grant's delegate, or reaches it through links
//     that are one to one (link_conflict), signed by both identifiers and the
//     registry (signature_invalid:link), and made while the old identifier was
//     active (link_old_inactive); otherwise presenter_not_delegate;
//  6. no grant on the chain carries a revocation, signed by a principal with
//     standing, whose effective_at is at or before observed_at
//     (revocation_incomplete when it states no grounds,
//     grant_revoked_dispute_open while an affected principal's dispute has no
//     resolution with standing, grant_revoked otherwise).
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
	"registration":          {[]string{"identifier", "keyid", "public_key"}, []string{"registered_at"}},
	"retirement":            {[]string{"identifier"}, []string{"retired_at"}},
	"identifier-revocation": {[]string{"identifier"}, []string{"revoked_at"}},
	"grant":                 {[]string{"grant_id", "issuer", "delegate"}, []string{"issued_at"}},
	"revocation":            {[]string{"revocation_id", "grant_id", "initiator"}, []string{"effective_at", "issued_at"}},
	"dispute":               {[]string{"dispute_id", "revocation_id", "filed_by"}, []string{"filed_at"}},
	"resolution":            {[]string{"dispute_id", "revocation_id", "decided_by", "outcome"}, []string{"decided_at"}},
	"link":                  {[]string{"link_id", "old", "new"}, []string{"linked_at"}},
	"presentation":          {[]string{"presenter"}, []string{"observed_at"}},
}

// dlRules are the rules the mutation sweep switches off one at a time.
var dlRules = []string{
	"signature", "relying_party_attestation", "link_registry_attestation", "chain",
	"presenter_active", "links", "link_conflict", "link_old_active", "revocation",
	"revocation_time", "standing", "revocation_complete", "dispute", "resolution",
	"resolution_standing",
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

// verify reports whether a record carries the signatures its type needs: the
// registry's for what the registry records, the signer's own registered key for
// everything else, and all three for a link.
func (s *dlState) verify(r *dlRecord) bool {
	if s.off("signature") {
		return true
	}
	registry := s.registryKeys()
	switch r.kind {
	case "registration", "retirement", "identifier-revocation":
		return s.signedBy(r, registry)
	case "grant":
		return s.signedBy(r, s.keys[r.str("issuer")])
	case "revocation":
		return s.signedBy(r, s.keys[r.str("initiator")])
	case "dispute":
		return s.signedBy(r, s.keys[r.str("filed_by")])
	case "resolution":
		return s.signedBy(r, s.keys[r.str("decided_by")])
	case "link":
		registered := s.off("link_registry_attestation") || s.signedBy(r, registry)
		return registered && s.signedBy(r, s.keys[r.str("old")]) && s.signedBy(r, s.keys[r.str("new")])
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
	viaLink, reason := s.holder(chain[len(chain)-1].str("delegate"), p.str("presenter"))
	if reason != "" {
		return dlReject(reason)
	}
	if reason := s.revoked(chain, p.str("presenter"), observed); reason != "" {
		return dlReject(reason)
	}
	if viaLink {
		return scDecision{Decision: "accept", Reason: "authority_valid_via_link"}
	}
	return scDecision{Decision: "accept", Reason: "authority_valid"}
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
		if r.kind == "link" && r.verified && r.str("old") == old {
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
	if !s.off("link_old_active") && s.inactive(old, link.times["linked_at"]) {
		return "", "link_old_inactive"
	}
	return link.str("new"), ""
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
