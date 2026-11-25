package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(authorityEpoch{}) }

// authorityEpoch judges corpora/vectors-authority-epoch-fence/. Each member is a signed
// authority log chained by digest, the signed head that closes it, one signed request and
// the keys a verifier pins. The reader applies the checks the Python reader applies, in the
// same order, and stops at the first that fails:
//
//  1. every file is a record of its type: no_verdict / malformed;
//  2. a head is present: refuse / epoch_unavailable;
//  3. the log walks (sequence, links, epochs, kind rules, signatures): refuse / log_invalid;
//  4. the head binds the last event under the current key: refuse / history_incomplete;
//  5. the holder key is pinned and signs the request: unknown_holder,
//     request_signature_invalid;
//  6. the request's epoch is current: epoch_closed, epoch_ahead;
//  7. the approval was not consumed: approval_consumed;
//  8. the grant is the subject's and not superseded: no_grant, grant_superseded;
//  9. the subject's standing: fork, parent_revoked, revoked, revoked_dispute_open,
//     suspended, or admit / authority_valid.
//
// The revocation status is unknown at checks 1 to 4 and is read from the log for the
// request's subject after them; an open dispute reads unknown and a new-admissions-only
// revocation reads partial, never closed.
type authorityEpoch struct{}

func (authorityEpoch) Suite() string { return "authority-epoch-fence/v1" }

const aeTypeURI = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/authority-epoch-fence"

var (
	aeNS    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	aeHex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	aeKinds = map[string]bool{
		"genesis": true, "epoch_open": true, "grant": true, "revoke": true, "suspend": true,
		"resume": true, "approval_consumed": true, "fork": true, "dispute_open": true,
		"dispute_closed": true,
	}
	aeCauses = map[string]bool{
		"clock_acknowledged": true, "restart": true, "root_change": true,
		"re_registration": true, "owner_change": true,
	}
)

type aeAnswer struct {
	Decision         string `json:"decision"`
	Reason           string `json:"reason"`
	RevocationStatus string `json:"revocation_status"`
}

type aeVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected aeAnswer          `json:"expected"`
	Status   string            `json:"status"`
}

type aeRule func(json.RawMessage) bool

func aeString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func aeText(raw json.RawMessage) bool { _, ok := aeString(raw); return ok }
func aeNamed(raw json.RawMessage) bool {
	s, ok := aeString(raw)
	return ok && s != ""
}
func aeOne(raw json.RawMessage) bool   { return string(bytes.TrimSpace(raw)) == "1" }
func aeCount(raw json.RawMessage) bool { return aeNS.Match(bytes.TrimSpace(raw)) }
func aeNs(raw json.RawMessage) bool {
	s, ok := aeString(raw)
	return ok && aeNS.MatchString(s)
}
func aeHexRule(raw json.RawMessage) bool {
	s, ok := aeString(raw)
	return ok && aeHex.MatchString(s)
}
func aeLink(raw json.RawMessage) bool {
	s, ok := aeString(raw)
	return ok && (s == "" || aeHex.MatchString(s))
}
func aeKind(raw json.RawMessage) bool {
	s, ok := aeString(raw)
	return ok && aeKinds[s]
}

var (
	aeEventRules = map[string]aeRule{
		"v": aeOne, "log_id": aeNamed, "seq": aeCount, "epoch": aeCount, "kind": aeKind,
		"subject": aeText, "ref": aeText, "parent": aeText, "cause": aeText, "scope": aeText,
		"at_ns": aeNs, "previous": aeLink, "kid": aeHexRule,
	}
	aeHeadRules = map[string]aeRule{
		"v": aeOne, "log_id": aeNamed, "seq": aeCount, "epoch": aeCount, "digest": aeHexRule,
		"at_ns": aeNs, "kid": aeHexRule,
	}
	aeRequestRules = map[string]aeRule{
		"v": aeOne, "request_id": aeNamed, "subject": aeNamed, "grant_id": aeNamed,
		"approval_id": aeText, "epoch": aeCount, "at_ns": aeNs, "kid": aeHexRule,
	}
)

// aeRecord is one signed record: its whole wire bytes, its claims bytes and the decoded
// claims. Every claim the three record types carry is decoded into one struct; a member a
// type does not carry stays zero.
type aeRecord struct {
	wire   json.RawMessage
	claims json.RawMessage
	sig    string
	c      aeClaims
}

type aeClaims struct {
	LogID      string `json:"log_id"`
	Seq        int64  `json:"seq"`
	Epoch      int64  `json:"epoch"`
	Kind       string `json:"kind"`
	Subject    string `json:"subject"`
	Ref        string `json:"ref"`
	Parent     string `json:"parent"`
	Cause      string `json:"cause"`
	Scope      string `json:"scope"`
	Previous   string `json:"previous"`
	Digest     string `json:"digest"`
	GrantID    string `json:"grant_id"`
	ApprovalID string `json:"approval_id"`
	Kid        string `json:"kid"`
}

var errAEMalformed = fmt.Errorf("malformed")

func aeReadRecord(caseDir, name string, rules map[string]aeRule) (*aeRecord, error) {
	body, err := readIn(caseDir, name)
	if err != nil {
		return nil, errAEMalformed
	}
	var wire map[string]json.RawMessage
	if strictUnmarshal(body, &wire) != nil || len(wire) != 2 {
		return nil, errAEMalformed
	}
	claimsRaw, okC := wire["claims"]
	sigRaw, okS := wire["sig"]
	var claims map[string]json.RawMessage
	if !okC || !okS || json.Unmarshal(claimsRaw, &claims) != nil || len(claims) != len(rules) {
		return nil, errAEMalformed
	}
	for name, rule := range rules {
		if raw, ok := claims[name]; !ok || !rule(raw) {
			return nil, errAEMalformed
		}
	}
	sig, ok := aeString(sigRaw)
	if !ok {
		return nil, errAEMalformed
	}
	if raw, err := decodeCanonical(base64.StdEncoding, sig); err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errAEMalformed
	}
	rec := &aeRecord{wire: body, claims: claimsRaw, sig: sig}
	if json.Unmarshal(claimsRaw, &rec.c) != nil {
		return nil, errAEMalformed
	}
	return rec, nil
}

func aeKey(text string) ([]byte, bool) {
	raw, err := decodeCanonical(base64.StdEncoding, text)
	return raw, err == nil && len(raw) == ed25519.PublicKeySize
}

func aeKid(key []byte) string { return sha(key) }

func aeCanonicalDigest(raw json.RawMessage) string {
	canonical, err := aee.Canonicalize(raw)
	if err != nil {
		return ""
	}
	return sha(canonical)
}

// aeVerifies checks the signature over DOMAIN || 0x00 || JCS(claims), ignoring kid.
func aeVerifies(rec *aeRecord, fragment string, key []byte) bool {
	sig, err := decodeCanonical(base64.StdEncoding, rec.sig)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return false
	}
	canonical, err := aee.Canonicalize(rec.claims)
	if err != nil {
		return false
	}
	msg := append([]byte(aeTypeURI+"#"+fragment+"\x00"), canonical...)
	return ed25519.Verify(ed25519.PublicKey(key), msg, sig)
}

func aeSigned(rec *aeRecord, fragment string, key []byte) bool {
	return rec.c.Kid == aeKid(key) && aeVerifies(rec, fragment, key)
}

type aeCase struct {
	logID   string
	genesis []byte
	holders map[string][]byte
	events  []*aeRecord
	head    *aeRecord
	request *aeRecord
}

type aeCaseFile struct {
	V     json.RawMessage `json:"v"`
	LogID string          `json:"log_id"`
	Keys  struct {
		Genesis string            `json:"genesis"`
		Holders map[string]string `json:"holders"`
	} `json:"keys"`
	Events  []string `json:"events"`
	Head    *string  `json:"head"`
	Request string   `json:"request"`
	NowNS   string   `json:"now_ns"`
}

func aeCaseShape(body []byte) (aeCaseFile, bool) {
	var members map[string]json.RawMessage
	var cf aeCaseFile
	if strictUnmarshal(body, &members) != nil || len(members) != 7 {
		return cf, false
	}
	for _, name := range []string{"v", "log_id", "keys", "events", "head", "request", "now_ns"} {
		if _, ok := members[name]; !ok {
			return cf, false
		}
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(members["keys"], &keys) != nil || len(keys) != 2 || json.Unmarshal(body, &cf) != nil {
		return cf, false
	}
	if _, ok := keys["holders"]; !ok || cf.Keys.Holders == nil || !aeOne(cf.V) || cf.LogID == "" {
		return cf, false
	}
	names := append([]string{cf.Request}, cf.Events...)
	if cf.Head != nil {
		names = append(names, *cf.Head)
	}
	for _, n := range names {
		if n == "" || strings.Contains(n, "/") {
			return cf, false
		}
	}
	return cf, aeNS.MatchString(cf.NowNS)
}

func aeLoad(caseDir string) (*aeCase, error) {
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return nil, errAEMalformed
	}
	cf, ok := aeCaseShape(body)
	if !ok {
		return nil, errAEMalformed
	}
	c := &aeCase{logID: cf.LogID, holders: map[string][]byte{}}
	for subject, text := range cf.Keys.Holders {
		key, ok := aeKey(text)
		if !ok {
			return nil, errAEMalformed
		}
		c.holders[subject] = key
	}
	if c.genesis, ok = aeKey(cf.Keys.Genesis); !ok {
		return nil, errAEMalformed
	}
	for _, name := range cf.Events {
		rec, err := aeReadRecord(caseDir, name, aeEventRules)
		if err != nil {
			return nil, err
		}
		c.events = append(c.events, rec)
	}
	if cf.Head != nil {
		if c.head, err = aeReadRecord(caseDir, *cf.Head, aeHeadRules); err != nil {
			return nil, err
		}
	}
	if c.request, err = aeReadRecord(caseDir, cf.Request, aeRequestRules); err != nil {
		return nil, err
	}
	return c, nil
}

// aeLog is a walked log: the events in order, the last wire object and the current key.
type aeLog struct {
	events []aeClaims
	last   *aeRecord
	key    []byte
}

func (l *aeLog) epoch() int64 { return l.events[len(l.events)-1].Epoch }

func (l *aeLog) grant(id string) *aeClaims {
	for i := range l.events {
		if l.events[i].Kind == "grant" && l.events[i].Ref == id {
			return &l.events[i]
		}
	}
	return nil
}

func (l *aeLog) openDisputes() map[string]bool {
	open := map[string]bool{}
	for _, e := range l.events {
		switch e.Kind {
		case "dispute_open":
			open[e.Ref] = true
		case "dispute_closed":
			delete(open, e.Ref)
		}
	}
	return open
}

func (l *aeLog) kindOK(c aeClaims) bool {
	switch c.Kind {
	case "epoch_open":
		switch c.Cause {
		case "root_change":
			_, ok := aeKey(c.Ref)
			return ok
		case "re_registration", "owner_change":
			return c.Subject != ""
		}
		return aeCauses[c.Cause]
	case "grant":
		return c.Ref != "" && c.Subject != "" && l.grant(c.Ref) == nil &&
			(c.Parent == "" || l.grant(c.Parent) != nil)
	case "revoke":
		named := c.Ref == ""
		if g := l.grant(c.Ref); c.Ref != "" && g != nil {
			named = g.Subject == c.Subject
		}
		return c.Subject != "" && (c.Scope == "all" || c.Scope == "new_admissions") && named
	case "dispute_open":
		revoked := false
		for _, e := range l.events {
			revoked = revoked || (e.Kind == "revoke" && strconv.FormatInt(e.Seq, 10) == c.Ref)
		}
		return revoked && !l.openDisputes()[c.Ref]
	case "dispute_closed":
		return l.openDisputes()[c.Ref] && (c.Cause == "confirmed" || c.Cause == "restored")
	case "approval_consumed":
		return c.Ref != ""
	case "suspend", "resume", "fork":
		return c.Subject != ""
	}
	return true
}

func (l *aeLog) eventOK(rec *aeRecord, index int, logID string) bool {
	c := rec.c
	if c.Seq != int64(index) || c.LogID != logID || (c.Kind == "genesis") != (index == 0) {
		return false
	}
	previous := ""
	if l.last != nil {
		previous = aeCanonicalDigest(l.last.wire)
	}
	if c.Previous != previous {
		return false
	}
	wantEpoch := int64(0)
	if len(l.events) > 0 {
		wantEpoch = l.epoch()
		if c.Kind == "epoch_open" {
			wantEpoch++
		}
	}
	return c.Epoch == wantEpoch && l.kindOK(c) && aeSigned(rec, "event", l.key)
}

func aeWalk(c *aeCase) *aeLog {
	log := &aeLog{key: c.genesis}
	for i, rec := range c.events {
		if !log.eventOK(rec, i, c.logID) {
			return nil
		}
		log.events = append(log.events, rec.c)
		log.last = rec
		if rec.c.Kind == "epoch_open" && rec.c.Cause == "root_change" {
			log.key, _ = aeKey(rec.c.Ref)
		}
	}
	if len(log.events) == 0 {
		return nil
	}
	return log
}

func aeHeadBinds(c *aeCase, log *aeLog) bool {
	h := c.head
	if h == nil || !aeSigned(h, "head", log.key) {
		return false
	}
	last := log.events[len(log.events)-1]
	return h.c.LogID == c.logID && h.c.Seq == last.Seq && h.c.Epoch == last.Epoch &&
		h.c.Digest == aeCanonicalDigest(log.last.wire)
}

func (l *aeLog) chain(g *aeClaims) []*aeClaims {
	var chain []*aeClaims
	seen := map[string]bool{}
	for g != nil && !seen[g.Ref] {
		seen[g.Ref] = true
		chain = append(chain, g)
		if g.Parent == "" {
			break
		}
		g = l.grant(g.Parent)
	}
	return chain
}

func (l *aeLog) standing(subject string, g *aeClaims) (string, string) {
	for _, e := range l.events {
		if e.Kind == "fork" && e.Subject == subject {
			return "fork", "closed"
		}
	}
	chain := l.chain(g)
	ids, ancestors := map[string]bool{}, map[string]bool{}
	for i, link := range chain {
		ids[link.Ref] = true
		if i > 0 {
			ancestors[link.Ref] = true
		}
	}
	var applying []aeClaims
	for _, e := range l.events {
		if e.Kind == "revoke" && ((e.Ref == "" && e.Subject == subject) || (e.Ref != "" && ids[e.Ref])) {
			applying = append(applying, e)
		}
	}
	if len(applying) > 0 {
		return l.revoked(applying, g, ancestors)
	}
	suspended := false
	for _, e := range l.events {
		if e.Subject == subject && (e.Kind == "suspend" || e.Kind == "resume") {
			suspended = e.Kind == "suspend"
		}
	}
	if suspended {
		return "suspended", "suspended"
	}
	return "", "live"
}

func (l *aeLog) revoked(applying []aeClaims, g *aeClaims, ancestors map[string]bool) (string, string) {
	reason := "revoked"
	open := l.openDisputes()
	disputed, partial := false, true
	for _, r := range applying {
		if g != nil && ancestors[r.Ref] && r.Seq < g.Seq {
			reason = "parent_revoked"
		}
		disputed = disputed || open[strconv.FormatInt(r.Seq, 10)]
		partial = partial && r.Scope == "new_admissions"
	}
	switch {
	case disputed:
		return "revoked_dispute_open", "unknown"
	case partial:
		return reason, "partial"
	}
	return reason, "closed"
}

func aeRequestFault(c *aeCase, log *aeLog) string {
	r := c.request.c
	subject, grantID, epoch := r.Subject, r.GrantID, r.Epoch
	key, pinned := c.holders[subject]
	switch {
	case !pinned || r.Kid != aeKid(key):
		return "unknown_holder"
	case !aeVerifies(c.request, "request", key):
		return "request_signature_invalid"
	case epoch < log.epoch():
		return "epoch_closed"
	case epoch > log.epoch():
		return "epoch_ahead"
	}
	for _, e := range log.events {
		if e.Kind == "approval_consumed" && r.ApprovalID != "" && e.Ref == r.ApprovalID {
			return "approval_consumed"
		}
	}
	g := log.grant(grantID)
	if g == nil || g.Subject != subject {
		return "no_grant"
	}
	for _, e := range log.events {
		if e.Kind == "epoch_open" && e.Cause == "re_registration" && e.Subject == subject && e.Seq > g.Seq {
			return "grant_superseded"
		}
	}
	return ""
}

func aeDecide(caseDir string) aeAnswer {
	c, err := aeLoad(caseDir)
	if err != nil {
		return aeAnswer{"no_verdict", "malformed", "unknown"}
	}
	if c.head == nil {
		return aeAnswer{"refuse", "epoch_unavailable", "unknown"}
	}
	log := aeWalk(c)
	if log == nil {
		return aeAnswer{"refuse", "log_invalid", "unknown"}
	}
	if !aeHeadBinds(c, log) {
		return aeAnswer{"refuse", "history_incomplete", "unknown"}
	}
	subject, grantID := c.request.c.Subject, c.request.c.GrantID
	held := log.grant(grantID)
	if held != nil && held.Subject != subject {
		held = nil
	}
	reason, status := log.standing(subject, held)
	if fault := aeRequestFault(c, log); fault != "" {
		return aeAnswer{"refuse", fault, status}
	}
	if reason != "" {
		return aeAnswer{"refuse", reason, status}
	}
	return aeAnswer{"admit", "authority_valid", status}
}

func (authorityEpoch) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v aeVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		caseDir := filepath.Join(dir, v.Path)
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = acFileFindings(caseDir, v.Files)
		if v.Status != "normative" && v.Status != "proposed" {
			member.Findings = append(member.Findings, fmt.Sprintf("status %q is neither normative nor proposed", v.Status))
		}
		if got := aeDecide(caseDir); got != v.Expected {
			member.Findings = append(member.Findings, fmt.Sprintf("derived %s/%s/%s, the manifest declares %s/%s/%s",
				got.Decision, got.Reason, got.RevocationStatus,
				v.Expected.Decision, v.Expected.Reason, v.Expected.RevocationStatus))
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}
