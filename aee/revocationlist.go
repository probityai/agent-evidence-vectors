package aee

// The reader of the one signed revocation list: a Go twin of
// probity_records.revocation, held to the same shared vectors
// (aee/testdata/revocation-list-v2.json and the v1 sets beside it) and the same
// order of checks.
//
// A signed list is {"body": BODY, "sig": base64(Ed25519 over
// RevocationDomain || JCS(BODY))}. The verifier pins root key ids and never
// reads one from a list: a list is checked under its presented key only once
// that key's id is a pinned root. Lists are chained by sequence number and
// digest. Two formats exist, and the verifier picks the one it reads, never
// the list:
//
//   - v2 (RevocationListType; NewRevocationState, VerifyRevocationChain): each
//     list is a delta. Its entries are only the subjects it newly revokes, the
//     revocations in force are the union of the chain, and a list naming a
//     subject an earlier list revoked is refused (revocation_entry_repeated), so
//     an entry's revokedAt never moves and nothing is un-revoked. An empty list
//     is a freshness list. Folding a list costs what its delta holds.
//   - v1 (RevocationListTypeV1; NewRevocationStateV1, VerifyRevocationChainV1):
//     each list is cumulative. An entry, once published, stays in every later
//     list byte for byte (revocation_list_drops_entry). The published corpus
//     revocation-list/v1 is this format.
//
// Each reader refuses the other format's type. Both read the type under either
// host this module recognises (internal/identifiers).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RevocationDomain is prepended to the canonical body before signing.
const RevocationDomain = "probity-revocation-v1\x00"

// RevocationListType is the body type of a v2 (delta) list.
const RevocationListType = "https://probityai.github.io/agent-evidence-vectors/predicate/v2/revocation-list"

// RevocationListTypeV1 is the body type of a v1 (cumulative) list.
const RevocationListTypeV1 = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list"

// revocationHosts are the hosts whose identifiers this module reads as its own. The core
// imports only the standard library, so it keeps this copy of internal/identifiers'
// rule; TestRevocationHostRuleIsTheModuleRule holds the copy to it.
var revocationHosts = [...]string{"probityai.github.io", "probityai.org"}

// sameRevocationType reports whether v is text naming want under a recognised host:
// the match is byte-exact on the scheme and the host, and a value that is not text
// is never a type.
func sameRevocationType(v any, want string) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	return canonicalRevocationIdentifier(s) == canonicalRevocationIdentifier(want)
}

func canonicalRevocationIdentifier(s string) string {
	for _, host := range revocationHosts {
		if rest, found := strings.CutPrefix(s, "https://"+host+"/"); found {
			return "https://" + revocationHosts[0] + "/" + rest
		}
	}
	return s
}

// RevocationKind is one of the eight subject kinds a list names. The queries take this type, so a kind
// the format does not define cannot be passed as a variable; the list's parser refuses an entry of any
// other kind, so no state ever holds one.
type RevocationKind string

// The eight subject kinds a list names. An idp-key is an identity provider's token-signing key, named
// by its RFC 7638 JWK thumbprint; it is never kind key and carries no successor.
const (
	KindAgent   RevocationKind = "agent"
	KindBuild   RevocationKind = "build"
	KindGrant   RevocationKind = "grant"
	KindIdpKey  RevocationKind = "idp-key"
	KindKey     RevocationKind = "key"
	KindPermit  RevocationKind = "permit"
	KindSponsor RevocationKind = "sponsor"
	KindStream  RevocationKind = "stream"
)

// RevocationKinds lists every kind, ascending.
var RevocationKinds = []RevocationKind{KindAgent, KindBuild, KindGrant, KindIdpKey, KindKey, KindPermit, KindSponsor, KindStream}

// RevocationSubject names one revocable thing: an id under a kind.
type RevocationSubject struct {
	Kind RevocationKind
	ID   string
}

// The refusals Apply reports, in the order it checks them: the first nine are
// common to both formats, the tenth is CodeEntryRepeated for v2 and CodeDropsEntry
// for v1.
const (
	CodeShape             = "revocation_list_shape"
	CodeSignerNotARoot    = "revocation_list_signer_not_a_root"
	CodeSignatureBad      = "revocation_list_signature_unverified"
	CodeOtherChain        = "revocation_list_other_chain"
	CodeRollback          = "revocation_list_rollback"
	CodeGap               = "revocation_list_gap"
	CodePreviousMismatch  = "revocation_list_previous_mismatch"
	CodeTimeReversed      = "revocation_list_time_reversed"
	CodeEntryFromFuture   = "revocation_entry_from_future"
	CodeDropsEntry        = "revocation_list_drops_entry"
	CodeEntryRepeated     = "revocation_entry_repeated"
	maxExactRevocationSeq = 1<<53 - 1
)

// RevocationRefusalCodes lists the ten codes a v2 reader reports, in the order Apply checks them.
var RevocationRefusalCodes = []string{
	CodeShape, CodeSignerNotARoot, CodeSignatureBad, CodeOtherChain, CodeRollback, CodeGap,
	CodePreviousMismatch, CodeTimeReversed, CodeEntryFromFuture, CodeEntryRepeated,
}

// RevocationRefusalCodesV1 lists the ten codes a v1 reader reports, in the order Apply checks them.
var RevocationRefusalCodesV1 = []string{
	CodeShape, CodeSignerNotARoot, CodeSignatureBad, CodeOtherChain, CodeRollback, CodeGap,
	CodePreviousMismatch, CodeTimeReversed, CodeEntryFromFuture, CodeDropsEntry,
}

// RevocationError is a refusal: Error() is the code, or "code:detail".
type RevocationError struct {
	Code   string
	Detail string
}

func (e *RevocationError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ":" + e.Detail
}

func refuse(code, format string, args ...any) error {
	return &RevocationError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

func shape(why string) error { return &RevocationError{Code: CodeShape, Detail: why} }

// RevocationState is a verifier's side: the format it reads, the pinned roots
// and the list in force (none: Seq 0, nothing revoked). It is a value; Apply
// returns a new one and never changes its receiver, so a caller must not edit
// Roots. States are safe to read and to apply lists to from any number of
// goroutines: an older state never sees a later list's entries, and two lists
// applied to one state give two independent states.
type RevocationState struct {
	// Roots are the pinned root key ids, sorted ascending.
	Roots []string
	// ListID, Seq, Head and IssuedAt describe the list in force; Head is
	// "" while no list is held.
	ListID   string
	Seq      int64
	Head     string
	IssuedAt string
	v1       bool      // reads the cumulative format
	entries  *revStore // nil while no list is held
	count    int       // how many of the store's keys this state sees
}

// NewRevocationState pins the given key ids, reads v2 (delta) lists and holds no list.
func NewRevocationState(rootKeyIDs []string) RevocationState {
	return RevocationState{Roots: sortedSet(rootKeyIDs, nil)}
}

// NewRevocationStateV1 pins the given key ids, reads v1 (cumulative) lists and holds no list.
func NewRevocationStateV1(rootKeyIDs []string) RevocationState {
	return RevocationState{Roots: sortedSet(rootKeyIDs, nil), v1: true}
}

// revStore holds the entries of one chain of lists, each with the seq of the list that
// added it. Only the state at the store's tip extends it, in place; every state sees the
// keys added at or before its own seq, and order holds the keys in the order they were
// added, so a state's keys are exactly the first count of them.
type revStore struct {
	mu    sync.RWMutex
	added map[[2]string]revHeld
	order [][2]string
	tip   int64
}

type revHeld struct {
	seq   int64
	canon []byte // JCS bytes of the entry
}

// held returns the JCS bytes of the entry under key the list in force holds.
func (s RevocationState) held(key [2]string) ([]byte, bool) {
	if s.entries == nil {
		return nil, false
	}
	s.entries.mu.RLock()
	h, ok := s.entries.added[key]
	s.entries.mu.RUnlock()
	if !ok || h.seq > s.Seq {
		return nil, false
	}
	return h.canon, true
}

// heldKeys returns the keys of the list in force, in the order they were added.
func (s RevocationState) heldKeys() [][2]string {
	if s.entries == nil {
		return nil
	}
	s.entries.mu.RLock()
	defer s.entries.mu.RUnlock()
	return append([][2]string(nil), s.entries.order[:s.count]...)
}

// extended returns a store holding this state's entries and delta's, added at seq, and
// the number of keys it holds: this state's store grown in place when the state is its
// tip, else a store of its own, built once from the keys this state sees.
func (s RevocationState) extended(seq int64, delta []revEntry) (*revStore, int) {
	if store := s.entries; store != nil {
		store.mu.Lock()
		if store.tip == s.Seq {
			for _, e := range delta {
				key := [2]string{e.kind, e.id}
				store.added[key] = revHeld{seq: seq, canon: e.canon}
				store.order = append(store.order, key)
			}
			store.tip = seq
			n := len(store.order)
			store.mu.Unlock()
			return store, n
		}
		store.mu.Unlock()
	}
	branch := &revStore{added: map[[2]string]revHeld{}, tip: seq}
	for _, key := range s.heldKeys() {
		canon, _ := s.held(key)
		branch.added[key] = revHeld{seq: s.Seq, canon: canon}
		branch.order = append(branch.order, key)
	}
	for _, e := range delta {
		key := [2]string{e.kind, e.id}
		branch.added[key] = revHeld{seq: seq, canon: e.canon}
		branch.order = append(branch.order, key)
	}
	return branch, len(branch.order)
}

func sortedSet(ids []string, drop map[string]bool) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		if !seen[id] && !drop[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (s RevocationState) isRoot(id string) bool {
	i := sort.SearchStrings(s.Roots, id)
	return i < len(s.Roots) && s.Roots[i] == id
}

// Revoked reports whether the list in force names id under kind.
func (s RevocationState) Revoked(kind RevocationKind, id string) bool {
	_, ok := s.held([2]string{string(kind), id})
	return ok
}

// Revokes reports whether the list in force names any of the subjects.
func (s RevocationState) Revokes(subjects ...RevocationSubject) bool {
	for _, p := range subjects {
		if s.Revoked(p.Kind, p.ID) {
			return true
		}
	}
	return false
}

// RevokedIDs returns the ids the list in force names under kind, sorted.
func (s RevocationState) RevokedIDs(kind RevocationKind) []string {
	out := []string{}
	for _, k := range s.heldKeys() {
		if k[0] == string(kind) {
			out = append(out, k[1])
		}
	}
	sort.Strings(out)
	return out
}

// ListDigest is "sha256:" + lowercase hex SHA-256 of JCS(body), for body the
// JSON bytes of a list's body member. A successor names it as previous and a
// permit names it as the list it was minted under.
func ListDigest(body []byte) (string, error) {
	canon, err := Canonicalize(body)
	if err != nil {
		return "", err
	}
	return digestOfCanonical(canon), nil
}

func digestOfCanonical(canon []byte) string {
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type revEntry struct {
	kind, id, revokedAt string
	successor           []byte // raw key, nil when absent
	canon               []byte
}

type revBody struct {
	listID, previous, issuedAt string
	hasPrevious                bool
	seq                        int64
	issuerKey                  []byte
	entries                    []revEntry
	canon                      []byte
}

// Apply returns the state with signed (the JSON bytes of a signed list, of the
// format the state reads) as the list in force, or a *RevocationError. The
// receiver is never changed.
func (s RevocationState) Apply(signed []byte) (RevocationState, error) {
	top, err := parseJSONValue(signed)
	if err != nil {
		return s, shape("signed_list_unreadable")
	}
	obj, ok := top.(*jsonObject)
	if !ok || len(obj.values) != 2 || !hasMember(obj, "body") || !hasMember(obj, "sig") {
		return s, shape("signed_list_members")
	}
	listType := RevocationListType
	if s.v1 {
		listType = RevocationListTypeV1
	}
	body, err := readRevBody(obj.values["body"], listType)
	if err != nil {
		return s, err
	}
	rawID := sha256.Sum256(body.issuerKey)
	if !s.isRoot(hex.EncodeToString(rawID[:])) {
		return s, &RevocationError{Code: CodeSignerNotARoot}
	}
	sig, ok := canonicalBase64(obj.values["sig"])
	if !ok || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(body.issuerKey), append([]byte(RevocationDomain), body.canon...), sig) {
		return s, &RevocationError{Code: CodeSignatureBad}
	}
	if s.v1 {
		return s.install(body)
	}
	return s.installDelta(body)
}

// RevocationChainVerdict is a chain of signed lists judged in order by a verifier that pins
// the given roots and holds no list yet.
type RevocationChainVerdict struct {
	// Verdict is VerdictValid when every list was accepted and VerdictInvalid otherwise.
	Verdict string
	// Refusal is the first refusal, nil when valid.
	Refusal *RevocationError
	// Index is the position of the refused list, -1 when valid.
	Index int
	// State is the list in force: after the last list when valid, and when invalid the one
	// the refused list was checked against.
	State RevocationState
}

// VerifyRevocationChain applies the signed v2 lists (the JSON bytes of each) in order, from a
// verifier that pins rootKeyIDs and holds no list, and stops at the first refusal.
func VerifyRevocationChain(rootKeyIDs []string, lists [][]byte) RevocationChainVerdict {
	return verifyRevocationChain(NewRevocationState(rootKeyIDs), lists)
}

// VerifyRevocationChainV1 is VerifyRevocationChain for v1 (cumulative) lists.
func VerifyRevocationChainV1(rootKeyIDs []string, lists [][]byte) RevocationChainVerdict {
	return verifyRevocationChain(NewRevocationStateV1(rootKeyIDs), lists)
}

func verifyRevocationChain(state RevocationState, lists [][]byte) RevocationChainVerdict {
	for i, list := range lists {
		next, err := state.Apply(list)
		if err != nil {
			refusal, _ := err.(*RevocationError)
			return RevocationChainVerdict{Verdict: VerdictInvalid, Refusal: refusal, Index: i, State: state}
		}
		state = next
	}
	return RevocationChainVerdict{Verdict: VerdictValid, Index: -1, State: state}
}

func hasMember(o *jsonObject, name string) bool {
	_, ok := o.values[name]
	return ok
}

// chainChecks runs the checks both formats share (4 to 9) on a list whose shape
// and signature are already proved.
func (s RevocationState) chainChecks(b revBody) error {
	if s.ListID != "" && b.listID != s.ListID {
		return &RevocationError{Code: CodeOtherChain}
	}
	if b.seq <= s.Seq {
		return refuse(CodeRollback, "%d<=%d", b.seq, s.Seq)
	}
	if b.seq > s.Seq+1 {
		return refuse(CodeGap, "%d>%d", b.seq, s.Seq+1)
	}
	if b.hasPrevious != (s.Head != "") || b.previous != s.Head {
		return &RevocationError{Code: CodePreviousMismatch}
	}
	if s.IssuedAt != "" && b.issuedAt < s.IssuedAt {
		return &RevocationError{Code: CodeTimeReversed}
	}
	for _, e := range b.entries {
		if e.revokedAt > b.issuedAt {
			return &RevocationError{Code: CodeEntryFromFuture}
		}
	}
	return nil
}

// install runs the v1 chain checks (4 to 10) on a list whose shape and
// signature are already proved: the list is cumulative, so it must hold every
// entry the list in force holds, byte for byte.
func (s RevocationState) install(b revBody) (RevocationState, error) {
	if err := s.chainChecks(b); err != nil {
		return s, err
	}
	entries := make(map[[2]string][]byte, len(b.entries))
	for _, e := range b.entries {
		entries[[2]string{e.kind, e.id}] = e.canon
	}
	// Held entries are checked in (kind, id) order, so a list that drops or edits several is
	// refused naming the first of them, the same one on every run.
	for _, key := range sortedEntryKeys(s.heldKeys()) {
		if held, _ := s.held(key); !bytes.Equal(entries[key], held) {
			return s, refuse(CodeDropsEntry, "%s:%.12s", key[0], key[1])
		}
	}
	// A revoked key is never a root, whatever the order of the entries: the successors of the held
	// roots this list revokes join, then every key id it revokes leaves, so a successor the same list
	// revokes does not stay.
	gone, joined := map[string]bool{}, []string{}
	for _, e := range b.entries {
		if e.kind != string(KindKey) {
			continue
		}
		gone[e.id] = true
		if e.successor != nil && s.isRoot(e.id) {
			sum := sha256.Sum256(e.successor)
			joined = append(joined, hex.EncodeToString(sum[:]))
		}
	}
	// A v1 list replaces the entries in force, so its store is its own.
	store := &revStore{added: make(map[[2]string]revHeld, len(b.entries)), tip: b.seq}
	for _, e := range b.entries {
		key := [2]string{e.kind, e.id}
		store.added[key] = revHeld{seq: b.seq, canon: e.canon}
		store.order = append(store.order, key)
	}
	return RevocationState{
		Roots:    sortedSet(append(append([]string{}, s.Roots...), joined...), gone),
		ListID:   b.listID,
		Seq:      b.seq,
		Head:     digestOfCanonical(b.canon),
		IssuedAt: b.issuedAt,
		v1:       true,
		entries:  store,
		count:    len(store.order),
	}, nil
}

// installDelta runs the v2 chain checks (4 to 10) on a list whose shape and
// signature are already proved: the list is a delta, so it must name no subject
// an earlier list of the chain revoked.
func (s RevocationState) installDelta(b revBody) (RevocationState, error) {
	if err := s.chainChecks(b); err != nil {
		return s, err
	}
	// Entries are strictly ascending, so a list that repeats several is refused naming the
	// first of them, the same one on every run.
	for _, e := range b.entries {
		if _, held := s.held([2]string{e.kind, e.id}); held {
			return s, refuse(CodeEntryRepeated, "%s:%.12s", e.kind, e.id)
		}
	}
	// A revoked key is never a root, whatever the order of the entries and whichever list revoked
	// it: the successors of the held roots this list revokes join unless an earlier list revoked
	// them, then every key id this list revokes leaves, so a successor the same list revokes does
	// not stay either.
	gone, joined := map[string]bool{}, []string{}
	for _, e := range b.entries {
		if e.kind != string(KindKey) {
			continue
		}
		gone[e.id] = true
		if e.successor != nil && s.isRoot(e.id) {
			sum := sha256.Sum256(e.successor)
			if successor := hex.EncodeToString(sum[:]); !s.Revoked(KindKey, successor) {
				joined = append(joined, successor)
			}
		}
	}
	store, count := s.extended(b.seq, b.entries)
	return RevocationState{
		Roots:    sortedSet(append(append([]string{}, s.Roots...), joined...), gone),
		ListID:   b.listID,
		Seq:      b.seq,
		Head:     digestOfCanonical(b.canon),
		IssuedAt: b.issuedAt,
		entries:  store,
		count:    count,
	}, nil
}

func sortedEntryKeys(keys [][2]string) [][2]string {
	keys = append([][2]string(nil), keys...)
	sort.Slice(keys, func(i, j int) bool {
		return keys[i][0] < keys[j][0] || keys[i][0] == keys[j][0] && keys[i][1] < keys[j][1]
	})
	return keys
}

func readRevBody(v any, listType string) (revBody, error) {
	var b revBody
	o, ok := v.(*jsonObject)
	if !ok || len(o.values) != 7 {
		return b, shape("body_members")
	}
	for _, name := range []string{"type", "listId", "seq", "previous", "issuedAt", "issuerKey", "entries"} {
		if !hasMember(o, name) {
			return b, shape("body_members")
		}
	}
	if !sameRevocationType(o.values["type"], listType) {
		return b, shape("type")
	}
	var listID string
	if listID, ok = o.values["listId"].(string); !ok || !isIdentifier(listID) {
		return b, shape("list_id_form")
	}
	b.listID = listID
	if err := readSeqAndPrevious(&b, o); err != nil {
		return b, err
	}
	var err error
	if b.issuedAt, err = readTime(o.values["issuedAt"], "issuedAt"); err != nil {
		return b, err
	}
	if b.issuerKey, err = readRawKey(o.values["issuerKey"], "issuerKey"); err != nil {
		return b, err
	}
	list, ok := o.values["entries"].([]any)
	if !ok {
		return b, shape("entries_not_a_list")
	}
	for _, item := range list {
		e, err := readRevEntry(item)
		if err != nil {
			return b, err
		}
		b.entries = append(b.entries, e)
	}
	for i := 1; i < len(b.entries); i++ {
		p, c := b.entries[i-1], b.entries[i]
		if p.kind > c.kind || p.kind == c.kind && p.id >= c.id {
			return b, shape("entries_not_strictly_ascending")
		}
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, o, 0); err != nil {
		return b, shape("body_not_canonical")
	}
	b.canon = buf.Bytes()
	return b, nil
}

func readSeqAndPrevious(b *revBody, o *jsonObject) error {
	n, ok := o.values["seq"].(json.Number)
	if !ok {
		return shape("seq_not_a_positive_exact_integer")
	}
	seq, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || seq < 1 || seq > maxExactRevocationSeq {
		return shape("seq_not_a_positive_exact_integer")
	}
	b.seq = seq
	switch p := o.values["previous"].(type) {
	case nil:
		if seq != 1 {
			return shape("previous_form")
		}
	case string:
		if seq == 1 || !isListDigest(p) {
			return shape("previous_form")
		}
		b.previous, b.hasPrevious = p, true
	default:
		return shape("previous_form")
	}
	return nil
}

func readRevEntry(v any) (revEntry, error) {
	var e revEntry
	o, ok := v.(*jsonObject)
	if !ok {
		return e, shape("entry_not_an_object")
	}
	for _, name := range o.keys {
		switch name {
		case "kind", "id", "revokedAt", "reason", "successor":
		default:
			return e, shape("entry_members")
		}
	}
	if !hasMember(o, "kind") || !hasMember(o, "id") || !hasMember(o, "revokedAt") {
		return e, shape("entry_members")
	}
	kind, _ := o.values["kind"].(string)
	if !isRevocationKind(kind) {
		return e, shape("entry_kind_unknown")
	}
	id, _ := o.values["id"].(string)
	if kind == string(KindGrant) || kind == string(KindKey) || kind == string(KindPermit) {
		if !isHex64(id) {
			return e, shape("entry_id_form:" + kind)
		}
	} else if kind == string(KindIdpKey) {
		if !isThumbprint(id) {
			return e, shape("entry_id_form:" + kind)
		}
	} else if !isIdentifier(id) {
		return e, shape("entry_id_form:" + kind)
	}
	e.kind, e.id = kind, id
	var err error
	if e.revokedAt, err = readTime(o.values["revokedAt"], "revokedAt"); err != nil {
		return e, err
	}
	if r, has := o.values["reason"]; has {
		if _, ok := r.(string); !ok {
			return e, shape("entry_reason_not_text")
		}
	}
	if sv, has := o.values["successor"]; has {
		if kind != string(KindKey) {
			return e, shape("successor_on_non_key_entry")
		}
		if e.successor, err = readRawKey(sv, "successor"); err != nil {
			return e, err
		}
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, o, 0); err != nil {
		return e, shape("entry_not_canonical")
	}
	e.canon = buf.Bytes()
	return e, nil
}

func isRevocationKind(kind string) bool {
	for _, k := range RevocationKinds {
		if string(k) == kind {
			return true
		}
	}
	return false
}

func isIdentifier(s string) bool {
	if len(s) < 1 || len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isHex64(s string) bool { return len(s) == 64 && isLowerHex(s) }

// isThumbprint accepts an RFC 7638 SHA-256 thumbprint in base64url without padding:
// 43 digits, the last carrying two zero bits, so each key has one spelling and a lookup
// by the thumbprint a reader computes cannot miss an entry written another way.
func isThumbprint(s string) bool {
	if len(s) != 43 {
		return false
	}
	for i := 0; i < 42; i++ {
		if c := s[i]; (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return strings.IndexByte("AEIMQUYcgkosw048", s[42]) >= 0
}

func isListDigest(s string) bool { return len(s) == 71 && s[:7] == "sha256:" && isLowerHex(s[7:]) }

// readTime accepts exactly YYYY-MM-DDTHH:MM:SSZ naming a real calendar instant.
func readTime(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok || len(s) != 20 || !digitsAt(s, 0, 4) || s[4] != '-' || !digitsAt(s, 5, 7) || s[7] != '-' ||
		!digitsAt(s, 8, 10) || s[10] != 'T' || !digitsAt(s, 11, 13) || s[13] != ':' || !digitsAt(s, 14, 16) ||
		s[16] != ':' || !digitsAt(s, 17, 19) || s[19] != 'Z' {
		return "", shape(what + "_not_a_utc_second")
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", s); err != nil || s[:4] == "0000" {
		return "", shape(what + "_not_a_calendar_instant")
	}
	return s, nil
}

func digitsAt(s string, from, to int) bool {
	for i := from; i < to; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// canonicalBase64 decodes padded standard base64 and accepts only its
// canonical spelling: the text must be what re-encoding the bytes gives.
func canonicalBase64(v any) ([]byte, bool) {
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

func readRawKey(v any, what string) ([]byte, error) {
	s, isText := v.(string)
	if !isText {
		return nil, shape(what + "_not_base64")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, shape(what + "_not_base64")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, shape(what + "_not_an_ed25519_key")
	}
	if base64.StdEncoding.EncodeToString(raw) != s {
		return nil, shape(what + "_not_canonical_base64")
	}
	return raw, nil
}
