package aee

// The reader of the one signed revocation list: a Go twin of
// probity_records.revocation, held to the same shared vectors
// (aee/testdata/revocation-list.json) and the same order of checks.
//
// A signed list is {"body": BODY, "sig": base64(Ed25519 over
// RevocationDomain || JCS(BODY))}. The verifier pins root key ids and never
// reads one from a list: a list is checked under its presented key only once
// that key's id is a pinned root. Lists are cumulative and chained by
// sequence number and digest, so an entry, once published, stays in every
// later list byte for byte.

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
	"time"
)

// RevocationDomain is prepended to the canonical body before signing.
const RevocationDomain = "probity-revocation-v1\x00"

// RevocationListType is the one body type a list carries.
const RevocationListType = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list"

// The seven subject kinds a list names.
const (
	KindAgent   = "agent"
	KindBuild   = "build"
	KindGrant   = "grant"
	KindKey     = "key"
	KindPermit  = "permit"
	KindSponsor = "sponsor"
	KindStream  = "stream"
)

// RevocationKinds lists every kind, ascending.
var RevocationKinds = []string{KindAgent, KindBuild, KindGrant, KindKey, KindPermit, KindSponsor, KindStream}

// The ten refusals Apply reports, in the order it checks them.
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
	maxExactRevocationSeq = 1<<53 - 1
)

// RevocationRefusalCodes lists the ten codes in the order Apply checks them.
var RevocationRefusalCodes = []string{
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

// RevocationState is a verifier's side: the pinned roots and the list in
// force (none: Seq 0, nothing revoked). It is a value; Apply returns a new
// one and never changes its receiver, so a caller must not edit Roots.
type RevocationState struct {
	// Roots are the pinned root key ids, sorted ascending.
	Roots []string
	// ListID, Seq, Head and IssuedAt describe the list in force; Head is
	// "" while no list is held.
	ListID   string
	Seq      int64
	Head     string
	IssuedAt string
	entries  map[[2]string][]byte // (kind, id) -> JCS bytes of the entry
}

// NewRevocationState pins the given key ids and holds no list.
func NewRevocationState(rootKeyIDs []string) RevocationState {
	return RevocationState{Roots: sortedSet(rootKeyIDs, nil)}
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
func (s RevocationState) Revoked(kind, id string) bool {
	_, ok := s.entries[[2]string{kind, id}]
	return ok
}

// Revokes reports whether the list in force names any of the (kind, id) pairs.
func (s RevocationState) Revokes(pairs ...[2]string) bool {
	for _, p := range pairs {
		if s.Revoked(p[0], p[1]) {
			return true
		}
	}
	return false
}

// RevokedIDs returns the ids the list in force names under kind, sorted.
func (s RevocationState) RevokedIDs(kind string) []string {
	out := []string{}
	for k := range s.entries {
		if k[0] == kind {
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

// Apply returns the state with signed (the JSON bytes of a signed list) as
// the list in force, or a *RevocationError. The receiver is never changed.
func (s RevocationState) Apply(signed []byte) (RevocationState, error) {
	top, err := parseJSONValue(signed)
	if err != nil {
		return s, shape("signed_list_unreadable")
	}
	obj, ok := top.(*jsonObject)
	if !ok || len(obj.values) != 2 || !hasMember(obj, "body") || !hasMember(obj, "sig") {
		return s, shape("signed_list_members")
	}
	body, err := readRevBody(obj.values["body"])
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
	return s.install(body)
}

func hasMember(o *jsonObject, name string) bool {
	_, ok := o.values[name]
	return ok
}

// install runs the chain checks (4 to 10) on a list whose shape and
// signature are already proved.
func (s RevocationState) install(b revBody) (RevocationState, error) {
	if s.ListID != "" && b.listID != s.ListID {
		return s, &RevocationError{Code: CodeOtherChain}
	}
	if b.seq <= s.Seq {
		return s, refuse(CodeRollback, "%d<=%d", b.seq, s.Seq)
	}
	if b.seq > s.Seq+1 {
		return s, refuse(CodeGap, "%d>%d", b.seq, s.Seq+1)
	}
	if b.hasPrevious != (s.Head != "") || b.previous != s.Head {
		return s, &RevocationError{Code: CodePreviousMismatch}
	}
	if s.IssuedAt != "" && b.issuedAt < s.IssuedAt {
		return s, &RevocationError{Code: CodeTimeReversed}
	}
	entries := make(map[[2]string][]byte, len(b.entries))
	for _, e := range b.entries {
		if e.revokedAt > b.issuedAt {
			return s, &RevocationError{Code: CodeEntryFromFuture}
		}
		entries[[2]string{e.kind, e.id}] = e.canon
	}
	for key, held := range s.entries {
		if !bytes.Equal(entries[key], held) {
			return s, refuse(CodeDropsEntry, "%s:%.12s", key[0], key[1])
		}
	}
	gone, joined := map[string]bool{}, []string{}
	for _, e := range b.entries {
		if e.kind == KindKey && s.isRoot(e.id) {
			gone[e.id] = true
			if e.successor != nil {
				sum := sha256.Sum256(e.successor)
				joined = append(joined, hex.EncodeToString(sum[:]))
			}
		}
	}
	return RevocationState{
		Roots:    sortedSet(append(append([]string{}, s.Roots...), joined...), gone),
		ListID:   b.listID,
		Seq:      b.seq,
		Head:     digestOfCanonical(b.canon),
		IssuedAt: b.issuedAt,
		entries:  entries,
	}, nil
}

func readRevBody(v any) (revBody, error) {
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
	if o.values["type"] != RevocationListType {
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
	for name := range o.values {
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
	if kind == KindGrant || kind == KindKey || kind == KindPermit {
		if !isHex64(id) {
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
		if kind != KindKey {
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
		if k == kind {
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
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isHex64(s string) bool { return len(s) == 64 && isLowerHex(s) }

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
