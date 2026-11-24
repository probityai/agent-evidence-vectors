package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(assertionGrade{}) }

// assertionGrade judges corpora/vectors-assertion-grade/. Each member is one
// record bundle and the trust a relying party pins. The reader derives, for
// every assertion in the bundle, the grade (I, W+, W, S, or none when the
// assertion cannot be read as signed), the route, whom it is independent of,
// the custody holder, the submission boundary, the counted witnesses with
// their coverage interval, the trust anchors, the properties, the label and
// the qualifier, with the rules the Python reader
// (packaging/agent_evidence_vectors/assertiongrade.py) applies in the same
// order; and the bundle's decision: accepted when no claim exceeds what was
// derived, rejected with the first rule that capped a claimed grade, a claimed
// route that differs at the same grade, or a claimed coverage interval wider
// than the computed one. It never reads the bundle's claim to raise a grade.
type assertionGrade struct{}

func (assertionGrade) Suite() string { return "assertion-grade/v1" }

var asgRank = map[string]int{"none": 0, "S": 1, "W": 2, "W+": 3, "I": 4}

const (
	asgMapDomain      = "agent-evidence-receipt-map/v1 key"
	asgMapCommitment  = "agent-evidence-receipt-map-commitment/v1"
	asgTenantDeclared = "tenant-declared counterparty"
	asgUnbound        = "unbound counterparty key"
	asgMutual         = "mutually signed"
	asgCustomerW      = "customer-held witness in quorum"
	asgSelfAttests    = "counterparty self-attests"
)

var asgReceiptFields = []string{"target_id", "key_id", "request_commitment", "actor_stamp_digest",
	"permit_id", "stage", "outcome", "signed_at"}

var errAsgMalformed = errors.New("bundle malformed")

type asgWitnessOut struct {
	From     int64  `json:"from"`
	Name     string `json:"name"`
	Operator string `json:"operator"`
	To       int64  `json:"to"`
}

type asgAnswer struct {
	Anchors       []string        `json:"anchors"`
	Boundary      string          `json:"boundary"`
	Custody       string          `json:"custody"`
	Grade         string          `json:"grade"`
	ID            string          `json:"id"`
	IndependentOf []string        `json:"independentOf"`
	Label         string          `json:"label"`
	Properties    []string        `json:"properties"`
	Qualifier     string          `json:"qualifier"`
	Route         string          `json:"route"`
	Witnesses     []asgWitnessOut `json:"witnesses"`
}

type asgDecision struct {
	Assertions []asgAnswer `json:"assertions"`
	Decision   string      `json:"decision"`
	Reason     string      `json:"reason"`
}

type asgVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected asgDecision       `json:"expected"`
}

// --- JSON access over a decoded tree -------------------------------------------------------

type asgMap = map[string]any

func asgObj(v any) (asgMap, bool) {
	o, ok := v.(map[string]any)
	return o, ok
}

func asgStr(o asgMap, k string) (string, bool) {
	s, ok := o[k].(string)
	return s, ok
}

// asgPins is a trust section, or an empty one when the verifier pins nothing there.
func asgPins(trust asgMap, name string) asgMap {
	o, _ := asgObj(trust[name])
	return o
}

// asgU64 converts an integer that asgInt has already checked is not negative.
func asgU64(i int64) uint64 {
	if i < 0 {
		return 0
	}
	return uint64(i) // #nosec G115 -- checked not negative on the line above
}

func asgInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil && i >= 0
}

func asgDecode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func asgCanon(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	c, err := aee.Canonicalize(raw)
	if err != nil {
		return nil
	}
	return c
}

func asgSHA(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func asgKey(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errAsgMalformed
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != s {
		return nil, errAsgMalformed
	}
	return raw, nil
}

func asgB64(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errAsgMalformed
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, errAsgMalformed
	}
	return raw, nil
}

func asgHashes(v any) ([][]byte, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, errAsgMalformed
	}
	out := make([][]byte, 0, len(list))
	for _, item := range list {
		h, err := asgB64(item)
		if err != nil || len(h) != 32 {
			return nil, errAsgMalformed
		}
		out = append(out, h)
	}
	return out, nil
}

func asgVerify(pub, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func asgSignedJSON(pub []byte, body any, sig any) bool {
	if _, ok := asgObj(body); !ok {
		return false
	}
	raw, err := asgB64(sig)
	return err == nil && asgVerify(pub, asgCanon(body), raw)
}

func asgKeyID(pub []byte) string { return hex.EncodeToString(asgSHA(pub)) }

func asgListHas(list any, v any) bool {
	l, _ := list.([]any)
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// --- RFC 9162 ----------------------------------------------------------------------------

func asgLeaf(data []byte) []byte { return asgSHA(append([]byte{0}, data...)) }

func asgNode(l, r []byte) []byte {
	b := make([]byte, 0, 65)
	b = append(b, 1)
	b = append(b, l...)
	return asgSHA(append(b, r...))
}

func asgShiftToSet(fn, sn uint64) (uint64, uint64) {
	for fn != 0 && fn&1 == 0 {
		fn, sn = fn>>1, sn>>1
	}
	return fn, sn
}

func asgInclusion(index, size uint64, leaf []byte, proof [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = asgNode(p, r)
			fn, sn = asgShiftToSet(fn, sn)
		} else {
			r = asgNode(r, p)
		}
		fn, sn = fn>>1, sn>>1
	}
	return sn == 0 && bytes.Equal(r, root)
}

func asgConsistencyFold(m, n uint64, proof [][]byte) ([]byte, []byte, bool) {
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn, sn = fn>>1, sn>>1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return nil, nil, false
		}
		if fn&1 == 1 || fn == sn {
			fr, sr = asgNode(c, fr), asgNode(c, sr)
			fn, sn = asgShiftToSet(fn, sn)
		} else {
			sr = asgNode(sr, c)
		}
		fn, sn = fn>>1, sn>>1
	}
	return fr, sr, sn == 0
}

func asgConsistency(m, n uint64, first, second []byte, proof [][]byte) bool {
	if m == 0 || m > n {
		return false
	}
	if m == n {
		return len(proof) == 0 && bytes.Equal(first, second)
	}
	if m&(m-1) == 0 {
		proof = append([][]byte{first}, proof...)
	}
	if len(proof) == 0 {
		return false
	}
	fr, sr, ok := asgConsistencyFold(m, n, proof)
	return ok && bytes.Equal(fr, first) && bytes.Equal(sr, second)
}

// --- receipt map ----------------------------------------------------------------------------

func asgU16(b []byte) []byte {
	out := make([]byte, 2, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b))) // #nosec G115 -- permit ids and stages are short; the generator writes both
	return append(out, b...)
}

func asgMapKey(issuer []byte, permit, stage string) []byte {
	b := append([]byte(asgMapDomain), issuer...)
	b = append(b, asgU16([]byte(permit))...)
	return asgSHA(append(b, asgU16([]byte(stage))...))
}

func asgMapEntry(key []byte, index uint64, leaf []byte) []byte {
	b := append([]byte{0}, key...)
	b = binary.BigEndian.AppendUint64(b, index)
	return asgSHA(append(b, leaf...))
}

type asgEntry struct {
	key   []byte
	index uint64
	leaf  []byte
}

func asgTerminal(v any) (asgEntry, bool) {
	t, ok := asgObj(v)
	if !ok {
		return asgEntry{}, false
	}
	ks, _ := asgStr(t, "key")
	ls, _ := asgStr(t, "leafHash")
	k, err1 := hex.DecodeString(ks)
	l, err2 := hex.DecodeString(ls)
	i, okI := asgInt(t["index"])
	if err1 != nil || err2 != nil || !okI || len(k) != 32 || len(l) != 32 {
		return asgEntry{}, false
	}
	return asgEntry{k, asgU64(i), l}, true
}

func asgSiblings(v any) ([][]byte, bool) {
	sibs, ok := v.([]any)
	if !ok || len(sibs) > 256 {
		return nil, false
	}
	out := make([][]byte, len(sibs))
	for i, s := range sibs {
		if s == nil {
			out[i] = make([]byte, 32)
			continue
		}
		h, err := asgB64(s)
		if err != nil || len(h) != 32 {
			return nil, false
		}
		out[i] = h
	}
	return out, true
}

// asgMapHolds is the entry the map holds for the proof's key under root, or
// false when the proof does not reproduce the root or ends anywhere but at the
// key's own entry.
func asgMapHolds(proof any, root []byte) (asgEntry, bool) {
	p, ok := asgObj(proof)
	if !ok {
		return asgEntry{}, false
	}
	ks, _ := asgStr(p, "key")
	key, err := hex.DecodeString(ks)
	siblings, okS := asgSiblings(p["siblings"])
	entry, okT := asgTerminal(p["terminal"])
	if err != nil || len(key) != 32 || !okS || !okT || !bytes.Equal(entry.key, key) {
		return asgEntry{}, false
	}
	k := new(big.Int).SetBytes(key)
	h := asgMapEntry(entry.key, entry.index, entry.leaf)
	for d := len(siblings) - 1; d >= 0; d-- {
		if k.Bit(255-d) == 1 {
			h = asgNode(siblings[d], h)
		} else {
			h = asgNode(h, siblings[d])
		}
	}
	return entry, bytes.Equal(h, root)
}

// --- C2SP notes -----------------------------------------------------------------------------

func asgKeyHash(name string, sigType byte, pub []byte) []byte {
	b := append([]byte(name+"\n"), sigType)
	return asgSHA(append(b, pub...))[:4]
}

type asgSigLine struct {
	name string
	blob []byte
}

func asgParseNote(v any) ([]byte, []asgSigLine, error) {
	text, ok := v.(string)
	if !ok || !strings.HasSuffix(text, "\n") || !strings.Contains(text, "\n\n") {
		return nil, nil, errAsgMalformed
	}
	split := strings.LastIndex(text, "\n\n")
	lines := strings.Split(text[split+2:], "\n")
	var sigs []asgSigLine
	for _, line := range lines[:len(lines)-1] {
		if !strings.HasPrefix(line, "— ") || strings.Count(line, " ") != 2 {
			return nil, nil, errAsgMalformed
		}
		parts := strings.Split(line, " ")
		blob, err := asgB64(parts[2])
		if err != nil {
			return nil, nil, err
		}
		sigs = append(sigs, asgSigLine{parts[1], blob})
	}
	return []byte(text[:split+1]), sigs, nil
}

func asgLogSigned(origin string, body []byte, sigs []asgSigLine, key []byte) bool {
	want := asgKeyHash(origin, 0x01, key)
	for _, s := range sigs {
		if s.name == origin && len(s.blob) == 68 && bytes.Equal(s.blob[:4], want) &&
			asgVerify(key, body, s.blob[4:]) {
			return true
		}
	}
	return false
}

func asgParseCheckpointBody(body []byte) (string, uint64, []byte, error) {
	lines := strings.Split(string(body), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return "", 0, nil, errAsgMalformed
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return "", 0, nil, errAsgMalformed
	}
	root, err := asgB64(lines[2])
	if err != nil {
		return "", 0, nil, err
	}
	return lines[0], size, root, nil
}

type asgCheckpoint struct {
	origin   string
	size     uint64
	root     []byte
	logOK    bool
	problems []string
	cosigs   map[string]int64
}

// asgCosigTime is the time a cosignature line carries.
func asgCosigTime(blob []byte) int64 {
	return int64(binary.BigEndian.Uint64(blob[4:12])) // #nosec G115 -- a cosignature time; compared, never used as a size
}

// asgCosigProblem is why a cosignature line under a pinned witness name is
// refused, or "" when it counts.
func asgCosigProblem(name string, blob, body []byte, pinned asgMap) (string, error) {
	key, err := asgKey(pinned["key"])
	if err != nil {
		return "", err
	}
	ts := asgCosigTime(blob)
	msg := append([]byte(fmt.Sprintf("cosignature/v1\ntime %d\n", ts)), body...)
	if !bytes.Equal(blob[:4], asgKeyHash(name, 0x04, key)) {
		return "witness_key_mismatch", nil
	}
	if !asgVerify(key, msg, blob[12:]) {
		return "witness_cosignature_invalid", nil
	}
	from, ok1 := asgInt(pinned["valid_from"])
	to, ok2 := asgInt(pinned["valid_to"])
	if !ok1 || !ok2 {
		return "", errAsgMalformed
	}
	if ts < from || ts > to {
		return "witness_key_expired", nil
	}
	return "", nil
}

func asgNewCheckpoint(text any, trust asgMap) (*asgCheckpoint, error) {
	body, sigs, err := asgParseNote(text)
	if err != nil {
		return nil, err
	}
	origin, size, root, err := asgParseCheckpointBody(body)
	if err != nil {
		return nil, err
	}
	cp := &asgCheckpoint{origin: origin, size: size, root: root, cosigs: map[string]int64{}}
	if pinned, ok := asgObj(asgPins(trust, "logs")[origin]); ok {
		key, err := asgKey(pinned["key"])
		if err != nil {
			return nil, err
		}
		cp.logOK = asgLogSigned(origin, body, sigs, key)
	}
	witnesses := asgPins(trust, "witnesses")
	for _, s := range sigs {
		pinned, ok := asgObj(witnesses[s.name])
		if !ok || s.name == origin || len(s.blob) != 76 {
			continue
		}
		problem, err := asgCosigProblem(s.name, s.blob, body, pinned)
		if err != nil {
			return nil, err
		}
		if problem != "" {
			cp.problems = append(cp.problems, problem)
			continue
		}
		ts := asgCosigTime(s.blob)
		if prev, seen := cp.cosigs[s.name]; !seen || ts < prev {
			cp.cosigs[s.name] = ts
		}
	}
	return cp, nil
}

type asgLog struct {
	origin      string
	operator    string
	pinned      bool
	checkpoints []*asgCheckpoint
	consistent  bool
}

func (l *asgLog) checkConsistent(proofs []any) error {
	for i, proof := range proofs {
		hs, err := asgHashes(proof)
		if err != nil {
			return err
		}
		a, b := l.checkpoints[i], l.checkpoints[i+1]
		if !asgConsistency(a.size, b.size, a.root, b.root, hs) {
			l.consistent = false
		}
	}
	seen := map[uint64][]byte{}
	for _, cp := range l.checkpoints {
		prev, ok := seen[cp.size]
		if (ok && !bytes.Equal(prev, cp.root)) || cp.origin != l.origin {
			l.consistent = false
		}
		if !ok {
			seen[cp.size] = cp.root
		}
	}
	return nil
}

func asgNewLog(doc any, trust asgMap) (*asgLog, error) {
	d, ok := asgObj(doc)
	if !ok {
		return nil, errAsgMalformed
	}
	origin, _ := asgStr(d, "origin")
	l := &asgLog{origin: origin, consistent: true}
	if pinned, ok := asgObj(asgPins(trust, "logs")[origin]); ok {
		l.pinned = true
		l.operator, _ = asgStr(pinned, "operator")
	}
	cps, _ := d["checkpoints"].([]any)
	for _, text := range cps {
		cp, err := asgNewCheckpoint(text, trust)
		if err != nil {
			return nil, err
		}
		l.checkpoints = append(l.checkpoints, cp)
	}
	proofs, ok := d["consistency"].([]any)
	if !ok || len(proofs) != max(len(l.checkpoints)-1, 0) {
		return nil, errAsgMalformed
	}
	return l, l.checkConsistent(proofs)
}

// --- one assertion while it is graded --------------------------------------------------------

type asgCap struct{ rule, grade string }

type asgCtx struct {
	trust   asgMap
	parties asgMap
	log     *asgLog
}

func (c *asgCtx) checkpoint(i int) *asgCheckpoint {
	if c.log == nil || i < 0 || i >= len(c.log.checkpoints) {
		return nil
	}
	return c.log.checkpoints[i]
}

type asgAssertion struct {
	a         asgMap
	ctx       *asgCtx
	st        asgMap
	about     string
	evidence  asgMap
	ceiling   string
	caps      []asgCap
	out       asgAnswer
	rootClass string
	pub       []byte
	operator  string
	root      string
	validity  asgMap
	leaf      []byte
	cpIndex   int
	tIncl     int64
	haveIncl  bool
}

func (x *asgAssertion) cap(rule, grade string) {
	x.caps = append(x.caps, asgCap{rule, grade})
	if asgRank[grade] < asgRank[x.ceiling] {
		x.ceiling = grade
	}
}

func asgNewAnswer(id string) asgAnswer {
	return asgAnswer{ID: id, Grade: "none", Route: "none", IndependentOf: []string{},
		Witnesses: []asgWitnessOut{}, Anchors: []string{}, Properties: []string{}}
}

func (x *asgAssertion) recordRole() any {
	kid, _ := asgStr(x.a, "key_id")
	pinned, _ := asgObj(asgPins(x.ctx.trust, "record_keys")[kid])
	return pinned["role"]
}

// --- counterparty key bindings ----------------------------------------------------------------

func asgClaimedKey(binding asgMap) []byte {
	kind, _ := asgStr(binding, "kind")
	holders := map[string]any{"tenant-declared": binding, "domain-document": binding["key"],
		"naming-log": binding["entry"], "rail-operator": binding["listing"]}
	h, ok := asgObj(holders[kind])
	if !ok {
		return nil
	}
	key, err := asgKey(h["key"])
	if err != nil {
		return nil
	}
	return key
}

func asgWithout(o asgMap, field string) asgMap {
	out := asgMap{}
	for k, v := range o {
		if k != field {
			out[k] = v
		}
	}
	return out
}

func asgContains(list any, item asgMap) bool {
	l, ok := list.([]any)
	if !ok {
		return false
	}
	want := asgCanon(item)
	for _, x := range l {
		if bytes.Equal(asgCanon(x), want) {
			return true
		}
	}
	return false
}

func asgCerts(v any, target string) ([]asgMap, bool) {
	chain, ok := v.([]any)
	if !ok || len(chain) == 0 {
		return nil, false
	}
	certs := make([]asgMap, len(chain))
	for i, c := range chain {
		o, ok := asgObj(c)
		if !ok {
			return nil, false
		}
		certs[i] = o
	}
	return certs, certs[0]["subject"] == target
}

func asgChainReachesRoot(certs []asgMap, trust asgMap) (bool, error) {
	for i := 0; i+1 < len(certs); i++ {
		parentKey, err := asgKey(certs[i+1]["key"])
		if err != nil {
			return false, err
		}
		if certs[i]["issuer"] != certs[i+1]["subject"] ||
			!asgSignedJSON(parentKey, asgWithout(certs[i], "sig"), certs[i]["sig"]) {
			return false, nil
		}
	}
	top := certs[len(certs)-1]
	issuer, _ := asgStr(top, "issuer")
	rootHex, ok := asgPins(trust, "web_roots")[issuer]
	if !ok {
		return false, nil
	}
	rootKey, err := asgKey(rootHex)
	if err != nil {
		return false, err
	}
	return asgSignedJSON(rootKey, asgWithout(top, "sig"), top["sig"]), nil
}

func asgBoundDomain(binding, trust asgMap, target string) (asgMap, string, bool, error) {
	doc, okD := asgObj(binding["document"])
	entry, okE := asgObj(binding["key"])
	if !okD || !okE || doc["domain"] != target || !asgContains(doc["keys"], entry) {
		return nil, "", false, nil
	}
	certs, ok := asgCerts(binding["chain"], target)
	if !ok {
		return nil, "", false, nil
	}
	leafKey, err := asgKey(certs[0]["key"])
	if err != nil {
		return nil, "", false, err
	}
	if !asgSignedJSON(leafKey, doc, binding["document_sig"]) {
		return nil, "", false, nil
	}
	reached, err := asgChainReachesRoot(certs, trust)
	if err != nil || !reached {
		return nil, "", false, err
	}
	issuer, _ := asgStr(certs[len(certs)-1], "issuer")
	return entry, "web-root:" + issuer, true, nil
}

func asgBoundNaming(binding, trust asgMap, target string) (asgMap, string, bool, error) {
	entry, okE := asgObj(binding["entry"])
	origin, _ := asgStr(binding, "origin")
	pinned, okP := asgObj(asgPins(trust, "naming_logs")[origin])
	if !okP || !okE || entry["name"] != target || entry["validation"] != "domain-control" {
		return nil, "", false, nil
	}
	body, sigs, err := asgParseNote(binding["checkpoint"])
	if err != nil {
		return nil, "", false, err
	}
	key, err := asgKey(pinned["key"])
	if err != nil {
		return nil, "", false, err
	}
	found, size, root, err := asgParseCheckpointBody(body)
	if err != nil {
		return nil, "", false, err
	}
	if found != origin || !asgLogSigned(origin, body, sigs, key) {
		return nil, "", false, nil
	}
	index, okI := asgInt(binding["leaf_index"])
	proof, err := asgHashes(binding["inclusion"])
	if !okI || err != nil {
		return nil, "", false, errAsgMalformed
	}
	if !asgInclusion(asgU64(index), size, asgLeaf(asgCanon(entry)), proof, root) {
		return nil, "", false, nil
	}
	return entry, "naming-log:" + origin, true, nil
}

func asgBoundRail(binding, trust asgMap, target string) (asgMap, string, bool, error) {
	rail, _ := asgStr(binding, "rail")
	listing, okL := asgObj(binding["listing"])
	pinned, okP := asgObj(asgPins(trust, "rail_operators")[rail])
	if !okP || !okL || listing["target"] != target {
		return nil, "", false, nil
	}
	key, err := asgKey(pinned["key"])
	if err != nil {
		return nil, "", false, err
	}
	if !asgSignedJSON(key, listing, binding["sig"]) {
		return nil, "", false, nil
	}
	return listing, "rail:" + rail, true, nil
}

var asgBindings = map[string]func(binding, trust asgMap, target string) (asgMap, string, bool, error){
	"domain-document": asgBoundDomain,
	"naming-log":      asgBoundNaming,
	"rail-operator":   asgBoundRail,
}

func asgAttested(doc any, trust asgMap) (asgMap, string, string, bool) {
	d, ok := asgObj(doc)
	if !ok {
		return nil, "", "", false
	}
	quote, ok := asgObj(d["quote"])
	if !ok {
		return nil, "", "", false
	}
	name, _ := asgStr(quote, "root")
	root, ok := asgObj(asgPins(trust, "attestation_roots")[name])
	if !ok {
		return nil, "", "", false
	}
	key, err := asgKey(root["key"])
	if err != nil || !asgSignedJSON(key, quote, d["sig"]) {
		return nil, "", "", false
	}
	class, _ := asgStr(root, "class")
	return quote, "attestation-root:" + name, class, true
}

// --- key resolution ---------------------------------------------------------------------------

func (x *asgAssertion) boundLabel(binding asgMap) (string, error) {
	kind, _ := asgStr(binding, "kind")
	check, ok := asgBindings[kind]
	if !ok {
		return asgUnbound, nil
	}
	target, _ := asgStr(x.ctx.parties, "counterparty")
	entry, anchor, bound, err := check(binding, x.ctx.trust, target)
	if err != nil || !bound {
		return asgUnbound, err
	}
	x.validity = entry
	x.out.Anchors = append(x.out.Anchors, anchor)
	return "", nil
}

func (x *asgAssertion) counterpartyLabel(binding asgMap, pub []byte) (string, error) {
	label := asgTenantDeclared
	if kind, _ := asgStr(binding, "kind"); kind != "tenant-declared" {
		var err error
		if label, err = x.boundLabel(binding); err != nil {
			return "", err
		}
	}
	pinned, ok := asgObj(asgPins(x.ctx.trust, "record_keys")[asgKeyID(pub)])
	if ok && pinned["operator"] == "tenant" {
		label = asgTenantDeclared
	}
	return label, nil
}

func (x *asgAssertion) resolveCounterparty() (bool, error) {
	binding, ok := asgObj(x.evidence["binding"])
	var pub []byte
	if ok {
		pub = asgClaimedKey(binding)
	}
	if pub == nil {
		x.cap("counterparty_key_unbound", "none")
		return false, nil
	}
	label, err := x.counterpartyLabel(binding, pub)
	if err != nil {
		return false, err
	}
	switch label {
	case asgTenantDeclared:
		x.cap("tenant_declared_counterparty", "W")
		x.out.Label = label
	case asgUnbound:
		x.cap("counterparty_key_unbound", "W")
		x.out.Label = label
	}
	x.pub, x.operator, x.root = pub, "counterparty", "counterparty"
	return true, nil
}

func (x *asgAssertion) resolveEnclave(doc any) (bool, error) {
	quote, anchor, class, ok := asgAttested(doc, x.ctx.trust)
	if !ok {
		x.cap("attestation_chain_unverified", "none")
		return false, nil
	}
	x.out.Anchors = append(x.out.Anchors, anchor)
	x.rootClass = class
	pub, err := asgKey(quote["enclave_key"])
	if err != nil {
		return false, err
	}
	x.pub, x.operator, x.root = pub, "enclave", "vendor-attestation"
	return true, nil
}

func (x *asgAssertion) resolve() (bool, error) {
	if x.about == "counterparty" {
		return x.resolveCounterparty()
	}
	if doc, ok := x.evidence["tee_decision"]; ok {
		return x.resolveEnclave(doc)
	}
	kid, _ := asgStr(x.a, "key_id")
	pinned, ok := asgObj(asgPins(x.ctx.trust, "record_keys")[kid])
	if !ok {
		x.cap("record_key_unknown", "none")
		return false, nil
	}
	pub, err := asgKey(pinned["key"])
	if err != nil {
		return false, err
	}
	x.pub = pub
	x.operator, _ = asgStr(pinned, "operator")
	x.root, _ = asgStr(pinned, "root")
	return true, nil
}

// --- the log and its witnesses ------------------------------------------------------------------

func (x *asgAssertion) included() (*asgCheckpoint, error) {
	ref, ok := asgObj(x.a["log"])
	log := x.ctx.log
	if !ok || log == nil {
		x.cap("not_witnessed", "S")
		return nil, nil
	}
	if !log.pinned {
		x.cap("log_unknown", "S")
		return nil, nil
	}
	c, okC := asgInt(ref["checkpoint"])
	if !okC || c > math.MaxInt32 {
		return nil, errAsgMalformed
	}
	x.cpIndex = int(c)
	cp := x.ctx.checkpoint(x.cpIndex)
	if cp == nil {
		return nil, errAsgMalformed
	}
	if !cp.logOK {
		x.cap("checkpoint_signature_invalid", "S")
		return nil, nil
	}
	index, okI := asgInt(ref["leaf_index"])
	proof, err := asgHashes(ref["inclusion"])
	if !okI || err != nil {
		return nil, errAsgMalformed
	}
	if !asgInclusion(asgU64(index), cp.size, x.leaf, proof, cp.root) {
		x.cap("inclusion_proof_invalid", "S")
		return nil, nil
	}
	if !log.consistent {
		x.cap("log_history_inconsistent", "S")
		return nil, nil
	}
	return cp, nil
}

func (x *asgAssertion) cosignatureTimes() map[string][]int64 {
	times := map[string][]int64{}
	for _, cp := range x.ctx.log.checkpoints[x.cpIndex:] {
		if !cp.logOK {
			continue
		}
		for _, p := range cp.problems {
			x.cap(p, "S")
		}
		for name, ts := range cp.cosigs {
			times[name] = append(times[name], ts)
		}
	}
	return times
}

func asgSpan(ts []int64) (int64, int64) {
	lo, hi := ts[0], ts[0]
	for _, t := range ts {
		lo, hi = min(lo, t), max(hi, t)
	}
	return lo, hi
}

func asgExternal(ws []asgWitnessOut) []asgWitnessOut {
	var out []asgWitnessOut
	for _, w := range ws {
		if w.Operator == "external" {
			out = append(out, w)
		}
	}
	return out
}

func (x *asgAssertion) countWitnesses(times map[string][]int64) {
	excluded := map[string]bool{}
	for _, p := range []string{x.operator, x.ctx.log.operator} {
		if p == "tenant" || p == "us" || p == "counterparty" {
			excluded[p] = true
		}
	}
	pins := asgPins(x.ctx.trust, "witnesses")
	names := make([]string, 0, len(times))
	for n := range times {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		pin, _ := asgObj(pins[name])
		op, _ := asgStr(pin, "operator")
		if !excluded[op] {
			lo, hi := asgSpan(times[name])
			x.out.Witnesses = append(x.out.Witnesses, asgWitnessOut{lo, name, op, hi})
		}
	}
}

func (x *asgAssertion) witnessing() error {
	cp, err := x.included()
	if err != nil || cp == nil {
		return err
	}
	x.countWitnesses(x.cosignatureTimes())
	if len(x.out.Witnesses) == 0 {
		x.cap("not_witnessed", "S")
		return nil
	}
	// Inclusion time is attested by the earliest external cosignature when there
	// is one: a witness the tenant runs could date its own line early.
	timed := asgExternal(x.out.Witnesses)
	if len(timed) == 0 {
		timed = x.out.Witnesses
	}
	x.tIncl, x.haveIncl = timed[0].From, true
	for _, w := range timed {
		x.tIncl = min(x.tIncl, w.From)
	}
	return nil
}

// --- routes -------------------------------------------------------------------------------------

func asgStage(stage string) bool {
	return stage == "accept" || stage == "execute" || stage == "settle" || stage == "final"
}

func (x *asgAssertion) receiptTuple() {
	for _, f := range asgReceiptFields {
		if _, ok := x.st[f]; !ok {
			x.cap("receipt_tuple_unbound", "W")
			return
		}
	}
	stage, _ := asgStr(x.st, "stage")
	target, _ := asgStr(x.ctx.parties, "counterparty")
	_, okSA := asgInt(x.st["signed_at"])
	if !asgStage(stage) || x.st["target_id"] != target || x.st["key_id"] != asgKeyID(x.pub) || !okSA {
		x.cap("receipt_tuple_unbound", "W")
	}
}

func asgInWindow(t int64, entry asgMap) bool {
	nb, ok1 := asgInt(entry["not_before"])
	na, ok2 := asgInt(entry["not_after"])
	return ok1 && ok2 && nb <= t && t <= na
}

func (x *asgAssertion) receiptWindow() {
	if !x.haveIncl {
		return
	}
	if x.validity != nil && !asgInWindow(x.tIncl, x.validity) {
		x.cap("receipt_key_not_valid_at_inclusion", "S")
	}
	stage, _ := asgStr(x.st, "stage")
	window, okW := asgInt(asgPins(x.ctx.trust, "receipt_windows")[stage])
	signedAt, okSA := asgInt(x.st["signed_at"])
	if !okSA || !okW || x.tIncl-signedAt < 0 || x.tIncl-signedAt > window {
		x.cap("receipt_window_exceeded", "S")
	}
}

func (x *asgAssertion) commitmentIncluded(proof asgMap, cp *asgCheckpoint, root []byte, aIndex int64) (bool, error) {
	commit, _ := asgObj(proof["commitment"])
	cIndex, okCI := asgInt(commit["leaf_index"])
	if !okCI || cIndex <= aIndex {
		return false, nil
	}
	inclusion, err := asgHashes(commit["inclusion"])
	if err != nil {
		return false, err
	}
	leaf := asgLeaf(asgCanon(asgMap{"format": asgMapCommitment, "root": hex.EncodeToString(root)}))
	return asgInclusion(asgU64(cIndex), cp.size, leaf, inclusion, cp.root), nil
}

func (x *asgAssertion) mapHolds(proof asgMap) (bool, error) {
	cp := x.ctx.checkpoint(x.cpIndex)
	permit, okP := asgStr(x.st, "permit_id")
	stage, _ := asgStr(x.st, "stage")
	if cp == nil || !okP || !asgStage(stage) {
		return false, nil
	}
	rootHex, _ := asgStr(proof, "root")
	root, err := hex.DecodeString(rootHex)
	if err != nil {
		return false, errAsgMalformed
	}
	ref, _ := asgObj(x.a["log"])
	aIndex, _ := asgInt(ref["leaf_index"])
	committed, err := x.commitmentIncluded(proof, cp, root, aIndex)
	if err != nil || !committed {
		return false, err
	}
	entry, ok := asgMapHolds(proof["proof"], root)
	key := asgMapKey(asgSHA(x.pub), permit, stage)
	return ok && bytes.Equal(entry.key, key) && entry.index == asgU64(aIndex) &&
		bytes.Equal(entry.leaf, x.leaf), nil
}

func (x *asgAssertion) counterparty() (string, []string, string, error) {
	x.receiptTuple()
	x.receiptWindow()
	proof, ok := asgObj(x.evidence["map"])
	if !ok {
		x.cap("map_proof_missing", "W")
		return "I-COUNTERPARTY", []string{"tenant"}, "target", nil
	}
	holds, err := x.mapHolds(proof)
	if err != nil {
		return "", nil, "", err
	}
	if !holds {
		x.cap("map_proof_mismatch", "W")
	}
	return "I-COUNTERPARTY", []string{"tenant"}, "target", nil
}

func (x *asgAssertion) enclave() (string, []string, string, error) {
	td, _ := asgObj(x.evidence["tee_decision"])
	quote, _ := asgObj(td["quote"])
	meas := asgPins(x.ctx.trust, "measurements")
	if !asgListHas(meas["decision_path"], quote["measurement"]) {
		x.cap("measurement_not_allowed", "W")
	}
	if quote["channel_termination"] != "attested-tls" {
		x.cap("channel_not_terminated_in_enclave", "W")
	}
	return "I-TEE", []string{"tenant", "us"}, "enclave channel", nil
}

func (x *asgAssertion) notary() (string, []string, string, error) {
	request, ok := asgObj(x.st["request"])
	if !ok || x.st["request_commitment"] != hex.EncodeToString(asgSHA(asgCanon(request))) {
		x.cap("notary_saw_commitment_only", "W")
	}
	if x.operator != "external" {
		x.cap("notary_not_independent", "W")
	}
	return "I-NOTARY", []string{"tenant", "us"}, "notary", nil
}

// route is the I route the assertion aims at, whom it would be independent of,
// and its boundary; the route's rules cap the grade on the way.
func (x *asgAssertion) route() (string, []string, string, error) {
	switch {
	case x.about == "counterparty":
		return x.counterparty()
	case x.operator == "enclave":
		return x.enclave()
	case (x.operator == "external" || x.operator == "tenant" || x.operator == "us") &&
		x.recordRole() == "notary":
		return x.notary()
	case x.about == "gateway":
		x.cap("gateway_self_attested", "W")
		return "I-HOSTED-WITNESS-QUORUM", []string{}, "gateway ingress", nil
	case x.operator == "tenant":
		x.cap("content_self_attested", "W+")
		return "", []string{}, "tenant signer", nil
	}
	return "I-HOSTED-WITNESS-QUORUM", []string{"tenant"}, "gateway ingress", nil
}

// --- the W+ counter routes ---------------------------------------------------------------------

func (x *asgAssertion) hsmAudit(hsm asgMap) ([]asgMap, error) {
	dname, _ := asgStr(hsm, "device")
	device, ok := asgObj(asgPins(x.ctx.trust, "hsm_devices")[dname])
	if !ok || device["per_key_usage_logging"] != true {
		return nil, nil
	}
	model, _ := asgStr(device, "model")
	x.out.Anchors = append(x.out.Anchors, "hsm:"+model)
	auditKey, err := asgKey(device["audit_key"])
	if err != nil {
		return nil, err
	}
	entries, _ := hsm["audit"].([]any)
	var rows []asgMap
	for _, e := range entries {
		eo, _ := asgObj(e)
		body, okB := asgObj(eo["entry"])
		if !okB || !asgSignedJSON(auditKey, body, eo["sig"]) {
			return nil, nil
		}
		rows = append(rows, body)
	}
	return rows, nil
}

func asgGap(rows []asgMap) bool {
	seq0, ok := asgInt(rows[0]["seq"])
	for i, row := range rows {
		s, okS := asgInt(row["seq"])
		if !ok || !okS || s != seq0+int64(i) {
			return true
		}
	}
	return false
}

func (x *asgAssertion) hsmAccounted(rows []asgMap, accounted []any) (bool, error) {
	var mine []asgMap
	hasLeaf := false
	for _, row := range rows {
		if row["key_id"] == asgKeyID(x.pub) {
			mine = append(mine, row)
			hasLeaf = hasLeaf || row["leaf_hash"] == hex.EncodeToString(x.leaf)
		}
	}
	cp := x.ctx.checkpoint(x.cpIndex)
	if cp == nil || len(accounted) != len(mine) || !hasLeaf {
		return false, nil
	}
	for i, row := range mine {
		acc, _ := asgObj(accounted[i])
		idx, okI := asgInt(acc["leaf_index"])
		proof, err := asgHashes(acc["inclusion"])
		lh, _ := asgStr(row, "leaf_hash")
		lb, errH := hex.DecodeString(lh)
		if !okI || err != nil || errH != nil {
			return false, errAsgMalformed
		}
		if !asgInclusion(asgU64(idx), cp.size, lb, proof, cp.root) {
			return false, nil
		}
	}
	return true, nil
}

func (x *asgAssertion) hsmRoute(hsm asgMap) (string, error) {
	rows, err := x.hsmAudit(hsm)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		x.cap("hsm_counter_not_attested", "W")
		return "", nil
	}
	if asgGap(rows) {
		x.cap("hsm_counter_gap", "W")
	}
	accounted, _ := hsm["accounted"].([]any)
	ok, err := x.hsmAccounted(rows, accounted)
	if err != nil {
		return "", err
	}
	if !ok {
		x.cap("hsm_signature_unaccounted", "W")
	}
	return "W+-HSM-STREAM", nil
}

func (x *asgAssertion) journalRoute(doc any) string {
	quote, anchor, class, ok := asgAttested(doc, x.ctx.trust)
	if !ok {
		x.cap("attestation_chain_unverified", "W")
		return ""
	}
	x.out.Anchors = append(x.out.Anchors, anchor)
	x.rootClass = class
	meas := asgPins(x.ctx.trust, "measurements")
	if !asgListHas(meas["journal"], quote["measurement"]) || quote["journal_key_id"] != asgKeyID(x.pub) {
		x.cap("measurement_not_allowed", "W")
	}
	if quote["nonce"] != x.ctx.trust["challenge"] {
		x.cap("stale_challenge", "W")
	}
	cp := x.ctx.checkpoint(x.cpIndex)
	size, okS := asgInt(quote["tree_size"])
	if cp == nil || quote["journal_head"] != hex.EncodeToString(cp.root) || !okS || asgU64(size) != cp.size {
		x.cap("journal_head_mismatch", "W")
	}
	return "W+-TEE-JOURNAL"
}

func (x *asgAssertion) counterRoute() (string, error) {
	if hsm, ok := x.evidence["hsm"]; ok {
		h, _ := asgObj(hsm)
		return x.hsmRoute(h)
	}
	if doc, ok := x.evidence["tee_journal"]; ok {
		return x.journalRoute(doc), nil
	}
	x.cap("no_key_use_counter", "W")
	return "", nil
}

func (x *asgAssertion) mutualSigned() bool {
	pop, ok := asgObj(x.evidence["pop"])
	rc, okR := x.st["request_commitment"]
	if !ok || !okR {
		return false
	}
	id, _ := asgStr(pop, "agent_key_id")
	agent, ok := asgObj(asgPins(x.ctx.trust, "agent_keys")[id])
	if !ok {
		return false
	}
	key, err := asgKey(agent["key"])
	return err == nil && asgSignedJSON(key, asgMap{"request_commitment": rc}, pop["sig"])
}

// --- one assertion end to end -------------------------------------------------------------------

func asgHasProp(props []string, p string) bool {
	for _, x := range props {
		if x == p {
			return true
		}
	}
	return false
}

func (x *asgAssertion) properties() {
	if (x.about == "gateway" || x.about == "tenant") && x.mutualSigned() {
		x.out.Properties = append(x.out.Properties, asgMutual)
	}
	if x.operator == "us" {
		for _, w := range x.out.Witnesses {
			if w.Operator == "tenant" {
				x.out.Properties = append(x.out.Properties, asgCustomerW)
				break
			}
		}
	}
	if x.ceiling == "I" && x.about == "counterparty" {
		x.out.Properties = append(x.out.Properties, asgSelfAttests)
	}
}

func (x *asgAssertion) place(routeI string, independent []string, counterRoute string) {
	switch x.ceiling {
	case "I":
		x.out.Route, x.out.IndependentOf = routeI, independent
	case "W+":
		x.out.Route = counterRoute
	case "W":
		x.out.Route, x.out.IndependentOf = "W-WITNESSED", []string{}
		if x.operator == "us" && x.about == "tenant" && asgHasProp(x.out.Properties, asgCustomerW) {
			x.out.Route, x.out.IndependentOf = "W-MANAGED-CUSTOMER-WITNESS", []string{"us"}
		}
	case "S":
		x.out.Route = "S-LOCAL"
	}
}

func (x *asgAssertion) qualify(external []asgWitnessOut) {
	if x.ceiling != "I" && x.ceiling != "W+" {
		return
	}
	pins := asgPins(x.ctx.trust, "witnesses")
	staging := len(external) > 0
	for _, w := range external {
		pin, _ := asgObj(pins[w.Name])
		staging = staging && pin["list"] == "staging"
	}
	if staging || x.rootClass != "production" {
		x.out.Qualifier = "staging-grade"
	}
}

func asgSortedSet(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func (x *asgAssertion) finish() asgAnswer {
	if x.ceiling == "none" {
		return asgNewAnswer(x.out.ID)
	}
	x.out.Grade = x.ceiling
	x.out.Properties = asgSortedSet(x.out.Properties)
	x.out.Anchors = asgSortedSet(x.out.Anchors)
	return x.out
}

func (x *asgAssertion) signedAndLogged() (bool, error) {
	ok, err := x.resolve()
	if err != nil || !ok {
		return false, err
	}
	x.out.Custody = x.operator
	sig, err := asgB64(x.a["sig"])
	if err != nil {
		return false, err
	}
	if !asgVerify(x.pub, asgCanon(x.st), sig) {
		x.cap("record_signature_invalid", "none")
		return false, nil
	}
	x.leaf = asgLeaf(asgCanon(asgMap{"key_id": asgKeyID(x.pub), "sig": x.a["sig"], "statement": x.st}))
	return true, x.witnessing()
}

func (x *asgAssertion) wrongTenant() bool {
	t, ok := asgStr(x.st, "tenant")
	return x.about != "counterparty" && (!ok || t != x.ctx.parties["tenant"])
}

func (x *asgAssertion) grade() (asgAnswer, error) {
	if x.st == nil || (x.about != "tenant" && x.about != "gateway" && x.about != "counterparty") {
		return asgAnswer{}, errAsgMalformed
	}
	if x.wrongTenant() {
		x.cap("wrong_tenant", "none")
		return x.finish(), nil
	}
	if ok, err := x.signedAndLogged(); err != nil || !ok {
		return x.finish(), err
	}
	routeI, independent, boundary, err := x.route()
	if err != nil {
		return asgAnswer{}, err
	}
	if x.root == "customer-custody" {
		x.cap("customer_custody_root", "W+")
	}
	counterRoute := ""
	if x.ceiling == "W+" {
		if counterRoute, err = x.counterRoute(); err != nil {
			return asgAnswer{}, err
		}
	}
	external := asgExternal(x.out.Witnesses)
	if len(x.out.Witnesses) > 0 && len(external) == 0 {
		x.cap("no_external_witness", "W")
	}
	x.properties()
	x.out.Boundary = boundary
	x.place(routeI, independent, counterRoute)
	x.qualify(external)
	return x.finish(), nil
}

func asgGradeAssertion(a asgMap, ctx *asgCtx) (asgAnswer, []asgCap) {
	id := fmt.Sprint(a["id"])
	st, _ := asgObj(a["statement"])
	about, _ := asgStr(a, "about")
	evidence, _ := asgObj(a["evidence"])
	x := &asgAssertion{a: a, ctx: ctx, st: st, about: about, evidence: evidence, ceiling: "I",
		out: asgNewAnswer(id), rootClass: "production", cpIndex: -1}
	ans, err := x.grade()
	if err != nil {
		return asgNewAnswer(id), []asgCap{{"bundle_malformed", "none"}}
	}
	return ans, x.caps
}

// --- the bundle's decision ----------------------------------------------------------------------

func asgCovered(claim asgMap, ws []asgWitnessOut) bool {
	cov, ok := claim["coverage"]
	if !ok {
		return true
	}
	c, ok := asgObj(cov)
	if !ok {
		return false
	}
	from, ok1 := asgInt(c["from"])
	to, ok2 := asgInt(c["to"])
	for _, w := range ws {
		if w.Name == c["witness"] {
			return ok1 && ok2 && w.From <= from && to <= w.To
		}
	}
	return false
}

func asgClaimedRank(claim asgMap) (string, int) {
	claimed, ok := asgStr(claim, "grade")
	if !ok {
		claimed = "S"
	}
	rank, known := asgRank[claimed]
	if !known {
		rank = len(asgRank)
	}
	return claimed, rank
}

// asgRefusal is why the bundle is refused on this assertion, or "".
func asgRefusal(out asgAnswer, caps []asgCap, claim asgMap) string {
	claimed, claimedRank := asgClaimedRank(claim)
	if out.Grade == "none" || claimedRank > asgRank[out.Grade] {
		want := claimedRank
		if out.Grade == "none" {
			want = asgRank["S"]
		}
		for _, c := range caps {
			if asgRank[c.grade] < want {
				return c.rule
			}
		}
		return "bundle_malformed"
	}
	if route, has := asgStr(claim, "route"); claimed == out.Grade && has && route != out.Route {
		return "claim_route_mismatch"
	}
	if !asgCovered(claim, out.Witnesses) {
		return "coverage_overclaimed"
	}
	return ""
}

func asgAssertions(bundle asgMap) ([]asgMap, bool) {
	list, _ := bundle["assertions"].([]any)
	ids := map[string]bool{}
	out := make([]asgMap, 0, len(list))
	for _, item := range list {
		a, ok := asgObj(item)
		id := fmt.Sprint(a["id"])
		if !ok || ids[id] {
			return nil, false
		}
		ids[id] = true
		out = append(out, a)
	}
	return out, len(out) > 0
}

// asgDecide is the reader's answer for one case document.
func asgDecide(doc any) asgDecision {
	d, _ := asgObj(doc)
	trust, okT := asgObj(d["trust"])
	bundle, okB := asgObj(d["bundle"])
	refused := asgDecision{Assertions: []asgAnswer{}, Decision: "rejected", Reason: "bundle_malformed"}
	if !okT || !okB {
		return refused
	}
	ctx := &asgCtx{trust: trust, parties: asgPins(trust, "parties")}
	if logDoc, ok := bundle["log"]; ok {
		l, err := asgNewLog(logDoc, trust)
		if err != nil {
			return refused
		}
		ctx.log = l
	}
	list, ok := asgAssertions(bundle)
	if !ok {
		return refused
	}
	answers := []asgAnswer{}
	refusal := ""
	for _, a := range list {
		out, caps := asgGradeAssertion(a, ctx)
		answers = append(answers, out)
		if refusal == "" {
			claim, _ := asgObj(a["claim"])
			refusal = asgRefusal(out, caps, claim)
		}
	}
	if refusal == "" {
		return asgDecision{Assertions: answers, Decision: "accepted", Reason: "grades_derived"}
	}
	return asgDecision{Assertions: answers, Decision: "rejected", Reason: refusal}
}

func (assertionGrade) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v asgVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = asgJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func asgJudgeMember(caseDir string, v asgVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, "case.json cannot be read: "+err.Error())
	}
	if err := refuseRepeatedMembers(body); err != nil {
		return append(findings, "case.json does not parse: "+err.Error())
	}
	doc, err := asgDecode(body)
	if err != nil {
		return append(findings, "case.json does not parse: "+err.Error())
	}
	got := asgDecide(doc)
	if !reflect.DeepEqual(got, v.Expected) {
		gotJSON, _ := json.Marshal(got)
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s: %s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason, gotJSON))
	}
	return findings
}
