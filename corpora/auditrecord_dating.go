package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/probityai/agent-evidence-vectors/aee"
)

// The dating check of Section 4.7.1 of draft-gilda-audit-agent-audit-record-00,
// restated from the draft for the Go rail. A retained record is an envelope
// beside the retention entry its retaining party keeps. The record is dated by
// the earliest anchor, of either origin, that validates over the digest of the
// RFC 8785 bytes of the envelope; an anchor that does not validate dates
// nothing and makes nothing malformed. The entry checks (R3, R4, R6, R7, R9)
// make the entry malformed and never change the envelope's verdict.
//
// Two anchor kinds validate on this rail, each as a hash commitment under
// Section 4.7.2 against what the manifest's anchorTrust holds. A
// transparency-log anchor is an RFC 9162 TransItem of type inclusion_proof_v2
// over the 32 bytes of envelopeDigest that recomputes to a held tree head. An
// opentimestamps anchor is a DetachedTimestampFile over envelopeDigest whose
// Bitcoin attestation's message is the Merkle root of the held 80-byte block
// header at that height; its time is the header's time, and a comparison with
// it allows 7200 seconds in place of the skew tolerance. An rfc3161 anchor
// dates nothing here, because this rail holds no time-stamping authority path.

const arInclusionProofV2 = 0x0106

type arTreeHeadJSON struct {
	LogID     string `json:"logId"`
	TreeSize  uint64 `json:"treeSize"`
	RootHash  string `json:"rootHash"`
	Timestamp string `json:"timestamp"`
}

type arBlockHeaderJSON struct {
	Height uint64 `json:"height"`
	Header string `json:"header"`
}

// arTreeHead is one thing a verifier holds to validate an anchor: a tree head,
// or, with block set, a block header whose root is its Merkle root.
type arTreeHead struct {
	logID     []byte
	treeSize  uint64
	root      []byte
	timestamp string
	block     bool
	height    uint64
}

// arRootResult is the delegation root's result (R13 to R15).
type arRootResult struct {
	Result    string `json:"result"`
	Algorithm string `json:"algorithm,omitempty"`
}

var arNotEstablished = arRootResult{Result: "not-established"}

const arOTSTolerance = 7200 * time.Second

var (
	arOTSMagic   = mustHex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
	arOTSBitcoin = mustHex("0588960d73d71901")
)

func mustHex(text string) []byte {
	out, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return out
}

// arDating is the dating result in the manifest's expected.dating shape.
type arDating struct {
	Entry   string   `json:"entry"`
	Codes   []string `json:"codes"`
	DatedAt string   `json:"datedAt,omitempty"`
	Receipt string   `json:"receipt,omitempty"`
	// DelegationRoot sits beside the verdict and the dating and changes neither.
	DelegationRoot arRootResult `json:"delegationRoot"`
}

func (d arDating) equal(other arDating) bool {
	if d.Entry != other.Entry || d.DatedAt != other.DatedAt || d.Receipt != other.Receipt ||
		d.DelegationRoot != other.DelegationRoot || len(d.Codes) != len(other.Codes) {
		return false
	}
	for i := range d.Codes {
		if d.Codes[i] != other.Codes[i] {
			return false
		}
	}
	return true
}

func arHeads(manifest *arManifest) []arTreeHead {
	var heads []arTreeHead
	for _, h := range manifest.AnchorTrust.TreeHeads {
		logID, errID := hex.DecodeString(h.LogID)
		root, errRoot := hex.DecodeString(h.RootHash)
		if errID == nil && errRoot == nil {
			heads = append(heads, arTreeHead{logID: logID, treeSize: h.TreeSize, root: root, timestamp: h.Timestamp})
		}
	}
	for _, b := range manifest.AnchorTrust.BlockHeaders {
		header, err := hex.DecodeString(b.Header)
		if err != nil || len(header) != 80 {
			continue
		}
		seconds := int64(header[68]) | int64(header[69])<<8 | int64(header[70])<<16 | int64(header[71])<<24
		heads = append(heads, arTreeHead{root: header[36:68], block: true, height: b.Height,
			timestamp: time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")})
	}
	return heads
}

// varuint reads an OpenTimestamps unsigned LEB128 integer of at most 9 bytes.
func (r *arTLS) varuint() (uint64, error) {
	var value uint64
	for shift := uint(0); shift <= 56; shift += 7 {
		raw, err := r.take(1)
		if err != nil {
			return 0, err
		}
		value |= uint64(raw[0]&0x7f) << shift
		if raw[0]&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errProof
}

const arOTSMaxBytes, arOTSMaxDepth = 4096, 256

func (r *arTLS) varbytes() ([]byte, error) {
	n, err := r.varuint()
	if err != nil || n > arOTSMaxBytes {
		return nil, errProof
	}
	return r.take(int(n))
}

type arAttestation struct{ message, tag, payload []byte }

// arOTSTimestamp reads one timestamp: items, each but the last after 0xff.
func arOTSTimestamp(r *arTLS, message []byte, out *[]arAttestation, depth int) error {
	if depth > arOTSMaxDepth {
		return errProof
	}
	for {
		raw, err := r.take(1)
		if err != nil {
			return err
		}
		tag, more := raw[0], raw[0] == 0xff
		if more {
			if raw, err = r.take(1); err != nil {
				return err
			}
			tag = raw[0]
		}
		if err := arOTSItem(r, tag, message, out, depth); err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

func arOTSItem(r *arTLS, tag byte, message []byte, out *[]arAttestation, depth int) error {
	var result []byte
	switch tag {
	case 0x00:
		kind, err := r.take(8)
		if err != nil {
			return err
		}
		payload, err := r.varbytes()
		if err != nil {
			return err
		}
		*out = append(*out, arAttestation{message, kind, payload})
		return nil
	case 0x08:
		sum := sha256.Sum256(message)
		result = sum[:]
	case 0xf0, 0xf1:
		arg, err := r.varbytes()
		if err != nil {
			return err
		}
		if tag == 0xf0 {
			result = append(append([]byte{}, message...), arg...)
		} else {
			result = append(append([]byte{}, arg...), message...)
		}
	default:
		return errProof
	}
	if len(result) > arOTSMaxBytes {
		return errProof
	}
	return arOTSTimestamp(r, result, out, depth+1)
}

// arOTSAttestations decodes a DetachedTimestampFile over digest.
func arOTSAttestations(proof, digest []byte) ([]arAttestation, error) {
	r := &arTLS{data: proof}
	magic, err := r.take(len(arOTSMagic))
	if err != nil || !bytes.Equal(magic, arOTSMagic) {
		return nil, errProof
	}
	if version, err := r.varuint(); err != nil || version != 1 {
		return nil, errProof
	}
	op, err := r.take(1)
	if err != nil || op[0] != 0x08 {
		return nil, errProof
	}
	if file, err := r.take(32); err != nil || !bytes.Equal(file, digest) {
		return nil, errProof
	}
	var out []arAttestation
	if err := arOTSTimestamp(r, digest, &out, 0); err != nil {
		return nil, err
	}
	if r.at != len(proof) {
		return nil, errProof
	}
	return out, nil
}

// arOTSTime is the lowest held block a Bitcoin attestation's message is the
// Merkle root of; a pending attestation validates nothing (R12).
func arOTSTime(proof, digest []byte, heads []arTreeHead) (string, uint64, bool) {
	attestations, err := arOTSAttestations(proof, digest)
	if err != nil {
		return "", 0, false
	}
	found, best, when := false, uint64(0), ""
	for _, a := range attestations {
		if !bytes.Equal(a.tag, arOTSBitcoin) {
			continue
		}
		pr := &arTLS{data: a.payload}
		height, err := pr.varuint()
		if err != nil || pr.at != len(a.payload) {
			return "", 0, false
		}
		for _, head := range heads {
			if head.block && head.height == height && bytes.Equal(head.root, a.message) && (!found || height < best) {
				found, best, when = true, height, head.timestamp
			}
		}
	}
	return when, best, found
}

var errProof = errors.New("inclusion proof unreadable")

type arTLS struct {
	data []byte
	at   int
}

func (r *arTLS) take(n int) ([]byte, error) {
	if n < 0 || r.at+n > len(r.data) {
		return nil, errProof
	}
	out := r.data[r.at : r.at+n]
	r.at += n
	return out, nil
}

func (r *arTLS) uint(n int) (uint64, error) {
	raw, err := r.take(n)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, b := range raw {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// arInclusionProof decodes an RFC 9162 Section 4.12 TransItem.
func arInclusionProof(proof []byte) (logID []byte, treeSize, leafIndex uint64, path [][]byte, err error) {
	r := &arTLS{data: proof}
	kind, err := r.uint(2)
	if err != nil || kind != arInclusionProofV2 {
		return nil, 0, 0, nil, errProof
	}
	idLen, err := r.uint(1)
	if err != nil || idLen < 2 || idLen > 127 {
		return nil, 0, 0, nil, errProof
	}
	if logID, err = r.take(int(idLen)); err != nil {
		return nil, 0, 0, nil, err
	}
	if treeSize, err = r.uint(8); err != nil {
		return nil, 0, 0, nil, err
	}
	if leafIndex, err = r.uint(8); err != nil {
		return nil, 0, 0, nil, err
	}
	pathLen, err := r.uint(2)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	if pathLen > uint64(len(proof)) {
		return nil, 0, 0, nil, errProof
	}
	raw, err := r.take(int(pathLen)) // #nosec G115 -- bounded by len(proof) above
	if err != nil || r.at != len(proof) {
		return nil, 0, 0, nil, errProof
	}
	nodes := &arTLS{data: raw}
	for nodes.at < len(raw) {
		n, err := nodes.uint(1)
		if err != nil || n < 32 {
			return nil, 0, 0, nil, errProof
		}
		node, err := nodes.take(int(n)) // #nosec G115 -- n is one octet, at most 255
		if err != nil {
			return nil, 0, 0, nil, err
		}
		path = append(path, node)
	}
	return logID, treeSize, leafIndex, path, nil
}

func arHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// arInclusionRoot is RFC 9162 Section 2.1.3.2, returning the root the path
// recomputes to, or nil when the path cannot be applied.
func arInclusionRoot(leaf []byte, leafIndex, treeSize uint64, path [][]byte) []byte {
	if leafIndex >= treeSize {
		return nil
	}
	fn, sn := leafIndex, treeSize-1
	r := arHash([]byte{0}, leaf)
	for _, p := range path {
		if sn == 0 {
			return nil
		}
		if fn&1 == 1 || fn == sn {
			r = arHash([]byte{1}, p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = arHash([]byte{1}, r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil
	}
	return r
}

// arAnchorTime returns the time an anchor establishes over digest, and for an
// opentimestamps anchor its block height with ots set; "" when it does not validate.
func arAnchorTime(anchor map[string]any, digest []byte, heads []arTreeHead) (string, uint64, bool) {
	text, _ := anchor["proof"].(string)
	proof, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", 0, false
	}
	switch anchor["kind"] {
	case "opentimestamps":
		return arOTSTime(proof, digest, heads)
	case "transparency-log":
	default:
		return "", 0, false
	}
	logID, size, index, path, err := arInclusionProof(proof)
	if err != nil {
		return "", 0, false
	}
	root := arInclusionRoot(digest, index, size, path)
	for _, head := range heads {
		if !head.block && bytes.Equal(head.logID, logID) && head.treeSize == size && root != nil && bytes.Equal(head.root, root) {
			return head.timestamp, 0, false
		}
	}
	return "", 0, false
}

type arRetained struct {
	entry      map[string]any
	received   bool
	issuedAt   time.Time
	receivedAt *time.Time
	retention  *time.Time
	digest     string
	// retentionOTS is set when the retention time is an opentimestamps time.
	retentionOTS bool
	rootDigest   string
	root         arRootResult
}

func (r *arRetained) tolerance() time.Duration {
	if r.retentionOTS {
		return arOTSTolerance
	}
	return arSkewTolerance
}

var arJWKAlgorithms = map[[2]string]string{
	{"OKP", "Ed25519"}: "Ed25519", {"OKP", "Ed448"}: "Ed448",
	{"EC", "P-256"}: "P-256", {"EC", "P-384"}: "P-384", {"EC", "P-521"}: "P-521",
}

func arJWKAlgorithm(material []byte) (string, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(material, &set); err != nil {
		return "", err
	}
	algorithm := ""
	for _, k := range set.Keys {
		a, ok := arJWKAlgorithms[[2]string{k.Kty, k.Crv}]
		if !ok || (algorithm != "" && a != algorithm) {
			return "", errProof
		}
		algorithm = a
	}
	if algorithm == "" {
		return "", errProof
	}
	return algorithm, nil
}

// arDelegationRoot establishes the root from a delegation-root element whose
// digest equals delegation.rootDigest (R13); none leaves it not established,
// never a pass (R14); an unequal digest makes the entry malformed (R15).
func arDelegationRoot(r *arRetained) error {
	data, _ := r.entry["validationData"].([]any)
	var elements []map[string]any
	for _, item := range data {
		if element, ok := item.(map[string]any); ok && element["for"] == "delegation-root" {
			elements = append(elements, element)
		}
	}
	if len(elements) > 1 || (len(elements) == 1 && r.rootDigest == "") {
		return arRefuse("entry-delegation-root-unexpected")
	}
	if len(elements) == 0 {
		return nil
	}
	text, _ := elements[0]["value"].(string)
	material, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return arRefuse("entry-delegation-root-unreadable")
	}
	sum := sha256.Sum256(material)
	if hex.EncodeToString(sum[:]) != r.rootDigest {
		return arRefuse("entry-delegation-root-mismatch")
	}
	algorithm, err := arJWKAlgorithm(material)
	if err != nil {
		return arRefuse("entry-delegation-root-unreadable")
	}
	r.root = arRootResult{Result: "established", Algorithm: algorithm}
	return nil
}

func arRetentionShape(entry map[string]any) error {
	_, digestOK := entry["envelopeDigest"].(string)
	_, receivedOK := entry["received"].(bool)
	within, withinOK := arMaxAge(entry["anchorWithin"])
	anchors, anchorsOK := entry["anchors"].([]any)
	if !digestOK || !receivedOK || !withinOK || within < 0 || !anchorsOK {
		return arRefuse("entry-shape-malformed")
	}
	for _, item := range anchors {
		anchor, ok := item.(map[string]any)
		kind, _ := anchor["kind"].(string)
		origin, _ := anchor["origin"].(string)
		_, proofOK := anchor["proof"].(string)
		if !ok || !proofOK || !arContains([]string{"rfc3161", "transparency-log", "opentimestamps"}, kind) ||
			!arContains([]string{"retainer", "received"}, origin) {
			return arRefuse("entry-shape-malformed")
		}
	}
	return nil
}

type arDatingRule struct {
	name  string
	check func(*arRetained) error
}

func arDatingRules() []arDatingRule {
	return []arDatingRule{
		{"entry-received-at", func(r *arRetained) error {
			raw, has := r.entry["receivedAt"]
			if r.received != has {
				return arRefuse("entry-received-at-inconsistent")
			}
			if has {
				text, _ := raw.(string)
				at, err := arInstant(text)
				if err != nil {
					return err
				}
				r.receivedAt = &at
			}
			return nil
		}},
		{"entry-envelope-digest", func(r *arRetained) error {
			if r.entry["envelopeDigest"] != r.digest {
				return arRefuse("entry-envelope-digest-mismatch")
			}
			return nil
		}},
		{"entry-retainer-anchor", func(r *arRetained) error {
			if !r.received {
				return nil
			}
			for _, item := range r.entry["anchors"].([]any) {
				if item.(map[string]any)["origin"] == "retainer" {
					return nil
				}
			}
			return arRefuse("entry-retainer-anchor-missing")
		}},
		{"entry-received-before-issued", func(r *arRetained) error {
			if r.receivedAt != nil && r.receivedAt.Before(r.issuedAt.Add(-arSkewTolerance)) {
				return arRefuse("entry-received-before-issued")
			}
			return nil
		}},
		{"entry-received-after-anchor", func(r *arRetained) error {
			if r.receivedAt != nil && r.retention != nil && r.receivedAt.After(r.retention.Add(r.tolerance())) {
				return arRefuse("entry-received-after-anchor")
			}
			return nil
		}},
		{"entry-anchor-late", func(r *arRetained) error {
			if r.retention == nil {
				return nil
			}
			start := r.issuedAt
			if r.receivedAt != nil {
				start = *r.receivedAt
			}
			within, _ := arMaxAge(r.entry["anchorWithin"])
			if r.retention.After(start.Add(time.Duration(within)*time.Second + r.tolerance())) {
				return arRefuse("entry-anchor-late")
			}
			return nil
		}},
		{"entry-delegation-root", arDelegationRoot},
	}
}

type arMoment struct {
	origin string
	at     time.Time
	text   string
	ots    bool
	height uint64
}

// arEarlier orders two opentimestamps anchors by block height, any other pair by time.
func arEarlier(a, b arMoment) bool {
	if a.ots && b.ots && a.height != b.height {
		return a.height < b.height
	}
	return a.at.Before(b.at)
}

// arAnchorMoments returns every anchor that validates over digest, earliest
// first. disabled of anchor-validation dates every anchor at the first held
// head, which is how the sweep asks whether validation is load-bearing.
func arAnchorMoments(entry map[string]any, digest []byte, heads []arTreeHead, disabled string) []arMoment {
	var moments []arMoment
	for _, item := range entry["anchors"].([]any) {
		anchor := item.(map[string]any)
		text, height, ots := arAnchorTime(anchor, digest, heads)
		if disabled == "anchor-validation" && len(heads) > 0 {
			text, height, ots = heads[0].timestamp, 0, false
		}
		if at, err := arInstant(text); text != "" && err == nil {
			moments = append(moments, arMoment{anchor["origin"].(string), at, text, ots, height})
		}
	}
	sort.SliceStable(moments, func(i, j int) bool { return arEarlier(moments[i], moments[j]) })
	return moments
}

// arDatedAt is the time of the earliest validating anchor of either origin;
// disabled of earliest-anchor reads only retainer anchors when there are any.
func arDatedAt(moments []arMoment, disabled string) string {
	chosen := moments
	if disabled == "earliest-anchor" {
		var retainerOnly []arMoment
		for _, m := range moments {
			if m.origin == "retainer" {
				retainerOnly = append(retainerOnly, m)
			}
		}
		if len(retainerOnly) > 0 {
			chosen = retainerOnly
		}
	}
	if len(chosen) == 0 {
		return ""
	}
	return chosen[0].text
}

// arRetainedState reads what the entry checks need from the envelope and entry.
func arRetainedState(envelope any, entry map[string]any, issuedAt string) (*arRetained, []byte, error) {
	marshalled, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := aee.Canonicalize(marshalled)
	if err != nil {
		return nil, nil, err
	}
	issued, err := arInstant(issuedAt)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(canonical)
	r := &arRetained{entry: entry, received: entry["received"].(bool), issuedAt: issued,
		digest: hex.EncodeToString(sum[:])}
	return r, sum[:], nil
}

// arDate runs the dating check over one envelope object and its entry.
func arDate(envelope any, entryRaw any, issuedAt, rootDigest string, heads []arTreeHead, disabled string) arDating {
	entry, ok := entryRaw.(map[string]any)
	if !ok {
		return arDating{Entry: "malformed", Codes: []string{"entry-shape-malformed"}, DelegationRoot: arNotEstablished}
	}
	if err := arRetentionShape(entry); err != nil {
		return arDating{Entry: "malformed", Codes: []string{err.Error()}, DelegationRoot: arNotEstablished}
	}
	r, digest, err := arRetainedState(envelope, entry, issuedAt)
	if err != nil {
		return arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}, DelegationRoot: arNotEstablished}
	}
	r.rootDigest, r.root = rootDigest, arNotEstablished
	moments := arAnchorMoments(entry, digest, heads, disabled)
	dating := arDating{Entry: "well-formed", Codes: []string{}, DatedAt: arDatedAt(moments, disabled),
		DelegationRoot: arNotEstablished}
	for _, m := range moments {
		if m.origin == "retainer" {
			at := m.at
			r.retention = &at
			r.retentionOTS = m.ots && disabled != "opentimestamps-tolerance"
			break
		}
	}
	for _, rule := range arDatingRules() {
		if rule.name == disabled {
			continue
		}
		if err := rule.check(r); err != nil {
			dating.Entry, dating.Codes = "malformed", []string{err.Error()}
			return dating
		}
	}
	dating.DelegationRoot = r.root
	if r.received {
		dating.Receipt = "asserted-unchecked"
		if r.retention != nil {
			dating.Receipt = "asserted-consistent"
		}
	}
	return dating
}

// arUnwrapRetained returns the envelope bytes and the parsed bundle of a
// retained member's file.
func arUnwrapRetained(raw []byte) ([]byte, map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var bundle map[string]any
	if err := decoder.Decode(&bundle); err != nil {
		return nil, nil, err
	}
	envelope, err := json.Marshal(bundle["envelope"])
	if err != nil {
		return nil, nil, err
	}
	return envelope, bundle, nil
}

// arVerifyRetained judges a retained record: the envelope's verdict and the
// dating result. disabled names one record rule or one dating rule to skip.
func arVerifyRetained(raw []byte, predicateType, observerKey string, heads []arTreeHead, disabled string) (arReport, arDating) {
	unreadable := arDating{Entry: "malformed", Codes: []string{"retained-unreadable"}, DelegationRoot: arNotEstablished}
	envelope, bundle, err := arUnwrapRetained(raw)
	if err != nil {
		return arReport{verdict: "malformed", code: "retained-unreadable"}, unreadable
	}
	_, hasEnvelope := bundle["envelope"]
	_, hasRetention := bundle["retention"]
	if !hasEnvelope || !hasRetention {
		return arReport{verdict: "malformed", code: "retained-unreadable"}, unreadable
	}
	report := arVerify(envelope, predicateType, observerKey, disabled)
	var parsed struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(envelope, &parsed) != nil {
		return report, arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}, DelegationRoot: arNotEstablished}
	}
	payload, err := base64.StdEncoding.DecodeString(parsed.Payload)
	if err != nil {
		return report, arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}, DelegationRoot: arNotEstablished}
	}
	var statement struct {
		Predicate struct {
			IssuedAt   string `json:"issuedAt"`
			Delegation struct {
				RootDigest string `json:"rootDigest"`
			} `json:"delegation"`
		} `json:"predicate"`
	}
	if json.Unmarshal(payload, &statement) != nil {
		return report, arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}, DelegationRoot: arNotEstablished}
	}
	return report, arDate(bundle["envelope"], bundle["retention"], statement.Predicate.IssuedAt,
		statement.Predicate.Delegation.RootDigest, heads, disabled)
}

// arDatingRuleNames lists every dating rule a sweep may disable.
func arDatingRuleNames() []string {
	names := []string{"anchor-validation", "earliest-anchor", "opentimestamps-tolerance"}
	for _, rule := range arDatingRules() {
		names = append(names, rule.name)
	}
	return names
}
