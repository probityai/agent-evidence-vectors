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
// The only anchor this rail validates is a transparency-log inclusion proof
// that recomputes to a tree head the verifier holds by a means other than its
// signature (the manifest's anchorTrust): a hash commitment under Section
// 4.7.2. The proof is an RFC 9162 TransItem of type inclusion_proof_v2 and the
// logged entry is the 32 bytes of envelopeDigest. An rfc3161 or opentimestamps
// anchor dates nothing here, because this rail holds no time-stamping
// authority path and no OpenTimestamps commitment.

const arInclusionProofV2 = 0x0106

type arTreeHeadJSON struct {
	LogID     string `json:"logId"`
	TreeSize  uint64 `json:"treeSize"`
	RootHash  string `json:"rootHash"`
	Timestamp string `json:"timestamp"`
}

type arTreeHead struct {
	logID     []byte
	treeSize  uint64
	root      []byte
	timestamp string
}

// arDating is the dating result in the manifest's expected.dating shape.
type arDating struct {
	Entry   string   `json:"entry"`
	Codes   []string `json:"codes"`
	DatedAt string   `json:"datedAt,omitempty"`
	Receipt string   `json:"receipt,omitempty"`
}

func (d arDating) equal(other arDating) bool {
	if d.Entry != other.Entry || d.DatedAt != other.DatedAt || d.Receipt != other.Receipt ||
		len(d.Codes) != len(other.Codes) {
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
			heads = append(heads, arTreeHead{logID, h.TreeSize, root, h.Timestamp})
		}
	}
	return heads
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

func arAnchorTime(anchor map[string]any, digest []byte, heads []arTreeHead) string {
	if anchor["kind"] != "transparency-log" {
		return ""
	}
	text, _ := anchor["proof"].(string)
	proof, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return ""
	}
	logID, size, index, path, err := arInclusionProof(proof)
	if err != nil {
		return ""
	}
	root := arInclusionRoot(digest, index, size, path)
	for _, head := range heads {
		if bytes.Equal(head.logID, logID) && head.treeSize == size && root != nil && bytes.Equal(head.root, root) {
			return head.timestamp
		}
	}
	return ""
}

type arRetained struct {
	entry      map[string]any
	received   bool
	issuedAt   time.Time
	receivedAt *time.Time
	retention  *time.Time
	digest     string
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
			if r.receivedAt != nil && r.retention != nil && r.receivedAt.After(r.retention.Add(arSkewTolerance)) {
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
			if r.retention.After(start.Add(time.Duration(within)*time.Second + arSkewTolerance)) {
				return arRefuse("entry-anchor-late")
			}
			return nil
		}},
	}
}

type arMoment struct {
	origin string
	at     time.Time
	text   string
}

// arAnchorMoments returns every anchor that validates over digest, earliest
// first. disabled of anchor-validation dates every anchor at the first held
// head, which is how the sweep asks whether validation is load-bearing.
func arAnchorMoments(entry map[string]any, digest []byte, heads []arTreeHead, disabled string) []arMoment {
	var moments []arMoment
	for _, item := range entry["anchors"].([]any) {
		anchor := item.(map[string]any)
		text := arAnchorTime(anchor, digest, heads)
		if disabled == "anchor-validation" && len(heads) > 0 {
			text = heads[0].timestamp
		}
		if at, err := arInstant(text); text != "" && err == nil {
			moments = append(moments, arMoment{anchor["origin"].(string), at, text})
		}
	}
	sort.SliceStable(moments, func(i, j int) bool { return moments[i].at.Before(moments[j].at) })
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
func arDate(envelope any, entryRaw any, issuedAt string, heads []arTreeHead, disabled string) arDating {
	entry, ok := entryRaw.(map[string]any)
	if !ok {
		return arDating{Entry: "malformed", Codes: []string{"entry-shape-malformed"}}
	}
	if err := arRetentionShape(entry); err != nil {
		return arDating{Entry: "malformed", Codes: []string{err.Error()}}
	}
	r, digest, err := arRetainedState(envelope, entry, issuedAt)
	if err != nil {
		return arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}}
	}
	moments := arAnchorMoments(entry, digest, heads, disabled)
	dating := arDating{Entry: "well-formed", Codes: []string{}, DatedAt: arDatedAt(moments, disabled)}
	for _, m := range moments {
		if m.origin == "retainer" {
			at := m.at
			r.retention = &at
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
	unreadable := arDating{Entry: "malformed", Codes: []string{"retained-unreadable"}}
	envelope, bundle, err := arUnwrapRetained(raw)
	if err != nil {
		return arReport{verdict: "malformed", code: "retained-unreadable"}, unreadable
	}
	report := arVerify(envelope, predicateType, observerKey, disabled)
	var parsed struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(envelope, &parsed) != nil {
		return report, arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}}
	}
	payload, err := base64.StdEncoding.DecodeString(parsed.Payload)
	if err != nil {
		return report, arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}}
	}
	var statement struct {
		Predicate struct {
			IssuedAt string `json:"issuedAt"`
		} `json:"predicate"`
	}
	if json.Unmarshal(payload, &statement) != nil {
		return report, arDating{Entry: "malformed", Codes: []string{"entry-record-unreadable"}}
	}
	return report, arDate(bundle["envelope"], bundle["retention"], statement.Predicate.IssuedAt, heads, disabled)
}

// arDatingRuleNames lists every dating rule a sweep may disable.
func arDatingRuleNames() []string {
	names := []string{"anchor-validation", "earliest-anchor"}
	for _, rule := range arDatingRules() {
		names = append(names, rule.name)
	}
	return names
}
