package corpora

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

func init() { register(ietfAgentRecord{}) }

// ietfAgentRecord judges vectors-ietf-agent-record-drafts/, the cases for three
// SCITT-wave Internet-Drafts: the AgentInteractionRecord chain of
// draft-emirdag-scitt-ai-agent-execution-01, checkpoint registration in
// draft-mih-scitt-checkpointed-local-log-02, and statement references in
// draft-gruszka-scitt-statement-identification-02.
//
// It is the Go rail over that corpus. The Python rail is the corpus's own
// check_vectors.py, and the rules below are that reader restated rather than
// imported, including its CBOR decoder: two spellings of one rule set are the
// only arrangement that finds a rule both get wrong the same way. Each member is
// judged twice, once with every rule and once as the draft's own procedure reads
// it (the rules marked [corpus] in the manifest switched off), and both verdicts
// are compared with the manifest.
type ietfAgentRecord struct{}

func (ietfAgentRecord) Suite() string { return "ietf-agent-record-drafts-conformance" }

const (
	iarDraftAIR = "draft-emirdag-scitt-ai-agent-execution-01"
	iarDraftCLL = "draft-mih-scitt-checkpointed-local-log-02"
	iarDraftSID = "draft-gruszka-scitt-statement-identification-02"
)

// iarRules is each draft's rule order, which is also its order of first refusal.
var iarRules = map[string][]string{
	iarDraftAIR: {"cose-shape", "signature", "content-hash", "chain-hash", "sequence",
		"header-payload", "prev-chain-link", "time-order", "position-unique"},
	iarDraftCLL: {"deterministic-encoding", "cose-shape", "signature", "claims", "continuity",
		"issued-at-order", "registration-time", "history-fork"},
	iarDraftSID: {"duplicate-key", "signature", "identity"},
}

// iarCorpusRules are the rules the drafts' text does not state. The draft
// reading switches them off; for statement identification it also hashes the
// protected header as written, which is what "identity-canonical" names.
var iarCorpusRules = map[string][]string{
	iarDraftAIR: {"header-payload", "prev-chain-link", "time-order", "position-unique"},
	iarDraftCLL: {"deterministic-encoding", "issued-at-order", "registration-time", "history-fork"},
	iarDraftSID: {"identity-canonical"},
}

var iarMalformed = map[string]bool{
	"cose-malformed": true, "claims-malformed": true,
	"cbor-not-deterministic": true, "cbor-duplicate-key": true,
}

type iarManifest struct {
	Keys struct {
		AIR struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"air-operator"`
		CLL struct {
			PublicKey string `json:"publicKey"`
		} `json:"cll-producer"`
		SID struct {
			PublicKey string `json:"publicKey"`
		} `json:"sid-issuer"`
	} `json:"keys"`
	Counts       map[string]int `json:"counts"`
	CorpusDigest string         `json:"corpusDigest"`
	Vectors      []iarVector    `json:"vectors"`
}

type iarVector struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Draft    string `json:"draft"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Parent   string `json:"parent"`
	Expected struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
	Readings []struct {
		Verdict string `json:"verdict"`
	} `json:"readings"`
	DraftReading struct {
		Verdict string `json:"verdict"`
	} `json:"draftReading"`
	DoesNotAssert []string `json:"does_not_assert"`
}

type iarKeys struct {
	air *ecdsa.PublicKey
	cll ed25519.PublicKey
	sid ed25519.PublicKey
}

type iarRefusal struct{ code string }

func (r *iarRefusal) Error() string { return r.code }

func iarRefuse(code string) error { return &iarRefusal{code} }

type iarReport struct{ verdict, code string }

func (ietfAgentRecord) Judge(dir string, raw []byte) (*Result, error) {
	var m iarManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	keys, err := iarLoadKeys(&m)
	if err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json: %w", dir, err)
	}
	result := &Result{}
	accepts := map[string]bool{}
	for _, v := range m.Vectors {
		if v.Kind == "accept" {
			accepts[v.ID] = true
		}
	}
	counts := map[string]int{}
	ids, files := []string{}, []string{}
	for _, v := range m.Vectors {
		counts[v.Kind]++
		ids, files = append(ids, v.ID), append(files, v.File)
		result.Members = append(result.Members,
			Member{ID: v.ID, Kind: v.Kind, Findings: iarJudgeMember(dir, keys, v, accepts)})
	}
	if msg := countsDisagree(m.Counts, counts); msg != "" {
		result.Findings = append(result.Findings, msg)
	}
	if digest, err := orderedCorpusDigest(dir, ids, files); err != nil || digest != m.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not match the committed bytes")
	}
	return result, nil
}

func iarLoadKeys(m *iarManifest) (*iarKeys, error) {
	x, okX := new(big.Int).SetString(m.Keys.AIR.X, 16)
	y, okY := new(big.Int).SetString(m.Keys.AIR.Y, 16)
	if !okX || !okY {
		return nil, errors.New("the air-operator key is not two hex coordinates")
	}
	cll, err := hex.DecodeString(m.Keys.CLL.PublicKey)
	if err != nil || len(cll) != ed25519.PublicKeySize {
		return nil, errors.New("the cll-producer key is not an Ed25519 public key")
	}
	sid, err := hex.DecodeString(m.Keys.SID.PublicKey)
	if err != nil || len(sid) != ed25519.PublicKeySize {
		return nil, errors.New("the sid-issuer key is not an Ed25519 public key")
	}
	air := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return &iarKeys{air: air, cll: cll, sid: sid}, nil
}

func iarJudgeMember(dir string, keys *iarKeys, v iarVector, accepts map[string]bool) []string {
	label := v.ID + " (" + v.Slug + ")"
	var findings []string
	if v.Kind != "accept" && !accepts[v.Parent] {
		findings = append(findings, label+": parent is not an accept member")
	}
	if len(v.DoesNotAssert) == 0 {
		findings = append(findings, label+": does_not_assert is empty")
	}
	body, err := readIn(dir, v.File)
	if err != nil {
		return append(findings, label+": the case file cannot be read")
	}
	if "v"+sha(body)[:16] != v.ID {
		findings = append(findings, label+": identifier does not recompute from the case's own bytes")
	}
	full := iarVerify(body, keys, nil)
	if v.Kind == "indeterminate" {
		allowed := false
		for _, r := range v.Readings {
			allowed = allowed || r.Verdict == full.verdict
		}
		if !allowed || v.Expected.Verdict != "" {
			findings = append(findings, fmt.Sprintf("%s: reached %s, which no reading allows", label, full.verdict))
		}
	} else {
		var codes []string
		if full.code != "" {
			codes = []string{full.code}
		}
		if full.verdict != v.Expected.Verdict || fmt.Sprint(codes) != fmt.Sprint(v.Expected.Codes) {
			findings = append(findings, fmt.Sprintf("%s: expected %s %v, reached %s %v",
				label, v.Expected.Verdict, v.Expected.Codes, full.verdict, codes))
		}
	}
	draft := iarVerify(body, keys, iarSet(iarCorpusRules[v.Draft]))
	if draft.verdict != v.DraftReading.Verdict {
		findings = append(findings, fmt.Sprintf("%s: the draft's own steps reach %s, the manifest records %s",
			label, draft.verdict, v.DraftReading.Verdict))
	}
	return findings
}

func iarSet(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

// iarVerify judges one case file with the rules in off switched off.
func iarVerify(body []byte, keys *iarKeys, off map[string]bool) iarReport {
	var head struct {
		Draft string `json:"draft"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return iarReport{"malformed", "cose-malformed"}
	}
	var err error
	switch head.Draft {
	case iarDraftAIR:
		err = iarVerifyAIR(body, keys.air, off)
	case iarDraftCLL:
		err = iarVerifyCLL(body, keys.cll, off)
	case iarDraftSID:
		err = iarVerifySID(body, keys.sid, off)
	default:
		err = iarRefuse("cose-malformed")
	}
	var refusal *iarRefusal
	if errors.As(err, &refusal) {
		if iarMalformed[refusal.code] {
			return iarReport{"malformed", refusal.code}
		}
		return iarReport{"invalid", refusal.code}
	}
	if err != nil {
		return iarReport{"malformed", "cose-malformed"}
	}
	return iarReport{"valid", ""}
}

// ---------------------------------------------------------------- CBOR

type iarTag struct {
	num uint64
	val any
}

// iarDecoder reads the CBOR subset the drafts use. policy is "strict" (the core
// deterministic encoding of RFC 8949 Section 4.2.1, refusing anything else),
// "last" or "first" (a repeated map key keeps its last or its first value).
type iarDecoder struct {
	data   []byte
	pos    int
	policy string
}

var errIarNotDeterministic = errors.New("not deterministic")

func iarDecode(data []byte, policy string) (any, error) {
	d := &iarDecoder{data: data, policy: policy}
	v, err := d.item()
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		if policy == "strict" {
			return nil, errIarNotDeterministic
		}
		return nil, errors.New("trailing bytes")
	}
	return v, nil
}

func (d *iarDecoder) head() (byte, uint64, error) {
	if d.pos >= len(d.data) {
		return 0, 0, errors.New("truncated")
	}
	start := d.pos
	initial := d.data[d.pos]
	major, ai := initial>>5, initial&0x1f
	d.pos++
	if ai < 24 {
		return major, uint64(ai), nil
	}
	if ai > 27 {
		return 0, 0, errors.New("indefinite length or reserved")
	}
	width := 1 << (ai - 24)
	if d.pos+width > len(d.data) {
		return 0, 0, errors.New("truncated")
	}
	var n uint64
	for _, b := range d.data[d.pos : d.pos+width] {
		n = n<<8 | uint64(b)
	}
	d.pos += width
	if d.policy == "strict" && !bytes.Equal(iarHead(major, n), d.data[start:d.pos]) {
		return 0, 0, errIarNotDeterministic
	}
	return major, n, nil
}

func (d *iarDecoder) item() (any, error) {
	major, n, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return int64(n), nil // #nosec G115 -- every integer in these cases fits an int64 with room to spare
	case 1:
		return -1 - int64(n), nil // #nosec G115 -- as above
	case 2, 3:
		if uint64(len(d.data)-d.pos) < n { // #nosec G115 -- d.pos never passes len(d.data)
			return nil, errors.New("truncated")
		}
		raw := d.data[d.pos : d.pos+int(n)] // #nosec G115 -- bounded by len(d.data) above
		d.pos += int(n)                     // #nosec G115 -- as above
		if major == 2 {
			return append([]byte{}, raw...), nil
		}
		return string(raw), nil
	case 4:
		out := []any{}
		for i := uint64(0); i < n; i++ {
			v, err := d.item()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		return d.mapItem(n)
	case 6:
		v, err := d.item()
		if err != nil {
			return nil, err
		}
		return iarTag{n, v}, nil
	}
	return nil, fmt.Errorf("major type %d is outside the subset", major)
}

func (d *iarDecoder) mapItem(n uint64) (any, error) {
	out := map[any]any{}
	var previous []byte
	for i := uint64(0); i < n; i++ {
		start := d.pos
		k, err := d.item()
		if err != nil {
			return nil, err
		}
		encoded := d.data[start:d.pos]
		if d.policy == "strict" && previous != nil && bytes.Compare(encoded, previous) <= 0 {
			return nil, errIarNotDeterministic
		}
		previous = encoded
		switch k.(type) {
		case int64, string:
		default:
			return nil, errors.New("a map key that is not an integer or a text string")
		}
		v, err := d.item()
		if err != nil {
			return nil, err
		}
		if _, seen := out[k]; seen && d.policy == "first" {
			continue
		}
		out[k] = v
	}
	return out, nil
}

// iarRepeatedKey reports whether any map in the well-formed item repeats a key.
func iarRepeatedKey(data []byte) bool {
	d := &iarDecoder{data: data, policy: "last"}
	repeated := false
	var walk func() error
	walk = func() error {
		major, n, err := d.head()
		if err != nil {
			return err
		}
		switch major {
		case 2, 3:
			d.pos += int(n) // #nosec G115 -- the item decoded above, so it fits
		case 4:
			for i := uint64(0); i < n; i++ {
				if err := walk(); err != nil {
					return err
				}
			}
		case 5:
			seen := map[string]bool{}
			for i := uint64(0); i < n; i++ {
				start := d.pos
				if err := walk(); err != nil {
					return err
				}
				key := string(d.data[start:d.pos])
				repeated = repeated || seen[key]
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case 6:
			return walk()
		}
		return nil
	}
	if walk() != nil {
		return false
	}
	return repeated
}

func iarHead(major byte, n uint64) []byte {
	lead := major << 5
	switch {
	case n < 24:
		return []byte{lead | byte(n)} // #nosec G115 -- n is below 24
	case n <= 0xff:
		return []byte{lead | 24, byte(n)} // #nosec G115 -- n fits one byte
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{lead | 25}, uint16(n)) // #nosec G115 -- n fits two bytes
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32([]byte{lead | 26}, uint32(n)) // #nosec G115 -- n fits four bytes
	}
	return binary.BigEndian.AppendUint64([]byte{lead | 27}, n)
}

// iarEncode writes the core deterministic encoding of the subset.
func iarEncode(v any) []byte {
	switch x := v.(type) {
	case int64:
		if x >= 0 {
			return iarHead(0, uint64(x))
		}
		return iarHead(1, uint64(-1-x))
	case []byte:
		return append(iarHead(2, uint64(len(x))), x...)
	case string:
		return append(iarHead(3, uint64(len(x))), x...)
	case []any:
		out := iarHead(4, uint64(len(x)))
		for _, item := range x {
			out = append(out, iarEncode(item)...)
		}
		return out
	case map[any]any:
		pairs := make([][2][]byte, 0, len(x))
		for k, item := range x {
			pairs = append(pairs, [2][]byte{iarEncode(k), iarEncode(item)})
		}
		sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i][0], pairs[j][0]) < 0 })
		out := iarHead(5, uint64(len(x)))
		for _, p := range pairs {
			out = append(append(out, p[0]...), p[1]...)
		}
		return out
	case iarTag:
		return append(iarHead(6, x.num), iarEncode(x.val)...)
	}
	return nil
}

func iarSigStructure(protected, payload []byte) []byte {
	return iarEncode([]any{"Signature1", protected, []byte{}, payload})
}

// iarCose splits a COSE_Sign1 into protected header bytes, payload and
// signature, refusing a non-deterministic encoding under the strict policy.
func iarCose(raw []byte, policy string, tagRequired bool) ([]byte, []byte, []byte, error) {
	item, err := iarDecode(raw, policy)
	if errors.Is(err, errIarNotDeterministic) {
		return nil, nil, nil, iarRefuse("cbor-not-deterministic")
	}
	if err != nil {
		return nil, nil, nil, iarRefuse("cose-malformed")
	}
	if tag, ok := item.(iarTag); ok {
		if tag.num != 18 {
			return nil, nil, nil, iarRefuse("cose-malformed")
		}
		item = tag.val
	} else if tagRequired {
		return nil, nil, nil, iarRefuse("cose-malformed")
	}
	parts, ok := item.([]any)
	if !ok || len(parts) != 4 {
		return nil, nil, nil, iarRefuse("cose-malformed")
	}
	protected, ok1 := parts[0].([]byte)
	payload, ok2 := parts[2].([]byte)
	signature, ok3 := parts[3].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, nil, iarRefuse("cose-malformed")
	}
	return protected, payload, signature, nil
}

func iarHeader(protected []byte, policy string) (map[any]any, error) {
	item, err := iarDecode(protected, policy)
	if errors.Is(err, errIarNotDeterministic) {
		return nil, iarRefuse("cbor-not-deterministic")
	}
	header, ok := item.(map[any]any)
	if err != nil || !ok {
		return nil, iarRefuse("cose-malformed")
	}
	return header, nil
}

// ---------------------------------------------------------------- AIR

type iarAIRCase struct {
	Predecessors []string `json:"predecessors"`
	Candidates   []string `json:"candidates"`
}

type iarAIRHeader struct {
	content, prev, chain []byte
	seq, ts              int64
	agent                string
}

func iarVerifyAIR(body []byte, key *ecdsa.PublicKey, off map[string]bool) error {
	var c iarAIRCase
	if err := json.Unmarshal(body, &c); err != nil {
		return iarRefuse("cose-malformed")
	}
	var prior *iarAIRHeader
	for _, raw := range c.Predecessors {
		h, err := iarAIRRecord(raw, key, off)
		if err != nil {
			return err
		}
		if err := iarAIRFollow(prior, h, off); err != nil {
			return err
		}
		prior = h
	}
	seen := map[string][]byte{}
	for _, raw := range c.Candidates {
		h, err := iarAIRRecord(raw, key, off)
		if err != nil {
			return err
		}
		if err := iarAIRFollow(prior, h, off); err != nil {
			return err
		}
		position := fmt.Sprintf("%s/%d", h.agent, h.seq)
		if previous, ok := seen[position]; ok && !off["position-unique"] && !bytes.Equal(previous, h.chain) {
			return iarRefuse("chain-position-equivocation")
		}
		seen[position] = h.chain
	}
	return nil
}

func iarAIRShape(h map[any]any, off map[string]bool) (*iarAIRHeader, error) {
	cwt, _ := h[int64(15)].(map[any]any)
	_, issOK := cwt[int64(1)].(string)
	_, subOK := cwt[int64(2)].(string)
	_, kidOK := h[int64(4)].([]byte)
	shaped := h[int64(1)] == int64(-7) && kidOK && issOK && subOK
	if !off["cose-shape"] && !shaped {
		return nil, iarRefuse("cose-malformed")
	}
	out := &iarAIRHeader{}
	var ok [6]bool
	out.content, ok[0] = h["content_hash"].([]byte)
	out.prev, ok[1] = h["prev_chain_hash"].([]byte)
	out.chain, ok[2] = h["chain_hash"].([]byte)
	out.seq, ok[3] = h["sequence_number"].(int64)
	out.ts, ok[4] = h["action_timestamp_ms"].(int64)
	out.agent, ok[5] = h["agent_id"].(string)
	for _, b := range ok {
		if !b {
			return nil, iarRefuse("cose-malformed")
		}
	}
	if len(out.content) != 32 || len(out.prev) != 32 || len(out.chain) != 32 {
		return nil, iarRefuse("cose-malformed")
	}
	return out, nil
}

func iarAIRRecord(rawHex string, key *ecdsa.PublicKey, off map[string]bool) (*iarAIRHeader, error) {
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, iarRefuse("cose-malformed")
	}
	protected, payload, signature, err := iarCose(raw, "last", true)
	if err != nil {
		return nil, err
	}
	header, err := iarHeader(protected, "last")
	if err != nil {
		return nil, err
	}
	h, err := iarAIRShape(header, off)
	if err != nil {
		return nil, err
	}
	if err := iarAIRIntegrity(h, protected, payload, signature, key, off); err != nil {
		return nil, err
	}
	return h, nil
}

// iarAIRIntegrity runs the record checks that need the decoded header: the
// signature, the content and chain hashes, and the header copy in the payload.
func iarAIRIntegrity(h *iarAIRHeader, protected, payload, signature []byte, key *ecdsa.PublicKey, off map[string]bool) error {
	if !off["signature"] {
		digest := sha256.Sum256(iarSigStructure(protected, payload))
		if len(signature) != 64 || !ecdsa.Verify(key, digest[:],
			new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return iarRefuse("signature-invalid")
		}
	}
	if content := sha256.Sum256(payload); !off["content-hash"] && !bytes.Equal(content[:], h.content) {
		return iarRefuse("content-hash-mismatch")
	}
	if !off["chain-hash"] && !bytes.Equal(iarChainHash(h), h.chain) {
		return iarRefuse("chain-hash-mismatch")
	}
	if !off["header-payload"] {
		var copyOf struct {
			TS    *int64  `json:"action_timestamp_ms"`
			Agent *string `json:"agent_id"`
		}
		if json.Unmarshal(payload, &copyOf) != nil || copyOf.TS == nil || copyOf.Agent == nil ||
			*copyOf.TS != h.ts || *copyOf.Agent != h.agent {
			return iarRefuse("header-payload-disagree")
		}
	}
	return nil
}

// iarChainHash is Section 5.7: SHA-256 over content_hash, prev_chain_hash, the
// timestamp as a big-endian u64, then agent_id behind a big-endian u32 length.
func iarChainHash(h *iarAIRHeader) []byte {
	pre := append(append([]byte{}, h.content...), h.prev...)
	pre = binary.BigEndian.AppendUint64(pre, uint64(h.ts))         // #nosec G115 -- a millisecond timestamp, never negative here
	pre = binary.BigEndian.AppendUint32(pre, uint32(len(h.agent))) // #nosec G115 -- an agent_id is short
	sum := sha256.Sum256(append(pre, h.agent...))
	return sum[:]
}

func iarAIRFollow(prior, h *iarAIRHeader, off map[string]bool) error {
	wantSeq, wantPrev := int64(0), make([]byte, 32)
	if prior != nil {
		wantSeq, wantPrev = prior.seq+1, prior.chain
	}
	if !off["sequence"] && h.seq != wantSeq {
		return iarRefuse("sequence-gap")
	}
	if !off["prev-chain-link"] && !bytes.Equal(h.prev, wantPrev) {
		return iarRefuse("prev-chain-hash-mismatch")
	}
	if !off["time-order"] && prior != nil && h.ts < prior.ts {
		return iarRefuse("timestamp-regression")
	}
	return nil
}

// ---------------------------------------------------------------- CLL

type iarCLLRegistration struct {
	LogSize    int64  `json:"log_size"`
	Commitment string `json:"commitment"`
	IssuedAt   string `json:"issued_at"`
}

type iarCLLCase struct {
	LogIdentity struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	} `json:"logIdentity"`
	Checkpoint string `json:"checkpoint"`
	RegisterAt string `json:"registerAt"`
	Clock      string `json:"clock"`
	Services   []struct {
		Name    string               `json:"name"`
		History []iarCLLRegistration `json:"history"`
	} `json:"services"`
	NamedServices []string `json:"namedServices"`
}

type iarClaims struct {
	logSize, prevSize    int64
	commitment, previous []byte
	issued               time.Time
	cadence              int64
	hasCadence           bool
}

func iarVerifyCLL(body []byte, key ed25519.PublicKey, off map[string]bool) error {
	var c iarCLLCase
	if err := json.Unmarshal(body, &c); err != nil {
		return iarRefuse("cose-malformed")
	}
	claims, err := iarCLLEnvelope(&c, key, off)
	if err != nil {
		return err
	}
	services := map[string][]iarCLLRegistration{}
	for _, s := range c.Services {
		services[s.Name] = s.History
	}
	if err := iarCLLRegistration2(&c, claims, services[c.RegisterAt], off); err != nil {
		return err
	}
	if off["history-fork"] {
		return nil
	}
	for _, name := range c.NamedServices {
		if name == c.RegisterAt {
			continue
		}
		for _, row := range services[name] {
			if row.LogSize == claims.logSize && row.Commitment != hex.EncodeToString(claims.commitment) {
				return iarRefuse("history-fork")
			}
		}
	}
	return nil
}

func iarCLLEnvelope(c *iarCLLCase, key ed25519.PublicKey, off map[string]bool) (*iarClaims, error) {
	policy := "strict"
	if off["deterministic-encoding"] {
		policy = "last"
	}
	raw, err := hex.DecodeString(c.Checkpoint)
	if err != nil {
		return nil, iarRefuse("cose-malformed")
	}
	protected, payload, signature, err := iarCose(raw, policy, true)
	if err != nil {
		return nil, err
	}
	header, err := iarHeader(protected, policy)
	if err != nil {
		return nil, err
	}
	item, err := iarDecode(payload, policy)
	if errors.Is(err, errIarNotDeterministic) {
		return nil, iarRefuse("cbor-not-deterministic")
	}
	m, ok := item.(map[any]any)
	if err != nil || !ok {
		return nil, iarRefuse("claims-malformed")
	}
	cwt, _ := header[int64(15)].(map[any]any)
	shaped := header[int64(1)] == int64(-19) && cwt[int64(1)] == c.LogIdentity.Iss && cwt[int64(2)] == c.LogIdentity.Sub
	if !off["cose-shape"] && !shaped {
		return nil, iarRefuse("cose-malformed")
	}
	if !off["signature"] && !ed25519.Verify(key, iarSigStructure(protected, payload), signature) {
		return nil, iarRefuse("signature-invalid")
	}
	return iarCLLClaims(m, off)
}

func iarCLLClaims(m map[any]any, off map[string]bool) (*iarClaims, error) {
	out := &iarClaims{}
	var ok [5]bool
	out.logSize, ok[0] = m["log_size"].(int64)
	out.prevSize, ok[1] = m["prev_size"].(int64)
	out.commitment, ok[2] = m["commitment"].([]byte)
	out.previous, ok[3] = m["prev_commitment"].([]byte)
	issued, isText := m["issued_at"].(string)
	ok[4] = isText
	for _, b := range ok {
		if !b {
			return nil, iarRefuse("claims-malformed")
		}
	}
	if !off["claims"] && m["kind"] != "cll-checkpoint" {
		return nil, iarRefuse("claims-malformed")
	}
	t, err := time.Parse(time.RFC3339, issued)
	if err != nil {
		return nil, iarRefuse("claims-malformed")
	}
	out.issued = t
	out.cadence, out.hasCadence = m["cadence"].(int64)
	return out, nil
}

// iarCLLRegistration2 is Section 4.5 continuity, then the two clock rules this
// corpus adds, against the service the case registers at.
func iarCLLRegistration2(c *iarCLLCase, claims *iarClaims, history []iarCLLRegistration, off map[string]bool) error {
	var last *iarCLLRegistration
	if len(history) > 0 {
		last = &history[len(history)-1]
	}
	if !off["continuity"] {
		if last == nil && claims.prevSize != 0 {
			return iarRefuse("not-continuous")
		}
		if last != nil && (claims.prevSize != last.LogSize || hex.EncodeToString(claims.previous) != last.Commitment) {
			return iarRefuse("not-continuous")
		}
	}
	if !off["issued-at-order"] && last != nil {
		before, err := time.Parse(time.RFC3339, last.IssuedAt)
		if err != nil {
			return iarRefuse("claims-malformed")
		}
		if claims.issued.Before(before) {
			return iarRefuse("issued-at-regression")
		}
	}
	if !off["registration-time"] && claims.hasCadence {
		clock, err := time.Parse(time.RFC3339, c.Clock)
		if err != nil {
			return iarRefuse("claims-malformed")
		}
		gap := clock.Sub(claims.issued)
		if gap < 0 {
			gap = -gap
		}
		if gap > time.Duration(claims.cadence)*time.Second {
			return iarRefuse("registration-late")
		}
	}
	return nil
}

// ---------------------------------------------------------------- statement identification

type iarSIDCase struct {
	Reference struct {
		Triple []any `json:"triple"`
	} `json:"reference"`
	Candidate string `json:"candidate"`
}

func iarVerifySID(body []byte, key ed25519.PublicKey, off map[string]bool) error {
	var c iarSIDCase
	if err := json.Unmarshal(body, &c); err != nil || len(c.Reference.Triple) != 3 {
		return iarRefuse("cose-malformed")
	}
	raw, err := hex.DecodeString(c.Candidate)
	if err != nil {
		return iarRefuse("cose-malformed")
	}
	protected, payload, signature, err := iarCose(raw, "last", false)
	if err != nil {
		return err
	}
	header, err := iarHeader(protected, "last")
	if err != nil {
		return err
	}
	if !off["duplicate-key"] && iarRepeatedKey(protected) {
		return iarRefuse("cbor-duplicate-key")
	}
	if !off["signature"] && !ed25519.Verify(key, iarSigStructure(protected, payload), signature) {
		return iarRefuse("signature-invalid")
	}
	if off["identity"] {
		return nil
	}
	signing := iarEncode(header)
	if off["identity-canonical"] {
		signing = protected
	}
	digest := sha256.Sum256(iarSigStructure(signing, payload))
	if want, _ := c.Reference.Triple[2].(string); hex.EncodeToString(digest[:]) != want {
		return iarRefuse("reference-mismatch")
	}
	return nil
}
