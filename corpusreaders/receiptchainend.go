package corpora

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() { register(receiptChainEnd{}) }

// receiptChainEnd judges vectors-receipt-chain-end/. Each member is a chain of
// signed receipts in the ActionReceipt v1 wire format, the consumer's trust inputs and,
// for some members, a head the consumer retained or a rotation endorsement. The
// reader applies the Python reader's eight checks in the same order and names
// the first that fails:
//
//  1. every receipt verifies under the key it names: signature_invalid;
//  2. the first receipt's key is a consumer root key: signer_untrusted;
//  3. every receipt names its predecessor's hash and the next sequence number,
//     and a key changes only at a rotation marker naming the real prior tail:
//     chain_link_broken;
//  4. the retiring key endorsed every rotation boundary: rotation_unendorsed;
//  5. every close names the run's real root hash, final sequence and count:
//     close_binding_invalid;
//  6. a retained head's hash is in the chain: head_missing;
//  7. a retained head's sequence number, segment key and index match the
//     receipt it names (or the last receipt, for a head with no hash):
//     head_position_mismatch;
//  8. a head retained as final is the last receipt: head_not_final.
//
// A chain that passes all eight is verified when a close of a run-scoped
// session or a final head naming the last receipt proves its end, and a prefix
// otherwise.
//
// A receipt is hashed and signed over its fields in the order the line gives
// them, with no spaces and non-ASCII kept as UTF-8, so the reader decodes every
// line into an order-preserving tree and re-encodes it the way CPython's
// json.dumps(separators=(",", ":"), ensure_ascii=False) does.
type receiptChainEnd struct{}

func (receiptChainEnd) Suite() string { return "receipt-chain-end/v1" }

type rceVector struct {
	ID              string            `json:"id"`
	Path            string            `json:"path"`
	Files           map[string]string `json:"files"`
	Expected        scDecision        `json:"expected"`
	SignaturesClean bool              `json:"signaturesVerify"`
}

const (
	rceGenesis   = "genesis"
	rceOpenLabel = "pipelock.receipt.session_open.v1"
)

var (
	rceEndorsementDomain = []byte("pipelock-rotation-endorsement-v1\x00")
	// Python's re.match with "$" also matches before one trailing newline.
	rceRunSession = regexp.MustCompile(`\A[^/\\]+\.run\.[0-9a-f]{32}\n?\z`)
)

func (receiptChainEnd) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	ids := map[string]bool{}
	for _, entry := range manifest.Vectors {
		var v rceVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		if ids[v.ID] {
			result.Findings = append(result.Findings, "duplicate vector identifier "+v.ID)
		}
		ids[v.ID] = true
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		if v.Path != "cases/"+v.ID {
			member.Findings = []string{"case path " + v.Path + " does not match the identifier"}
		} else {
			member.Findings = rceJudgeMember(filepath.Join(dir, v.Path), v)
		}
		result.Members = append(result.Members, member)
	}
	if len(manifest.Vectors) == 0 {
		result.Findings = append(result.Findings, "the manifest lists no vectors")
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	if finding := rceCaseDirectories(dir, ids); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// rceCaseDirectories reports a case directory the manifest does not list, or a
// listed one that is absent.
func rceCaseDirectories(dir string, ids map[string]bool) string {
	entries, err := os.ReadDir(filepath.Join(dir, "cases"))
	if err != nil {
		return "cases/ cannot be read: " + err.Error()
	}
	found := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			found[e.Name()] = true
		}
	}
	var extra, missing []string
	for name := range found {
		if !ids[name] {
			extra = append(extra, name)
		}
	}
	for id := range ids {
		if !found[id] {
			missing = append(missing, id)
		}
	}
	if len(extra)+len(missing) == 0 {
		return ""
	}
	sort.Strings(extra)
	sort.Strings(missing)
	return fmt.Sprintf("case directories do not match the manifest: unlisted %v, absent %v", extra, missing)
}

func rceJudgeMember(caseDir string, v rceVector) []string {
	findings := rceFileFindings(caseDir, v.Files)
	in, err := rceLoad(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	clean := true
	for _, r := range in.receipts {
		clean = clean && rceReceiptVerifies(r)
	}
	if clean != v.SignaturesClean {
		findings = append(findings, fmt.Sprintf(
			"every receipt signature verifies: %t, the manifest declares %t", clean, v.SignaturesClean))
	}
	got := rceVerify(in)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// rceFileFindings compares a member's file set and bytes with the manifest.
func rceFileFindings(caseDir string, files map[string]string) []string {
	entries, err := os.ReadDir(caseDir)
	if err != nil {
		return []string{"the case directory cannot be read: " + err.Error()}
	}
	present := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			present[e.Name()] = true
		}
	}
	var findings []string
	for name := range present {
		if _, declared := files[name]; !declared {
			findings = append(findings, name+" is present and not declared")
		}
	}
	sort.Strings(findings)
	for _, name := range sortedKeys(files) {
		body, err := readIn(caseDir, name)
		if err != nil {
			findings = append(findings, name+" is declared and absent")
		} else if sha(body) != files[name] {
			findings = append(findings, name+" does not match its manifest digest")
		}
	}
	return findings
}

// rceVal is a JSON value that keeps its object members in document order.
type rceVal struct {
	kind  byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' bool, 'z' null
	keys  []string
	vals  []*rceVal
	items []*rceVal
	str   string
	num   json.Number
	b     bool
}

func rceParse(raw []byte) (*rceVal, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := rceDecode(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

func rceDecode(dec *json.Decoder) (*rceVal, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '[' {
			v := &rceVal{kind: 'a'}
			for dec.More() {
				item, err := rceDecode(dec)
				if err != nil {
					return nil, err
				}
				v.items = append(v.items, item)
			}
			_, err := dec.Token()
			return v, err
		}
		v := &rceVal{kind: 'o'}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := keyTok.(string)
			val, err := rceDecode(dec)
			if err != nil {
				return nil, err
			}
			// CPython keeps the last value of a repeated name, at the place
			// the name first appeared.
			if i := v.index(key); i >= 0 {
				v.vals[i] = val
				continue
			}
			v.keys, v.vals = append(v.keys, key), append(v.vals, val)
		}
		_, err := dec.Token()
		return v, err
	case string:
		return &rceVal{kind: 's', str: t}, nil
	case json.Number:
		return &rceVal{kind: 'n', num: t}, nil
	case bool:
		return &rceVal{kind: 'b', b: t}, nil
	default:
		return &rceVal{kind: 'z'}, nil
	}
}

func (v *rceVal) index(key string) int {
	if v == nil || v.kind != 'o' {
		return -1
	}
	for i, k := range v.keys {
		if k == key {
			return i
		}
	}
	return -1
}

// get is Python's dict.get: nil for an absent member or a non-object.
func (v *rceVal) get(key string) *rceVal {
	if i := v.index(key); i >= 0 {
		return v.vals[i]
	}
	return nil
}

func (v *rceVal) has(key string) bool { return v.index(key) >= 0 }

func (v *rceVal) isObject() bool { return v != nil && v.kind == 'o' }

// without is the object minus one member, order kept.
func (v *rceVal) without(key string) *rceVal {
	out := &rceVal{kind: 'o'}
	for i, k := range v.keys {
		if k != key {
			out.keys, out.vals = append(out.keys, k), append(out.vals, v.vals[i])
		}
	}
	return out
}

// compact is json.dumps(value, separators=(",", ":"), ensure_ascii=False).
func (v *rceVal) compact() ([]byte, error) {
	var buf bytes.Buffer
	err := v.encode(&buf)
	return buf.Bytes(), err
}

func (v *rceVal) encode(buf *bytes.Buffer) error {
	switch v.kind {
	case 'o':
		buf.WriteByte('{')
		for i, k := range v.keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writePythonString(buf, k, false)
			buf.WriteByte(':')
			if err := v.vals[i].encode(buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case 'a':
		buf.WriteByte('[')
		for i, item := range v.items {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := item.encode(buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case 's':
		writePythonString(buf, v.str, false)
	case 'n':
		return encodePythonOpts(buf, v.num, pyEncodeOpts{})
	case 'b':
		buf.WriteString(strconv.FormatBool(v.b))
	default:
		buf.WriteString("null")
	}
	return nil
}

// rceNumeric is the value Python compares a number or a bool by.
func rceNumeric(v *rceVal) (*big.Float, bool) {
	switch {
	case v == nil:
		return nil, false
	case v.kind == 'b':
		if v.b {
			return big.NewFloat(1), true
		}
		return big.NewFloat(0), true
	case v.kind == 'n':
		f, ok := new(big.Float).SetPrec(256).SetString(v.num.String())
		return f, ok
	}
	return nil, false
}

// rceEqual is Python's == over two parsed values; nil (absent) equals null.
func rceEqual(a, b *rceVal) bool {
	aNil, bNil := a == nil || a.kind == 'z', b == nil || b.kind == 'z'
	if aNil || bNil {
		return aNil && bNil
	}
	if x, ok := rceNumeric(a); ok {
		y, ok := rceNumeric(b)
		return ok && x.Cmp(y) == 0
	}
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case 's':
		return a.str == b.str
	case 'a':
		return rceEqualArrays(a, b)
	default:
		return rceEqualObjects(a, b)
	}
}

func rceEqualArrays(a, b *rceVal) bool {
	if len(a.items) != len(b.items) {
		return false
	}
	for i := range a.items {
		if !rceEqual(a.items[i], b.items[i]) {
			return false
		}
	}
	return true
}

// rceEqualObjects compares members by name, as a Python dict does.
func rceEqualObjects(a, b *rceVal) bool {
	if len(a.keys) != len(b.keys) {
		return false
	}
	for i, k := range a.keys {
		if !b.has(k) || !rceEqual(a.vals[i], b.get(k)) {
			return false
		}
	}
	return true
}

func rceStr(s string) *rceVal           { return &rceVal{kind: 's', str: s} }
func rceInt(n int) *rceVal              { return &rceVal{kind: 'n', num: json.Number(strconv.Itoa(n))} }
func rceIsStr(v *rceVal, s string) bool { return rceEqual(v, rceStr(s)) }

// rcePyStr is Python's str() of a scalar member, with def for an absent one.
func rcePyStr(v *rceVal, def string) string {
	if v == nil {
		return def
	}
	switch v.kind {
	case 's':
		return v.str
	case 'z':
		return "None"
	case 'b':
		if v.b {
			return "True"
		}
		return "False"
	case 'n':
		if n, ok := new(big.Int).SetString(v.num.String(), 10); ok {
			return n.String()
		}
		return v.num.String()
	}
	body, _ := v.compact()
	return string(body)
}

func rceSHA(v *rceVal) (string, error) {
	body, err := v.compact()
	if err != nil {
		return "", err
	}
	return sha(body), nil
}

func rceHexSig(v *rceVal) []byte {
	if v == nil || v.kind != 's' || !strings.HasPrefix(v.str, "ed25519:") {
		return nil
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(v.str, "ed25519:"))
	if err != nil {
		return nil
	}
	return sig
}

func rceKey(v *rceVal) []byte {
	key, err := hex.DecodeString(rcePyStr(v, ""))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	return key
}

// rceReceiptVerifies: the signature is over SHA-256 of the compact record.
func rceReceiptVerifies(r *rceVal) bool {
	sig, key, record := rceHexSig(r.get("signature")), rceKey(r.get("signer_key")), r.get("action_record")
	if sig == nil || key == nil || !record.isObject() {
		return false
	}
	body, err := record.compact()
	if err != nil {
		return false
	}
	digest := sha256.Sum256(body)
	return ed25519.Verify(ed25519.PublicKey(key), digest[:], sig)
}

// rceEndorsementVerifies: the retiring key signs the domain-separated body.
func rceEndorsementVerifies(e *rceVal) bool {
	if !e.isObject() {
		return false
	}
	sig, key := rceHexSig(e.get("endorsement")), rceKey(e.get("prior_signer_key"))
	if sig == nil || key == nil {
		return false
	}
	body, err := e.without("endorsement").compact()
	if err != nil {
		return false
	}
	digest := sha256.Sum256(append(append([]byte{}, rceEndorsementDomain...), body...))
	return ed25519.Verify(ed25519.PublicKey(key), digest[:], sig)
}

// rceSessionOpenGenesis is the bound genesis a session open commits to; ok is
// false where the Python reader would raise on the payload.
func rceSessionOpenGenesis(p *rceVal) (string, bool) {
	h := sha256.New()
	frame := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	frame([]byte(rceOpenLabel))
	for _, name := range []string{"run_nonce", "open_nonce", "recorder_session", "policy_hash", "signer_key_epoch"} {
		frame([]byte(rcePyStr(p.get(name), "")))
	}
	beat, ok := rcePyInt(p.get("heartbeat_seconds"))
	if !ok || beat.BitLen() > 64 {
		return "", false
	}
	if beat.Sign() < 0 {
		beat = new(big.Int)
	}
	var n [8]byte
	beat.FillBytes(n[:])
	frame(n[:])
	for _, name := range []string{"genesis_anchor_head", "genesis_anchor_log", "posture_capsule_sha256",
		"containment_nonce", "contained_uid"} {
		frame([]byte(rcePyStr(p.get(name), "")))
	}
	return "g1:" + hex.EncodeToString(h.Sum(nil)), true
}

// rcePyInt is Python's int() of a member, absent reading as 0.
func rcePyInt(v *rceVal) (*big.Int, bool) {
	if v == nil {
		return new(big.Int), true
	}
	switch v.kind {
	case 'b':
		if v.b {
			return big.NewInt(1), true
		}
		return new(big.Int), true
	case 'n':
		if n, ok := new(big.Int).SetString(v.num.String(), 10); ok {
			return n, true
		}
		// CPython reads a non-integer token as a double, and int() of an
		// infinite double raises.
		f, err := strconv.ParseFloat(v.num.String(), 64)
		if err != nil || math.IsInf(f, 0) {
			return nil, false
		}
		n, _ := big.NewFloat(f).Int(nil)
		return n, true
	case 's':
		n, ok := new(big.Int).SetString(strings.TrimSpace(v.str), 10)
		return n, ok
	}
	return nil, false
}

// rceControl is the payload of a session control record of one kind.
func rceControl(record *rceVal, kind string) *rceVal {
	control := record.get("session_control")
	if !control.isObject() || !rceIsStr(control.get("kind"), kind) {
		return nil
	}
	payload := control.get(strings.TrimPrefix(kind, "session_"))
	if !payload.isObject() {
		return nil
	}
	return payload
}

type rceRun struct {
	open   *rceVal
	closed bool
}

type rceWalk struct {
	receipts   []*rceVal
	hashes     []string
	linksHold  bool
	boundaries [][2]int
	closesHold bool
	opens      map[string]*rceRun
}

func rceNewWalk(receipts []*rceVal) (*rceWalk, error) {
	w := &rceWalk{receipts: receipts, linksHold: true, closesHold: true, opens: map[string]*rceRun{}}
	for _, r := range receipts {
		digest, err := rceSHA(r)
		if err != nil {
			return nil, err
		}
		w.hashes = append(w.hashes, digest)
	}
	w.walk()
	return w, nil
}

func (w *rceWalk) prior(i int) string {
	if i-1 < 0 {
		return w.hashes[len(w.hashes)-1]
	}
	return w.hashes[i-1]
}

func (w *rceWalk) first(record *rceVal) bool {
	if !rceEqual(record.get("chain_seq"), rceInt(0)) || record.has("key_transition") {
		return false
	}
	prev := record.get("chain_prev_hash")
	if rceIsStr(prev, rceGenesis) {
		return true
	}
	opened := rceControl(record, "session_open")
	if opened == nil {
		return false
	}
	genesis, ok := rceSessionOpenGenesis(opened)
	return ok && rceIsStr(prev, genesis) && rceIsStr(opened.get("genesis_hash"), genesis)
}

func (w *rceWalk) walk() {
	rs := w.receipts
	if len(rs) == 0 || !rs[0].get("action_record").isObject() || !w.first(rs[0].get("action_record")) {
		w.linksHold = false
		return
	}
	key, seq, count := rs[0].get("signer_key"), 0, 1
	w.lifecycle(0, count)
	for i := 1; i < len(rs); i++ {
		record := rs[i].get("action_record")
		if !record.isObject() || !rceIsStr(record.get("chain_prev_hash"), w.hashes[i-1]) {
			w.linksHold = false
			return
		}
		if marker := record.get("key_transition"); marker.isObject() {
			if !rceEqual(record.get("chain_seq"), rceInt(0)) || rceEqual(rs[i].get("signer_key"), key) ||
				!rceEqual(marker.get("prior_signer_key"), key) ||
				!rceEqual(marker.get("prior_chain_seq"), rceInt(seq)) ||
				!rceIsStr(marker.get("prior_chain_hash"), w.hashes[i-1]) {
				w.linksHold = false
				return
			}
			w.boundaries = append(w.boundaries, [2]int{i - 1, i})
			key, seq, count = rs[i].get("signer_key"), 0, 1
		} else {
			if !rceEqual(rs[i].get("signer_key"), key) || !rceEqual(record.get("chain_seq"), rceInt(seq+1)) {
				w.linksHold = false
				return
			}
			seq, count = seq+1, count+1
		}
		w.lifecycle(i, count)
	}
}

func (w *rceWalk) lifecycle(i, count int) {
	record := w.receipts[i].get("action_record")
	if opened := rceControl(record, "session_open"); opened != nil {
		w.opens[rcePyStr(opened.get("run_nonce"), "None")] = &rceRun{open: opened}
		return
	}
	run := w.opens[rcePyStr(record.get("run_nonce"), "None")]
	if run != nil && run.closed {
		w.closesHold = false
	}
	closing := rceControl(record, "session_close")
	if closing == nil {
		return
	}
	if run == nil || !rceEqual(closing.get("run_nonce"), record.get("run_nonce")) ||
		!rceEqual(closing.get("open_nonce"), run.open.get("open_nonce")) ||
		!rceIsStr(closing.get("root_hash"), w.prior(i)) ||
		!rceEqual(closing.get("final_seq"), record.get("chain_seq")) ||
		!rceEqual(closing.get("receipt_count"), rceInt(count)) {
		w.closesHold = false
		return
	}
	run.closed = true
}

type rceInput struct {
	trust        *rceVal
	receipts     []*rceVal
	head         *rceVal
	endorsements []*rceVal
}

func rceReadValue(caseDir, name string) (*rceVal, error) {
	body, err := readIn(caseDir, name)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", name, err)
	}
	v, err := rceParse(body)
	if err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", name, err)
	}
	return v, nil
}

func rceLoad(caseDir string) (*rceInput, error) {
	c, err := rceReadValue(caseDir, "case.json")
	if err != nil {
		return nil, err
	}
	in := &rceInput{trust: c.get("trust")}
	chain := c.get("chain")
	if !in.trust.isObject() || chain == nil || chain.kind != 's' {
		return nil, errors.New("case.json carries no chain or no trust object")
	}
	if in.receipts, err = rceLoadChain(caseDir, chain.str); err != nil {
		return nil, err
	}
	if in.head, err = rceLoadHead(caseDir, c.get("head")); err != nil {
		return nil, err
	}
	in.endorsements, err = rceLoadEndorsements(caseDir, in.trust.get("endorsements"))
	return in, err
}

// rceLoadChain reads one receipt per non-empty line.
func rceLoadChain(caseDir, name string) ([]*rceVal, error) {
	chain, err := readIn(caseDir, name)
	if err != nil {
		return nil, fmt.Errorf("the chain cannot be read: %w", err)
	}
	var receipts []*rceVal
	for _, line := range bytes.Split(chain, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		r, err := rceParse(line)
		if err != nil || !r.isObject() {
			return nil, errors.New("a chain line is not a JSON object")
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
}

// rceLoadHead reads the retained head a case names, or returns nil when it names none.
func rceLoadHead(caseDir string, name *rceVal) (*rceVal, error) {
	if name == nil {
		return nil, nil
	}
	if name.kind != 's' {
		return nil, errors.New("case.json names a head that is not a file name")
	}
	head, err := rceReadValue(caseDir, name.str)
	if err != nil {
		return nil, err
	}
	if !head.isObject() {
		return nil, errors.New("the retained head is not a JSON object")
	}
	return head, nil
}

func rceLoadEndorsements(caseDir string, names *rceVal) ([]*rceVal, error) {
	if names == nil {
		return nil, nil
	}
	var out []*rceVal
	for _, name := range names.items {
		if name.kind != 's' {
			return nil, errors.New("an endorsement name is not a file name")
		}
		e, err := rceReadValue(caseDir, name.str)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (in *rceInput) endorsed(w *rceWalk) bool {
	session := in.trust.get("session")
	for _, b := range w.boundaries {
		prior, next := w.receipts[b[0]], w.receipts[b[1]]
		matches := 0
		for _, e := range in.endorsements {
			if rceEndorsementVerifies(e) &&
				rceEqual(e.get("session_id"), session) &&
				rceEqual(e.get("prior_signer_key"), prior.get("signer_key")) &&
				rceEqual(e.get("prior_final_seq"), prior.get("action_record").get("chain_seq")) &&
				rceIsStr(e.get("prior_tail_hash"), w.hashes[b[0]]) &&
				rceEqual(e.get("new_signer_key"), next.get("signer_key")) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

// headIndex is the receipt a retained head names, or -2 when it names none.
func (in *rceInput) headIndex(w *rceWalk) int {
	if in.head.has("receipt_hash") {
		for i, h := range w.hashes {
			if rceIsStr(in.head.get("receipt_hash"), h) {
				return i
			}
		}
		return -2
	}
	return len(w.receipts) - 1
}

func (in *rceInput) positionHolds(w *rceWalk, index int) bool {
	r := w.receipts[index]
	if in.head.has("final_seq") && !rceEqual(in.head.get("final_seq"), r.get("action_record").get("chain_seq")) {
		return false
	}
	if in.head.has("segment_signer_key") && !rceEqual(in.head.get("segment_signer_key"), r.get("signer_key")) {
		return false
	}
	if in.head.has("receipt_index") {
		at := in.head.get("receipt_index")
		if !rceEqual(at, rceInt(index)) && !rceEqual(at, rceInt(index-len(w.receipts))) {
			return false
		}
	}
	return true
}

func (in *rceInput) firstFailure(w *rceWalk) string {
	for _, r := range in.receipts {
		if !rceReceiptVerifies(r) {
			return "signature_invalid"
		}
	}
	trusted := false
	if len(in.receipts) > 0 && in.trust.get("root_keys") != nil {
		for _, k := range in.trust.get("root_keys").items {
			trusted = trusted || rceEqual(in.receipts[0].get("signer_key"), k)
		}
	}
	if !trusted {
		return "signer_untrusted"
	}
	if !w.linksHold {
		return "chain_link_broken"
	}
	if !in.endorsed(w) {
		return "rotation_unendorsed"
	}
	if !w.closesHold {
		return "close_binding_invalid"
	}
	if in.head == nil {
		return ""
	}
	index := in.headIndex(w)
	if index == -2 {
		return "head_missing"
	}
	if index < 0 || !in.positionHolds(w, index) {
		return "head_position_mismatch"
	}
	if rceIsStr(in.head.get("kind"), "final") && index != len(w.receipts)-1 {
		return "head_not_final"
	}
	return ""
}

func (w *rceWalk) endProvenByClose() bool {
	if len(w.receipts) == 0 {
		return false
	}
	closing := rceControl(w.receipts[len(w.receipts)-1].get("action_record"), "session_close")
	if closing == nil {
		return false
	}
	run := w.opens[rcePyStr(closing.get("run_nonce"), "None")]
	return run != nil && rceRunSession.MatchString(rcePyStr(run.open.get("recorder_session"), ""))
}

func rceVerify(in *rceInput) scDecision {
	w, err := rceNewWalk(in.receipts)
	if err != nil {
		return scDecision{"error", err.Error()}
	}
	if failure := in.firstFailure(w); failure != "" {
		return scDecision{"rejected", failure}
	}
	if w.endProvenByClose() {
		return scDecision{"verified", "end_proven_close"}
	}
	if in.head != nil && rceIsStr(in.head.get("kind"), "final") && in.head.has("receipt_hash") &&
		len(w.hashes) > 0 && rceIsStr(in.head.get("receipt_hash"), w.hashes[len(w.hashes)-1]) {
		return scDecision{"verified", "end_proven_head"}
	}
	return scDecision{"prefix", "end_unproven"}
}
