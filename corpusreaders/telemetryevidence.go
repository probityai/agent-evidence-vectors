package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

func init() { register(telemetryEvidence{}) }

// telemetryEvidence judges corpora/vectors-telemetry-evidence/. Two record kinds
// share the corpus. An evidence-digest record carries a digest manifest (as the
// exact text its producer wrote), the copies a consumer reads and the keys the
// consumer pinned. An event-log record carries one session log, the head the
// consumer kept outside it, the consumer's pinned first link and its coverage
// boundary. The reader derives each member's decision and reason from the
// record bytes with the rules the Python reader applies, in the same order.
//
// Digest rules: record_shape (a repeated member anywhere is
// no_duplicate_member); signature; signer_pinned (a manifest key agrees only
// when the consumer pinned its SHA-256); no_duplicate_reference; coverage (every
// consumed item carries a digest, and no items at all is empty_denominator);
// canonical_form; consumed_copy_bound.
//
// Log rules: record_shape; coverage_boundary; signature; signer_pinned;
// no_duplicate_event; sequence; chain_order; head_anchor.
type telemetryEvidence struct{}

func (telemetryEvidence) Suite() string { return "telemetry-evidence/v1" }

const (
	teManifestSchema = "evidence-digest-manifest/v1"
	teHeadFormat     = "probity-witness-ledger-head-v0"
	teSafeInt        = float64(1 << 53)
	teMaxCBORDepth   = 16
)

// teRefused is a rule the record fails: a contradicted decision with the
// rule's code. Any other error means the record could not be read at all,
// which is a finding and not a decision.
type teRefused struct{ code string }

func (e *teRefused) Error() string { return e.code }

func teRefuse(code string) error { return &teRefused{code} }

type teVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

type teRecord struct {
	Claim            string          `json:"claim"`
	Consumed         json.RawMessage `json:"consumed"`
	ManifestText     *string         `json:"manifest_text"`
	Pinned           []string        `json:"pinned_key_sha256"`
	RequireSignature bool            `json:"require_signature"`
	Coverage         json.RawMessage `json:"coverage"`
	EventsText       *string         `json:"events_text"`
	FirstPrev        *string         `json:"first_prev"`
	HeadText         *string         `json:"head_text"`
}

func (telemetryEvidence) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v teVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = teJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func teJudgeMember(caseDir string, v teVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record teRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	got, err := teJudge(record)
	if err != nil {
		return append(findings, "the record cannot be judged: "+err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func teJudge(r teRecord) (scDecision, error) {
	judge := teJudgeLog
	if r.Claim == "evidence-digest" {
		judge = teJudgeDigest
	}
	decision, reason, err := judge(r)
	var refused *teRefused
	if errors.As(err, &refused) {
		return scDecision{"contradicted", refused.code}, nil
	}
	if err != nil {
		return scDecision{}, err
	}
	return scDecision{decision, reason}, nil
}

// --- strict JSON -----------------------------------------------------------------------------

// teStrict parses JSON text, refusing a member name repeated at any depth
// (no_duplicate_member) and anything that is not one JSON value (record_shape).
// A repeated name is raised when its object closes, as the Python object hook
// does, so a syntax error later in the same object still wins.
func teStrict(text string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	value, err := teStrictValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, teRefuse("record_shape")
	}
	return value, nil
}

func teStrictValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, teRefuse("record_shape")
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch delim {
	case '{':
		return teStrictObject(dec)
	case '[':
		items := []any{}
		for dec.More() {
			item, err := teStrictValue(dec)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		if _, err := dec.Token(); err != nil {
			return nil, teRefuse("record_shape")
		}
		return items, nil
	}
	return nil, teRefuse("record_shape")
}

func teStrictObject(dec *json.Decoder) (any, error) {
	out := map[string]any{}
	duplicate := false
	for dec.More() {
		keyTok, err := dec.Token()
		key, ok := keyTok.(string)
		if err != nil || !ok {
			return nil, teRefuse("record_shape")
		}
		value, err := teStrictValue(dec)
		if err != nil {
			return nil, err
		}
		if _, seen := out[key]; seen {
			duplicate = true
		}
		out[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, teRefuse("record_shape")
	}
	if duplicate {
		return nil, teRefuse("no_duplicate_member")
	}
	return out, nil
}

func teHexd(value any, size int) (string, error) {
	text, ok := value.(string)
	if !ok || len(text) != size {
		return "", teRefuse("record_shape")
	}
	for _, c := range text {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", teRefuse("record_shape")
		}
	}
	return text, nil
}

// teB64 decodes base64: the url alphabet without padding in its one canonical
// spelling, or the standard alphabet with padding and no line breaks.
func teB64(value any, url bool) ([]byte, error) {
	text, ok := value.(string)
	if !ok {
		return nil, teRefuse("record_shape")
	}
	if url {
		raw, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != text {
			return nil, teRefuse("record_shape")
		}
		return raw, nil
	}
	if strings.ContainsAny(text, "\r\n") {
		return nil, teRefuse("record_shape")
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, teRefuse("record_shape")
	}
	return raw, nil
}

// --- the signed bytes: RFC 8785 over the integers-only profile --------------------------------

func teJCS(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := teJCSWrite(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func teJCSWrite(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case string:
		writeJCSString(buf, v)
	case json.Number:
		text, err := teJCSNumber(v)
		if err != nil {
			return err
		}
		buf.WriteString(text)
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := teJCSWrite(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(a, b int) bool { return utf16Less(keys[a], keys[b]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := teJCSWrite(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("%T is not a JSON value", value)
	}
	return nil
}

// teJCSNumber writes an integer as its digits and any other number by its
// value when that value is an integer inside the safe range; anything else has
// no form under the suite's profile.
func teJCSNumber(n json.Number) (string, error) {
	token := n.String()
	if !strings.ContainsAny(token, ".eE") {
		i, ok := new(big.Int).SetString(token, 10)
		if !ok {
			return "", fmt.Errorf("%q is not a JSON number", token)
		}
		return i.String(), nil
	}
	f, err := strconv.ParseFloat(token, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return "", err
	}
	if math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) >= teSafeInt {
		return "", fmt.Errorf("%q is outside the integers-only profile", token)
	}
	if f == 0 {
		return "0", nil
	}
	return strconv.FormatFloat(f, 'f', 0, 64), nil
}

// --- deterministic CBOR -----------------------------------------------------------------------

type teCBOR struct {
	major byte // 0 unsigned, 1 negative, 2 bytes, 3 text, 4 array, 5 map, 7 simple
	arg   uint64
	raw   []byte
	items []*teCBOR
	pairs [][2]*teCBOR
}

func teCBORArgument(buf []byte, pos int, info byte) (uint64, int, error) {
	if info < 24 {
		return uint64(info), pos, nil
	}
	size := 1 << (info - 24)
	if pos+size > len(buf) {
		return 0, pos, teRefuse("canonical_form")
	}
	var arg uint64
	for _, b := range buf[pos : pos+size] {
		arg = arg<<8 | uint64(b)
	}
	return arg, pos + size, nil
}

func teCBORItem(buf []byte, pos, depth int) (*teCBOR, int, error) {
	if depth > teMaxCBORDepth || pos >= len(buf) {
		return nil, pos, teRefuse("canonical_form")
	}
	major, info := buf[pos]>>5, buf[pos]&31
	pos++
	if major == 7 && info >= 20 && info <= 22 {
		return &teCBOR{major: 7, arg: uint64(info)}, pos, nil
	}
	if major == 6 || major == 7 || info > 27 {
		return nil, pos, teRefuse("canonical_form")
	}
	arg, pos, err := teCBORArgument(buf, pos, info)
	if err != nil {
		return nil, pos, err
	}
	switch major {
	case 0, 1:
		return &teCBOR{major: major, arg: arg}, pos, nil
	case 2, 3:
		if arg > uint64(len(buf)-pos) {
			return nil, pos, teRefuse("canonical_form")
		}
		end := pos + int(arg) // #nosec G115 -- arg is at most the remaining length, checked above
		return &teCBOR{major: major, raw: buf[pos:end]}, end, nil
	}
	return teCBORContainer(buf, pos, major, arg, depth)
}

func teCBORContainer(buf []byte, pos int, major byte, arg uint64, depth int) (*teCBOR, int, error) {
	node := &teCBOR{major: major}
	seen := map[string]bool{}
	duplicate := false
	for n := uint64(0); n < arg; n++ {
		first, next, err := teCBORItem(buf, pos, depth+1)
		if err != nil {
			return nil, next, err
		}
		pos = next
		if major == 4 {
			node.items = append(node.items, first)
			continue
		}
		value, next, err := teCBORItem(buf, pos, depth+1)
		if err != nil {
			return nil, next, err
		}
		pos = next
		key := teCBORRepr(first)
		duplicate = duplicate || seen[key]
		seen[key] = true
		node.pairs = append(node.pairs, [2]*teCBOR{first, value})
	}
	if duplicate {
		return nil, pos, teRefuse("no_duplicate_member")
	}
	return node, pos, nil
}

// teCBORRepr spells a value structurally, so two map keys are the same key
// exactly when their spellings agree.
func teCBORRepr(n *teCBOR) string {
	switch n.major {
	case 2, 3:
		return fmt.Sprintf("%d:%x", n.major, n.raw)
	case 4:
		parts := make([]string, len(n.items))
		for i, item := range n.items {
			parts[i] = teCBORRepr(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case 5:
		parts := make([]string, len(n.pairs))
		for i, p := range n.pairs {
			parts[i] = teCBORRepr(p[0]) + "=" + teCBORRepr(p[1])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return fmt.Sprintf("%d#%d", n.major, n.arg)
}

func teCBORHead(major byte, arg uint64) []byte {
	if arg < 24 {
		return []byte{major<<5 | byte(arg)}
	}
	for _, step := range []struct {
		info byte
		size int
	}{{24, 1}, {25, 2}, {26, 4}, {27, 8}} {
		if step.size == 8 || arg < 1<<(8*uint(step.size)) {
			out := []byte{major<<5 | step.info}
			for shift := (step.size - 1) * 8; shift >= 0; shift -= 8 {
				out = append(out, byte(arg>>uint(shift))) // #nosec G115 -- the low byte is the byte wanted
			}
			return out
		}
	}
	return nil
}

func teCBOREncode(n *teCBOR) []byte {
	switch n.major {
	case 7:
		return map[uint64][]byte{20: {0xf4}, 21: {0xf5}, 22: {0xf6}}[n.arg]
	case 0, 1:
		return teCBORHead(n.major, n.arg)
	case 2, 3:
		return append(teCBORHead(n.major, uint64(len(n.raw))), n.raw...)
	case 4:
		out := teCBORHead(4, uint64(len(n.items)))
		for _, item := range n.items {
			out = append(out, teCBOREncode(item)...)
		}
		return out
	}
	type encoded struct{ key, value []byte }
	pairs := make([]encoded, len(n.pairs))
	for i, p := range n.pairs {
		pairs[i] = encoded{teCBOREncode(p[0]), teCBOREncode(p[1])}
	}
	sort.SliceStable(pairs, func(a, b int) bool {
		if c := bytes.Compare(pairs[a].key, pairs[b].key); c != 0 {
			return c < 0
		}
		return bytes.Compare(pairs[a].value, pairs[b].value) < 0
	})
	out := teCBORHead(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(append(out, p.key...), p.value...)
	}
	return out
}

// --- canonical bytes of a consumed copy -------------------------------------------------------

func teCanonical(form string, data []byte) ([]byte, error) {
	switch form {
	case "raw":
		return data, nil
	case "rfc8785":
		if !utf8.Valid(data) {
			return nil, teRefuse("canonical_form")
		}
		value, err := teStrict(string(data))
		if err != nil {
			return nil, err
		}
		if a2aLoneSurrogate(data) {
			return nil, teRefuse("canonical_form")
		}
		canonical, err := rfc8785Bytes(value)
		if err != nil {
			return nil, teRefuse("canonical_form")
		}
		return canonical, nil
	}
	value, end, err := teCBORItem(data, 0, 0)
	if err != nil {
		return nil, err
	}
	if end != len(data) || !bytes.Equal(teCBOREncode(value), data) {
		return nil, teRefuse("canonical_form")
	}
	return data, nil
}

// --- evidence-digest records ------------------------------------------------------------------

type teCopy struct {
	id   string
	data []byte
	null bool
}

type teRef struct {
	alg, form, digest string
	hasForm           bool
}

var teHashSize = map[string]int{"sha-256": 32, "sha-384": 48, "sha-512": 64}

func teHash(alg string, data []byte) string {
	switch alg {
	case "sha-384":
		sum := sha512.Sum384(data)
		return hex.EncodeToString(sum[:])
	case "sha-512":
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// teConsumed reads the consumed copies in the order the record writes them.
func teConsumed(raw json.RawMessage) ([]teCopy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("consumed is not an object")
	}
	var out []teCopy
	index := map[string]int{}
	for dec.More() {
		keyTok, err := dec.Token()
		key, ok := keyTok.(string)
		if err != nil || !ok {
			return nil, errors.New("consumed is not an object")
		}
		var entry json.RawMessage
		if err := dec.Decode(&entry); err != nil {
			return nil, err
		}
		item, err := teCopyOf(key, entry)
		if err != nil {
			return nil, err
		}
		if at, seen := index[key]; seen {
			out[at] = item
			continue
		}
		index[key] = len(out)
		out = append(out, item)
	}
	return out, nil
}

func teCopyOf(id string, entry json.RawMessage) (teCopy, error) {
	if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
		return teCopy{id: id, null: true}, nil
	}
	var fields map[string]string
	if err := json.Unmarshal(entry, &fields); err != nil || len(fields) != 1 {
		return teCopy{}, errors.New("a consumed copy is {text} or {hex}")
	}
	if text, ok := fields["text"]; ok {
		return teCopy{id: id, data: []byte(text)}, nil
	}
	if digits, ok := fields["hex"]; ok {
		data, err := hex.DecodeString(digits)
		if err != nil {
			return teCopy{}, fmt.Errorf("a consumed copy's hex does not decode: %w", err)
		}
		return teCopy{id: id, data: data}, nil
	}
	return teCopy{}, errors.New("a consumed copy is {text} or {hex}")
}

func teManifest(text string) (map[string]any, error) {
	value, err := teStrict(text)
	if err != nil {
		return nil, err
	}
	manifest, ok := value.(map[string]any)
	if !ok || manifest["schema_version"] != teManifestSchema {
		return nil, teRefuse("record_shape")
	}
	if _, ok := manifest["refs"].([]any); !ok {
		return nil, teRefuse("record_shape")
	}
	for key := range manifest {
		if key != "schema_version" && key != "refs" && key != "signature" {
			return nil, teRefuse("record_shape")
		}
	}
	return manifest, nil
}

// tePinned refuses a key the consumer did not pin; with no pins at all the
// signer is not established, which is a reason and not a refusal.
func tePinned(key []byte, pins []string) (string, error) {
	if pins == nil {
		return "signer_not_established", nil
	}
	sum := sha256.Sum256(key)
	for _, pin := range pins {
		if pin == hex.EncodeToString(sum[:]) {
			return "", nil
		}
	}
	return "", teRefuse("signer_pinned")
}

// teManifestSigner returns the not-established reason the signature leaves, or
// "" when it leaves none; a bad signature is refused.
func teManifestSigner(manifest map[string]any, r teRecord) (string, error) {
	signature, present := manifest["signature"]
	if present && signature == nil {
		return "", teRefuse("record_shape")
	}
	if signature == nil {
		if r.RequireSignature {
			return "unsigned_manifest", nil
		}
		return "", nil
	}
	fields, ok := signature.(map[string]any)
	if !ok || len(fields) != 3 || fields["alg"] != "Ed25519" {
		return "", teRefuse("record_shape")
	}
	_, hasKey := fields["public_key"]
	_, hasValue := fields["value"]
	if !hasKey || !hasValue {
		return "", teRefuse("record_shape")
	}
	key, err := teB64(fields["public_key"], true)
	if err != nil {
		return "", err
	}
	body := map[string]any{}
	for k, v := range manifest {
		if k != "signature" {
			body[k] = v
		}
	}
	canonical, err := teJCS(body)
	if err != nil {
		return "", err
	}
	message := append([]byte(teManifestSchema+"\x00"), canonical...)
	if len(key) != ed25519.PublicKeySize {
		return "", teRefuse("signature")
	}
	sig, err := teB64(fields["value"], true)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(ed25519.PublicKey(key), message, sig) {
		return "", teRefuse("signature")
	}
	return tePinned(key, r.Pinned)
}

func teReferences(manifest map[string]any) (map[string]teRef, error) {
	refs := map[string]teRef{}
	for _, item := range manifest["refs"].([]any) {
		fields, ok := item.(map[string]any)
		if !ok {
			return nil, teRefuse("record_shape")
		}
		for key := range fields {
			if key != "id" && key != "hash_alg" && key != "canonicalization" && key != "digest" {
				return nil, teRefuse("record_shape")
			}
		}
		alg, _ := fields["hash_alg"].(string)
		id, idOK := fields["id"].(string)
		size, algOK := teHashSize[alg]
		ref := teRef{alg: alg, form: "rfc8785"}
		if form, present := fields["canonicalization"]; present {
			text, isText := form.(string)
			if !isText || (text != "rfc8785" && text != "cbor-deterministic" && text != "raw") {
				return nil, teRefuse("record_shape")
			}
			ref.form, ref.hasForm = text, true
		}
		if !algOK || !idOK {
			return nil, teRefuse("record_shape")
		}
		digest, err := teHexd(fields["digest"], size*2)
		if err != nil {
			return nil, err
		}
		ref.digest = digest
		if _, seen := refs[id]; seen {
			return nil, teRefuse("no_duplicate_reference")
		}
		refs[id] = ref
	}
	return refs, nil
}

// teBindCopies recomputes each digest over its consumed copy and returns a
// not-established reason, or "" when every copy is bound.
func teBindCopies(consumed []teCopy, refs map[string]teRef) (string, error) {
	undeclared, unavailable := false, false
	for _, c := range consumed {
		ref := refs[c.id]
		switch {
		case !ref.hasForm:
			undeclared = true
		case c.null:
			unavailable = true
		default:
			canonical, err := teCanonical(ref.form, c.data)
			if err != nil {
				return "", err
			}
			if teHash(ref.alg, canonical) != ref.digest {
				return "", teRefuse("consumed_copy_bound")
			}
		}
	}
	if undeclared {
		return "undeclared_canonical_form", nil
	}
	if unavailable {
		return "consumed_copy_unavailable", nil
	}
	return "", nil
}

func teJudgeDigest(r teRecord) (string, string, error) {
	consumed, err := teConsumed(r.Consumed)
	if err != nil {
		return "", "", err
	}
	if r.ManifestText == nil {
		return "", "", errors.New("manifest_text is absent")
	}
	manifest, err := teManifest(*r.ManifestText)
	if err != nil {
		return "", "", err
	}
	pending, err := teManifestSigner(manifest, r)
	if err != nil {
		return "", "", err
	}
	refs, err := teReferences(manifest)
	if err != nil {
		return "", "", err
	}
	if len(consumed) == 0 {
		return "cannot-tell", "empty_denominator", nil
	}
	for _, c := range consumed {
		if _, covered := refs[c.id]; !covered {
			return "", "", teRefuse("coverage")
		}
	}
	unbound, err := teBindCopies(consumed, refs)
	if err != nil {
		return "", "", err
	}
	if unbound == "undeclared_canonical_form" {
		return "cannot-tell", unbound, nil
	}
	if pending != "" {
		return "cannot-tell", pending, nil
	}
	if unbound != "" {
		return "cannot-tell", unbound, nil
	}
	return "agrees", "digests_bind_consumed_copy", nil
}

// --- event-log records ------------------------------------------------------------------------

type teEvent struct {
	fields map[string]any
	seq    *big.Int
	prev   string
}

func teEvents(text string) ([]teEvent, error) {
	var events []teEvent
	for _, line := range strings.Split(text, "\n") {
		if strings.Trim(line, " \t\r") == "" {
			continue
		}
		value, err := teStrict(line)
		if err != nil {
			return nil, err
		}
		fields, _ := value.(map[string]any)
		number, isNumber := fields["seq"].(json.Number)
		if !isNumber || strings.ContainsAny(number.String(), ".eE") {
			return nil, teRefuse("record_shape")
		}
		seq, ok := new(big.Int).SetString(number.String(), 10)
		if !ok {
			return nil, teRefuse("record_shape")
		}
		prev, err := teHexd(fields["prev"], 64)
		if err != nil {
			return nil, err
		}
		events = append(events, teEvent{fields: fields, seq: seq, prev: prev})
	}
	return events, nil
}

type teHead struct {
	count *big.Int
	head  any
}

// teReadHead returns the retained head and the not-established reason its key
// leaves; a bad head is refused.
func teReadHead(r teRecord) (*teHead, string, error) {
	if r.HeadText == nil {
		return nil, "", nil
	}
	value, err := teStrict(*r.HeadText)
	if err != nil {
		return nil, "", err
	}
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 5 || fields["format"] != teHeadFormat {
		return nil, "", teRefuse("record_shape")
	}
	for _, name := range []string{"count", "head", "keyid", "signature"} {
		if _, present := fields[name]; !present {
			return nil, "", teRefuse("record_shape")
		}
	}
	number, isNumber := fields["count"].(json.Number)
	if !isNumber || strings.ContainsAny(number.String(), ".eE") {
		return nil, "", teRefuse("record_shape")
	}
	count, ok := new(big.Int).SetString(number.String(), 10)
	if !ok {
		return nil, "", teRefuse("record_shape")
	}
	keyHex, err := teHexd(fields["keyid"], 64)
	if err != nil {
		return nil, "", err
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, "", teRefuse("record_shape")
	}
	canonical, err := teJCS(map[string]any{"format": fields["format"], "count": fields["count"], "head": fields["head"]})
	if err != nil {
		return nil, "", err
	}
	sig, err := teB64(fields["signature"], false)
	if err != nil {
		return nil, "", err
	}
	if !ed25519.Verify(ed25519.PublicKey(key), append([]byte(teHeadFormat+"\x00"), canonical...), sig) {
		return nil, "", teRefuse("signature")
	}
	pending, err := tePinned(key, r.Pinned)
	if err != nil {
		return nil, "", err
	}
	return &teHead{count: count, head: fields["head"]}, pending, nil
}

func teEventDigest(event teEvent) (string, error) {
	canonical, err := teJCS(event.fields)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func teOrder(events []teEvent, digests []string, r teRecord, first *big.Int) error {
	seen := map[string]bool{}
	for _, d := range digests {
		if seen[d] {
			return teRefuse("no_duplicate_event")
		}
		seen[d] = true
	}
	for i, e := range events {
		if e.seq.Cmp(new(big.Int).Add(first, big.NewInt(int64(i)))) != 0 {
			return teRefuse("sequence")
		}
	}
	for i, e := range events {
		want := ""
		if i == 0 {
			if r.FirstPrev == nil {
				return errors.New("first_prev is absent")
			}
			want = *r.FirstPrev
		} else {
			want = digests[i-1]
		}
		if e.prev != want {
			return teRefuse("chain_order")
		}
	}
	return nil
}

func teCoverage(raw json.RawMessage) (map[string]any, *big.Int, error) {
	value, err := decodeJSONNumbers(raw)
	if err != nil {
		return nil, nil, errors.New("coverage is absent or does not parse")
	}
	coverage, ok := value.(map[string]any)
	if !ok {
		return nil, nil, errors.New("coverage is not an object")
	}
	number, isNumber := coverage["first_seq"].(json.Number)
	first, ok := new(big.Int).SetString(number.String(), 10)
	if !isNumber || !ok {
		return nil, nil, errors.New("coverage.first_seq is not an integer")
	}
	return coverage, first, nil
}

func teJudgeLog(r teRecord) (string, string, error) {
	if r.EventsText == nil {
		return "", "", errors.New("events_text is absent")
	}
	events, err := teEvents(*r.EventsText)
	if err != nil {
		return "", "", err
	}
	if len(events) == 0 {
		return "cannot-tell", "empty_denominator", nil
	}
	coverage, first, err := teCoverage(r.Coverage)
	if err != nil {
		return "", "", err
	}
	if session, bounded := coverage["session"]; bounded {
		for _, e := range events {
			if !reflect.DeepEqual(e.fields["session"], session) {
				return "", "", teRefuse("coverage_boundary")
			}
		}
	}
	head, pending, err := teReadHead(r)
	if err != nil {
		return "", "", err
	}
	digests := make([]string, len(events))
	for i, e := range events {
		if digests[i], err = teEventDigest(e); err != nil {
			return "", "", err
		}
	}
	if err := teOrder(events, digests, r, first); err != nil {
		return "", "", err
	}
	if head == nil {
		return "cannot-tell", "head_not_anchored", nil
	}
	if head.count.Cmp(big.NewInt(int64(len(events)))) != 0 || head.head != digests[len(digests)-1] {
		return "", "", teRefuse("head_anchor")
	}
	if pending != "" {
		return "cannot-tell", pending, nil
	}
	return "agrees", "event_log_complete", nil
}
