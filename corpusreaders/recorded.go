package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() { register(recordedSets{}) }

// recordedSets judges vectors-recorded/. A member is a directory of files kept
// byte for byte beside the SHA256SUMS list its publisher wrote. Recorded
// members come from live runs and are not generated; synthetic members are one
// mutation away from an intact synthetic set. The codes, their meaning and the
// order-free code set each member must draw are the ones the Python reader
// (packaging/agent_evidence_vectors/recorded.py) applies:
//
//	sums-missing, sums-malformed, path-unsafe, file-missing, digest-mismatch,
//	file-unlisted, sums-unpinned, binding-malformed, binding-mismatch.
//
// opentimestamps-file-digest reads only the proof file's header: it holds when
// the header commits to the SHA-256 of the named subject file.
// opentimestamps-bitcoin-header also runs every operation of the proof: one
// Bitcoin attestation at the held block's height must commit to the Merkle
// root of the held 80-byte header, which must hash to its block id
// (anchor-mismatch); an optional "after" pointer names a height in the subject
// that must be below the anchor (anchor-not-after-seen), and an optional
// "statedTime" pointer a Unix time no later than the header time plus 7200
// seconds (stated-after-anchor). Proof of work is not checked.
type recordedSets struct{}

func (recordedSets) Suite() string { return "recorded-set-conformance/v1" }

const recordedSums = "SHA256SUMS"

var (
	recordedLine     = regexp.MustCompile(`^([0-9a-f]{64}) [ *](.+)$`)
	recordedOTSMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")
)

type recordedBinding struct {
	Type       string         `json:"type"`
	Proof      string         `json:"proof"`
	Subject    string         `json:"subject"`
	Block      *recordedBlock `json:"block"`
	After      *string        `json:"after"`
	StatedTime *string        `json:"statedTime"`
}

type recordedBlock struct {
	Height *uint64 `json:"height"`
	Header string  `json:"header"`
	ID     string  `json:"id"`
}

const recordedOTSTolerance = 7200

func recordedBlockID(header []byte) string {
	first := sha256.Sum256(header)
	second := sha256.Sum256(first[:])
	for i, j := 0, len(second)-1; i < j; i, j = i+1, j-1 {
		second[i], second[j] = second[j], second[i]
	}
	return hex.EncodeToString(second[:])
}

// recordedPointer is the integer an RFC 6901 pointer names in a JSON subject.
func recordedPointer(subject []byte, pointer string) (int64, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return 0, false
	}
	decoder := json.NewDecoder(bytes.NewReader(subject))
	decoder.UseNumber()
	var doc any
	if err := decoder.Decode(&doc); err != nil {
		return 0, false
	}
	for _, token := range strings.Split(pointer[1:], "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch node := doc.(type) {
		case map[string]any:
			next, ok := node[token]
			if !ok {
				return 0, false
			}
			doc = next
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(node) || strconv.Itoa(index) != token {
				return 0, false
			}
			doc = node[index]
		default:
			return 0, false
		}
	}
	number, ok := doc.(json.Number)
	if !ok || strings.ContainsAny(number.String(), ".eE") {
		return 0, false
	}
	value, err := number.Int64()
	return value, err == nil
}

// recordedAnchorCodes is what an opentimestamps-bitcoin-header binding adds.
// recordedAnchorMatched reports whether the proof carries a Bitcoin attestation
// for the pinned block; ok is false when the proof cannot be read.
func recordedAnchorMatched(b recordedBinding, proof, subject, header []byte) (matched, ok bool) {
	digest := sha256.Sum256(subject)
	attestations, err := arOTSAttestations(proof, digest[:])
	if err != nil {
		return false, false
	}
	for _, a := range attestations {
		if !bytes.Equal(a.tag, arOTSBitcoin) {
			continue
		}
		pr := &arTLS{data: a.payload}
		height, err := pr.varuint()
		if err != nil || pr.at != len(a.payload) {
			return false, false
		}
		if height == *b.Block.Height && bytes.Equal(a.message, header[36:68]) {
			matched = true
		}
	}
	return matched, true
}

// recordedTimeCodes returns the ordering codes for the declared "after" and
// "statedTime" pointers; ok is false when a pointer does not resolve.
func recordedTimeCodes(b recordedBinding, subject, header []byte) (codes []string, ok bool) {
	if b.After != nil {
		seen, found := recordedPointer(subject, *b.After)
		if !found {
			return nil, false
		}
		if seen >= 0 && uint64(seen) >= *b.Block.Height {
			codes = append(codes, "anchor-not-after-seen")
		}
	}
	if b.StatedTime != nil {
		stated, found := recordedPointer(subject, *b.StatedTime)
		if !found {
			return nil, false
		}
		seconds := int64(header[68]) | int64(header[69])<<8 | int64(header[70])<<16 | int64(header[71])<<24
		if stated > seconds+recordedOTSTolerance {
			codes = append(codes, "stated-after-anchor")
		}
	}
	return codes, true
}

func recordedAnchorCodes(b recordedBinding, proof, subject []byte) []string {
	if b.Block == nil || b.Block.Height == nil {
		return []string{"binding-malformed"}
	}
	header, err := hex.DecodeString(b.Block.Header)
	if err != nil || len(header) != 80 || recordedBlockID(header) != b.Block.ID {
		return []string{"binding-malformed"}
	}
	matched, ok := recordedAnchorMatched(b, proof, subject, header)
	if !ok {
		return []string{"binding-malformed"}
	}
	var codes []string
	if !matched {
		codes = append(codes, "anchor-mismatch")
	}
	later, ok := recordedTimeCodes(b, subject, header)
	if !ok {
		return []string{"binding-malformed"}
	}
	return append(codes, later...)
}

type recordedEntry struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Dir        string            `json:"dir"`
	SumsSHA256 *string           `json:"sumsSha256"`
	Bindings   []recordedBinding `json:"bindings"`
	Expected   struct {
		Verdict string   `json:"verdict"`
		Codes   []string `json:"codes"`
	} `json:"expected"`
}

func recordedUnsafe(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) || path == recordedSums {
		return true
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return true
		}
	}
	return false
}

// recordedParse returns the listed path -> digest map, or nil when the list
// does not parse, and the codes the parse drew.
func recordedParse(data []byte) (map[string]string, map[string]bool) {
	codes := map[string]bool{}
	if !bytes.HasSuffix(data, []byte("\n")) {
		codes["sums-malformed"] = true
		return nil, codes
	}
	listed := map[string]string{}
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		m := recordedLine.FindStringSubmatch(line)
		if m == nil {
			codes["sums-malformed"] = true
			return nil, codes
		}
		path := strings.TrimPrefix(m[2], "./")
		if _, dup := listed[path]; dup || recordedUnsafe(path) {
			codes["path-unsafe"] = true
			continue
		}
		listed[path] = m[1]
	}
	return listed, codes
}

func recordedPresent(dir string) (map[string]bool, bool, error) {
	present := map[string]bool{}
	linked := false
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- the directory the caller named for judging
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			linked = true
			return nil
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			if rel = filepath.ToSlash(rel); rel != recordedSums {
				present[rel] = true
			}
		}
		return nil
	})
	return present, linked, err
}

func recordedBindingCodes(dir string, b recordedBinding, listed map[string]string) []string {
	_, proofListed := listed[b.Proof]
	_, subjectListed := listed[b.Subject]
	known := b.Type == "opentimestamps-file-digest" || b.Type == "opentimestamps-bitcoin-header"
	if !known || !proofListed || !subjectListed {
		return []string{"binding-malformed"}
	}
	proof, err := readIn(dir, b.Proof)
	if err != nil {
		return []string{"binding-malformed"}
	}
	subject, err := readIn(dir, b.Subject)
	if err != nil {
		return []string{"binding-malformed"}
	}
	head := len(recordedOTSMagic)
	if !bytes.HasPrefix(proof, recordedOTSMagic) || len(proof) < head+34 ||
		proof[head] != 0x01 || proof[head+1] != 0x08 {
		return []string{"binding-malformed"}
	}
	if hex.EncodeToString(proof[head+2:head+34]) != sha(subject) {
		return []string{"binding-mismatch"}
	}
	if b.Type == "opentimestamps-bitcoin-header" {
		return recordedAnchorCodes(b, proof, subject)
	}
	return nil
}

// recordedCheck returns every code a set draws, sorted; none means verified.
func recordedCheck(dir string, pin *string, bindings []recordedBinding) ([]string, error) {
	data, err := readIn(dir, recordedSums)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{"sums-missing"}, nil
		}
		return nil, err
	}
	codes := map[string]bool{}
	if pin != nil && sha(data) != *pin {
		codes["sums-unpinned"] = true
	}
	listed, parseCodes := recordedParse(data)
	for code := range parseCodes {
		codes[code] = true
	}
	if listed != nil {
		present, linked, err := recordedPresent(dir)
		if err != nil {
			return nil, err
		}
		if linked {
			codes["path-unsafe"] = true
		}
		for path, digest := range listed {
			if !present[path] {
				codes["file-missing"] = true
				continue
			}
			body, err := readIn(dir, path)
			if err != nil {
				return nil, err
			}
			if sha(body) != digest {
				codes["digest-mismatch"] = true
			}
		}
		for path := range present {
			if _, ok := listed[path]; !ok {
				codes["file-unlisted"] = true
			}
		}
		for _, b := range bindings {
			for _, code := range recordedBindingCodes(dir, b, listed) {
				codes[code] = true
			}
		}
	}
	return sortedKeys(codes), nil
}

// recordedTreeID is "v" and the first sixteen hex characters of the digest over
// the compact sorted JSON map from each file's path to its SHA-256.
func recordedTreeID(dir string) (string, error) {
	listing := map[string]any{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- the directory the caller named for judging
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path) // #nosec G304,G122 -- a path inside the corpus being judged
		if err != nil {
			return err
		}
		listing[filepath.ToSlash(rel)] = sha(body)
		return nil
	})
	if err != nil {
		return "", err
	}
	encoded, err := pythonCompactJSON(listing)
	if err != nil {
		return "", err
	}
	return "v" + sha(encoded)[:16], nil
}

func (recordedSets) Judge(dir string, manifest []byte) (*Result, error) {
	var head struct {
		CorpusDigest string          `json:"corpusDigest"`
		Vectors      json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(manifest, &head); err != nil {
		return nil, err
	}
	var entries []recordedEntry
	if err := json.Unmarshal(head.Vectors, &entries); err != nil {
		return nil, err
	}
	result := &Result{}
	generic, err := decodeJSONNumbers(head.Vectors)
	if err != nil {
		return nil, err
	}
	encoded, err := pythonCompactJSON(generic)
	if err != nil {
		return nil, err
	}
	if sha(encoded) != head.CorpusDigest {
		result.Findings = append(result.Findings, "corpusDigest does not recompute over the vectors")
	}
	result.Findings = append(result.Findings, recordedStrays(dir, entries)...)
	for _, e := range entries {
		m, err := recordedMember(dir, e)
		if err != nil {
			return nil, err
		}
		result.Members = append(result.Members, m)
	}
	return result, nil
}

// recordedStrays names every set directory on disk that no manifest row declares.
func recordedStrays(dir string, entries []recordedEntry) []string {
	var found []string
	declared := map[string]bool{}
	for _, e := range entries {
		declared[e.Dir] = true
	}
	stray, _ := filepath.Glob(filepath.Join(dir, "*", "*", "bytes"))
	sort.Strings(stray)
	for _, path := range stray {
		rel, err := filepath.Rel(dir, path)
		if err == nil && !declared[filepath.ToSlash(rel)] {
			found = append(found, rel+" holds a set no manifest row names")
		}
	}
	return found
}

// recordedMember judges one manifest row against the bytes of its set.
func recordedMember(dir string, e recordedEntry) (Member, error) {
	m := Member{ID: e.ID, Kind: e.Kind}
	memberDir := filepath.Join(dir, filepath.FromSlash(e.Dir))
	id, err := recordedTreeID(memberDir)
	switch {
	case err != nil:
		m.Findings = append(m.Findings, fmt.Sprintf("%s cannot be read: %v", e.Dir, err))
	case id != e.ID:
		m.Findings = append(m.Findings, "identifier does not recompute over the member's bytes")
	default:
		codes, err := recordedCheck(memberDir, e.SumsSHA256, e.Bindings)
		if err != nil {
			return m, err
		}
		verdict := "verified"
		if len(codes) > 0 {
			verdict = "failed"
		}
		want := e.Expected.Codes
		if want == nil {
			want = []string{}
		}
		if verdict != e.Expected.Verdict || strings.Join(codes, ",") != strings.Join(want, ",") {
			m.Findings = append(m.Findings, fmt.Sprintf("expected %s %v, got %s %v",
				e.Expected.Verdict, want, verdict, codes))
		}
	}
	return m, nil
}
