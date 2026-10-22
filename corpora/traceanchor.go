package corpora

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

func init() { register(traceAnchor{}) }

// traceAnchor judges vectors-trace-anchor/: TRACE Registry Anchor Format v1 as
// amended by trace-spec#533, where a Level 2 verdict rests on the registry
// entry itself and a merkle_root or leaf_count the receipt carries is a claim
// checked against that entry. Each member's case.json holds the three inputs
// section 5.1 names (claim, receipt, entry), any of which may be missing. The
// reader applies the checks the Python reader applies, in the same order, and
// names the first one that fails:
//
//  1. a receipt was supplied: receipt_absent;
//  2. the receipt is well formed: receipt_malformed;
//  3. an entry was supplied: entry_absent;
//  4. the entry carries the five section 4 fields and types: entry_malformed;
//  5. a carried merkle_root equals the entry's: receipt_root_mismatch;
//  6. a carried leaf_count equals the entry's: receipt_count_mismatch;
//  7. the leaf index is inside the entry's batch: index_out_of_range;
//  8. the claim is inside the section 1 profile: claim_outside_profile;
//  9. the section 5.1 replay reaches the entry's root: proof_does_not_replay.
//
// A member that passes all nine is anchored with included_link_unchecked,
// because nothing yet defines how a transparency value names an entry.
//
// Every number is decoded as json.Number, so an integer token and a float token
// stay distinct the way CPython's json.loads keeps them, and the replay runs in
// math/big so an index or count of any size is judged exactly rather than
// wrapped.
type traceAnchor struct{}

func (traceAnchor) Suite() string { return "trace-registry-anchor/v1" }

type taVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
}

const taLinkUnchecked = "included_link_unchecked"

// taSafeInteger is 2^53 - 1, the bound section 1 holds a claim's integers to.
var taSafeInteger = new(big.Int).SetUint64(1<<53 - 1)

func (traceAnchor) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	ids := map[string]bool{}
	for _, entry := range manifest.Vectors {
		var v taVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		if ids[v.ID] {
			result.Findings = append(result.Findings, "duplicate vector identifier "+v.ID)
		}
		ids[v.ID] = true
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = taJudgeMember(dir, v)
		result.Members = append(result.Members, member)
	}
	if len(manifest.Vectors) == 0 {
		result.Findings = append(result.Findings, "the manifest lists no vectors")
	}
	if finding := taCaseDirFinding(dir, ids); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// taCaseDirFinding requires the cases/ directories to be exactly the manifest's
// identifiers, so a case added or removed without the manifest is a finding.
func taCaseDirFinding(dir string, ids map[string]bool) string {
	listing, err := os.ReadDir(filepath.Join(dir, "cases"))
	if err != nil {
		return fmt.Sprintf("cases/ cannot be listed: %v", err)
	}
	onDisk := map[string]bool{}
	for _, item := range listing {
		if item.IsDir() {
			onDisk[item.Name()] = true
		}
	}
	extra, missing := declaredMinusUsed(onDisk, ids), declaredMinusUsed(ids, onDisk)
	if len(extra) > 0 || len(missing) > 0 {
		return fmt.Sprintf("case directories do not match the manifest: on disk only %v, manifest only %v",
			extra, missing)
	}
	return ""
}

func taJudgeMember(dir string, v taVector) []string {
	if v.Path != "cases/"+v.ID {
		return []string{fmt.Sprintf("path %q does not match the identifier", v.Path)}
	}
	caseDir := filepath.Join(dir, v.Path)
	findings := taFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, fmt.Sprintf("case.json cannot be read: %v", err))
	}
	value, err := decodeJSONNumbers(body)
	if err != nil {
		return append(findings, fmt.Sprintf("case.json does not parse: %v", err))
	}
	c, ok := value.(map[string]any)
	if !ok {
		return append(findings, "case.json is not a JSON object")
	}
	got := scDecision{"anchored", taLinkUnchecked}
	if failure := taFirstFailure(c); failure != "" {
		got = scDecision{"refused", failure}
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// taFileFindings holds a member's directory to exactly the files the manifest
// binds, each at its digest.
func taFileFindings(caseDir string, files map[string]string) []string {
	findings := acFileFindings(caseDir, files)
	listing, err := os.ReadDir(caseDir)
	if err != nil {
		return append(findings, fmt.Sprintf("the case directory cannot be listed: %v", err))
	}
	for _, item := range listing {
		if !item.IsDir() {
			if _, declared := files[item.Name()]; !declared {
				findings = append(findings, item.Name()+" is present and not declared")
			}
		}
	}
	return findings
}

// taFirstFailure names the first of the nine checks the case fails, or "".
// Each check after the second relies on the ones before it, as the order is
// the contract: by check 5 the receipt is a well-formed object and the entry a
// well-formed section 4 entry, so the comparisons below compare typed values.
func taFirstFailure(c map[string]any) string {
	receiptValue, receiptGiven := c["receipt"]
	if !receiptGiven || receiptValue == nil {
		return "receipt_absent"
	}
	receipt, ok := receiptValue.(map[string]any)
	if !ok || taReceiptMalformed(receipt) {
		return "receipt_malformed"
	}
	entryValue, entryGiven := c["entry"]
	if !entryGiven || entryValue == nil {
		return "entry_absent"
	}
	entry, ok := entryValue.(map[string]any)
	if !ok || taEntryMalformed(entry) {
		return "entry_malformed"
	}
	entryRoot := entry["merkle_root"].(string)
	count, _ := taInt(entry["leaf_count"])
	if root, carried := receipt["merkle_root"]; carried && root.(string) != entryRoot {
		return "receipt_root_mismatch"
	}
	if carried, present := receipt["leaf_count"]; present {
		if n, _ := taInt(carried); n.Cmp(count) != 0 {
			return "receipt_count_mismatch"
		}
	}
	index, _ := taInt(receipt["leaf_index"])
	if index.Sign() < 0 || index.Cmp(count) >= 0 {
		return "index_out_of_range"
	}
	leaf, ok := taCanonicalClaim(c["claim"])
	if !ok {
		return "claim_outside_profile"
	}
	if !taReplays(leaf, index, receipt["audit_path"].([]any), count, entryRoot) {
		return "proof_does_not_replay"
	}
	return ""
}

// taInt reads a JSON integer token. A token with a fraction or an exponent is a
// float to CPython's json.loads, and a JSON true is not the integer 1.
func taInt(value any) (*big.Int, bool) {
	n, ok := value.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return nil, false
	}
	return new(big.Int).SetString(n.String(), 10)
}

// taHash reads a sha256:<64 lowercase hex> string and returns its bytes.
func taHash(value any) ([]byte, bool) {
	s, ok := value.(string)
	if !ok || len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return nil, false
	}
	digest := s[len("sha256:"):]
	if strings.ToLower(digest) != digest {
		return nil, false
	}
	raw, err := hex.DecodeString(digest)
	return raw, err == nil
}

func taReceiptMalformed(receipt map[string]any) bool {
	if _, ok := taInt(receipt["leaf_index"]); !ok {
		return true
	}
	path, ok := receipt["audit_path"].([]any)
	if !ok {
		return true
	}
	for _, node := range path {
		if _, ok := taHash(node); !ok {
			return true
		}
	}
	if root, carried := receipt["merkle_root"]; carried {
		if _, ok := taHash(root); !ok {
			return true
		}
	}
	if count, carried := receipt["leaf_count"]; carried {
		if _, ok := taInt(count); !ok {
			return true
		}
	}
	return false
}

func taEntryMalformed(entry map[string]any) bool {
	for _, key := range []string{"ts", "producer", "batch_id"} {
		if s, ok := entry[key].(string); !ok || s == "" {
			return true
		}
	}
	if _, ok := taHash(entry["merkle_root"]); !ok {
		return true
	}
	count, ok := taInt(entry["leaf_count"])
	return !ok || count.Sign() < 1
}

// taCanonicalClaim returns the section 1 bytes of the claim, or false when the
// claim is not an object or holds a float or an integer outside the safe range.
func taCanonicalClaim(claim any) ([]byte, bool) {
	object, ok := claim.(map[string]any)
	if !ok || !taInsideProfile(object) {
		return nil, false
	}
	compact, err := pythonCompactJSON(object)
	return compact, err == nil
}

func taInsideProfile(value any) bool {
	switch v := value.(type) {
	case json.Number:
		n, ok := taInt(v)
		return ok && n.CmpAbs(taSafeInteger) <= 0
	case map[string]any:
		for _, item := range v {
			if !taInsideProfile(item) {
				return false
			}
		}
	case []any:
		for _, item := range v {
			if !taInsideProfile(item) {
				return false
			}
		}
	}
	return true
}

// taReplays is the section 5.1 replay with the RFC 6962 leaf and node prefixes,
// over an index the caller has already placed inside [0, count).
func taReplays(leaf []byte, index *big.Int, path []any, count *big.Int, root string) bool {
	target, ok := taHash(root)
	if !ok {
		return false
	}
	fn := new(big.Int).Set(index)
	sn := new(big.Int).Sub(count, big.NewInt(1))
	r := taDigest([]byte{0x00}, leaf)
	for _, node := range path {
		p, ok := taHash(node)
		if !ok || sn.Sign() == 0 {
			return false
		}
		if fn.Bit(0) == 1 || fn.Cmp(sn) == 0 {
			r = taDigest([]byte{0x01}, p, r)
			if fn.Bit(0) == 0 {
				for fn.Sign() != 0 && fn.Bit(0) == 0 {
					fn.Rsh(fn, 1)
					sn.Rsh(sn, 1)
				}
			}
		} else {
			r = taDigest([]byte{0x01}, r, p)
		}
		fn.Rsh(fn, 1)
		sn.Rsh(sn, 1)
	}
	return sn.Sign() == 0 && bytes.Equal(r, target)
}

func taDigest(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
