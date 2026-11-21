package corpusreaders

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
)

func init() { register(rsaDigestInfo{}) }

// rsaDigestInfo judges corpora/vectors-rsa-digestinfo/. Each member is one
// RSASSA-PKCS1-v1_5 SHA-256 signature over a message, with the public key. The
// reader recovers the whole block and compares it byte for byte with the two
// encodings that exist, as packaging/agent_evidence_vectors/rsadigestinfo.py
// does, in the same order:
//
//  1. signature_length: the signature is not exactly the modulus length, or is
//     not below the modulus (invalid);
//  2. rfc8017: the block is the RFC 8017 encoding, SHA-256 DigestInfo with NULL
//     parameters (valid);
//  3. absent_null_parameters: the same DigestInfo with the NULL parameters
//     omitted, which the consumer's profile decides (profile-dependent);
//  4. block_not_exact_encoding: any other block, including every block that
//     only ends in the digest (invalid).
//
// Comparing only the trailing 32 bytes with the digest would accept four of the
// corpus's invalid members, which is what the corpus exists to refuse.
type rsaDigestInfo struct{}

func (rsaDigestInfo) Suite() string { return "rsa-digestinfo/v1" }

var (
	rdiSHA256       = rdiHex("3031300d060960864801650304020105000420")
	rdiSHA256Absent = rdiHex("302f300b06096086480165030402010420")
)

func rdiHex(text string) []byte {
	raw, err := hex.DecodeString(text)
	if err != nil {
		panic("rsa-digestinfo: bad constant " + text)
	}
	return raw
}

type rdiRecord struct {
	Key struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func (rsaDigestInfo) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v scVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = rdiJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func rdiJudgeMember(caseDir string, v scVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record rdiRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	got, err := rdiDecide(record)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// rdiB64 decodes base64url with or without padding, as the Python reader does.
func rdiB64(text string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(text, "="))
}

// rdiBlock is the full-length EMSA-PKCS1-v1_5 block around t.
func rdiBlock(t []byte, k int) []byte {
	if k < len(t)+3 {
		return nil
	}
	out := make([]byte, 0, k)
	out = append(out, 0x00, 0x01)
	out = append(out, bytes.Repeat([]byte{0xff}, k-len(t)-3)...)
	out = append(out, 0x00)
	return append(out, t...)
}

func rdiDecide(r rdiRecord) (scDecision, error) {
	nBytes, err := rdiB64(r.Key.N)
	if err != nil {
		return scDecision{}, fmt.Errorf("key.n is not base64url: %w", err)
	}
	eBytes, err := rdiB64(r.Key.E)
	if err != nil {
		return scDecision{}, fmt.Errorf("key.e is not base64url: %w", err)
	}
	sig, err := rdiB64(r.Signature)
	if err != nil {
		return scDecision{}, fmt.Errorf("signature is not base64url: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.Sign() == 0 {
		return scDecision{}, fmt.Errorf("key.n is zero")
	}
	k := (n.BitLen() + 7) / 8
	s := new(big.Int).SetBytes(sig)
	if len(sig) != k || s.Cmp(n) >= 0 {
		return scDecision{"invalid", "signature_length"}, nil
	}
	recovered := new(big.Int).Exp(s, e, n).FillBytes(make([]byte, k))
	digest := sha256.Sum256([]byte(r.Message))
	if bytes.Equal(recovered, rdiBlock(append(append([]byte{}, rdiSHA256...), digest[:]...), k)) {
		return scDecision{"valid", "rfc8017"}, nil
	}
	if bytes.Equal(recovered, rdiBlock(append(append([]byte{}, rdiSHA256Absent...), digest[:]...), k)) {
		return scDecision{"profile-dependent", "absent_null_parameters"}, nil
	}
	return scDecision{"invalid", "block_not_exact_encoding"}, nil
}
