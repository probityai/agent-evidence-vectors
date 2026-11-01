package corpora

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(anchoredChain{}) }

// anchoredChain judges vectors-anchored-chain/. Each member is a stored history
// of signed memory records, an anchor over that history signed by a key the
// store does not hold, and the consumer's trust inputs. The reader derives each
// member's decision with the checks the Python reader applies, in the same
// order, and names the first one that fails:
//
//  1. every stored record verifies under the producer key: signature_invalid;
//  2. the anchor verifies under the anchor key: anchor_signature_invalid;
//  3. every record names the chain under test: record_from_other_chain;
//  4. every record names the digest of the stored line before it:
//     chain_link_broken;
//  5. the store still holds the record the anchor names:
//     anchored_head_missing;
//  6. that record's digest is the one the anchor commits to:
//     anchored_head_mismatch.
//
// A store that passes all six is verified, with records_after_last_anchor when
// records follow the anchored one and chain_anchored otherwise. The reader also
// recomputes each member's declared signature property, because the corpus's
// claim is that several rejected stores pass every signature check.
type anchoredChain struct{}

func (anchoredChain) Suite() string { return "anchored-record-chain/v1" }

type acVector struct {
	ID              string            `json:"id"`
	Path            string            `json:"path"`
	Files           map[string]string `json:"files"`
	Expected        scDecision        `json:"expected"`
	SignaturesClean bool              `json:"storeSignaturesVerify"`
}

type acCase struct {
	Store  string            `json:"store"`
	Anchor string            `json:"anchor"`
	Chain  string            `json:"chain"`
	Keys   map[string]string `json:"keys"`
}

type acEnvelope struct {
	Record json.RawMessage `json:"record"`
	Anchor json.RawMessage `json:"anchor"`
	Sig    string          `json:"sig"`
}

type acRecord struct {
	Chain string `json:"chain"`
	Prev  string `json:"prev"`
}

type acAnchorBody struct {
	Head  string `json:"head"`
	Index int    `json:"index"`
}

const acGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

func (anchoredChain) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v acVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = acJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func acJudgeMember(caseDir string, v acVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	got, clean, err := acDecide(caseDir)
	if err != nil {
		return append(findings, err.Error())
	}
	if clean != v.SignaturesClean {
		findings = append(findings, fmt.Sprintf(
			"every stored signature verifies: %t, the manifest declares %t", clean, v.SignaturesClean))
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// acFileFindings compares a member's files with the digests the manifest binds.
func acFileFindings(caseDir string, files map[string]string) []string {
	var findings []string
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

// acDecide applies the six checks to one member and reports whether every
// stored record's signature verifies. An error means an input could not be read
// at all, which is a finding, not a decision.
func acDecide(caseDir string) (scDecision, bool, error) {
	var c acCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return scDecision{}, false, err
	}
	producer, perr := hex.DecodeString(c.Keys["producer"])
	anchorKey, aerr := hex.DecodeString(c.Keys["anchor"])
	if perr != nil || aerr != nil {
		return scDecision{}, false, fmt.Errorf("case.json keys are not hex")
	}
	store, err := readIn(caseDir, c.Store)
	if err != nil {
		return scDecision{}, false, fmt.Errorf("%s cannot be read: %w", c.Store, err)
	}
	var anchor acEnvelope
	if err := scReadJSON(caseDir, c.Anchor, &anchor); err != nil {
		return scDecision{}, false, err
	}
	lines, envs, err := acParseStore(store)
	if err != nil {
		return scDecision{}, false, err
	}
	clean := true
	for _, env := range envs {
		clean = clean && acSigned(env.Record, env.Sig, producer)
	}
	return acFirstFailure(c, lines, envs, anchor, anchorKey, clean), clean, nil
}

func acParseStore(store []byte) ([][]byte, []acEnvelope, error) {
	var lines [][]byte
	var envs []acEnvelope
	for _, line := range bytes.Split(store, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var env acEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return nil, nil, fmt.Errorf("a stored line does not parse: %w", err)
		}
		lines, envs = append(lines, line), append(envs, env)
	}
	return lines, envs, nil
}

func acFirstFailure(c acCase, lines [][]byte, envs []acEnvelope, anchor acEnvelope,
	anchorKey []byte, clean bool) scDecision {
	if !clean {
		return scDecision{"rejected", "signature_invalid"}
	}
	var body acAnchorBody
	if !acSigned(anchor.Anchor, anchor.Sig, anchorKey) || json.Unmarshal(anchor.Anchor, &body) != nil {
		return scDecision{"rejected", "anchor_signature_invalid"}
	}
	records := make([]acRecord, len(envs))
	for i, env := range envs {
		if json.Unmarshal(env.Record, &records[i]) != nil || records[i].Chain != c.Chain {
			return scDecision{"rejected", "record_from_other_chain"}
		}
	}
	for i, record := range records {
		want := acGenesis
		if i > 0 {
			want = sha(lines[i-1])
		}
		if record.Prev != want {
			return scDecision{"rejected", "chain_link_broken"}
		}
	}
	if body.Index < 0 || body.Index >= len(lines) {
		return scDecision{"rejected", "anchored_head_missing"}
	}
	if sha(lines[body.Index]) != body.Head {
		return scDecision{"rejected", "anchored_head_mismatch"}
	}
	if body.Index < len(lines)-1 {
		return scDecision{"verified", "records_after_last_anchor"}
	}
	return scDecision{"verified", "chain_anchored"}
}

// acSigned reports whether sig is a valid Ed25519 signature by key over the
// RFC 8785 form of body.
func acSigned(body json.RawMessage, sig string, key []byte) bool {
	if len(body) == 0 || len(key) != ed25519.PublicKeySize {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	canonical, err := aee.Canonicalize(body)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key), canonical, raw)
}
