package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/probityai/agent-evidence-vectors/aee"
)

func init() { register(revocationList{}) }

// revocationList judges corpora/vectors-revocation-list/. Each member is what one
// verifier sees: the root key ids it pins (roots.json) and the signed lists it is
// handed, in order, each in the published form. The reader runs
// aee.VerifyRevocationChain, the reference reader of the one revocation list, and
// holds the member to every fact its manifest row states:
//
//  1. the decision, the full refusal text (code, or code:detail) and the index of
//     the refused list;
//  2. the list in force when the verdict was reached: its id, sequence number,
//     head, issue time, pinned roots and the ids revoked under each kind, read
//     back through the reader's own queries (RevokedIDs, Revoked, Revokes);
//  3. the ListDigest of every list file, or null where the body cannot be
//     canonicalized.
//
// A panic in the reader on a member is a finding against that member, never a
// crash of the run: a verifier that falls over on hostile bytes has not refused them.
type revocationList struct{}

func (revocationList) Suite() string { return "revocation-list/v1" }

type revVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Lists    []string          `json:"lists"`
	Expected revExpected       `json:"expected"`
}

type revExpected struct {
	Decision    string    `json:"decision"`
	Reason      string    `json:"reason"`
	Index       *int      `json:"index"`
	State       revState  `json:"state"`
	ListDigests []*string `json:"listDigests"`
}

type revState struct {
	ListID   string              `json:"listId"`
	Seq      int64               `json:"seq"`
	Head     string              `json:"head"`
	IssuedAt string              `json:"issuedAt"`
	Roots    []string            `json:"roots"`
	Revoked  map[string][]string `json:"revoked"`
}

type revManifest struct {
	Counts map[string]int `json:"counts"`
}

func (revocationList) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	var counts revManifest
	if err := json.Unmarshal(raw, &counts); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	measured := map[string]int{}
	for _, entry := range manifest.Vectors {
		var v revVector
		if err := strictUnmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		measured[v.Expected.Decision]++
		result.Members = append(result.Members, Member{
			ID: v.ID, Kind: v.Expected.Decision, Findings: revJudgeMember(filepath.Join(dir, v.Path), v),
		})
	}
	if finding := countsDisagree(counts.Counts, measured); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func revJudgeMember(caseDir string, v revVector) (findings []string) {
	defer func() {
		if r := recover(); r != nil {
			findings = append(findings, fmt.Sprintf("the reader panicked: %v", r))
		}
	}()
	findings = acFileFindings(caseDir, v.Files)
	var pins struct {
		Roots []string `json:"roots"`
	}
	if err := scReadJSON(caseDir, "roots.json", &pins); err != nil {
		return append(findings, err.Error())
	}
	lists := make([][]byte, len(v.Lists))
	for i, name := range v.Lists {
		body, err := readIn(caseDir, name)
		if err != nil {
			return append(findings, name+" cannot be read")
		}
		lists[i] = body
	}
	got := aee.VerifyRevocationChain(pins.Roots, lists)
	findings = append(findings, revVerdictFindings(got, v.Expected)...)
	findings = append(findings, revStateFindings(got.State, v.Expected.State)...)
	return append(findings, revDigestFindings(lists, v.Expected.ListDigests)...)
}

func revVerdictFindings(got aee.RevocationChainVerdict, want revExpected) []string {
	decision, reason := "accept", "in_force"
	if got.Verdict != aee.VerdictValid {
		decision, reason = "reject", "no refusal named"
		if got.Refusal != nil {
			reason = got.Refusal.Error()
		}
	}
	index := -1
	if want.Index != nil {
		index = *want.Index
	}
	if decision != want.Decision || reason != want.Reason || got.Index != index {
		return []string{fmt.Sprintf("%s %q at index %d, the manifest declares %s %q at index %d",
			decision, reason, got.Index, want.Decision, want.Reason, index)}
	}
	return nil
}

func revStateFindings(got aee.RevocationState, want revState) []string {
	var findings []string
	if got.ListID != want.ListID || got.Seq != want.Seq || got.Head != want.Head || got.IssuedAt != want.IssuedAt {
		findings = append(findings, fmt.Sprintf("list in force %q seq %d head %s issued %s, the manifest declares %q seq %d head %s issued %s",
			got.ListID, got.Seq, short(got.Head), got.IssuedAt, want.ListID, want.Seq, short(want.Head), want.IssuedAt))
	}
	if strings.Join(got.Roots, ",") != strings.Join(want.Roots, ",") {
		findings = append(findings, fmt.Sprintf("pinned roots %v, the manifest declares %v", got.Roots, want.Roots))
	}
	if got.Revokes() || got.Revokes(aee.RevocationSubject{Kind: aee.KindAgent}) {
		findings = append(findings, "Revokes answers true for no subject, or for an id no list can name")
	}
	for _, kind := range aee.RevocationKinds {
		ids := got.RevokedIDs(kind)
		if !reflect.DeepEqual(ids, append([]string{}, want.Revoked[string(kind)]...)) {
			findings = append(findings, fmt.Sprintf("revoked %s %v, the manifest declares %v", kind, ids, want.Revoked[string(kind)]))
		}
		for _, id := range want.Revoked[string(kind)] {
			if !got.Revoked(kind, id) || !got.Revokes(aee.RevocationSubject{Kind: kind}, aee.RevocationSubject{Kind: kind, ID: id}) {
				findings = append(findings, fmt.Sprintf("Revoked and Revokes do not name %s %s", kind, id))
			}
		}
	}
	return findings
}

// revDigestFindings recomputes the ListDigest of every list file's body: the digest a
// successor names as previous, or null where the file carries no body or the body
// cannot be canonicalized.
func revDigestFindings(lists [][]byte, want []*string) []string {
	if len(want) != len(lists) {
		return []string{fmt.Sprintf("%d list digests declared for %d lists", len(want), len(lists))}
	}
	var findings []string
	for i, list := range lists {
		got := "null"
		var signed map[string]json.RawMessage
		if json.Unmarshal(list, &signed) == nil && signed["body"] != nil {
			if digest, err := aee.ListDigest(signed["body"]); err == nil {
				got = digest
			}
		}
		expected := "null"
		if want[i] != nil {
			expected = *want[i]
		}
		if got != expected {
			findings = append(findings, fmt.Sprintf("list %d digest %s, the manifest declares %s", i, got, expected))
		}
	}
	return findings
}
