package corpusreaders

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
)

func init() { register(emptyInterval{}) }

// emptyInterval judges corpora/vectors-empty-interval-statement/. Each member is a
// revocation ledger, a signed statement about one credential and one interval of it,
// and the verifier's query and federation. The reader derives each member's value of
// the revocation_establishment term with the checks the Python reader applies, in the
// same order, and names the first one that fails:
//
//  1. the query returned an answer: query_failed / ledger_query_failed;
//  2. the ledger's federation is the verifier's, or bridged:
//     cross_federation_unsynchronised / federation_not_synchronised;
//  3. the statement verifies under the ledger key: statement_signature_invalid;
//  4. the statement is about the credential, ledger and positions asked about:
//     statement_for_other_interval;
//  5. the checkpoint verifies under the ledger key: checkpoint_signature_invalid;
//  6. the checkpoint carries a signing time: checkpoint_not_timestamped;
//  7. the checkpoint covers the end of the interval:
//     checkpoint_does_not_cover_range;
//  8. every event up to the checkpoint verifies: ledger_event_invalid;
//  9. every event names the digest of the line before it, at its own position:
//     chain_link_broken;
//  10. the checkpoint names the digest of the event it points at:
//     checkpoint_head_mismatch.
//
// Checks 3 to 10 give undetermined. A statement that passes all ten is read against
// the ledger itself: a revocation of the credential inside the interval is recorded,
// none is not_recorded. The reader also recomputes each member's declared signature
// facts from the stored bytes.
type emptyInterval struct{}

func (emptyInterval) Suite() string { return "empty-interval-statement/v1" }

type eiVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained struct {
		CheckpointSigned *bool `json:"checkpointSigned"`
		StatementSigned  *bool `json:"statementSigned"`
	} `json:"retained"`
}

type eiCase struct {
	Federation struct {
		Ledger           string   `json:"ledger"`
		SynchronisedWith []string `json:"synchronisedWith"`
		Verifier         string   `json:"verifier"`
	} `json:"federation"`
	Keys   map[string]string `json:"keys"`
	Ledger string            `json:"ledger"`
	Query  struct {
		Credential string `json:"credential"`
		FromIndex  int    `json:"fromIndex"`
		Ledger     string `json:"ledger"`
		ToIndex    int    `json:"toIndex"`
	} `json:"query"`
	Response struct {
		Status string `json:"status"`
	} `json:"response"`
	Statement *string `json:"statement"`
}

type eiEnvelope struct {
	Record     json.RawMessage `json:"record"`
	Statement  json.RawMessage `json:"statement"`
	Checkpoint json.RawMessage `json:"checkpoint"`
	Sig        string          `json:"sig"`
}

type eiStatementBody struct {
	Checkpoint eiEnvelope `json:"checkpoint"`
	Credential string     `json:"credential"`
	FromIndex  int        `json:"fromIndex"`
	Ledger     string     `json:"ledger"`
	Listed     []int      `json:"listed"`
	ToIndex    int        `json:"toIndex"`
}

type eiCheckpointBody struct {
	Head     string `json:"head"`
	Index    *int   `json:"index"`
	SignedAt string `json:"signedAt"`
}

type eiRecord struct {
	Credential string `json:"credential"`
	Index      int    `json:"index"`
	Kind       string `json:"kind"`
	Prev       string `json:"prev"`
}

const eiGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

var eiInstant = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

func (emptyInterval) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v eiVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = eiJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func eiJudgeMember(caseDir string, v eiVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var c eiCase
	if err := scReadJSON(caseDir, "case.json", &c); err != nil {
		return append(findings, err.Error())
	}
	in, err := eiLoad(caseDir, c)
	if err != nil {
		return append(findings, err.Error())
	}
	got := in.decide()
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	if declared, derived := eiSignedFacts(v), in.signedFacts(); declared != derived {
		findings = append(findings, fmt.Sprintf(
			"statement and checkpoint signatures verify: %s, the manifest declares %s", derived, declared))
	}
	return findings
}

func eiSignedFacts(v eiVector) string {
	return eiFact(v.Retained.StatementSigned) + "/" + eiFact(v.Retained.CheckpointSigned)
}

func eiFact(b *bool) string {
	if b == nil {
		return "absent"
	}
	return fmt.Sprintf("%t", *b)
}

// eiInput is one member's decoded inputs.
type eiInput struct {
	c         eiCase
	key       []byte
	lines     [][]byte
	events    []eiEnvelope
	statement *eiEnvelope
	body      eiStatementBody
	bodyOK    bool
	cp        eiCheckpointBody
	cpOK      bool
}

func eiLoad(caseDir string, c eiCase) (eiInput, error) {
	in := eiInput{c: c}
	key, err := hex.DecodeString(c.Keys["ledger"])
	if err != nil {
		return in, fmt.Errorf("case.json key is not hex")
	}
	in.key = key
	store, err := readIn(caseDir, c.Ledger)
	if err != nil {
		return in, fmt.Errorf("%s cannot be read: %w", c.Ledger, err)
	}
	for _, line := range bytes.Split(store, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var env eiEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			return in, fmt.Errorf("a ledger line does not parse: %w", err)
		}
		in.lines, in.events = append(in.lines, line), append(in.events, env)
	}
	if c.Statement != nil {
		var env eiEnvelope
		if err := scReadJSON(caseDir, *c.Statement, &env); err != nil {
			return in, err
		}
		in.statement = &env
		in.bodyOK = json.Unmarshal(env.Statement, &in.body) == nil
		if in.bodyOK {
			in.cpOK = json.Unmarshal(in.body.Checkpoint.Checkpoint, &in.cp) == nil
		}
	}
	return in, nil
}

func (in eiInput) signedFacts() string {
	if in.statement == nil {
		return "absent/absent"
	}
	return fmt.Sprintf("%t/%t", acSigned(in.statement.Statement, in.statement.Sig, in.key),
		acSigned(in.body.Checkpoint.Checkpoint, in.body.Checkpoint.Sig, in.key))
}

func (in eiInput) decide() scDecision {
	if in.c.Response.Status != "ok" {
		return scDecision{"query_failed", "ledger_query_failed"}
	}
	f := in.c.Federation
	if f.Ledger != f.Verifier && !slices.Contains(f.SynchronisedWith, f.Ledger) {
		return scDecision{"cross_federation_unsynchronised", "federation_not_synchronised"}
	}
	if reason := in.firstFailure(); reason != "" {
		return scDecision{"undetermined", reason}
	}
	return in.readLedger()
}

func (in eiInput) firstFailure() string {
	q := in.c.Query
	if in.statement == nil || !in.bodyOK || !acSigned(in.statement.Statement, in.statement.Sig, in.key) {
		return "statement_signature_invalid"
	}
	b := in.body
	if b.Credential != q.Credential || b.Ledger != q.Ledger || b.FromIndex != q.FromIndex || b.ToIndex != q.ToIndex {
		return "statement_for_other_interval"
	}
	if !in.cpOK || !acSigned(b.Checkpoint.Checkpoint, b.Checkpoint.Sig, in.key) {
		return "checkpoint_signature_invalid"
	}
	if !eiInstant.MatchString(in.cp.SignedAt) {
		return "checkpoint_not_timestamped"
	}
	if in.cp.Index == nil || *in.cp.Index < q.ToIndex {
		return "checkpoint_does_not_cover_range"
	}
	if reason := in.chainFailure(min(len(in.lines), *in.cp.Index+1)); reason != "" {
		return reason
	}
	if *in.cp.Index >= len(in.lines) || sha(in.lines[*in.cp.Index]) != in.cp.Head {
		return "checkpoint_head_mismatch"
	}
	return ""
}

// chainFailure checks the ledger events below upto: every event signature first,
// then every chain link, so a bad signature anywhere outranks a broken link.
func (in eiInput) chainFailure(upto int) string {
	for i := 0; i < upto; i++ {
		if !acSigned(in.events[i].Record, in.events[i].Sig, in.key) {
			return "ledger_event_invalid"
		}
	}
	for i := 0; i < upto; i++ {
		var rec eiRecord
		want := eiGenesis
		if i > 0 {
			want = sha(in.lines[i-1])
		}
		if json.Unmarshal(in.events[i].Record, &rec) != nil || rec.Prev != want || rec.Index != i {
			return "chain_link_broken"
		}
	}
	return ""
}

func (in eiInput) readLedger() scDecision {
	q := in.c.Query
	var found []int
	for _, env := range in.events {
		var rec eiRecord
		if json.Unmarshal(env.Record, &rec) != nil {
			continue
		}
		if rec.Kind == "revoked" && rec.Credential == q.Credential && rec.Index >= q.FromIndex && rec.Index <= q.ToIndex {
			found = append(found, rec.Index)
		}
	}
	if len(found) == 0 {
		return scDecision{"not_recorded", "no_revocation_in_covered_interval"}
	}
	for _, index := range found {
		if !slices.Contains(in.body.Listed, index) {
			return scDecision{"recorded", "statement_omits_recorded_event"}
		}
	}
	return scDecision{"recorded", "revocation_recorded"}
}
