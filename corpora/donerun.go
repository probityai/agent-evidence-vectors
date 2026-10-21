package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
)

// The done-contract and done-receipt corpora, and the three that build on them.
//
// Five corpora share one reader because they share one question: given the records
// of a coding agent's run, what does an outside verifier conclude? A member is a
// directory of records and, for each check the manifest declares, the consumer's case
// and policy for it; the manifest declares what the reader derives, and the reader
// recomputes it. The Python reader is packaging/agent_evidence_vectors/donerun.py and
// the two must print the same findings.

const (
	doneContractSuite = "done-contract/v2"
	doneReceiptSuite  = "done-receipt/v2"
	doneSpoofedSuite  = "spoofed-tool-output/v2"
	doneTamperSuite   = "test-tampering/v2"
	doneGraderSuite   = "grader-isolation/v2"

	doneURI          = "https://w3id.org/agent-evidence/predicate/v1/"
	doneContractType = doneURI + "done-contract"
	doneReceiptType  = doneURI + "done-receipt"
	doneStatement    = "https://in-toto.io/Statement/v1"
)

// jsonZero is the exit status a completion claim holds each visible command to.
var jsonZero any = json.Number("0")

func init() {
	for _, suite := range []string{doneContractSuite, doneReceiptSuite, doneSpoofedSuite, doneTamperSuite, doneGraderSuite} {
		register(doneReader{suite})
	}
}

type doneReader struct{ suite string }

func (r doneReader) Suite() string { return r.suite }

func doneEqual(a, b any) bool { return reflect.DeepEqual(a, b) }

// normalize re-encodes a value so decoded and constructed JSON compare alike.
func normalize(value any) any {
	raw, _ := json.Marshal(value)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

// --- the done-contract statement ------------------------------------------------------------

func doneContractStatement(data []byte) (doneObject, error) {
	raw, err := doneStrictJSON(data, "statement")
	if err != nil {
		return nil, err
	}
	statement, err := doneFields(raw, "statement", []string{"_type", "subject", "predicateType", "predicate"})
	if err != nil {
		return nil, err
	}
	if statement["_type"] != doneStatement {
		return nil, refuse("statement_type_wrong")
	}
	if statement["predicateType"] != doneContractType {
		return nil, refuse("statement_predicate_type_wrong")
	}
	subject, ok := statement["subject"].([]any)
	if !ok || len(subject) != 1 {
		return nil, refuse("statement_subject_malformed")
	}
	entry, ok := subject[0].(doneObject)
	digest := doneObj(entry["digest"])
	name, nameOK := entry["name"].(string)
	value, valueOK := digest["sha256"].(string)
	if !ok || len(entry) != 2 || !nameOK || name == "" || len(digest) != 1 || !valueOK || !doneHex64.MatchString(value) {
		return nil, refuse("statement_subject_malformed")
	}
	return statement, nil
}

func doneJudgeContract(member string) (map[string]any, error) {
	statementBytes, err := doneMemberFile(member, "statement.json", "member_unreadable")
	if err != nil {
		return nil, err
	}
	contractBytes, err := doneMemberFile(member, "contract.json", "member_unreadable")
	if err != nil {
		return nil, err
	}
	if statementBytes == nil || contractBytes == nil {
		return nil, refuse("member_incomplete")
	}
	verdict := func() error {
		statement, err := doneContractStatement(statementBytes)
		if err != nil {
			return err
		}
		record, err := doneContract(contractBytes)
		if err != nil {
			return err
		}
		subject := doneObj(doneObj(doneList(statement["subject"])[0])["digest"])
		if subject["sha256"] != sha(contractBytes) {
			return refuse("statement_subject_unbound")
		}
		if !doneEqual(normalize(statement["predicate"]), normalize(record)) {
			return refuse("statement_predicate_differs")
		}
		return nil
	}()
	if verdict != nil {
		return map[string]any{"verdict": "invalid", "code": doneRefusal(verdict)}, nil
	}
	return map[string]any{"verdict": "valid"}, nil
}

// --- one member --------------------------------------------------------------------------------

// doneJudgeChecks is each declared check's verdict and, over all five, the two verdicts.
func doneJudgeChecks(member string, declared []string) map[string]any {
	wanted := map[string]bool{}
	for _, claimType := range declared {
		wanted[claimType] = true
	}
	verdicts := map[string]doneVerdict{}
	rows := map[string]any{}
	for _, claimType := range doneDeclarable {
		if !wanted[claimType] {
			continue
		}
		verdict, err := doneRunCheck(claimType, member)
		if err != nil {
			rows[claimType] = map[string]any{"refused": doneRefusal(err)}
			continue
		}
		verdicts[claimType] = verdict
		rows[claimType] = doneProjection(verdict)
	}
	out := map[string]any{"checks": rows}
	for _, claimType := range doneClaimTypes {
		if _, decided := verdicts[claimType]; !decided {
			return out
		}
	}
	axes := doneAxes(verdicts)
	out["outcome"] = doneAxisProjection(doneObj(axes["outcome"]))
	out["integrity"] = doneAxisProjection(doneObj(axes["integrity"]))
	out["accepted"] = axes["accepted"]
	return out
}

func doneJudgeMember(suite, member string, declared []string) map[string]any {
	if suite != doneContractSuite {
		return doneJudgeChecks(member, declared)
	}
	verdict, err := doneJudgeContract(member)
	if err != nil {
		return map[string]any{"refused": doneRefusal(err)}
	}
	return map[string]any{"contract": verdict}
}

// --- corpus ------------------------------------------------------------------------------------

type doneVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Kind     string            `json:"kind"`
	Files    map[string]string `json:"files"`
	Checks   []string          `json:"checks"`
	Expected map[string]any    `json:"expected"`
}

func (r doneReader) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v doneVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Kind}
		member.Findings = r.judgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func (r doneReader) judgeMember(caseDir string, v doneVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	got := doneJudgeMember(r.suite, caseDir, v.Checks)
	if !doneEqual(normalize(got), normalize(v.Expected)) {
		declared, _ := json.Marshal(v.Expected)
		derived, _ := json.Marshal(got)
		findings = append(findings, fmt.Sprintf("derived %s, the manifest declares %s", derived, declared))
	}
	return findings
}

// DoneCheck is one check's verdict on a done corpus member, as a corpus declares it.
func DoneCheck(claimType, member string) (map[string]any, error) {
	verdict, err := doneRunCheck(claimType, member)
	if err != nil {
		return nil, err
	}
	return doneProjection(verdict), nil
}
