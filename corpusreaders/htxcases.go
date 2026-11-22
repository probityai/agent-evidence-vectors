package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
)

func init() { register(htxCases{}) }

// htxCases judges corpora/vectors-htx-cases/. Each member is plain JSON in one
// of two shapes. A transaction confirmation (HTX P18.01 section 6) holds the
// request the person confirmed and the request about to be carried out; the
// reader names the first failing check of not-confirmed and
// request-changed-after-confirmation. A consent and disclosure record holds
// what the person agreed to share and what is about to be disclosed; the
// reader names the first failing check of not-agreed, purpose-changed,
// recipient-changed, refused-field-disclosed and field-not-consented. A record
// in neither shape is record-shape-unknown. The checks and their order are the
// Python reader's.
type htxCases struct{}

const (
	htxTransaction = "transaction-confirmation"
	htxConsent     = "consent-disclosure"
)

func (htxCases) Suite() string { return "htx-cases/v1" }

type htxVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained map[string]any    `json:"retained"`
}

func (htxCases) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v htxVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = htxJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func htxJudgeMember(caseDir string, v htxVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record map[string]any
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if got := htxRetained(record); !reflect.DeepEqual(got, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := htxDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func htxObject(parent map[string]any, key string) map[string]any {
	child, _ := parent[key].(map[string]any)
	return child
}

func htxStrings(parent map[string]any, key string) []string {
	var out []string
	items, _ := parent[key].([]any)
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func htxShape(r map[string]any) string {
	if htxObject(r, "confirmation") != nil && htxObject(r, "action") != nil {
		return htxTransaction
	}
	if htxObject(r, "consent") != nil && htxObject(r, "disclosure") != nil {
		return htxConsent
	}
	return ""
}

func htxRetained(r map[string]any) map[string]any {
	switch htxShape(r) {
	case htxTransaction:
		return map[string]any{"outcome": htxObject(r, "confirmation")["outcome"], "shape": htxTransaction}
	case htxConsent:
		return map[string]any{
			"disclosedFields": float64(len(htxStrings(htxObject(r, "disclosure"), "fields"))),
			"outcome":         htxObject(r, "consent")["outcome"], "shape": htxConsent,
		}
	}
	return map[string]any{"shape": nil}
}

type htxCheck struct {
	reason string
	fails  func() bool
}

func htxDecide(r map[string]any) scDecision {
	switch htxShape(r) {
	case htxTransaction:
		return htxRun(htxTransactionChecks(r), "request-matches-confirmation")
	case htxConsent:
		return htxRun(htxConsentChecks(r), "disclosure-within-consent")
	}
	return scDecision{"deny", "record-shape-unknown"}
}

func htxRun(checks []htxCheck, allowed string) scDecision {
	for _, c := range checks {
		if c.fails() {
			return scDecision{"deny", c.reason}
		}
	}
	return scDecision{"allow", allowed}
}

func htxTransactionChecks(r map[string]any) []htxCheck {
	confirmation, action := htxObject(r, "confirmation"), htxObject(r, "action")
	return []htxCheck{
		{"not-confirmed", func() bool { return confirmation["outcome"] != "confirmed" }},
		{"request-changed-after-confirmation", func() bool {
			return !reflect.DeepEqual(confirmation["request"], action["request"])
		}},
	}
}

func htxConsentChecks(r map[string]any) []htxCheck {
	consent, disclosure := htxObject(r, "consent"), htxObject(r, "disclosure")
	disclosed := htxStrings(disclosure, "fields")
	allowed := map[string]bool{}
	fields := htxObject(consent, "fields")
	for _, name := range append(htxStrings(fields, "required"), htxStrings(fields, "optional_granted")...) {
		allowed[name] = true
	}
	refused := map[string]bool{}
	for _, name := range htxStrings(consent, "refused_optional") {
		refused[name] = true
	}
	anyDisclosed := func(test func(string) bool) bool {
		for _, name := range disclosed {
			if test(name) {
				return true
			}
		}
		return false
	}
	return []htxCheck{
		{"not-agreed", func() bool { return consent["outcome"] != "agreed" && len(disclosed) > 0 }},
		{"purpose-changed", func() bool { return !reflect.DeepEqual(disclosure["purpose"], consent["purpose"]) }},
		{"recipient-changed", func() bool { return !reflect.DeepEqual(disclosure["recipient"], consent["recipient"]) }},
		{"refused-field-disclosed", func() bool { return anyDisclosed(func(n string) bool { return refused[n] }) }},
		{"field-not-consented", func() bool { return anyDisclosed(func(n string) bool { return !allowed[n] }) }},
	}
}
