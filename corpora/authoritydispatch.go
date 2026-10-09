package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"time"
)

func init() { register(authorityDispatch{}) }

// authorityDispatch judges vectors-authority-at-dispatch/. Each member is one
// record of an attempted dispatch and the bytes dispatched. The reader derives
// each member's decision with the checks the Python reader applies, in the
// same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the authority-at-dispatch contract: contract_id_unknown;
//  3. evidenceAgeSeconds is the decision time minus the observation time:
//     evidence_age_inconsistent;
//  4. that age is within the freshness limit: authority_evidence_stale;
//  5. no grant in the chain was revoked at or before the decision:
//     grant_revoked;
//  6. the decision falls inside every grant's window: grant_expired;
//  7. each hop's scope is a subset of the hop before: scope_amplified;
//  8. the dispatched tool, target and bytes are the approved ones and the tool
//     is in the last hop's scope: dispatch_not_approved.
//
// The reader also recomputes each member's declared dispatchMatchesApproval,
// because the corpus's claim is that several denied records dispatch exactly
// the approved bytes.
type authorityDispatch struct{}

const adContractID = "https://probityai.github.io/agent-evidence-observer/contract/authority-at-dispatch/v1"

func (authorityDispatch) Suite() string { return "authority-at-dispatch/v1" }

type adVector struct {
	ID              string            `json:"id"`
	Path            string            `json:"path"`
	Files           map[string]string `json:"files"`
	Expected        scDecision        `json:"expected"`
	DispatchMatches bool              `json:"dispatchMatchesApproval"`
}

type adHop struct {
	GrantID   string   `json:"grantId"`
	Scope     []string `json:"scope"`
	NotBefore string   `json:"notBefore"`
	ExpiresAt string   `json:"expiresAt"`
}

type adRecord struct {
	ContractID   *string `json:"contractId"`
	DecisionTime string  `json:"decisionTime"`
	Approved     struct {
		Tool, Target  string
		PayloadSha256 string `json:"payloadSha256"`
	} `json:"approvedAction"`
	Dispatch struct {
		Tool, Target string
		PayloadFile  string `json:"payloadFile"`
	} `json:"dispatch"`
	Delegation []adHop `json:"delegation"`
	Evidence   struct {
		AgeSeconds    float64 `json:"evidenceAgeSeconds"`
		MaxAgeSeconds float64 `json:"maxAgeSeconds"`
		ObservedAt    string  `json:"observedAt"`
		RevokedGrants []struct {
			GrantID   string `json:"grantId"`
			RevokedAt string `json:"revokedAt"`
		} `json:"revokedGrants"`
	} `json:"authorityEvidence"`
}

// adClock parses timestamps and keeps the first failure, so a record with one
// unparseable time is reported once rather than at every comparison.
type adClock struct{ err error }

func (k *adClock) at(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil && k.err == nil {
		k.err = fmt.Errorf("timestamp %q does not parse", value)
	}
	return parsed
}

func (authorityDispatch) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v adVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = adJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func adJudgeMember(caseDir string, v adVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record adRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	dispatched, err := readIn(caseDir, record.Dispatch.PayloadFile)
	if err != nil {
		return append(findings, fmt.Sprintf("%s cannot be read: %v", record.Dispatch.PayloadFile, err))
	}
	matches := adMatchesApproval(record, dispatched)
	if matches != v.DispatchMatches {
		findings = append(findings, fmt.Sprintf(
			"dispatch matches approval: %t, the manifest declares %t", matches, v.DispatchMatches))
	}
	got, err := adDecide(record, matches)
	if err != nil {
		return append(findings, err.Error())
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func adMatchesApproval(r adRecord, dispatched []byte) bool {
	return r.Dispatch.Tool == r.Approved.Tool && r.Dispatch.Target == r.Approved.Target &&
		sha(dispatched) == r.Approved.PayloadSha256
}

func adDecide(r adRecord, matches bool) (scDecision, error) {
	var clock adClock
	decided := clock.at(r.DecisionTime)
	age := decided.Sub(clock.at(r.Evidence.ObservedAt)).Seconds()
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", r.ContractID == nil},
		{"contract_id_unknown", r.ContractID != nil && *r.ContractID != adContractID},
		{"evidence_age_inconsistent", r.Evidence.AgeSeconds != age},
		{"authority_evidence_stale", r.Evidence.AgeSeconds > r.Evidence.MaxAgeSeconds},
		{"grant_revoked", adRevoked(r, decided, &clock)},
		{"grant_expired", adExpired(r, decided, &clock)},
		{"scope_amplified", adAmplified(r.Delegation)},
		{"dispatch_not_approved", !matches || len(r.Delegation) == 0 ||
			!slices.Contains(r.Delegation[len(r.Delegation)-1].Scope, r.Dispatch.Tool)},
	}
	if clock.err != nil {
		return scDecision{}, clock.err
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}, nil
		}
	}
	return scDecision{"allow", "authorized"}, nil
}

func adRevoked(r adRecord, decided time.Time, clock *adClock) bool {
	revoked := false
	for _, entry := range r.Evidence.RevokedGrants {
		inChain := slices.ContainsFunc(r.Delegation, func(h adHop) bool { return h.GrantID == entry.GrantID })
		revoked = revoked || (inChain && !clock.at(entry.RevokedAt).After(decided))
	}
	return revoked
}

func adExpired(r adRecord, decided time.Time, clock *adClock) bool {
	expired := false
	for _, hop := range r.Delegation {
		expired = expired || decided.Before(clock.at(hop.NotBefore)) || !decided.Before(clock.at(hop.ExpiresAt))
	}
	return expired
}

func adAmplified(hops []adHop) bool {
	for i := 1; i < len(hops); i++ {
		for _, scope := range hops[i].Scope {
			if !slices.Contains(hops[i-1].Scope, scope) {
				return true
			}
		}
	}
	return false
}
