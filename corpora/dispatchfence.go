package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

func init() { register(dispatchFence{}) }

// dispatchFence judges vectors-dispatch-fence/. Each member is one record of an
// exclusive dispatch: a policy check, the fence taken to dispatch, the effect
// and the commit. The reader derives each member's decision with the checks the
// Python reader applies, in the same order, and names the first one that fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the dispatch-fence contract: contract_id_unknown;
//  3. the fence names the sequence number the check read:
//     fence_not_bound_to_check;
//  4. no state event falls after the check's read and at or before the fence's
//     append: state_changed_between_check_and_fence;
//  5. a declared runtime above the initial time to live has a renewal:
//     runtime_exceeds_hold;
//  6. the effect ended at or before the hold's expiry:
//     hold_expired_before_effect_ended;
//  7. no other proposal was admitted from acquisition to the effect's end:
//     concurrent_dispatch_admitted;
//  8. the commit was at or before the hold's expiry: commit_after_hold_expired.
//
// The reader also recomputes each member's declared holdCoversCommit.
type dispatchFence struct{}

const dfContractID = "https://probityai.github.io/agent-evidence-observer/contract/dispatch-fence/v1"

func (dispatchFence) Suite() string { return "dispatch-fence/v1" }

type dfVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Covers   bool              `json:"holdCoversCommit"`
}

type dfRecord struct {
	ContractID  *string `json:"contractId"`
	ProposalID  string  `json:"proposalId"`
	StateEvents []struct {
		Seq int `json:"seq"`
	} `json:"stateEvents"`
	Check struct {
		ReadSeq int `json:"readSeq"`
	} `json:"check"`
	Fence struct {
		AppendSeq   int    `json:"appendSeq"`
		ExpectedSeq *int   `json:"expectedSeq"`
		AcquiredAt  string `json:"acquiredAt"`
		TTLSeconds  int    `json:"ttlSeconds"`
		Renewals    []struct {
			ExpiresAt string `json:"expiresAt"`
		} `json:"renewals"`
	} `json:"fence"`
	Effect struct {
		Declared *int   `json:"declaredMaxRuntimeSeconds"`
		EndedAt  string `json:"endedAt"`
	} `json:"effect"`
	Commit struct {
		At string `json:"at"`
	} `json:"commit"`
	Others []struct {
		ProposalID string `json:"proposalId"`
		BeganAt    string `json:"beganAt"`
		Admitted   bool   `json:"admitted"`
	} `json:"otherAttempts"`
}

// dfClock parses timestamps and keeps the first failure, so a record with one
// unparseable time is reported once rather than at every comparison.
type dfClock struct{ err error }

func (k *dfClock) at(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil && k.err == nil {
		k.err = fmt.Errorf("timestamp %q does not parse", value)
	}
	return parsed
}

func (dispatchFence) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v dfVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = dfJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func dfJudgeMember(caseDir string, v dfVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record dfRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	var clock dfClock
	expiry := dfExpiry(record, &clock)
	covers := !clock.at(record.Effect.EndedAt).After(expiry) && !clock.at(record.Commit.At).After(expiry)
	if clock.err != nil {
		return append(findings, clock.err.Error())
	}
	if covers != v.Covers {
		findings = append(findings, fmt.Sprintf(
			"hold covers commit: %t, the manifest declares %t", covers, v.Covers))
	}
	got := dfDecide(record, expiry, &clock)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// dfExpiry is the latest of the initial expiry and every renewal's expiry.
func dfExpiry(r dfRecord, clock *dfClock) time.Time {
	expiry := clock.at(r.Fence.AcquiredAt).Add(time.Duration(r.Fence.TTLSeconds) * time.Second)
	for _, renewal := range r.Fence.Renewals {
		if later := clock.at(renewal.ExpiresAt); later.After(expiry) {
			expiry = later
		}
	}
	return expiry
}

func dfDecide(r dfRecord, expiry time.Time, clock *dfClock) scDecision {
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", r.ContractID == nil},
		{"contract_id_unknown", r.ContractID != nil && *r.ContractID != dfContractID},
		{"fence_not_bound_to_check", r.Fence.ExpectedSeq == nil || *r.Fence.ExpectedSeq != r.Check.ReadSeq},
		{"state_changed_between_check_and_fence", dfStateChanged(r)},
		{"runtime_exceeds_hold", r.Effect.Declared != nil && *r.Effect.Declared > r.Fence.TTLSeconds &&
			len(r.Fence.Renewals) == 0},
		{"hold_expired_before_effect_ended", clock.at(r.Effect.EndedAt).After(expiry)},
		{"concurrent_dispatch_admitted", dfConcurrent(r, clock)},
		{"commit_after_hold_expired", clock.at(r.Commit.At).After(expiry)},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "exclusive"}
}

func dfStateChanged(r dfRecord) bool {
	for _, event := range r.StateEvents {
		if r.Check.ReadSeq < event.Seq && event.Seq <= r.Fence.AppendSeq {
			return true
		}
	}
	return false
}

func dfConcurrent(r dfRecord, clock *dfClock) bool {
	start, end := clock.at(r.Fence.AcquiredAt), clock.at(r.Effect.EndedAt)
	concurrent := false
	for _, other := range r.Others {
		began := clock.at(other.BeganAt)
		concurrent = concurrent || (other.Admitted && other.ProposalID != r.ProposalID &&
			!began.Before(start) && !began.After(end))
	}
	return concurrent
}
