package corpora

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"time"
)

func init() { register(uncertainEffect{}) }

// uncertainEffect judges vectors-uncertain-effect/. Each member is one
// runtime's trail for one intended effect whose reply may have been lost: the
// operation and its idempotency key, each dispatch attempt, the leases the
// dispatching workers held, the effect owner's reconciliation answers, the
// effect count its own ledger shows, the reservation held and the outcome the
// runtime reported. The reader derives each member's decision with the checks
// the Python reader applies, in the same order, and names the first one that
// fails:
//
//  1. the record carries contractId: contract_id_missing;
//  2. contractId is the uncertain-effect contract: contract_id_unknown;
//  3. the operation and every attempt carry an idempotency key and an
//     arguments digest: operation_identity_missing;
//  4. no attempt reuses the operation's key with other arguments:
//     idempotency_key_args_changed;
//  5. every attempt was dispatched inside a lease its worker held, before a
//     lease with a higher fencing token was granted (only when the record
//     lists leases): dispatch_beyond_lease;
//  6. no attempt follows one of unknown outcome unless the owner deduplicates
//     by that key inside its retention window or a final reconciliation said
//     the effect is absent: retry_after_unknown;
//  7. the owner's ledger shows at most one effect: duplicate_effect;
//  8. a reservation for an unknown outcome is still charged:
//     unknown_released;
//  9. the runtime did not report an unknown outcome as committed or not run:
//     outcome_settled_without_authority;
//  10. the runtime reported the outcome the owner's answers settle:
//     outcome_disagrees_with_authority.
//
// The reader also recomputes each member's retained attempts, idempotency key,
// operation, settled outcome, owner effects and unknown attempts.
type uncertainEffect struct{}

const ueContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"

func (uncertainEffect) Suite() string { return "uncertain-effect/v1" }

type ueRetained struct {
	Attempts        int    `json:"attempts"`
	IdempotencyKey  string `json:"idempotencyKey"`
	Operation       string `json:"operation"`
	Outcome         string `json:"outcome"`
	OwnerEffects    int    `json:"ownerEffects"`
	UnknownAttempts int    `json:"unknownAttempts"`
}

type ueVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained ueRetained        `json:"retained"`
}

type ueAttempt struct {
	ArgsDigest     string  `json:"argsDigest"`
	DispatchedAt   string  `json:"dispatchedAt"`
	IdempotencyKey string  `json:"idempotencyKey"`
	Reply          string  `json:"reply"`
	Worker         *string `json:"worker"`
	FencingToken   *int64  `json:"fencingToken"`
}

type ueLease struct {
	AcquiredAt   string `json:"acquiredAt"`
	ExpiresAt    string `json:"expiresAt"`
	FencingToken int64  `json:"fencingToken"`
	Worker       string `json:"worker"`
}

type ueReconciliation struct {
	At     string `json:"at"`
	Final  bool   `json:"final"`
	Result string `json:"result"`
}

type ueRecord struct {
	ContractID  json.RawMessage `json:"contractId"`
	EffectOwner struct {
		DeduplicatesByKey bool     `json:"deduplicatesByKey"`
		KeyRetention      *float64 `json:"keyRetentionSeconds"`
	} `json:"effectOwner"`
	Operation struct {
		ArgsDigest     string `json:"argsDigest"`
		ID             string `json:"id"`
		IdempotencyKey string `json:"idempotencyKey"`
	} `json:"operation"`
	Attempts        []ueAttempt        `json:"attempts"`
	Leases          []ueLease          `json:"leases"`
	Reconciliations []ueReconciliation `json:"reconciliations"`
	OwnerEffects    int                `json:"ownerEffects"`
	Reservation     *struct {
		Charged bool `json:"charged"`
	} `json:"reservation"`
	Reported struct {
		Outcome string `json:"outcome"`
	} `json:"reported"`
}

func (uncertainEffect) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v ueVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = ueJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func ueJudgeMember(caseDir string, v ueVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record ueRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	if err := ueValidateTimes(record); err != nil {
		return append(findings, err.Error())
	}
	if kept := ueRetain(record); !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	got := ueDecide(record)
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

// ueValidateTimes refuses a record whose timestamps are not RFC 3339, so the
// checks below can read every time without a failure path.
func ueValidateTimes(r ueRecord) error {
	stamps := []string{}
	for _, a := range r.Attempts {
		stamps = append(stamps, a.DispatchedAt)
	}
	for _, c := range r.Reconciliations {
		stamps = append(stamps, c.At)
	}
	for _, l := range r.Leases {
		stamps = append(stamps, l.AcquiredAt, l.ExpiresAt)
	}
	for _, stamp := range stamps {
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			return fmt.Errorf("record.json carries a timestamp that is not RFC 3339: %q", stamp)
		}
	}
	return nil
}

func ueAt(stamp string) time.Time {
	t, _ := time.Parse(time.RFC3339, stamp) // validated by ueValidateTimes
	return t
}

func ueIsUnknown(reply string) bool { return reply == "timeout" || reply == "connection_lost" }

func ueFinalAbsentBetween(r ueRecord, start time.Time, end *time.Time) bool {
	for _, c := range r.Reconciliations {
		at := ueAt(c.At)
		if c.Result == "absent" && c.Final && !at.Before(start) && (end == nil || !at.After(*end)) {
			return true
		}
	}
	return false
}

func ueSettled(r ueRecord) string {
	for _, a := range r.Attempts {
		if a.Reply == "confirmed" {
			return "committed"
		}
	}
	for _, c := range r.Reconciliations {
		if c.Result == "present" {
			return "committed"
		}
	}
	var last time.Time
	found := false
	for _, a := range r.Attempts {
		if at := ueAt(a.DispatchedAt); ueIsUnknown(a.Reply) && (!found || at.After(last)) {
			last, found = at, true
		}
	}
	if !found || ueFinalAbsentBetween(r, last, nil) {
		return "not_run"
	}
	return "unknown"
}

func ueRetain(r ueRecord) ueRetained {
	unknown := 0
	for _, a := range r.Attempts {
		if ueIsUnknown(a.Reply) {
			unknown++
		}
	}
	return ueRetained{Attempts: len(r.Attempts), IdempotencyKey: r.Operation.IdempotencyKey,
		Operation: r.Operation.ID, Outcome: ueSettled(r), OwnerEffects: r.OwnerEffects,
		UnknownAttempts: unknown}
}

func ueDecide(r ueRecord) scDecision {
	var contract string
	known := len(r.ContractID) > 0 && json.Unmarshal(r.ContractID, &contract) == nil && contract == ueContractID
	settled := ueSettled(r)
	checks := []struct {
		reason string
		fails  bool
	}{
		{"contract_id_missing", len(r.ContractID) == 0},
		{"contract_id_unknown", len(r.ContractID) > 0 && !known},
		{"operation_identity_missing", ueIdentityMissing(r)},
		{"idempotency_key_args_changed", ueKeyArgsChanged(r)},
		{"dispatch_beyond_lease", ueBeyondLease(r)},
		{"retry_after_unknown", ueUnprotectedRetry(r)},
		{"duplicate_effect", r.OwnerEffects > 1},
		{"unknown_released", r.Reservation != nil && settled == "unknown" && !r.Reservation.Charged},
		{"outcome_settled_without_authority", settled == "unknown" &&
			(r.Reported.Outcome == "committed" || r.Reported.Outcome == "not_run")},
		{"outcome_disagrees_with_authority", settled != "unknown" && r.Reported.Outcome != settled},
	}
	for _, check := range checks {
		if check.fails {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "effect_held"}
}

func ueIdentityMissing(r ueRecord) bool {
	if r.Operation.IdempotencyKey == "" || r.Operation.ArgsDigest == "" {
		return true
	}
	for _, a := range r.Attempts {
		if a.IdempotencyKey == "" || a.ArgsDigest == "" {
			return true
		}
	}
	return false
}

func ueKeyArgsChanged(r ueRecord) bool {
	for _, a := range r.Attempts {
		if a.IdempotencyKey == r.Operation.IdempotencyKey && a.ArgsDigest != r.Operation.ArgsDigest {
			return true
		}
	}
	return false
}

func ueBeyondLease(r ueRecord) bool {
	if len(r.Leases) == 0 {
		return false
	}
	for _, a := range r.Attempts {
		if ueOutsideLease(a, r.Leases) {
			return true
		}
	}
	return false
}

func ueOutsideLease(a ueAttempt, leases []ueLease) bool {
	var held *ueLease
	for i := range leases {
		if a.Worker != nil && *a.Worker == leases[i].Worker &&
			a.FencingToken != nil && *a.FencingToken == leases[i].FencingToken {
			held = &leases[i]
			break
		}
	}
	if held == nil {
		return true
	}
	sent := ueAt(a.DispatchedAt)
	if sent.Before(ueAt(held.AcquiredAt)) || !sent.Before(ueAt(held.ExpiresAt)) {
		return true
	}
	for _, other := range leases {
		if other.FencingToken > held.FencingToken && !ueAt(other.AcquiredAt).After(sent) {
			return true
		}
	}
	return false
}

func ueProtectedRetry(r ueRecord, earlier, later ueAttempt) bool {
	sent, resent := ueAt(earlier.DispatchedAt), ueAt(later.DispatchedAt)
	retention := r.EffectOwner.KeyRetention
	deduplicated := r.EffectOwner.DeduplicatesByKey && later.IdempotencyKey == earlier.IdempotencyKey &&
		(retention == nil || resent.Sub(sent).Seconds() <= *retention)
	return deduplicated || ueFinalAbsentBetween(r, sent, &resent)
}

func ueUnprotectedRetry(r ueRecord) bool {
	attempts := append([]ueAttempt(nil), r.Attempts...)
	sort.SliceStable(attempts, func(i, j int) bool {
		return ueAt(attempts[i].DispatchedAt).Before(ueAt(attempts[j].DispatchedAt))
	})
	for i, earlier := range attempts {
		if !ueIsUnknown(earlier.Reply) {
			continue
		}
		for _, later := range attempts[i+1:] {
			if !ueProtectedRetry(r, earlier, later) {
				return true
			}
		}
	}
	return false
}
