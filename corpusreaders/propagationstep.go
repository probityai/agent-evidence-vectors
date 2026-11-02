package corpusreaders

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"time"
)

func init() { register(propagationStep{}) }

// propagationStep judges corpora/vectors-propagation-step/. Each member is one
// hop's attribution between two agents: the hop and how it is attributed, the
// message log, the digest chain the attribution cites, each agent's exposures
// to outside sources and when the receiving agent's effect happened. The
// reader applies the Python reader's checks in the same order:
//
//  1. contract_id_missing; 2. contract_id_unknown;
//  3. hop_endpoints_missing: the hop names two different agents;
//  4. chain_digest_mismatch: every link names a logged message and its digest;
//  5. chain_not_connected: the chain runs from the sender to the receiver;
//  6. edge_after_effect: chain messages are in order and precede the effect;
//  7. propagation_without_edge: a propagation attribution cites a chain;
//  8. common_cause_unsupported: a common-cause attribution names a source both
//     agents were exposed to before the effect.
type propagationStep struct{}

const psContractID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/propagation-step"

func (propagationStep) Suite() string { return "propagation-step/v1" }

type psRetained struct {
	AttributedAs string `json:"attributedAs"`
	ChainLength  int    `json:"chainLength"`
	From         string `json:"from"`
	To           string `json:"to"`
}

type psVector struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Files    map[string]string `json:"files"`
	Expected scDecision        `json:"expected"`
	Retained psRetained        `json:"retained"`
}

type psMessage struct {
	Digest string `json:"digest"`
	From   string `json:"from"`
	ID     string `json:"id"`
	SentAt string `json:"sentAt"`
	To     string `json:"to"`
}

type psRecord struct {
	ContractID json.RawMessage `json:"contractId"`
	Chain      []struct {
		Digest    string `json:"digest"`
		MessageID string `json:"messageId"`
	} `json:"chain"`
	Effect struct {
		At string `json:"at"`
	} `json:"effect"`
	Exposures []struct {
		Agent  string `json:"agent"`
		At     string `json:"at"`
		Source string `json:"source"`
	} `json:"exposures"`
	Hop struct {
		AttributedAs string `json:"attributedAs"`
		From         string `json:"from"`
		To           string `json:"to"`
	} `json:"hop"`
	Messages []psMessage `json:"messages"`
}

func (propagationStep) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	for _, entry := range manifest.Vectors {
		var v psVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = psJudgeMember(filepath.Join(dir, v.Path), v)
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func psJudgeMember(caseDir string, v psVector) []string {
	findings := acFileFindings(caseDir, v.Files)
	var record psRecord
	if err := scReadJSON(caseDir, "record.json", &record); err != nil {
		return append(findings, err.Error())
	}
	stamps := []string{record.Effect.At}
	for _, m := range record.Messages {
		stamps = append(stamps, m.SentAt)
	}
	for _, e := range record.Exposures {
		stamps = append(stamps, e.At)
	}
	for _, stamp := range stamps {
		if _, err := time.Parse(time.RFC3339, stamp); err != nil {
			return append(findings, fmt.Sprintf("record.json carries a timestamp that is not RFC 3339: %q", stamp))
		}
	}
	kept := psRetained{AttributedAs: record.Hop.AttributedAs, ChainLength: len(record.Chain),
		From: record.Hop.From, To: record.Hop.To}
	if !reflect.DeepEqual(kept, v.Retained) {
		findings = append(findings, "retained fields: the record gives something other than the manifest declares")
	}
	if got := psDecide(record); got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}

func psAt(stamp string) time.Time { t, _ := time.Parse(time.RFC3339, stamp); return t }

func psDecide(r psRecord) scDecision {
	var contract string
	known := len(r.ContractID) > 0 && json.Unmarshal(r.ContractID, &contract) == nil && contract == psContractID
	byID := map[string]psMessage{}
	for _, m := range r.Messages {
		byID[m.ID] = m
	}
	mismatch := false
	var sent []psMessage
	for _, l := range r.Chain {
		m, ok := byID[l.MessageID]
		if !ok || m.Digest != l.Digest {
			mismatch = true
		}
		sent = append(sent, m)
	}
	hop := r.Hop
	checks := []struct {
		reason string
		fails  func() bool
	}{
		{"contract_id_missing", func() bool { return len(r.ContractID) == 0 }},
		{"contract_id_unknown", func() bool { return len(r.ContractID) > 0 && !known }},
		{"hop_endpoints_missing", func() bool { return hop.From == "" || hop.To == "" || hop.From == hop.To }},
		{"chain_digest_mismatch", func() bool { return mismatch }},
		{"chain_not_connected", func() bool { return psNotConnected(sent, hop.From, hop.To) }},
		{"edge_after_effect", func() bool { return psAfterEffect(sent, psAt(r.Effect.At)) }},
		{"propagation_without_edge", func() bool { return hop.AttributedAs == "propagation" && len(r.Chain) == 0 }},
		{"common_cause_unsupported", func() bool { return hop.AttributedAs == "common_cause" && !psSharedSource(r) }},
	}
	for _, check := range checks {
		if check.fails() {
			return scDecision{"deny", check.reason}
		}
	}
	return scDecision{"allow", "attribution_supported"}
}

func psNotConnected(sent []psMessage, from, to string) bool {
	if len(sent) == 0 {
		return false
	}
	if sent[0].From != from || sent[len(sent)-1].To != to {
		return true
	}
	for i := 1; i < len(sent); i++ {
		if sent[i-1].To != sent[i].From {
			return true
		}
	}
	return false
}

func psAfterEffect(sent []psMessage, effect time.Time) bool {
	for i, m := range sent {
		at := psAt(m.SentAt)
		if !at.Before(effect) || (i > 0 && at.Before(psAt(sent[i-1].SentAt))) {
			return true
		}
	}
	return false
}

func psSharedSource(r psRecord) bool {
	effect := psAt(r.Effect.At)
	seen := map[string]bool{}
	for _, e := range r.Exposures {
		if e.Agent == r.Hop.From && psAt(e.At).Before(effect) {
			seen[e.Source] = true
		}
	}
	for _, e := range r.Exposures {
		if e.Agent == r.Hop.To && psAt(e.At).Before(effect) && seen[e.Source] {
			return true
		}
	}
	return false
}
