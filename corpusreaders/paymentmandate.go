package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

func init() { register(paymentMandateReader{}) }

// paymentMandateReader judges corpora/vectors-agent-payment-mandate/: a dispute evidence pack
// for an agent-initiated payment. It verifies the issuer's Ed25519 signature over the mandate
// and the settlement witness's over the receipt against the keys the corpus's policy.json pins,
// and the mandated agent's over the charge against the agent key the issuer-signed terms name.
// It refuses a record that could be read two ways (a duplicate member, an amount that is not a
// positive integer, a timestamp without a zone, a missing limit), a charge that leaves the
// mandate in agent, time, amount, currency, merchant, rail or token, a single-use mandate settled
// twice, an unsigned field that relaxes a signed limit, and a pack in which one single-use
// mandate or token settled in two records. The rules and their order are those of
// packaging/agent_evidence_vectors/paymentmandate.py.
type paymentMandateReader struct{}

func (paymentMandateReader) Suite() string { return "agent-payment-mandate/v1" }

const (
	pmAccept    = "mandate_chain_holds"
	pmMalformed = "record_malformed"
	pmPackRule  = "mandate_spent_twice"
	pmPack      = "agent-payment-mandate-pack/v1"
)

var (
	pmHex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pmHex128  = regexp.MustCompile(`^[0-9a-f]{128}$`)
	pmRFC3339 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$`)
)

type pmPolicy struct {
	Issuer  map[string]string `json:"issuer_keys"`
	Witness map[string]string `json:"witness_keys"`
}

type pmRule struct {
	code  string
	fires func(r any, p pmPolicy) bool
}

func pmTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || !pmRFC3339.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func pmPositiveInt(v any) bool {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return false
	}
	i, err := n.Int64()
	return err == nil && i > 0
}

func pmNumber(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func pmStrList(v any) bool {
	l, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range l {
		if _, isStr := item.(string); !isStr {
			return false
		}
	}
	return true
}

func pmVerifies(keyHex string, sig map[string]any, message []byte) bool {
	value := rlStr(sig["value"])
	if !pmHex64.MatchString(keyHex) || !pmHex128.MatchString(value) {
		return false
	}
	key, _ := hex.DecodeString(keyHex)
	signature, _ := hex.DecodeString(value)
	return ed25519.Verify(ed25519.PublicKey(key), message, signature)
}

func pmSigOK(keys map[string]string, sig map[string]any, message []byte) bool {
	if sig == nil {
		return false
	}
	key, ok := keys[rlStr(sig["key_id"])]
	return ok && pmVerifies(key, sig, message)
}

func pmWithout(v any, drop string) map[string]any {
	out := map[string]any{}
	for k, value := range rlMap(v) {
		if k != drop {
			out[k] = value
		}
	}
	return out
}

func pmCompact(v any) []byte {
	b, err := pythonCompactJSON(v)
	if err != nil {
		return nil
	}
	return b
}

func pmMalformedRecord(r any, _ pmPolicy) bool {
	terms := rlMap(rlGet(r, "mandate.terms"))
	agent := rlMap(rlGet(r, "mandate.terms.agent"))
	if terms == nil || agent == nil {
		return true
	}
	_, issued := pmTime(terms["issued_at"])
	_, expires := pmTime(terms["expires_at"])
	_, ran := pmTime(rlGet(r, "execution.executed_at"))
	_, agentID := agent["key_id"].(string)
	_, execAgent := rlGet(r, "execution.agent_key_id").(string)
	_, rail := rlGet(r, "execution.rail").(string)
	singleUse, singleUseIsBool := terms["single_use"].(bool)
	return !(pmPositiveInt(terms["max_amount_minor"]) &&
		pmPositiveInt(rlGet(r, "execution.amount_minor")) &&
		issued && expires && ran && agentID &&
		pmHex64.MatchString(rlStr(agent["public_key"])) &&
		execAgent && pmStrList(terms["rails"]) && len(rlList(terms["rails"])) > 0 && rail &&
		singleUseIsBool && pmStrList(terms["post_checkout_required"]) &&
		(!singleUse || pmPositiveInt(rlGet(r, "receipt.token_use_seq"))))
}

func pmRules() []pmRule {
	same := func(a, b any) bool { return reflect.DeepEqual(a, b) }
	return []pmRule{
		{pmMalformed, pmMalformedRecord},
		{"mandate_unsigned", func(r any, _ pmPolicy) bool {
			sig := rlMap(rlGet(r, "mandate.signature"))
			return sig == nil || rlStr(sig["key_id"]) == "" || !pmHex128.MatchString(rlStr(sig["value"]))
		}},
		{"mandate_signature_invalid", func(r any, p pmPolicy) bool {
			message := append([]byte("agent-payment-mandate/v1:mandate:"), rlStr(rlGet(r, "mandate.digest"))...)
			return !pmSigOK(p.Issuer, rlMap(rlGet(r, "mandate.signature")), message)
		}},
		{"mandate_digest_mismatch", func(r any, _ pmPolicy) bool {
			return rlStr(rlGet(r, "mandate.digest")) != rlDigest(rlGet(r, "mandate.terms"))
		}},
		{"credential_not_bound_to_mandate", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "credential.mandate_digest"), rlGet(r, "mandate.digest"))
		}},
		{"credential_widens_mandate", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "credential.single_use"), rlGet(r, "mandate.terms.single_use"))
		}},
		{"agent_not_the_mandated_agent", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "execution.agent_key_id"), rlGet(r, "mandate.terms.agent.key_id"))
		}},
		{"agent_proof_invalid", func(r any, _ pmPolicy) bool {
			sig := rlMap(rlGet(r, "execution.agent_signature"))
			agent := rlMap(rlGet(r, "mandate.terms.agent"))
			if sig == nil || agent == nil || !same(sig["key_id"], agent["key_id"]) {
				return true
			}
			body := pmCompact(pmWithout(rlGet(r, "execution"), "agent_signature"))
			if body == nil {
				return true
			}
			message := append([]byte("agent-payment-mandate/v1:agent:"), rlStr(rlGet(r, "mandate.digest"))...)
			message = append(append(message, ':'), body...)
			return !pmVerifies(rlStr(agent["public_key"]), sig, message)
		}},
		{"charge_before_mandate", func(r any, _ pmPolicy) bool {
			issued, ok1 := pmTime(rlGet(r, "mandate.terms.issued_at"))
			ran, ok2 := pmTime(rlGet(r, "execution.executed_at"))
			return !ok1 || !ok2 || ran.Before(issued)
		}},
		{"mandate_expired", func(r any, _ pmPolicy) bool {
			ran, ok1 := pmTime(rlGet(r, "execution.executed_at"))
			ends, ok2 := pmTime(rlGet(r, "mandate.terms.expires_at"))
			return !ok1 || !ok2 || ran.After(ends)
		}},
		{"amount_over_limit", func(r any, _ pmPolicy) bool {
			amount, ok1 := pmNumber(rlGet(r, "execution.amount_minor"))
			ceiling, ok2 := pmNumber(rlGet(r, "mandate.terms.max_amount_minor"))
			return !ok1 || !ok2 || amount > ceiling
		}},
		{"currency_mismatch", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "execution.currency"), rlGet(r, "mandate.terms.currency"))
		}},
		{"merchant_mismatch", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "execution.merchant"), rlGet(r, "mandate.terms.merchant"))
		}},
		{"rail_not_mandated", func(r any, _ pmPolicy) bool {
			rails, ok := rlGet(r, "mandate.terms.rails").([]any)
			if !ok {
				return true
			}
			for _, rail := range rails {
				if same(rail, rlGet(r, "execution.rail")) {
					return false
				}
			}
			return true
		}},
		{"token_not_the_executed_token", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "execution.token_id"), rlGet(r, "credential.token_id"))
		}},
		{"single_use_token_replayed", func(r any, _ pmPolicy) bool {
			if !rlTrue(rlGet(r, "mandate.terms.single_use")) {
				return false
			}
			consumed := rlStringSet(rlGet(r, "credential.consumed_token_ids"))
			seq, ok := rlGet(r, "receipt.token_use_seq").(json.Number)
			return consumed[rlStr(rlGet(r, "execution.token_id"))] || !ok || seq.String() != "1"
		}},
		{"receipt_not_bound_to_execution", func(r any, _ pmPolicy) bool {
			return !same(rlGet(r, "receipt.mandate_digest"), rlGet(r, "mandate.digest")) ||
				rlStr(rlGet(r, "receipt.execution_digest")) != rlDigest(rlGet(r, "execution"))
		}},
		{"receipt_signer_not_witness", func(r any, p pmPolicy) bool {
			sig := rlMap(rlGet(r, "receipt.signature"))
			if sig == nil {
				return true
			}
			_, ok := p.Witness[rlStr(sig["key_id"])]
			return !ok
		}},
		{"receipt_signature_invalid", func(r any, p pmPolicy) bool {
			body := pmCompact(pmWithout(rlGet(r, "receipt"), "signature"))
			if body == nil {
				return true
			}
			message := append([]byte("agent-payment-mandate/v1:receipt:"), body...)
			return !pmSigOK(p.Witness, rlMap(rlGet(r, "receipt.signature")), message)
		}},
		{"post_checkout_action_missing", func(r any, _ pmPolicy) bool {
			required := rlStringSet(rlGet(r, "mandate.terms.post_checkout_required"))
			for k := range rlStringSet(rlGet(r, "post_checkout.required")) {
				required[k] = true
			}
			return !rlSubset(required, rlStringSet(rlGet(r, "post_checkout.recorded")))
		}},
	}
}

func pmDecideOne(record any, p pmPolicy) rlExpected {
	if rlMap(record) == nil {
		return rlExpected{Decision: "rejected", Reason: pmMalformed}
	}
	for _, rule := range pmRules() {
		if rule.fires(record, p) {
			return rlExpected{Decision: "rejected", Reason: rule.code}
		}
	}
	return rlExpected{Decision: "accepted", Reason: pmAccept}
}

func pmSpentTwice(records []any) bool {
	seen := map[string]bool{}
	for _, r := range records {
		if !rlTrue(rlGet(r, "mandate.terms.single_use")) {
			continue
		}
		for _, key := range []string{
			"mandate:" + rlStr(rlGet(r, "mandate.digest")),
			"token:" + rlStr(rlGet(r, "execution.token_id")),
		} {
			if seen[key] {
				return true
			}
			seen[key] = true
		}
	}
	return false
}

func pmDecide(record any, p pmPolicy) rlExpected {
	if rlStr(rlGet(record, "schema")) != pmPack {
		return pmDecideOne(record, p)
	}
	members := rlList(rlGet(record, "records"))
	if len(members) < 2 {
		return rlExpected{Decision: "rejected", Reason: pmMalformed}
	}
	for _, member := range members {
		if got := pmDecideOne(member, p); got.Decision == "rejected" {
			return got
		}
	}
	if pmSpentTwice(members) {
		return rlExpected{Decision: "rejected", Reason: pmPackRule}
	}
	return rlExpected{Decision: "accepted", Reason: pmAccept}
}

// pmHasDuplicate reports whether any JSON object in raw names one member twice.
func pmHasDuplicate(raw []byte) (bool, error) {
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	done := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expectKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
			if delim, ok := tok.(json.Delim); ok && delim == '}' {
				stack = stack[:n-1]
				done()
				continue
			}
			key, _ := tok.(string)
			if stack[n-1].keys[key] {
				return true, nil
			}
			stack[n-1].keys[key] = true
			stack[n-1].expectKey = false
			continue
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, &frame{object: true, keys: map[string]bool{}, expectKey: true})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			case ']':
				stack = stack[:len(stack)-1]
			}
		}
		done()
	}
}

func (paymentMandateReader) Judge(dir string, raw []byte) (*Result, error) {
	var manifest scManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%s/MANIFEST.json does not parse: %w", dir, err)
	}
	result := &Result{}
	var policy pmPolicy
	if body, err := readIn(dir, "policy.json"); err != nil {
		result.Findings = append(result.Findings, "policy.json cannot be read: "+err.Error())
	} else if err := json.Unmarshal(body, &policy); err != nil {
		result.Findings = append(result.Findings, "policy.json does not parse: "+err.Error())
	}
	accepted := map[string]bool{}
	var vectors []rlVector
	for _, entry := range manifest.Vectors {
		var v rlVector
		if err := json.Unmarshal(entry, &v); err != nil {
			result.Findings = append(result.Findings, fmt.Sprintf("a manifest row does not parse: %v", err))
			continue
		}
		accepted[v.ID] = v.Expected.Decision == "accepted"
		vectors = append(vectors, v)
	}
	for _, v := range vectors {
		member := Member{ID: v.ID, Kind: v.Expected.Decision}
		member.Findings = pmJudgeMember(filepath.Join(dir, v.Path), v, policy)
		if v.Expected.Decision == "rejected" && !accepted[v.Twin] {
			member.Findings = append(member.Findings, "a rejected member must name an accepted twin")
		}
		result.Members = append(result.Members, member)
	}
	if finding := scCorpusDigest(manifest); finding != "" {
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

func pmJudgeMember(caseDir string, v rlVector, policy pmPolicy) []string {
	findings := acFileFindings(caseDir, v.Files)
	body, err := readIn(caseDir, "case.json")
	if err != nil {
		return append(findings, "case.json cannot be read: "+err.Error())
	}
	got := rlExpected{Decision: "rejected", Reason: pmMalformed}
	duplicate, err := pmHasDuplicate(body)
	if err != nil {
		return append(findings, "case.json does not parse: "+err.Error())
	}
	if !duplicate {
		record, err := decodeJSONNumbers(body)
		if err != nil {
			return append(findings, "case.json does not parse: "+err.Error())
		}
		got = pmDecide(record, policy)
	}
	if got != v.Expected {
		findings = append(findings, fmt.Sprintf("derived %s/%s, the manifest declares %s/%s",
			got.Decision, got.Reason, v.Expected.Decision, v.Expected.Reason))
	}
	return findings
}
