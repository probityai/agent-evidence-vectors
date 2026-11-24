package corpusreaders

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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
// judges the issuer key by the dates the policy gives it (at the signed issue time, and a
// revoked key also at the witnessed charge), and verifies the mandated agent's proof over the
// charge against the agent the issuer-signed terms name. It refuses a record that could be read
// two ways, a charge that leaves the mandate in agent, time, amount, currency, merchant, rail
// or token, a single-use mandate settled twice, an unsigned field that relaxes a signed limit,
// and a pack in which one single-use mandate or token settled in two records. An x402 record
// carries the facilitator request in x402 v2 field names; its agent's proof is the EIP-3009
// signature, whose signer is recovered (evmsig.go), never read from a field. The rules and
// their order are those of packaging/agent_evidence_vectors/paymentmandate.py.
type paymentMandateReader struct{}

func (paymentMandateReader) Suite() string { return "agent-payment-mandate/v1" }

const (
	pmAccept     = "mandate_chain_holds"
	pmMalformed  = "record_malformed"
	pmPackRule   = "mandate_spent_twice"
	pmPack       = "agent-payment-mandate-pack/v1"
	pmX402Scheme = "x402-exact-evm-eip3009"
	pmX402Rail   = "x402"
)

var (
	pmHex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pmHex128      = regexp.MustCompile(`^[0-9a-f]{128}$`)
	pmRFC3339     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$`)
	pmSignatureRe = regexp.MustCompile(`^0x[0-9a-fA-F]{130}$`)
)

// pmPolicy is the relying party's trust root: each issuer key with the dates it was valid,
// and the witness keys.
type pmPolicy struct {
	Issuer  map[string]map[string]any `json:"issuer_keys"`
	Witness map[string]string         `json:"witness_keys"`
}

type pmCheck func(r any, p pmPolicy) bool

type pmRule struct {
	code       string
	card, x402 pmCheck
}

func pmIsX402(r any) bool { return rlStr(rlGet(r, "scheme")) == pmX402Scheme }

func pmNever(any, pmPolicy) bool { return false }

func pmTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || !pmRFC3339.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func pmWhole(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func pmPositiveInt(v any) bool {
	i, ok := pmWhole(v)
	return ok && i > 0
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

func pmDecimal(v any) *big.Int {
	s, ok := v.(string)
	if !ok || !evmUintRe.MatchString(s) {
		return nil
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func pmX(r any, path string) any { return rlGet(r, "credential.facilitator_request."+path) }

func pmSameAddress(a, b any) bool {
	sa, ok1 := a.(string)
	sb, ok2 := b.(string)
	return ok1 && ok2 && evmAddressRe.MatchString(sa) && evmAddressRe.MatchString(sb) && strings.EqualFold(sa, sb)
}

func pmSame(a, b any) bool { return reflect.DeepEqual(a, b) }

// pmChargedAt is when the charge ran, as the witness-signed execution states it: the
// execution time on the card profiles, the block time on x402.
func pmChargedAt(r any) (time.Time, bool) {
	if !pmIsX402(r) {
		return pmTime(rlGet(r, "execution.executed_at"))
	}
	block, ok := pmWhole(rlGet(r, "execution.block_timestamp"))
	return time.Unix(block, 0).UTC(), ok
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

// --- shape ---------------------------------------------------------------------------

func pmSignedLimitsOK(terms map[string]any) bool {
	_, issued := pmTime(terms["issued_at"])
	_, expires := pmTime(terms["expires_at"])
	_, singleUse := terms["single_use"].(bool)
	return pmPositiveInt(terms["max_amount_minor"]) && issued && expires &&
		pmStrList(terms["rails"]) && len(rlList(terms["rails"])) > 0 &&
		singleUse && pmStrList(terms["post_checkout_required"])
}

func pmCardShapeOK(r any) bool {
	agent := rlMap(rlGet(r, "mandate.terms.agent"))
	_, ran := pmTime(rlGet(r, "execution.executed_at"))
	_, execAgent := rlGet(r, "execution.agent_key_id").(string)
	_, rail := rlGet(r, "execution.rail").(string)
	if agent == nil || !ran || !execAgent || !rail {
		return false
	}
	_, agentID := agent["key_id"].(string)
	seqOK := !rlTrue(rlGet(r, "mandate.terms.single_use")) || pmPositiveInt(rlGet(r, "receipt.token_use_seq"))
	return agentID && pmHex64.MatchString(rlStr(agent["public_key"])) &&
		pmPositiveInt(rlGet(r, "execution.amount_minor")) && seqOK
}

func pmX402ShapeOK(r any) bool {
	address, ok := rlGet(r, "mandate.terms.agent.address").(string)
	_, block := pmWhole(rlGet(r, "execution.block_timestamp"))
	return ok && evmAddressRe.MatchString(address) && block
}

func pmMalformedRecord(r any, _ pmPolicy) bool {
	terms := rlMap(rlGet(r, "mandate.terms"))
	if terms == nil || !pmSignedLimitsOK(terms) {
		return true
	}
	if pmIsX402(r) {
		return !pmX402ShapeOK(r)
	}
	return !pmCardShapeOK(r)
}

// --- the mandate's signature and its key ---------------------------------------------

func pmIssuerKey(r any, p pmPolicy) map[string]any {
	sig := rlMap(rlGet(r, "mandate.signature"))
	if sig == nil {
		return nil
	}
	return p.Issuer[rlStr(sig["key_id"])]
}

func pmUnsigned(r any, _ pmPolicy) bool {
	sig := rlMap(rlGet(r, "mandate.signature"))
	return sig == nil || rlStr(sig["key_id"]) == "" || !pmHex128.MatchString(rlStr(sig["value"]))
}

func pmKeyUnknown(r any, p pmPolicy) bool { return pmIssuerKey(r, p) == nil }

func pmMandateSignatureInvalid(r any, p pmPolicy) bool {
	entry := pmIssuerKey(r, p)
	sig := rlMap(rlGet(r, "mandate.signature"))
	if entry == nil || sig == nil {
		return true
	}
	message := append([]byte("agent-payment-mandate/v1:mandate:"), rlStr(rlGet(r, "mandate.digest"))...)
	return !pmVerifies(rlStr(entry["public_key"]), sig, message)
}

func pmDigestMismatch(r any, _ pmPolicy) bool {
	return rlStr(rlGet(r, "mandate.digest")) != rlDigest(rlGet(r, "mandate.terms"))
}

// pmKeyDate reads one validity date of the signing key: stated is false for a null or
// missing date, and ok is false when a stated date is not an RFC 3339 date-time.
func pmKeyDate(r any, p pmPolicy, field string) (date time.Time, stated, ok bool) {
	value := pmIssuerKey(r, p)[field]
	if value == nil {
		return time.Time{}, false, false
	}
	date, ok = pmTime(value)
	return date, true, ok
}

func pmKeyNotYetValid(r any, p pmPolicy) bool {
	signed, ok1 := pmTime(rlGet(r, "mandate.terms.issued_at"))
	since, _, ok2 := pmKeyDate(r, p, "valid_from")
	return !ok1 || !ok2 || signed.Before(since)
}

func pmKeyRotatedOut(r any, p pmPolicy) bool {
	until, stated, ok := pmKeyDate(r, p, "valid_until")
	if !stated {
		return false
	}
	signed, ok1 := pmTime(rlGet(r, "mandate.terms.issued_at"))
	return !ok || !ok1 || !signed.Before(until)
}

// pmKeyRevoked fires when revocation took effect at or before the signed issue time or at
// or before the witnessed charge: a revoked key's holder can sign any issue time.
func pmKeyRevoked(r any, p pmPolicy) bool {
	revoked, stated, ok := pmKeyDate(r, p, "revoked_effective_from")
	if !stated {
		return false
	}
	signed, ok1 := pmTime(rlGet(r, "mandate.terms.issued_at"))
	charged, ok2 := pmChargedAt(r)
	if !ok || !ok1 || !ok2 {
		return true
	}
	return !revoked.After(signed) || !revoked.After(charged)
}

// --- the charge against the terms ----------------------------------------------------

func pmNotBound(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "credential.mandate_digest"), rlGet(r, "mandate.digest"))
}

func pmCredentialWidens(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "credential.single_use"), rlGet(r, "mandate.terms.single_use"))
}

func pmBeforeMandate(r any, _ pmPolicy) bool {
	issued, ok1 := pmTime(rlGet(r, "mandate.terms.issued_at"))
	ran, ok2 := pmChargedAt(r)
	return !ok1 || !ok2 || ran.Before(issued)
}

func pmExpired(r any, _ pmPolicy) bool {
	ran, ok1 := pmChargedAt(r)
	ends, ok2 := pmTime(rlGet(r, "mandate.terms.expires_at"))
	return !ok1 || !ok2 || ran.After(ends)
}

func pmOverLimit(r any, _ pmPolicy) bool {
	amount, ok1 := pmNumber(rlGet(r, "execution.amount_minor"))
	ceiling, ok2 := pmNumber(rlGet(r, "mandate.terms.max_amount_minor"))
	return !ok1 || !ok2 || amount > ceiling
}

func pmXOverLimit(r any, _ pmPolicy) bool {
	value := pmDecimal(pmX(r, "paymentPayload.payload.authorization.value"))
	ceiling, ok := pmWhole(rlGet(r, "mandate.terms.max_amount_minor"))
	return value == nil || !ok || value.Cmp(big.NewInt(ceiling)) > 0
}

func pmCurrency(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "execution.currency"), rlGet(r, "mandate.terms.currency"))
}

func pmXCurrency(r any, _ pmPolicy) bool {
	required := pmX(r, "paymentRequirements.asset")
	return !pmSameAddress(pmX(r, "paymentPayload.accepted.asset"), required) ||
		!pmSameAddress(required, rlGet(r, "mandate.terms.currency"))
}

func pmMerchant(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "execution.merchant"), rlGet(r, "mandate.terms.merchant"))
}

func pmXMerchant(r any, _ pmPolicy) bool {
	payTo := pmX(r, "paymentRequirements.payTo")
	return !pmSameAddress(pmX(r, "paymentPayload.payload.authorization.to"), payTo) ||
		!pmSameAddress(pmX(r, "paymentPayload.accepted.payTo"), payTo) ||
		!pmSameAddress(payTo, rlGet(r, "mandate.terms.merchant"))
}

func pmRailIn(r any, rail any) bool {
	rails, ok := rlGet(r, "mandate.terms.rails").([]any)
	if !ok {
		return false
	}
	for _, mandated := range rails {
		if pmSame(mandated, rail) {
			return true
		}
	}
	return false
}

func pmRail(r any, _ pmPolicy) bool { return !pmRailIn(r, rlGet(r, "execution.rail")) }

func pmXRail(r any, _ pmPolicy) bool { return !pmRailIn(r, pmX402Rail) }

func pmXNetwork(r any, _ pmPolicy) bool {
	required, ok := pmX(r, "paymentRequirements.network").(string)
	return !ok || rlStr(pmX(r, "paymentPayload.accepted.network")) != required ||
		rlStr(rlGet(r, "mandate.terms.network")) != required
}

func pmXNotOfferAmount(r any, _ pmPolicy) bool {
	required := pmDecimal(pmX(r, "paymentRequirements.amount"))
	value := pmDecimal(pmX(r, "paymentPayload.payload.authorization.value"))
	accepted := pmDecimal(pmX(r, "paymentPayload.accepted.amount"))
	return required == nil || value == nil || accepted == nil ||
		value.Cmp(required) != 0 || accepted.Cmp(required) != 0
}

// pmXOutsideWindow: EIP-3009 settles only when validAfter < block time < validBefore.
func pmXOutsideWindow(r any, _ pmPolicy) bool {
	settled, ok := pmWhole(rlGet(r, "execution.block_timestamp"))
	after := pmDecimal(pmX(r, "paymentPayload.payload.authorization.validAfter"))
	before := pmDecimal(pmX(r, "paymentPayload.payload.authorization.validBefore"))
	if !ok || after == nil || before == nil {
		return true
	}
	t := big.NewInt(settled)
	return after.Cmp(t) >= 0 || t.Cmp(before) >= 0
}

// --- the agent -----------------------------------------------------------------------

func pmOtherAgent(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "execution.agent_key_id"), rlGet(r, "mandate.terms.agent.key_id"))
}

func pmXOtherAgent(r any, _ pmPolicy) bool {
	return !pmSameAddress(pmX(r, "paymentPayload.payload.authorization.from"), rlGet(r, "mandate.terms.agent.address"))
}

func pmSignature(r any) ([]byte, bool) {
	text := rlStr(pmX(r, "paymentPayload.payload.signature"))
	if !pmSignatureRe.MatchString(text) {
		return nil, false
	}
	sig, err := hex.DecodeString(text[2:])
	return sig, err == nil
}

func pmXNotCanonical(r any, _ pmPolicy) bool {
	sig, ok := pmSignature(r)
	return !ok || !evmLowS(sig)
}

func pmAgentProofInvalid(r any, _ pmPolicy) bool {
	sig := rlMap(rlGet(r, "execution.agent_signature"))
	agent := rlMap(rlGet(r, "mandate.terms.agent"))
	if sig == nil || agent == nil || !pmSame(sig["key_id"], agent["key_id"]) {
		return true
	}
	body := pmCompact(pmWithout(rlGet(r, "execution"), "agent_signature"))
	if body == nil {
		return true
	}
	message := append([]byte("agent-payment-mandate/v1:agent:"), rlStr(rlGet(r, "mandate.digest"))...)
	message = append(append(message, ':'), body...)
	return !pmVerifies(rlStr(agent["public_key"]), sig, message)
}

// pmSigner recovers the signer under the requirement's token domain. An unsigned
// payload member naming a signer is never read.
func pmSigner(r any) (string, bool) {
	auth := rlMap(pmX(r, "paymentPayload.payload.authorization"))
	sig, ok := pmSignature(r)
	if auth == nil || !ok {
		return "", false
	}
	digest, err := eip3009Digest(auth, pmX(r, "paymentRequirements.network"), pmX(r, "paymentRequirements.asset"),
		pmX(r, "paymentRequirements.extra.name"), pmX(r, "paymentRequirements.extra.version"))
	if err != nil {
		return "", false
	}
	return evmRecover(digest, sig)
}

func pmXAgentProofInvalid(r any, _ pmPolicy) bool {
	signer, ok := pmSigner(r)
	return !ok || !pmSameAddress(signer, pmX(r, "paymentPayload.payload.authorization.from"))
}

// --- the token, the settlement and the receipt ---------------------------------------

func pmTokenMismatch(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "execution.token_id"), rlGet(r, "credential.token_id"))
}

func pmXOtherNonce(r any, _ pmPolicy) bool {
	nonce := rlStr(pmX(r, "paymentPayload.payload.authorization.nonce"))
	used := rlStr(rlGet(r, "execution.authorization_used.nonce"))
	return !pmSameAddress(rlGet(r, "execution.authorization_used.authorizer"),
		pmX(r, "paymentPayload.payload.authorization.from")) ||
		!evmBytes32Re.MatchString(nonce) || !strings.EqualFold(used, nonce)
}

func pmXTransferDiffers(r any, _ pmPolicy) bool {
	auth := "paymentPayload.payload.authorization."
	value := pmDecimal(pmX(r, auth+"value"))
	moved := pmDecimal(rlGet(r, "execution.transfer.value"))
	return !pmSameAddress(rlGet(r, "execution.transfer.from"), pmX(r, auth+"from")) ||
		!pmSameAddress(rlGet(r, "execution.transfer.to"), pmX(r, auth+"to")) ||
		value == nil || moved == nil || value.Cmp(moved) != 0 ||
		!pmSameAddress(rlGet(r, "execution.asset"), pmX(r, "paymentRequirements.asset")) ||
		rlStr(rlGet(r, "execution.network")) != rlStr(pmX(r, "paymentRequirements.network"))
}

func pmReplayed(r any, _ pmPolicy) bool {
	if !rlTrue(rlGet(r, "mandate.terms.single_use")) {
		return false
	}
	consumed := rlStringSet(rlGet(r, "credential.consumed_token_ids"))
	seq, ok := rlGet(r, "receipt.token_use_seq").(json.Number)
	return consumed[rlStr(rlGet(r, "execution.token_id"))] || !ok || seq.String() != "1"
}

func pmXReplayed(r any, _ pmPolicy) bool {
	nonce := strings.ToLower(rlStr(pmX(r, "paymentPayload.payload.authorization.nonce")))
	for _, used := range rlList(rlGet(r, "execution.nonces_used_before")) {
		if strings.ToLower(rlStr(used)) == nonce {
			return true
		}
	}
	return false
}

func pmReceiptUnbound(r any, _ pmPolicy) bool {
	return !pmSame(rlGet(r, "receipt.mandate_digest"), rlGet(r, "mandate.digest")) ||
		rlStr(rlGet(r, "receipt.execution_digest")) != rlDigest(rlGet(r, "execution"))
}

// pmXReceiptUnbound is the x402 half of receipt_not_bound_to_execution: the facilitator's
// settlement response must succeed and name this transaction, network, payer and amount.
func pmXReceiptUnbound(r any, p pmPolicy) bool {
	response := rlMap(rlGet(r, "receipt.settlement_response"))
	if pmReceiptUnbound(r, p) || response == nil {
		return true
	}
	amount, hasAmount := response["amount"]
	amountOK := !hasAmount
	if hasAmount {
		a, b := pmDecimal(amount), pmDecimal(rlGet(r, "execution.transfer.value"))
		amountOK = a != nil && b != nil && a.Cmp(b) == 0
	}
	return !rlTrue(response["success"]) ||
		rlStr(response["transaction"]) != rlStr(rlGet(r, "execution.transaction")) || rlStr(response["transaction"]) == "" ||
		rlStr(response["network"]) != rlStr(rlGet(r, "execution.network")) ||
		!pmSameAddress(response["payer"], pmX(r, "paymentPayload.payload.authorization.from")) ||
		!amountOK
}

func pmReceiptSignerNotWitness(r any, p pmPolicy) bool {
	sig := rlMap(rlGet(r, "receipt.signature"))
	if sig == nil {
		return true
	}
	_, ok := p.Witness[rlStr(sig["key_id"])]
	return !ok
}

func pmReceiptSignatureInvalid(r any, p pmPolicy) bool {
	sig := rlMap(rlGet(r, "receipt.signature"))
	body := pmCompact(pmWithout(rlGet(r, "receipt"), "signature"))
	if sig == nil || body == nil {
		return true
	}
	key, ok := p.Witness[rlStr(sig["key_id"])]
	message := append([]byte("agent-payment-mandate/v1:receipt:"), body...)
	return !ok || !pmVerifies(key, sig, message)
}

func pmPostCheckoutMissing(r any, _ pmPolicy) bool {
	required := rlStringSet(rlGet(r, "mandate.terms.post_checkout_required"))
	for k := range rlStringSet(rlGet(r, "post_checkout.required")) {
		required[k] = true
	}
	return !rlSubset(required, rlStringSet(rlGet(r, "post_checkout.recorded")))
}

// pmRules is the one table both profiles share, in the order of paymentmandate.py: each row
// names the check for the AP2, Verifiable Intent and shared-token records and the one for x402.
func pmRules() []pmRule {
	return []pmRule{
		{pmMalformed, pmMalformedRecord, pmMalformedRecord},
		{"mandate_unsigned", pmUnsigned, pmUnsigned},
		{"signing_key_unknown", pmKeyUnknown, pmKeyUnknown},
		{"mandate_signature_invalid", pmMandateSignatureInvalid, pmMandateSignatureInvalid},
		{"mandate_digest_mismatch", pmDigestMismatch, pmDigestMismatch},
		{"signing_key_not_yet_valid", pmKeyNotYetValid, pmKeyNotYetValid},
		{"signing_key_rotated_out", pmKeyRotatedOut, pmKeyRotatedOut},
		{"signing_key_revoked", pmKeyRevoked, pmKeyRevoked},
		{"credential_not_bound_to_mandate", pmNotBound, pmNotBound},
		{"credential_widens_mandate", pmCredentialWidens, pmNever},
		{"charge_before_mandate", pmBeforeMandate, pmBeforeMandate},
		{"mandate_expired", pmExpired, pmExpired},
		{"amount_over_limit", pmOverLimit, pmXOverLimit},
		{"currency_mismatch", pmCurrency, pmXCurrency},
		{"merchant_mismatch", pmMerchant, pmXMerchant},
		{"rail_not_mandated", pmRail, pmXRail},
		{"network_mismatch", pmNever, pmXNetwork},
		{"amount_not_offer_amount", pmNever, pmXNotOfferAmount},
		{"authorization_outside_validity_window", pmNever, pmXOutsideWindow},
		{"agent_not_the_mandated_agent", pmOtherAgent, pmXOtherAgent},
		{"signature_not_canonical", pmNever, pmXNotCanonical},
		{"agent_proof_invalid", pmAgentProofInvalid, pmXAgentProofInvalid},
		{"token_not_the_executed_token", pmTokenMismatch, pmXOtherNonce},
		{"settlement_not_the_authorization", pmNever, pmXTransferDiffers},
		{"single_use_token_replayed", pmReplayed, pmXReplayed},
		{"receipt_not_bound_to_execution", pmReceiptUnbound, pmXReceiptUnbound},
		{"receipt_signer_not_witness", pmReceiptSignerNotWitness, pmReceiptSignerNotWitness},
		{"receipt_signature_invalid", pmReceiptSignatureInvalid, pmReceiptSignatureInvalid},
		{"post_checkout_action_missing", pmPostCheckoutMissing, pmPostCheckoutMissing},
	}
}

func pmDecideOne(record any, p pmPolicy) rlExpected {
	if rlMap(record) == nil {
		return rlExpected{Decision: "rejected", Reason: pmMalformed}
	}
	x402 := pmIsX402(record)
	for _, rule := range pmRules() {
		check := rule.card
		if x402 {
			check = rule.x402
		}
		if check(record, p) {
			return rlExpected{Decision: "rejected", Reason: rule.code}
		}
	}
	return rlExpected{Decision: "accepted", Reason: pmAccept}
}

// pmTokenOf is the single-use token a record spends: the token id, or the x402 nonce.
func pmTokenOf(r any) string {
	if pmIsX402(r) {
		return strings.ToLower(rlStr(pmX(r, "paymentPayload.payload.authorization.nonce")))
	}
	return rlStr(rlGet(r, "execution.token_id"))
}

func pmSpentTwice(records []any) bool {
	seen := map[string]bool{}
	for _, r := range records {
		if !rlTrue(rlGet(r, "mandate.terms.single_use")) {
			continue
		}
		for _, key := range []string{"mandate:" + rlStr(rlGet(r, "mandate.digest")), "token:" + pmTokenOf(r)} {
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

type pmFrame struct {
	object    bool
	keys      map[string]bool
	expectKey bool
}

// pmHasDuplicate reports whether any JSON object in raw names one member twice.
func pmHasDuplicate(raw []byte) (bool, error) {
	var stack []*pmFrame
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
				stack = append(stack, &pmFrame{object: true, keys: map[string]bool{}, expectKey: true})
				continue
			case '[':
				stack = append(stack, &pmFrame{})
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
