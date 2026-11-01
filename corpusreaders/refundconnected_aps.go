package corpora

// Step 2 of the refund-connected reader: the APS intent and approval receipts,
// the decision components, the action and payload references, the single use of
// the approval and the PIC claim's binding to it.

import (
	"bytes"
	"strings"
)

var rcAPSKeyFields = []string{"signer", "key_id", "role", "public_key", "not_before", "not_after", "revoked_at"}

// apsKey is _aps_key: the public key a signature descriptor names, when the
// receipt's issue time falls in the key's window.
func apsKey(trust any, signer, keyID, issuedAt string, atIssuance bool) ([]byte, bool) {
	for _, key := range rcIter(rcItem(trust, "keys")) {
		if !rcEqStr(rcItem(key, "signer"), signer) || !rcEqStr(rcItem(key, "key_id"), keyID) {
			continue
		}
		if rcLess(issuedAt, rcItem(key, "not_before")) {
			return nil, false
		}
		if after := rcItem(key, "not_after"); after != nil && rcLessEq(after, issuedAt) {
			return nil, false
		}
		if atIssuance {
			if revoked := rcItem(key, "revoked_at"); revoked != nil && rcLessEq(revoked, issuedAt) {
				return nil, false
			}
		}
		return rcBytesFromHex(rcItem(key, "public_key")), true
	}
	return nil, false
}

// apsReceiptOK is _aps_receipt_ok.
func apsReceiptOK(receipt any, receiptType string, trust any, issuer string, atIssuance bool) bool {
	r, ok := receipt.(*rcObj)
	if !ok || !rcEqStr(r.get("profile"), "aps-receipt-v1") || !rcEqStr(r.get("receipt_type"), receiptType) ||
		!rcEqStr(r.get("issuer"), issuer) {
		return false
	}
	sigs, isList := rcList(r.get("signatures"))
	if !isList || len(sigs) == 0 {
		return false
	}
	body := rcWithout(r, "receipt_id", "signatures")
	if !rcEqStr(r.get("receipt_id"), rcTagRef("APS-RECEIPT-ID-V1", body)) {
		return false
	}
	unsigned := rcWithout(r, "signatures")
	for _, sig := range sigs {
		if !apsSignatureOK(r, sig, unsigned, trust, atIssuance) {
			return false
		}
	}
	return true
}

func apsSignatureOK(receipt *rcObj, sig any, unsigned *rcObj, trust any, atIssuance bool) bool {
	so, ok := sig.(*rcObj)
	if !ok || !rcEqStr(so.get("alg"), "Ed25519") || !rcIsStr(so.get("value")) {
		return false
	}
	pub, found := apsKey(trust, rcStr(so.get("signer")), rcStr(so.get("key_id")), rcStr(receipt.get("issued_at")), atIssuance)
	descriptor := rcWithout(so, "value")
	message := append([]byte("APS-RECEIPT-SIG-V1\x00"), rcJCS(rcMake("receipt", unsigned, "signer", descriptor))...)
	value, hexOK := rcFromHex(so.m["value"].(string))
	return hexOK && found && rcEdVerify(pub, message, value)
}

func (j *rcJudge) checkAPS(c *rcCase, consumedAt string) {
	j.inputsReady(c)
	trust := c.p("trust/aps-consumption.json")
	j.apsTrust(trust)
	intent, approval := c.p("inputs/aps-intent.json"), c.p("inputs/aps-approval.json")
	decision, action := c.p("inputs/decision-evidence.json"), c.p("inputs/aps-action.json")
	payload := c.p("inputs/aps-payload.json")
	j.apsReceipts(trust, intent, approval, decision)
	j.apsBinding(intent, approval, decision)
	j.apsDecision(trust, approval, consumedAt)
	targetID := j.apsAction(action, approval)
	j.apsPayload(action, payload, targetID)
	merchant := j.apsMerchant(decision)
	j.apsPIC(c, merchant, approval, payload, consumedAt)
	c.decisionID, c.approvalID = rcItem(merchant, "decision_id"), rcItem(approval, "receipt_id")
}

func (j *rcJudge) apsTrust(trust any) {
	good := false
	if obj, isObj := trust.(*rcObj); isObj && rcKeysAre(obj, "schema", "profile", "scope", "keys") &&
		rcEqStr(obj.m["schema"], "hs-aps-consumption-trust/0.1") && rcEqStr(obj.m["profile"], "aps-receipt-v1") &&
		rcEq(obj.m["scope"], []any{"payments:refund"}) {
		keys, isList := rcList(obj.m["keys"])
		good = isList && len(keys) > 0
	}
	j.needR(good, "TRUST_SELECTION")
	for _, key := range rcIter(rcItem(trust, "keys")) {
		ko, isObj := key.(*rcObj)
		j.needR(isObj && rcKeysAre(ko, rcAPSKeyFields...) && rcIsHex64(ko.m["public_key"]), "TRUST_SELECTION")
	}
}

func (j *rcJudge) apsReceipts(trust, intent, approval, decision any) {
	io, isObj := intent.(*rcObj)
	j.needR(isObj && rcEqStr(io.get("issuer"), rcWorker) && rcEqStr(io.get("subject_agent"), rcWorker), "INTENT_IDENTITY")
	j.needR(apsReceiptOK(intent, "aps:action-intent:v1", trust, rcWorker, true), "INTENT_NOT_VALID")
	j.needR(rcClosed(decision, []string{"authority_state", "policy_input", "decision_context", "decision_output"}), "DECISION_COMPONENTS")
	ao, isObj := approval.(*rcObj)
	j.needR(isObj && rcEqStr(ao.get("issuer"), rcBoundary), "APPROVAL_ISSUER")
	j.needR(apsReceiptOK(approval, "aps:policy-decision:v1", trust, rcBoundary, false), "APPROVAL_NOT_VALID")
}

func (j *rcJudge) apsBinding(intent, approval, decision any) {
	components := rcMake(
		"profile", "aps-decision-ref-v1",
		"action_ref", rcItem(approval, "action_ref"),
		"authority_state_ref", rcTagRef("APS-DECISION-AUTHORITY-V1", rcItem(decision, "authority_state")),
		"policy_ref", rcTagRef("APS-DECISION-POLICY-V1", rcItem(decision, "policy_input")),
		"context_ref", rcTagRef("APS-DECISION-CONTEXT-V1", rcItem(decision, "decision_context")),
		"decision_output_ref", rcTagRef("APS-DECISION-OUTPUT-V1", rcItem(decision, "decision_output")),
	)
	j.needR(rcEqStr(rcGet(approval, "decision_ref"), rcTagRef("APS-DECISION-REF-V1", components)) &&
		bytes.Equal(rcJCS(rcItem(decision, "decision_output")), rcJCS(rcGet(approval, "result"))), "DECISION_NOT_BOUND")
	j.needR(rcEq(rcGet(approval, "prev"), rcItem(intent, "receipt_id")), "APPROVAL_PREV")
	j.needR(rcEq(rcItem(approval, "action_ref"), rcGet(intent, "action_ref")) &&
		rcEq(rcGet(approval, "subject_agent"), rcGet(intent, "subject_agent")), "APPROVAL_INTENT_ACTION")
	j.needR(rcLessEq(rcStr(rcItem(intent, "issued_at")), rcStr(rcItem(approval, "issued_at"))), "APPROVAL_BEFORE_INTENT")
}

func (j *rcJudge) apsDecision(trust, approval any, consumedAt string) {
	result := rcItem(approval, "result")
	ro, isObj := result.(*rcObj)
	j.needR(isObj && rcEqStr(ro.get("verdict"), "permit"), "VERDICT_NOT_PERMIT")
	j.needR(rcEq(rcGet(result, "constraints"), []any{}), "DECISION_CONSTRAINTS")
	j.needR(rcLessEq(rcItem(approval, "issued_at"), consumedAt), "APPROVAL_AFTER_CONSUMPTION")
	j.needR(rcLess(consumedAt, rcStr(rcGet(result, "valid_until"))), "DECISION_EXPIRED_AT_CONSUMPTION")
	for _, sig := range rcIter(rcItem(approval, "signatures")) {
		for _, key := range rcIter(rcItem(trust, "keys")) {
			signer, keyID := rcItem(key, "signer"), rcItem(key, "key_id")
			sigSigner, sigKeyID := rcItem(sig, "signer"), rcItem(sig, "key_id")
			if rcEq(signer, sigSigner) && rcEq(keyID, sigKeyID) {
				revoked := rcItem(key, "revoked_at")
				j.needR(revoked == nil || rcLess(consumedAt, revoked), "APPROVAL_SIGNER_REVOKED_AT_CONSUMPTION")
			}
		}
	}
}

func (j *rcJudge) apsAction(action, approval any) string {
	ao, isObj := action.(*rcObj)
	j.needR(isObj && rcEqStr(ao.get("profile"), "aps-action-ref-v2") && rcEqStr(ao.get("action_type"), "refund") &&
		rcEq(ao.get("scope_required"), []any{"payments:refund"}) && rcEqStr(ao.get("agent_id"), rcWorker), "ACTION_INPUT")
	target, isStr := rcGet(action, "target").(string)
	j.needR(isStr && strings.HasPrefix(target, rcPrefix) && strings.HasSuffix(target, rcSuffix), "TARGET")
	if !isStr {
		rcRaise("TypeError", "target is not subscriptable")
	}
	// The prefix and suffix are ASCII, so their lengths in bytes are their lengths
	// in characters; a target the two overlap in slices to the empty string.
	start, stop := len(rcPrefix), len(target)-len(rcSuffix)
	targetID := ""
	if stop > start && stop <= len(target) {
		targetID = target[start:stop]
	}
	j.needR(rcEqStr(rcItem(approval, "action_ref"), rcTagRef("APS-ACTION-REF-V2", action)), "ACTION_REF")
	return targetID
}

func (j *rcJudge) apsPayload(action, payload any, targetID string) {
	j.needR(rcRefundArgsOK(payload), "PAYLOAD_SCHEMA")
	j.needR(rcEqStr(rcGet(action, "payload_ref"), rcTagRef("APS-ACTION-PAYLOAD-V1", payload)), "PAYLOAD_REF")
	j.needR(rcEqStr(rcItem(payload, "payment_id"), targetID), "TARGET_PAYMENT_ID")
}

func (j *rcJudge) apsMerchant(decision any) any {
	var merchant any
	if policy, ok := rcItem(decision, "policy_input").(*rcObj); ok {
		merchant = policy.get("merchant_decision")
	}
	mo, isObj := merchant.(*rcObj)
	j.needR(isObj && rcASCIIID(mo.get("decision_id")), "DECISION_ID")
	return merchant
}

func (j *rcJudge) apsPIC(c *rcCase, merchant, approval, payload any, consumedAt string) {
	j.needR(rcEq(c.claim.item("decision_id"), rcItem(merchant, "decision_id")), "PIC_DECISION_ID")
	j.needR(rcEq(c.claim.item("approval_ref"), rcItem(approval, "receipt_id")), "PIC_APPROVAL_REF")
	j.needR(rcLess(consumedAt, c.expiry()), "PIC_EXPIRED_AT_CONSUMPTION")
	j.needR(bytes.Equal(rcJCS(c.picArgs), rcJCS(payload)), "PIC_ARGS_NOT_PAYLOAD")
}

// expiry is the attestation's expiry in the millisecond spelling the native
// windows use.
func (c *rcCase) expiry() string {
	text, ok := c.attestation.item("expires_at").(string)
	if !ok {
		rcRaise("AttributeError", "expires_at has no replace")
	}
	return strings.ReplaceAll(text, "Z", ".000Z")
}

// rcBound is one native time window of the approval, as written.
type rcBound struct{ low, high any }

// nativeBounds is native_bounds.
func (c *rcCase) nativeBounds() []rcBound {
	approval := c.p("inputs/aps-approval.json")
	expires := c.expiry()
	issued := rcItem(approval, "issued_at")
	return []rcBound{
		{issued, rcItem(rcItem(approval, "result"), "valid_until")},
		{issued, expires},
	}
}
