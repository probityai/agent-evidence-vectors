package corpusreaders

import (
	"net/url"
	"reflect"
	"strings"
)

func init() { register(x402EvidenceJoin()) }

// x4Eq compares two decoded JSON values as the Python reader's == does.
func x4Eq(a, b any) bool { return reflect.DeepEqual(a, b) }

func x4Differs(r any, a, b string) bool { return !x4Eq(rlGet(r, a), rlGet(r, b)) }

// x4Host is the lower-cased host of a URL, as urllib.parse.urlsplit reports it.
func x4Host(v any) string {
	u, err := url.Parse(rlStr(v))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func x4HasKey(keys any, key any) bool {
	for _, k := range rlList(keys) {
		if x4Eq(k, key) {
			return true
		}
	}
	return false
}

func x4NoLedger(r any) bool { return rlGet(r, "settlement.ledger") == nil }

// x402EvidenceJoin judges corpora/vectors-x402-evidence-join/: one x402 evidence
// package, refused when the evidence present contradicts the offer-to-settlement
// join (seller key, offer digest, payment construction, settlement, delivery or
// fulfilment) and indeterminate when the evidence needed to establish the join is
// absent. The rules and their order are those of
// packaging/agent_evidence_vectors/x402join.py.
func x402EvidenceJoin() ruleCorpus {
	return ruleCorpus{suite: "x402-evidence-join/v1", accept: "join_holds", rules: []rlRule{
		{"seller_key_not_domain_bound", func(r any) bool {
			keys := rlGet(r, "seller.key_ids")
			domain := rlStr(rlGet(r, "seller.domain"))
			return !x4HasKey(keys, rlGet(r, "offer.signature.key_id")) ||
				!x4HasKey(keys, rlGet(r, "receipt.key_id")) ||
				domain == "" || domain != x4Host(rlGet(r, "offer.resource.url"))
		}},
		{"offer_digest_mismatch", func(r any) bool {
			covered := map[string]any{"accepted": rlGet(r, "offer.accepted"), "resource": rlGet(r, "offer.resource")}
			digest := rlStr(rlGet(r, "offer.digest"))
			return digest == "" || digest != rlDigest(covered) ||
				rlStr(rlGet(r, "offer.signature.value_sha256")) != sha([]byte(digest))
		}},
		{"payment_not_for_offer", func(r any) bool { return x4Differs(r, "payment.offer_digest", "offer.digest") }},
		{"payer_not_authorization_signer", func(r any) bool {
			return rlStr(rlGet(r, "payment.authorization.from")) == "" ||
				x4Differs(r, "payment.signature.signer", "payment.authorization.from") ||
				x4Differs(r, "settlement.facilitator.payer", "payment.authorization.from")
		}},
		{"payee_not_offer_payee", func(r any) bool { return x4Differs(r, "payment.authorization.to", "offer.accepted.payTo") }},
		{"amount_not_offer_amount", func(r any) bool {
			return x4Differs(r, "payment.authorization.value", "offer.accepted.amount")
		}},
		{"receipt_names_other_offer", func(r any) bool {
			return rlGet(r, "receipt.offer_digest") != nil && x4Differs(r, "receipt.offer_digest", "offer.digest")
		}},
		{"receipt_offer_unbound", func(r any) bool { return rlGet(r, "receipt.offer_digest") == nil }},
		{"settlement_reference_missing", func(r any) bool {
			return rlStr(rlGet(r, "receipt.transaction")) == "" && x4NoLedger(r)
		}},
		{"settlement_conflict", func(r any) bool {
			if rlStr(rlGet(r, "receipt.transaction")) != "" && x4Differs(r, "receipt.transaction", "settlement.facilitator.transaction") {
				return true
			}
			if x4NoLedger(r) {
				return false
			}
			return (rlTrue(rlGet(r, "settlement.facilitator.success")) && rlGet(r, "settlement.ledger.status") != "success") ||
				x4Differs(r, "settlement.ledger.transaction", "settlement.facilitator.transaction")
		}},
		{"ledger_transfer_not_offer_terms", func(r any) bool {
			if x4NoLedger(r) {
				return false
			}
			return x4Differs(r, "settlement.ledger.network", "offer.accepted.network") ||
				x4Differs(r, "settlement.ledger.asset", "offer.accepted.asset") ||
				x4Differs(r, "settlement.ledger.to", "offer.accepted.payTo") ||
				x4Differs(r, "settlement.ledger.value", "offer.accepted.amount") ||
				x4Differs(r, "settlement.ledger.from", "payment.authorization.from")
		}},
		{"settlement_asserted_by_facilitator_only", x4NoLedger},
		{"delivery_digest_mismatch", func(r any) bool {
			declared := rlGet(r, "delivery.body_sha256")
			return rlStr(declared) != sha([]byte(rlStr(rlGet(r, "delivery.body")))) ||
				!x4Eq(rlGet(r, "receipt.delivery_digest"), declared)
		}},
		{"fulfilment_not_met", func(r any) bool {
			if !rlTrue(rlGet(r, "fulfilment.evaluated")) {
				return false
			}
			return !gfHex64.MatchString(rlStr(rlGet(r, "fulfilment.criteria_digest"))) ||
				rlGet(r, "fulfilment.outcome") != "met"
		}},
	}, indeterminate: map[string]bool{
		"receipt_offer_unbound":                   true,
		"settlement_reference_missing":            true,
		"settlement_asserted_by_facilitator_only": true,
	}}
}
