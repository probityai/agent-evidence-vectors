package corpora

func init() { register(paymentMandate()) }

// paymentMandate judges vectors-agent-payment-mandate/: a dispute evidence pack
// for an agent-initiated payment, refused when the mandate is unsigned or its
// digest does not cover its terms, when the credential is not bound to it, when
// the charge leaves it in time, amount, currency, merchant or token, when a
// single-use token is replayed, when the receipt does not bind the execution, or
// when a required post-checkout action is not recorded. The rules and their
// order are those of packaging/agent_evidence_vectors/paymentmandate.py.
func paymentMandate() ruleCorpus {
	return ruleCorpus{suite: "agent-payment-mandate/v1", accept: "mandate_chain_holds", rules: []rlRule{
		{"mandate_unsigned", func(r any) bool {
			sig := rlMap(rlGet(r, "mandate.signature"))
			return sig == nil || rlStr(sig["key_id"]) == "" || !gfHex64.MatchString(rlStr(sig["value_sha256"]))
		}},
		{"mandate_digest_mismatch", func(r any) bool {
			return rlStr(rlGet(r, "mandate.digest")) != rlDigest(rlGet(r, "mandate.terms"))
		}},
		{"credential_not_bound_to_mandate", func(r any) bool {
			return rlGet(r, "credential.mandate_digest") != rlGet(r, "mandate.digest")
		}},
		{"mandate_expired", func(r any) bool {
			return rlStr(rlGet(r, "execution.executed_at")) > rlStr(rlGet(r, "mandate.terms.expires_at"))
		}},
		{"amount_over_limit", func(r any) bool {
			return rlInt(rlGet(r, "execution.amount_minor")) > rlInt(rlGet(r, "mandate.terms.max_amount_minor"))
		}},
		{"currency_mismatch", func(r any) bool {
			return rlGet(r, "execution.currency") != rlGet(r, "mandate.terms.currency")
		}},
		{"merchant_mismatch", func(r any) bool {
			return rlGet(r, "execution.merchant") != rlGet(r, "mandate.terms.merchant")
		}},
		{"token_not_the_executed_token", func(r any) bool {
			return rlGet(r, "execution.token_id") != rlGet(r, "credential.token_id")
		}},
		{"single_use_token_replayed", func(r any) bool {
			consumed := rlStringSet(rlGet(r, "credential.consumed_token_ids"))
			return rlTrue(rlGet(r, "credential.single_use")) && consumed[rlStr(rlGet(r, "execution.token_id"))]
		}},
		{"receipt_not_bound_to_execution", func(r any) bool {
			return rlGet(r, "receipt.mandate_digest") != rlGet(r, "mandate.digest") ||
				rlStr(rlGet(r, "receipt.execution_digest")) != rlDigest(rlGet(r, "execution"))
		}},
		{"post_checkout_action_missing", func(r any) bool {
			return !rlSubset(rlStringSet(rlGet(r, "post_checkout.required")), rlStringSet(rlGet(r, "post_checkout.recorded")))
		}},
	}}
}
