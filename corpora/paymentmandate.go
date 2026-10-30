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
	return ruleCorpus{suite: "agent-payment-mandate/v1", accept: "mandate_chain_holds", rules: []rcRule{
		{"mandate_unsigned", func(r any) bool {
			sig := rcMap(rcGet(r, "mandate.signature"))
			return sig == nil || rcStr(sig["key_id"]) == "" || !gfHex64.MatchString(rcStr(sig["value_sha256"]))
		}},
		{"mandate_digest_mismatch", func(r any) bool {
			return rcStr(rcGet(r, "mandate.digest")) != rcDigest(rcGet(r, "mandate.terms"))
		}},
		{"credential_not_bound_to_mandate", func(r any) bool {
			return rcGet(r, "credential.mandate_digest") != rcGet(r, "mandate.digest")
		}},
		{"mandate_expired", func(r any) bool {
			return rcStr(rcGet(r, "execution.executed_at")) > rcStr(rcGet(r, "mandate.terms.expires_at"))
		}},
		{"amount_over_limit", func(r any) bool {
			return rcInt(rcGet(r, "execution.amount_minor")) > rcInt(rcGet(r, "mandate.terms.max_amount_minor"))
		}},
		{"currency_mismatch", func(r any) bool {
			return rcGet(r, "execution.currency") != rcGet(r, "mandate.terms.currency")
		}},
		{"merchant_mismatch", func(r any) bool {
			return rcGet(r, "execution.merchant") != rcGet(r, "mandate.terms.merchant")
		}},
		{"token_not_the_executed_token", func(r any) bool {
			return rcGet(r, "execution.token_id") != rcGet(r, "credential.token_id")
		}},
		{"single_use_token_replayed", func(r any) bool {
			consumed := rcStringSet(rcGet(r, "credential.consumed_token_ids"))
			return rcTrue(rcGet(r, "credential.single_use")) && consumed[rcStr(rcGet(r, "execution.token_id"))]
		}},
		{"receipt_not_bound_to_execution", func(r any) bool {
			return rcGet(r, "receipt.mandate_digest") != rcGet(r, "mandate.digest") ||
				rcStr(rcGet(r, "receipt.execution_digest")) != rcDigest(rcGet(r, "execution"))
		}},
		{"post_checkout_action_missing", func(r any) bool {
			return !rcSubset(rcStringSet(rcGet(r, "post_checkout.required")), rcStringSet(rcGet(r, "post_checkout.recorded")))
		}},
	}}
}
