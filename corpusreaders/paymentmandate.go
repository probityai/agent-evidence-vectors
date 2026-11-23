package corpusreaders

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"regexp"
	"strings"
	"time"
)

func init() { register(paymentMandate()) }

// paymentMandate judges corpora/vectors-agent-payment-mandate/: a dispute evidence pack
// for an agent-initiated payment, refused when the mandate is unsigned or its
// digest does not cover its terms, when the credential is not bound to it, when
// the charge leaves it in time, amount, currency, merchant or token, when a
// single-use token is replayed, when the receipt does not bind the execution, or
// when a required post-checkout action is not recorded. The rules and their
// order are those of packaging/agent_evidence_vectors/paymentmandate.py. An x402
// record carries the facilitator request in x402 v2 field names; its signer is
// recovered from the EIP-712 signature (evmsig.go), never read from a field.
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
		{"mandate_expired", pmProfile(func(r any) bool {
			return rlStr(rlGet(r, "execution.executed_at")) > rlStr(rlGet(r, "mandate.terms.expires_at"))
		}, func(r any) bool {
			settled, ok := pmWhole(rlGet(r, "execution.block_timestamp"))
			expiry, err := time.Parse(time.RFC3339, rlStr(rlGet(r, "mandate.terms.expires_at")))
			return !ok || err != nil || settled > expiry.Unix()
		})},
		{"amount_over_limit", pmProfile(func(r any) bool {
			return rlInt(rlGet(r, "execution.amount_minor")) > rlInt(rlGet(r, "mandate.terms.max_amount_minor"))
		}, func(r any) bool {
			value := pmDecimal(pmX(r, "paymentPayload.payload.authorization.value"))
			ceiling, ok := pmWhole(rlGet(r, "mandate.terms.max_amount_minor"))
			return value == nil || !ok || value.Cmp(big.NewInt(ceiling)) > 0
		})},
		{"currency_mismatch", pmProfile(func(r any) bool {
			return rlGet(r, "execution.currency") != rlGet(r, "mandate.terms.currency")
		}, func(r any) bool {
			required := pmX(r, "paymentRequirements.asset")
			return !(pmSameAddress(pmX(r, "paymentPayload.accepted.asset"), required) &&
				pmSameAddress(required, rlGet(r, "mandate.terms.currency")))
		})},
		{"merchant_mismatch", pmProfile(func(r any) bool {
			return rlGet(r, "execution.merchant") != rlGet(r, "mandate.terms.merchant")
		}, func(r any) bool {
			payTo := pmX(r, "paymentRequirements.payTo")
			return !(pmSameAddress(pmX(r, "paymentPayload.payload.authorization.to"), payTo) &&
				pmSameAddress(pmX(r, "paymentPayload.accepted.payTo"), payTo) &&
				pmSameAddress(payTo, rlGet(r, "mandate.terms.merchant")))
		})},
		{"network_mismatch", pmX402Only(func(r any) bool {
			required, ok := pmX(r, "paymentRequirements.network").(string)
			return !ok || rlStr(pmX(r, "paymentPayload.accepted.network")) != required ||
				rlStr(rlGet(r, "mandate.terms.network")) != required
		})},
		{"amount_not_offer_amount", pmX402Only(func(r any) bool {
			required := pmDecimal(pmX(r, "paymentRequirements.amount"))
			value := pmDecimal(pmX(r, "paymentPayload.payload.authorization.value"))
			accepted := pmDecimal(pmX(r, "paymentPayload.accepted.amount"))
			return required == nil || value == nil || accepted == nil ||
				value.Cmp(required) != 0 || accepted.Cmp(required) != 0
		})},
		{"authorization_outside_validity_window", pmX402Only(func(r any) bool {
			settled, ok := pmWhole(rlGet(r, "execution.block_timestamp"))
			after := pmDecimal(pmX(r, "paymentPayload.payload.authorization.validAfter"))
			before := pmDecimal(pmX(r, "paymentPayload.payload.authorization.validBefore"))
			if !ok || after == nil || before == nil {
				return true
			}
			t := big.NewInt(settled)
			return !(after.Cmp(t) < 0 && t.Cmp(before) < 0)
		})},
		{"signature_not_canonical", pmX402Only(func(r any) bool {
			sig, ok := pmSignature(r)
			return !ok || !evmLowS(sig)
		})},
		{"payer_not_authorization_signer", pmX402Only(func(r any) bool {
			signer, ok := pmSigner(r)
			return !ok || !pmSameAddress(signer, pmX(r, "paymentPayload.payload.authorization.from"))
		})},
		{"payer_not_mandated_agent", pmX402Only(func(r any) bool {
			return !pmSameAddress(pmX(r, "paymentPayload.payload.authorization.from"), rlGet(r, "mandate.terms.agent_payer"))
		})},
		{"token_not_the_executed_token", pmProfile(func(r any) bool {
			return rlGet(r, "execution.token_id") != rlGet(r, "credential.token_id")
		}, func(r any) bool {
			nonce := rlStr(pmX(r, "paymentPayload.payload.authorization.nonce"))
			used := rlStr(rlGet(r, "execution.authorization_used.nonce"))
			return !(pmSameAddress(rlGet(r, "execution.authorization_used.authorizer"),
				pmX(r, "paymentPayload.payload.authorization.from")) &&
				evmBytes32Re.MatchString(nonce) && strings.EqualFold(used, nonce))
		})},
		{"settlement_not_the_authorization", pmX402Only(func(r any) bool {
			auth := "paymentPayload.payload.authorization."
			value := pmDecimal(pmX(r, auth+"value"))
			moved := pmDecimal(rlGet(r, "execution.transfer.value"))
			return !(pmSameAddress(rlGet(r, "execution.transfer.from"), pmX(r, auth+"from")) &&
				pmSameAddress(rlGet(r, "execution.transfer.to"), pmX(r, auth+"to")) &&
				value != nil && moved != nil && value.Cmp(moved) == 0 &&
				pmSameAddress(rlGet(r, "execution.asset"), pmX(r, "paymentRequirements.asset")) &&
				rlStr(rlGet(r, "execution.network")) == rlStr(pmX(r, "paymentRequirements.network")))
		})},
		{"single_use_token_replayed", pmProfile(func(r any) bool {
			consumed := rlStringSet(rlGet(r, "credential.consumed_token_ids"))
			return rlTrue(rlGet(r, "credential.single_use")) && consumed[rlStr(rlGet(r, "execution.token_id"))]
		}, func(r any) bool {
			nonce := strings.ToLower(rlStr(pmX(r, "paymentPayload.payload.authorization.nonce")))
			for _, used := range rlList(rlGet(r, "execution.nonces_used_before")) {
				if strings.ToLower(rlStr(used)) == nonce {
					return true
				}
			}
			return false
		})},
		{"receipt_not_bound_to_execution", pmProfile(pmReceiptUnbound, func(r any) bool {
			response := rlMap(rlGet(r, "receipt.settlement_response"))
			if pmReceiptUnbound(r) || response == nil {
				return true
			}
			amount, hasAmount := response["amount"]
			amountOK := !hasAmount
			if hasAmount {
				a, b := pmDecimal(amount), pmDecimal(rlGet(r, "execution.transfer.value"))
				amountOK = a != nil && b != nil && a.Cmp(b) == 0
			}
			return !(rlTrue(response["success"]) &&
				rlStr(response["transaction"]) == rlStr(rlGet(r, "execution.transaction")) && rlStr(response["transaction"]) != "" &&
				rlStr(response["network"]) == rlStr(rlGet(r, "execution.network")) &&
				pmSameAddress(response["payer"], pmX(r, "paymentPayload.payload.authorization.from")) &&
				amountOK)
		})},
		{"post_checkout_action_missing", func(r any) bool {
			return !rlSubset(rlStringSet(rlGet(r, "post_checkout.required")), rlStringSet(rlGet(r, "post_checkout.recorded")))
		}},
		{"signing_key_unknown", func(r any) bool {
			_, entry, ok := pmSigningKey(r)
			return ok && entry == nil
		}},
		{"signing_key_not_yet_valid", func(r any) bool {
			signed, entry, ok := pmSigningKey(r)
			return ok && entry != nil && signed < rlStr(entry["valid_from"])
		}},
		{"signing_key_rotated_out", func(r any) bool {
			signed, entry, ok := pmSigningKey(r)
			return ok && entry != nil && entry["valid_until"] != nil && signed >= rlStr(entry["valid_until"])
		}},
		{"signing_key_revoked", func(r any) bool {
			signed, entry, ok := pmSigningKey(r)
			return ok && entry != nil && entry["revoked_effective_from"] != nil &&
				signed >= rlStr(entry["revoked_effective_from"])
		}},
	}}
}

// pmSigningKey returns the signing time and the key-history entry for the signing key.
// ok is false when the record states no signing time or carries no key history, so
// the key rules then make no statement.
func pmSigningKey(r any) (signed string, entry map[string]any, ok bool) {
	signed = rlStr(rlGet(r, "mandate.signature.signed_at"))
	keys, isList := rlGet(r, "key_history.keys").([]any)
	if signed == "" || !isList {
		return "", nil, false
	}
	keyID := rlStr(rlGet(r, "mandate.signature.key_id"))
	for _, k := range keys {
		if m := rlMap(k); m != nil && rlStr(m["key_id"]) == keyID {
			return signed, m, true
		}
	}
	return signed, nil, true
}

// pmX402Scheme names the records judged as x402 exact payments on EVM; the
// shared refusal codes take their x402 meaning on them, and the x402-only codes
// never fire on the card-side records.
const pmX402Scheme = "x402-exact-evm-eip3009"

func pmIsX402(r any) bool { return rlStr(rlGet(r, "scheme")) == pmX402Scheme }

func pmProfile(card, x402 func(any) bool) func(any) bool {
	return func(r any) bool {
		if pmIsX402(r) {
			return x402(r)
		}
		return card(r)
	}
}

func pmX402Only(x402 func(any) bool) func(any) bool {
	return pmProfile(func(any) bool { return false }, x402)
}

func pmX(r any, path string) any { return rlGet(r, "credential.facilitator_request."+path) }

func pmSameAddress(a, b any) bool {
	sa, ok1 := a.(string)
	sb, ok2 := b.(string)
	return ok1 && ok2 && evmAddressRe.MatchString(sa) && evmAddressRe.MatchString(sb) && strings.EqualFold(sa, sb)
}

func pmDecimal(v any) *big.Int {
	s, ok := v.(string)
	if !ok || !evmUintRe.MatchString(s) {
		return nil
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

func pmWhole(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

var pmSignatureRe = regexp.MustCompile(`^0x[0-9a-fA-F]{130}$`)

func pmSignature(r any) ([]byte, bool) {
	text := rlStr(pmX(r, "paymentPayload.payload.signature"))
	if !pmSignatureRe.MatchString(text) {
		return nil, false
	}
	sig, err := hex.DecodeString(text[2:])
	return sig, err == nil
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

func pmReceiptUnbound(r any) bool {
	return rlGet(r, "receipt.mandate_digest") != rlGet(r, "mandate.digest") ||
		rlStr(rlGet(r, "receipt.execution_digest")) != rlDigest(rlGet(r, "execution"))
}
