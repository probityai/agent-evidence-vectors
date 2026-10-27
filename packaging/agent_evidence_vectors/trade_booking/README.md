# One FX trade booking after a lost reply, seven claims judged apart

This corpus freezes one synthetic FX trade booking: a client, a quote, a booking reference
and a booking system. An agent books the trade, and then the reply is lost, the liquidity
provider rejects the trade, or an operations desk reverses the booking by hand. The booking
system, the liquidity provider and the agent system each leave signed statements, and the
reader judges seven claims about the one booking, each apart from the others.

A lost reply stays unresolved by default; only a counted booking_system record by booking
reference, or a reconciliation_close absent record, settles it. The agent system's own
ledger never establishes what the booking system holds.

## Claims

| Axis | ESTABLISHED means | It does not mean |
| --- | --- | --- |
| `booking_committed` | A counted booking-system acknowledgement, or a counted record showing the booking booked or cancelled, names this booking. | That the trade was filled. Contradicted when a counted record of the reconciliation close shows the booking absent while a counted acknowledgement, a counted record or a ledger with no timeout says it exists. |
| `cancel_confirmed` | A counted booking-system record shows the booking cancelled with a cancel event, or a counted cancel reply is confirmed or already cancelled and names an event. | That the agent's own claim of a cancel is true. A ledger that claims a confirmed cancel while the latest counted record shows booked is contradicted. |
| `single_compensation` | Exactly one distinct cancel event is counted on the booking, whether operations or the agent system authored it. | That the cancel was the right action. Two or more events are contradicted. |
| `release_backed` | The ledger released capacity, and either one confirmed cancel with exactly one event stands behind it, or a counted record of the reconciliation close shows the booking absent. | That the limit copy is right. Capacity still held is not established. A release at a timeout, at a search miss, after an unconfirmed cancel or after duplicate compensation is contradicted. |
| `one_live_booking_per_quote` | A counted booking-system statement shows the booking (a duplicate rejection counts) and no counted statement shows a second live booking of the quote under another reference. | That the booking is correct. A second live reference is contradicted. |
| `limit_copy_matches` | The agent's copy of the limit used equals the counted booking-system usage, which includes every live or unresolved deal. | That the limit is sufficient. No counted usage is not established. |
| `resolved` | The booking is in the state the trade intends, in one of three ways: no timeout, a counted record shows it booked, and a counted liquidity provider result says it filled; or a counted record of the reconciliation close shows it absent; or it was booked and compensated exactly once. | That a booked record with no timeout is enough: when the liquidity provider rejected the trade, or says nothing, that way does not apply, so a rejected trade whose cancel failed stays open for operations. A ledger claiming a cancel the record does not show, or compensation more than once, is contradicted. |

The lost-reply rule above applies to `booking_committed`, `release_backed` and `resolved`
together: a timeout, a lost acknowledgement or a search by reference that finds nothing
settles none of them.

## Statement kinds

Each statement is signed by exactly one role. It counts only if its signature verifies under
a key the trust inputs name for that role. A statement signed by an unknown key, or by a key
trusted for another role, does not count. A statement that names another booking reference
or another client says nothing about this booking and is set aside. A statement that would
count except that its signature fails makes the axis it feeds contradicted.

| Statement | Signed by | Carries | A broken signature contradicts |
| --- | --- | --- | --- |
| `booking_ack` | booking system | binding, trade id | `booking_committed` |
| `booking_record` | booking system | binding, status (booked, cancelled or absent), scope (`search_by_ref` or `reconciliation_close`), cancel events with their actor, observed time | `booking_committed` |
| `cancel_reply` | booking system | binding, outcome (confirmed, already cancelled or error), optional event id | `cancel_confirmed` |
| `duplicate_rejection` | booking system | binding, reason | `one_live_booking_per_quote` |
| `limit_usage` | booking system | client, used, limit | `limit_copy_matches` |
| `other_quote_records` | booking system | quote id, reference and status of each other booking of the quote | `one_live_booking_per_quote` |
| `lp_result` | liquidity provider | binding, outcome (rejected or filled) | `resolved` |
| `ledger` | agent system | binding, timed out, capacity released, claims cancel confirmed, limit copy used | `release_backed` |

The latest counted record by observed time is the current record. Cancel events are counted
once by event id across every counted record and cancel reply.

## Relation to the lost-call cases

The [occurrence-binding corpus](../occurrence_binding/README.md) settles a lost paid call as
not run only on the responder's signed statement naming that occurrence, and its controls
`lost_call_no_statement` and `lost_call_settled_not_run` show a bare missing reply staying
unresolved and a signed statement settling it. This corpus asks the same question of a
booking that may have run: the lost reply stays unresolved until the booking system's own
record by reference, or its record of the reconciliation close, says what it holds, and
the compensation that follows is counted event by event.

## The frozen inputs

| File | Holds |
| --- | --- |
| `corpus/occurrence.json` | The booking: booking system, client `CLIENT-A`, pair, notional, quote `Q-1` and reference `R1`, with the limit and the amount used before the deal, and the verifier command. |
| `corpus/trust.json` | The trust inputs: each key and the role it is trusted for. TEST keys from the published recipe `sha256("aev-trade-booking-test-key/<role>/v1")`, for the roles `booking_system`, `liquidity_provider` and `agent_system`. |
| `corpus/cases.json` | Each case's signed statements and its expected answer per axis. |
| `corpus/manifest.json` | The sha256 of every other member. The runner refuses a corpus whose members differ. |

The binding is `sha256` over the RFC 8785 bytes of
`{"booking_ref", "booking_system", "client", "quote_id"}`. A signature is Ed25519 over the
RFC 8785 bytes of the statement. All data is synthetic.

## Run it

```sh
python -m pip install agent-evidence-vectors==VERSION
agent-evidence-vectors-trade-booking --output trade-booking-result
```

The command checks every corpus member against `corpus/manifest.json`, judges all cases
without reading their expected answers, writes `report.json`, and exits 1 if any case
differs. From a checkout, run `python -m agent_evidence_vectors.trade_booking.run` inside
`packaging/` with `--implementation-revision "$(git rev-parse HEAD)"`.

## Cases

Built by `scripts/trade-booking-build.py`; CI checks that the committed files are what it
writes. Every axis has `ESTABLISHED`, `CONTRADICTED` and `NOT_ESTABLISHED` answers in the
corpus.

- Control: `control_normal_success`.
- Variant 1, the booking reply is lost: `v1_lost_ack_found_by_search_cancelled_once`,
  `v1_late_booking_held_until_reconciliation_cancelled_once`,
  `v1_search_absent_reconciliation_closes_never_booked`,
  `v1_late_booking_released_at_search_not_found`,
  `v1_lost_ack_released_on_timeout_no_evidence`, `v1_resend_same_reference_rejected`,
  `v1_resend_new_reference_duplicate_booking`,
  `v1_unresolved_deal_dropped_from_limit_copy` and `v1_cancel_claimed_by_agent_only`.
- Variant 2, the liquidity provider rejects after the booking exists:
  `v2_lp_reject_cancel_confirmed_once`, `v2_lp_reject_cancel_error_held_for_operations`,
  `v2_lp_reject_cancel_retried_two_events` and
  `v2_lp_reject_cancel_unconfirmed_released_anyway`.
- Variant 3, operations reverse the booking: `v3_ops_reversed_first_agent_skips_cancel`,
  `v3_ops_reversed_then_agent_cancel_accepted_two_events` and
  `v3_agent_cancel_rejected_already_cancelled`.
- Reconciliation break, the agent system holds a deal the booking system lacks:
  `break_agent_booked_booking_system_absent`.
- Trust controls: `booking_record_signed_by_agent`, `booking_record_names_other_reference`
  and `cancel_reply_signature_broken`.

A producer can test its own records by mapping its acknowledgement, record, cancel reply,
limit usage and ledger onto the statement shapes above, and its keys onto `trust.json`.
