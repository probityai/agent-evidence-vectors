---
title: "Did the agent's approved purchase become the charged, ordered and delivered one?"
subtitle: "An operator-side check from shopper approval to payment, order and effect"
description: "What an authority-to-effect assessment of an agent checkout records per case, which parts are public and which stay with the operator."
toc: false
---

A shopper approves a basket in an AI assistant. The merchant's checkout takes
the order, a payment provider authorizes and captures an amount, and a warehouse
ships it, or the order is cancelled and refunded. Each system keeps its own
record. Which of them shows that the effect matched the approval?

No single record does. An approval signature says what was approved. A payment
webhook says what was charged. An order record says what the merchant accepted,
and a fulfillment or refund record says what happened next. When an assistant,
a merchant checkout and a payment provider each own one of these, a disputed
order needs all four joined, case by case.

<a id="what-is-checked"></a>

## What an assessment checks

An authority-to-effect assessment runs one operator's real flow and asks, for
every case, whether each step carried the approved state unchanged:

| Assertion | Compared records |
|----|----|
| The approval is authentic | approval or mandate bytes against the key the operator selected beforehand |
| The charged state is the approved state | items, quantities, prices, promotions, currency and merchant at approval against the authorized and captured amount |
| The order is the charged state | the provider's signed charge record against the merchant's order record |
| The effect is the order | fulfillment, cancellation or refund observation against the order and its cutoff |
| There is one effect | no second charge, order or refund for one approval |

Each assertion ends **established**, **contradicted** or **not established**,
with a pointer to the bytes behind it. A missing webhook or an unobserved
shipment is not established, never a pass. The assessment also records whether
the operator's existing control, chosen before the run, caught each break.

<a id="what-each-case-records"></a>

## What each case records

The operator, the surface and the rail; the approval bytes; the exact checkout
state at approval; the payer as an identity class and a tokenized instrument
class; the price the provider actually captured; the provider's signed record;
the order record; and the later effect with its time. Cases include a basket or
price changed after approval, a substituted merchant or amount, a duplicate
completion, a response lost after the merchant committed, a missing or
reordered webhook, a payment that disagrees with the order, a settlement with
no delivery, a refund against a state the shopper never approved, and two
purchases that each pass a shared budget together.

<a id="public-and-private"></a>

## What is public and what stays with the operator

The method is public and runnable today: the
[refund-handoff conformance profile](https://github.com/probityai/agent-evidence-observer/blob/38e75b16a967fb01048ef93ed4e12290c8f3a540/docs/reference/REFUND-HANDOFF-CONFORMANCE.md)
in Observer, the [authority and effect controls](authority-effect-cases.html)
and the [request and effect join cases](request-effect-join.html). Any project
can run them in its own CI.

An operator's credentials, records, connectors, control comparison and findings
stay with that operator. None of them enters this repository, a Lab result or a
paper. Cases added to the public set after such work are written from scratch
and synthetic.

Bring a reader or a retained synthetic run to the
[Lab thread](https://github.com/probityai/agent-evidence-vectors/issues/352).
An operator that wants its own flow checked can ask there; the conversation
about its records continues privately.
