# Reserve cost before a tool call

`probity-spend-reservation` gives a host one SQLite budget shared by its local
processes. Reserve the maximum cost, claim that exact call once, then invoke
the bounded tool. Apply the host's receipt afterward. Changed arguments,
targets and attempts keep their own bindings.

```sh
python -m pip install ./consumers/spend-reservation
probity-spend-budget reserve --database budget.sqlite \
  --policy policy.json --prices prices.json --call call.json
```

The Python API exposes `Budget.reserve`, `dispatch`, `settle`, `cancel` and
`trace`. `dispatch` claims the reservation; the host invokes the tool afterward.
The host owns the prices, clock, database and cost bounds. Rates and quantities
are bounded integers in one declared unit. Select the exact price-table hash
and each route's price hash; unknown, changed and expired prices refuse calls.

For a route, maximum cost is `input_limit * input_rate + output_limit *
output_rate + fixed_cost`. Concurrent reservations include every unsettled
maximum. Settlement frees the unused amount. Cancellation frees only an
undispatched reservation. An interrupted dispatched call keeps its maximum;
a receipt above the bound records the liability and freezes further admission.
Retries need a new attempt; changing arguments does not reset the budget.

## Run the local qualification

The [workflow](../../../../.github/workflows/package-admission.yml) installs the API
and pinned Observer, checks their source bytes before import, and retains the
original outputs. Twenty controls include two actual processes racing for one
budget. Seven local scenarios bind reserve, dispatch, settle and refund records
to Observer checkpoints and signed file effects. A checkpoint precedes each
protected write. Policy, prices and trace remain separate pinned inputs. The actual installed
[Verify adapter](https://github.com/probityai/probity-verify/tree/03e77cfa88905bdb2a95ee355b0d90b1aacc1808)
replays all seven captured journals twice. Seven repinned mutations check
unaffordable reservations, changed calls and prices, reordered events, missing
refunds and missing consumer pins. A correct refusal supports the budget record;
it gives the refused call no permission. Missing receipts keep their full cost
held, while execution outcomes remain unestablished by this budget reader.

The motivating [S005 study](https://github.com/piiiico/agent-errata/blob/e9a247004c84aa505e8df0dbfc5fbbdae5924298/studies/S005.md)
used a local stand-in API and synthetic costs. Our corresponding vector reserves
3.015 million synthetic micro-units against a one-million limit and refuses
before execution. The other cases price bytes in a bounded local file tool.
These author-operated fixtures use PEER keys and synthetic prices. A real host
must enforce the input/output bounds at its own tool boundary and reconcile its
own receipts; monetary billing and outside custody have separate evidence.
