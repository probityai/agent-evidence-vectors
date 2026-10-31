# ADK response-routing replay

The selected SDK is Google ADK `86a47f6974bae349a5c9ea15a74a4b450614ae42`.
Observer implementation `de522aa60966309599d03b06d02f50a52d7fb58f` retains three
three-turn cases: confirmation granted, confirmation denied and a host-completed
long-running tool. The supplied response reaches its issuing agent and call;
later plain text returns to the root. Raw events, sessions, requests and callback
snapshots are retained with signed Observer file history. Observed writes are
1/0/1; the LRO write belongs to the same host operator, separately from its
native start-only tool body.

Native run 37202968778 used Python 3.13.15. The installed framework-free routing
reader ran twice with identical decisions. All 19 semantic controls passed.
The actual Verify CLI at `e835ce2bd6a960e7a1cc2fa6522f16d55dce728a` ran six
`event_absence/v1` cases twice each with identical decisions and three boundary
controls. Its original implementation and 11 selected Python files are unchanged.
Coverage names the finite yielded event population delivered to the registered
plugin. Native timestamps are projected to Verify v1 whole seconds; the original
fractional timestamps remain in the raw captures. All execution, keys and custody
are author-operated PEER work.

## Originals

| attempt | native run | artifact | bytes | ZIP members | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| original reader failure | 37178588953 | 11293929868 | 2636306 | 850 | b6080fea3c0dcd50e9de2c9b853aedea673b007490cc47f550f0dda1dffb3f2a |
| label-boundary correction | 37202352798 | 11303905668 | 2640126 | 857 | ad66c11b615d0e020dedaecba7121a89bc0ce9225e5e877f6dd679cca5d216b7 |
| routing and actual Verify | 37202968778 | 11303836144 | 2742751 | 960 | c9f86ee644798ed44f902484d195ed05c94fb85b92b96ab897b61537fad46e9d |

The first attempt completed all three native cases. Its reader compared the
before-model callback directly with model-entry bytes; ADK adds the agent-name
label between those positions. The correction checks only that exact native
enrichment, retains both originals and refuses any other request change.

## Replay the passing packet

Verify the original ZIP digest before extraction. Pin the public implementation
for its reader dependency lock:

```sh
git clone https://github.com/probityai/agent-evidence-observer qualified-observer
git -C qualified-observer checkout de522aa60966309599d03b06d02f50a52d7fb58f
unzip original-artifact.zip -d retained
mkdir -p retained/packet/cases/approval-denied/workspace
python3.13 -m venv replay-env
replay-env/bin/python -m pip install --no-compile --require-hashes \
  -r qualified-observer/interop/adk-user-responses-2026-10-04/requirements-reader.lock
replay-env/bin/python -m pip install --no-compile --no-deps \
  retained/wheels/agent_evidence_observer-0.0.1-py3-none-any.whl \
  retained/wheels/probity_adk_user_responses-0.0.1-py3-none-any.whl \
  retained/verify-consumer/probity_verify-0.1.0-py3-none-any.whl
packet="$(pwd)/retained/packet"
policy="$(pwd)/retained/host-policy.json"
for attempt in 1 2; do
  replay-env/bin/python -I -B -c \
    'from probity_adk_responses.reader import main; raise SystemExit(main())' \
    "$packet" --policy "$policy" \
    --policy-sha256 165b16a66c8af5cd919a28877d8b50b23e1a8227359adf19cb7cfa59b276e8a0 \
    --output "$(pwd)/replay-decision-$attempt.json" > "replay-decision-$attempt.stdout"
done
cmp replay-decision-1.json replay-decision-2.json
cmp replay-decision-1.json retained/decision-1.json
for directory in retained/verify-consumer/cases/*/*; do
  for attempt in 1 2; do
    replay-env/bin/python -I -B -c \
      'from probity_verify.cli import main; raise SystemExit(main())' \
      "$directory/case.json" --policy "$directory/policy.json" --json \
      > "$directory/replayed-$attempt.stdout"
  done
  cmp "$directory/replayed-1.stdout" "$directory/replayed-2.stdout"
  cmp "$directory/replayed-1.stdout" "$directory/verify-1.stdout"
done
```

Actions ZIPs omit empty directories. The `mkdir` restores the originally empty
denied-workspace directory and adds no file bytes. The recorded denied tool body
and signed write history remain empty. Replaying the packet performs no native
tools or target writes. The profile workflow is the runnable source for a new
native execution and all controls.

The older 16-row comparison retains its original pins and definitions. The
prospective eight-task implementation-owned study remains not started.

The separate [merged-main original](main-artifact.zip) repeats the same three
cases at Observer `7eb1875`, run 37204220648. Its host-policy digest is
`f51e3a0249dae35fcb157bc846dcdc0f0014eb2c46cb83e499e6bc33d49844d4`.
Use that digest when replaying the main original. The [report](report.json) and
[provenance](provenance.json) keep all four attempts and both passing runs distinct.

```sh
python3 experiments/google-adk-responses-2026-10-04/validate_capsule.py
```
