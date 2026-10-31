# Raw admission and Go JCS

Go 1.25.5 and 1.27.1 each ran 1,263 public conformance cases: 1,077 exact byte matches, 181 raw refusals and five scalar-root refusals. The reports keep all 1,263 bare Go outcomes alongside the consumer results.

The adapter admits original bytes before the pinned Go writer runs, then requires exact canonical-byte agreement. RFC 8785 and opt-in I-JSON keep distinct numeric and string policies. Go already detects duplicate names; malformed UTF-8 and surrogate pairing show why its documented input assumptions need a raw gate.

Six original CI archives preserve every member: two final-PR, two branch-push and two merged-main executions. They repeat the same 1,263 case identities on two runtimes. Source pins, runtime evidence and profile outcomes stay separate.

```sh
python3 experiments/go-jcs-2026-10-04/validate_capsule.py
```

[Source contract](https://github.com/probityai/jcs-admit/blob/7573937b882de4f32cbc4cd69dfaab8098729412/interop/go-jcs/README.md), [reports](report.json), [provenance](provenance.json) and [source pins](source-pins.json).
