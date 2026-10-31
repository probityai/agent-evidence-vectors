# Literal decisions and an explicit requested-effect comparison

The [original Frequency fixture](https://github.com/altrudev/frequency-open-evidence-lab/tree/f5bc64d883564ac5cc6f23f96d346ed8ad6528ae)
retains its nine cases and three test groups. Its input decisions are supplied
assertions. Its `assess` function uses Python truthiness, so a nonempty string
such as `"false"` selects the authorized branch.

[Pico's dated Lab report](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529871573)
describes a cold replay operated by Pico AI under Håkon Åmdal. That disclosed
outside operation is separate from independently established signatures or
observations, and from host adoption or commercial use.

Probity's separate `probity.frequency-supplied-claims/v1` control accepts
immutable JSON bytes with exactly these fields:

| Field | Meaning |
| --- | --- |
| `profile` | The exact profile above. |
| `id` | A bounded nonempty identifier. |
| `authorized` | A literal Boolean declaration, never verified authorization. |
| `executionReported` | A literal Boolean completion-report declaration. |
| `requestedEffect` | The requested value as a bounded nonempty string. |
| `observation` | A supplied current string, or `null` for no observation. |

The three output labels are `suppliedDecision`, `completionReport` and
`requestedEffectComparison`. The latter is `MATCHES_REQUEST`,
`DIFFERS_FROM_REQUEST` or `NOT_ESTABLISHED`. It does not decide whether a refusal
preserved the right state. `requiredPostDecisionState` remains `NOT_SUPPLIED`.
For example, a refused request for `v1` can correctly leave `v0` unchanged;
the observation then differs from the request without showing an incorrect refusal.
This field meaning is explicit for our control. It does not claim agreement on
the original fixture's ambiguous `expected_effect` meaning.

The table covers all twelve decision/report/observation combinations, including
the three absent original cells. Sixteen additional inputs put strings,
integers, null, containers and a floating number in each Boolean field. They
must be refused. The installed API and isolated CLI retain the same comparison
results or explicit refusal, with complete stdout, stderr and exit codes.

```sh
.venv/bin/python -I -m authority_effect.cli frequency-controls --output frequency-controls
```

Expected answers are exposed reference labels. This author-operated control
does not add a signature, independently collected observation or producer CI gate.
The signed-intent reader retains its separate contract and does not consume
an `authorized` assertion. [Claim P-90](https://probityai.github.io/agent-evidence-atlas/claims.html) binds this control.
