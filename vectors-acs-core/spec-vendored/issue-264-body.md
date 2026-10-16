### The problem

The trace can't tell when the Observed Agent applied something other than the verdict it received, even though the spec requires it to in two cases:

- **§6.3.** A `MODIFY` whose `modifications` break the composition rules MUST be treated as `DENY`.
- **§6.5.** A `MODIFY` the client cannot apply MUST be treated as `DENY`. At `postCompact`, the client keeps the original summary instead.

In both cases the Guardian's `acs.decision` event says `modify`, while the action was blocked or ran unchanged. The #228 change rules these out as decision failures, so they produce no `acs.decision.failure` event either. A reader counting applied modifications from the trace counts ones that never happened. §6.5 names exactly this harm: "the audit log recorded a modification that never happened."

The Observed Agent already MUST record an audit event in both cases (§6.3, §6.5). What's missing is the Trace form of that audit event.

### Why the wire has to carry it

It doesn't. This is Trace vocabulary, not a wire change. It is a span event the Observed Agent emits on its own step span, defined in `otel-mapping.json` next to `decision_event` and `decision_failure_event`.

### Which constituencies this affects

- Observed Agent implementers, who would emit it
- Auditors and incident responders, who would read it to count applied outcomes

### Alternatives considered

- **Reuse `acs.decision.failure` with a new class.** Rejected in the #228 review. A substitution is the spec working as designed, not a failure, and it would inflate the failure count.
- **Leave it to the deployment's audit log.** That is today's state. It means Trace alone overstates applied `MODIFY` verdicts, which undercuts requirement 3 of the ACS-Trace bar.
- **A sketch of the proposal:** a span event `acs.decision.substituted` on the Observed Agent's step span, carrying `acs.decision` (the verdict received) and `acs.substitution.applied` (`deny` or `original_kept`). Add `acs.substitution.reason` if a reason code is wanted (`modify_unsupported`, `modify_composition`). A reader MUST NOT count a `modify` verdict as applied when this event shares its session and request id.

This came out of the adversarial review of the #228 change. It was left out of that PR on purpose because it adds vocabulary beyond #228's scope.

### Discussion link

No Discussion yet. This issue is filed so it can be triaged and tracked. It relates to #228 (decision event), #37 (decision failure event) and #235 (OCSF class fit). It needs an OCSF form too once #235 settles.

### Current Priority Scope

This is deferred or out of scope and I am filing it to be tracked
