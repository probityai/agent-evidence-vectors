| Case | Step | Code that ran it | Expected | Verdict |
|---|---|---|---|---|
| J01 | 1 input: PIC native verification | pic-standard examples/refund-sandbox (PIC) | exit 0, result allow | ESTABLISHED |
| J01 | 1 input: APS receipt, decision, action, payload and PIC binding checks | horizon-shield aps-receipt adapter over APS SDK 8.0.1 (Horizon Shield, APS) | verified, steps 0 to 8 | ESTABLISHED |
| J01 | 2 single-use admission: one committed record | admission stand-in in this harness (door not built) | committed | ESTABLISHED |
| J01 | 3 signature and trust: handoff signed and verified | checkout-runner sandbox_signer (Probity) | verifies under the issuance snapshot | ESTABLISHED |
| J01 | 3 signature and trust: executor pre-dispatch authorization | checkout-runner sandbox_executor (Probity) | authorized | CONTRADICTED |
| J01 | 4 execution: one dispatch to the provider | checkout-runner sandbox_executor (Probity) | 1 apply request | CONTRADICTED |
| J01 | 5 observed effect: bound effect at the report cutoff | checkout-runner sandbox_executor and sandbox_sim (Probity) | observed_success, 1 effect | CONTRADICTED |
| N1a | changed amount in the signed PIC proposal | pic-standard (PIC) | PIC blocks | ESTABLISHED |
| N1b | changed amount in the APS payload | horizon-shield adapter (Horizon Shield, APS) | refused at step 5 | ESTABLISHED |
| N1c | changed amount at dispatch | checkout-runner sandbox_executor (Probity) | alternate-arguments, no new apply | CONTRADICTED |
| N2 | replayed admission of the consumed approval | admission stand-in, executor (Probity) | existing operation, no second dispatch | CONTRADICTED |
| N3 | reissued approval with new matching PIC evidence | PIC, Horizon adapter, admission stand-in, signer, executor | resolved_existing, signed resolution, never dispatches | CONTRADICTED |
| N3b | new APS receipt with the old PIC proposal | horizon-shield adapter (Horizon Shield) | refused at step 7 | ESTABLISHED |
| N4 | provider commits, response lost, then retry and reconcile | checkout-runner sandbox_executor and sandbox_sim (Probity) | unresolved until lookup, then observed_success, 1 apply | CONTRADICTED |
| all | effect count across the run | sandbox_sim (Probity) | 2 effects (J01, N4); 0 from every negative | CONTRADICTED |
