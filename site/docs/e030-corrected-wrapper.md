# Check the report behind PASS

Compare the command result with the actual report

A wrapper can finish successfully and still leave you without a usable report. This check compares the actual command result, the recorded status and the report's fields.

The corrected Frequency wrapper now returns failed command exits. It still prints `PASS` when an exit-zero verifier produces no report or a bad one. The reader catches those cases and keeps each raw result.

[Run the example](examples/e030-corrected-wrapper/README.md), compare another wrapper, or keep the check in your CI. Bring your output to the [shared case thread](https://github.com/probityai/agent-evidence/issues/31).

The retained run covers 14 cases and 63 tests. Failed commands, absent and malformed reports, wrong inputs, stale times and a linked report stay separate. These are injected commands and example reports; they do not run the producer's verifier.

Credit stays with imokokok for the original finding, Pico/Håkon Åmdal for the outside E030 run and kept check, and the native producers for their contracts. The original vector and outside result remain unchanged.

<details>

<summary>

Source, run contract and retained results
</summary>

The wrapper is pinned at `cf7389097fe3a404b3557da2e72fdd8cbe962b81`. [The source map](examples/e030-corrected-wrapper/docs/SOURCE-MAP.md) names every input and owner. [The contract](examples/e030-corrected-wrapper/docs/CONTRACT.md) separates an observed command result from a producer-declared report time.

[Qualification](examples/e030-corrected-wrapper/QUALIFICATION.json), [test results](examples/e030-corrected-wrapper/qualification/tests.xml), [case results](examples/e030-corrected-wrapper/qualification/demonstration.json) and [integration](examples/e030-corrected-wrapper/INTEGRATION.json) retain the exact preparation source and checks.

Operator identity is caller-declared. The native report has no invocation token. A copied report with a forged current time cannot establish fresh execution.

</details>

[HTML view](e030-corrected-wrapper.html) | [Agent guide](llms.txt)
