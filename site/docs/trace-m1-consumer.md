# Check a signed result and its selected report

Probity reader for REMORA's public signed-result fixtures.

[Probity](https://github.com/probityai) wrote this Python program to check [REMORA's public synthetic fixtures](https://github.com/darklordVirtual/REMORA-research/commit/a4a948cae7044a474fdb55099daea866130c466f). Each case supplies a signed result, a report about an execution attempt and optional declared execution details. The program checks the signature and verifies that the result selects the supplied report by identity and digest.

Probity wrote and ran its own implementation without importing REMORA's runtime or reference verifier. The author had already read REMORA's protocol and expected cases, so this comparison uses known answers.

The [retained result](interop/trace-m1/retained/public-report.json) agrees with all 12 expected decisions: three cases bind to their selected reports and nine are refused. When a result binds, the reader keeps the producer's outcome and reason, including `CONTRADICTED`, along with report identity, its digest commitment, the execution-attempt sequence and explicit selection. Probity's refusal codes describe its own checks and are not translations of REMORA's codes.

The [qualification record](interop/trace-m1/retained/QUALIFICATION.json) reports 118 passed tests and a passed coverage gate for every production module. The tests change the selected report, use a Boolean as an integer sequence, add unsupported fields, supply invalid elliptic-curve signing points and attempt claims beyond the declared evidence.

With [uv installed](https://docs.astral.sh/uv/getting-started/installation/), run the [reader and tests](https://github.com/probityai/agent-evidence-vectors/tree/main/site/interop/trace-m1) from a fresh checkout:

``` sh
git clone https://github.com/probityai/agent-evidence-atlas.git
cd agent-evidence-atlas/interop/trace-m1
bash scripts/qualify.sh
```

The command downloads fixtures using [a manifest of the producer commit and file digests](interop/trace-m1/INPUT-MANIFEST.json), runs the tests and prints case and agreement counts. Existing result paths are refused before logs are written. Third-party fixtures stay local under their upstream license. The public report includes observed decisions; the locally generated full report also retains producer expectations and execution details.

Signature verification checks byte integrity. It does not establish workload identity, authority, effects or the truth of the producer's result. The [supported ASCII JSON profile](https://github.com/probityai/agent-evidence-vectors/blob/main/site/interop/trace-m1/src/json_profile.py) covers a subset of the [JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html), and an unsigned mapping of external evidence remains outside [TRACE Trust Record](https://github.com/agentrust-io/trace-spec/blob/4c7d6eccc468c87f2d00e02118b29164a4a5479b/schema/trace-claim.json) and conformance claims.

[Find other retained runs](runs.md), or [bring an evidence question to the Open Evidence Lab](lab.md).

[HTML view](trace-m1-consumer.html) | [Agent guide](llms.txt)
