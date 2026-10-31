# Check signed results and selected reports

[Probity](https://github.com/probityai) wrote this Python reader for REMORA's synthetic signed-result fixtures. Each test case supplies a signed result, a report about an execution attempt and any declared execution context. The reader verifies the Ed25519 signature against the supplied trusted keys, then checks that the result names the report's identity and digest. When a case declares execution details, the reader checks their context digest against the report and compares tenant and principal values with supplied expectations.

The [input manifest](INPUT-MANIFEST.json) pins REMORA's producer source at [a4a948ca](https://github.com/darklordVirtual/REMORA-research/commit/a4a948cae7044a474fdb55099daea866130c466f) and records each fixture's digest. The implementation uses its own verification code without importing REMORA's runtime or reference verifier. Its author had read the producer protocol and expected cases, so this comparison uses known answers.

With [uv installed](https://docs.astral.sh/uv/getting-started/installation/), run in a fresh Atlas checkout:

```sh
git clone https://github.com/probityai/agent-evidence
cd agent-evidence/site/interop/trace-m1
bash scripts/qualify.sh
```

The script uses the [locked runtime requirements](pyproject.toml), fetches the fixtures, checks code style and test coverage, and replays the cases. It refuses existing result paths before writing logs. The replay writes report.json and public-report.json under results/replay-r1 and prints the case and agreement counts. A `BOUND` decision means the signed result matches the selected report and any declared context; a `REFUSED` decision names the failed check. [The retained result](retained/public-report.json) shows each observed decision and producer outcome, and [the qualification record](retained/QUALIFICATION.json) includes source hashes and coverage measurements. Downloaded producer fixtures stay local under their upstream license.

The [supported JSON profile](src/json_profile.py) accepts ASCII strings, unique object keys, safe integers and bounded arrays. Base64 must use the standard alphabet and padding, and match its re-encoding. Retention declarations use the fixture's `P1Y` value. Signature verification checks point admissibility with [libsodium's documented subgroup check](https://doc.libsodium.org/advanced/point-arithmetic), while the ASCII serializer follows the string rules of the [JSON Canonicalization Scheme (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2.2.2).

Because a valid signature can carry a contradicted claim, binding preserves the producer's reported outcome and keeps its reason. It does not establish the report's truth, workload identity, authority or effects. An unsigned mapping of external evidence remains an external evidence source; [the mapping checks](src/mapping.py) refuse a [TRACE Trust Record](https://github.com/agentrust-io/trace-spec/blob/4c7d6eccc468c87f2d00e02118b29164a4a5479b/schema/trace-claim.json) or conformance claim. Full JSON Canonicalization Scheme support remains outside the supported profile. Probity keeps its refusal codes separate from the producer's codes.
