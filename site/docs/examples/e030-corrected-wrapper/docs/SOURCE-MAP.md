# Source and ownership

The [corrected wrapper](https://github.com/altrudev/Frequency-Federation-Review/blob/cf7389097fe3a404b3557da2e72fdd8cbe962b81/capsules/aps-priorseal-v0.1/run-pinned.sh)
at `cf7389097fe3a404b3557da2e72fdd8cbe962b81` propagates failed commands and records their status.
Its SHA-256 is `4b289714de31174a917b9c0f856e1d8900828e1bcbf637cdc8e97bc2deec2e34`.
It still prints `PASS` after an exit-zero verifier without checking the report's presence or content.
The regression observes that behavior without changing producer source.

The [producer output contract](https://github.com/altrudev/Frequency-Federation-Review/blob/cf7389097fe3a404b3557da2e72fdd8cbe962b81/capsules/aps-priorseal-v0.1/OUTPUT-CONTRACT.md)
and [verifier source](https://github.com/altrudev/Frequency-Federation-Review/blob/cf7389097fe3a404b3557da2e72fdd8cbe962b81/capsules/aps-priorseal-v0.1/adapter/verify.mjs)
own the profile, native pins, claim IDs, result meanings and generation timestamp.
`expected.json` projects the relevant pin and claim fields from the existing
[Atlas record](https://github.com/probityai/agent-evidence-atlas/blob/89250120e9cafe14eafb87eaa9c1454bab64683c/experiments/aps-priorseal-source-replay/recorded.json).
This projection does not replace the producer's full report contract or signature checks.

| Relationship | Owner or source |
| --- | --- |
| Original wrapper finding | imokokok |
| Original negative vector | Probity; original `89250120` bytes are unchanged |
| Existing outside keeper and run | Pico, an AI agent operated by Håkon Åmdal, for Agent Errata |
| Native wrapper/report semantics | Frequency's pinned public source |
| This regression and injected reports | Probity |
| Each future run and kept CI check | Its explicitly declared operator |

The source checkouts remain clean. The harness removes inherited Git routing and shell startup
settings before reading or invoking them. Output is outside each producer tree, including through
parent symlinks.

Pico's [historical outside result](https://github.com/probityai/agent-evidence/issues/31)
uses the old wrapper at `b12879d5878991d9c3ed260d06ee11716eb99d33`.
It does not qualify the corrected wrapper. This experiment does not rewrite its record,
its attribution, or its expected answers.
