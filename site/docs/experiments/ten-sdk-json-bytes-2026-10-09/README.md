# Which retained SDK serializer outputs matched the selected canonical bytes, differed, or refused, across the complete recorded input population?

[Report](report.json) · [Original source and output](provenance.json) · [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-ten-sdk-json-bytes-2026-10-09)

This packet retains historical evidence from `probityai/agent-evidence-vectors` at
`16d6c5edc700fea2f22cda6044f90953e01d7d8e`. The [original host run](https://github.com/probityai/agent-evidence-vectors/actions/runs/37944695894)
keeps its own date, command and result. The report reads that original output.
The Atlas reader repeats no original workload.

## What the evidence supports

The [complete report](report.json) keeps the measured fields separate from source
assertions and author reports. The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-ten-sdk-json-bytes-2026-10-09)
shows each claim result, the operator roles and the unexercised claims.

- The 27 recorded rows include the row for the bounded profile. Earlier summaries with 26 rows do not cover the full artifact population.
- The raw canonical, differs and refused values are byte-comparison outcomes. They do not grade whether an SDK met its contract.
- The workflow reports differences by default; its green jobs do not establish canonicalization conformance
- The same retained JCS oracle report appears in each ZIP; it is not ten independent oracle runs
- No current SDK behavior, deployment, incident or paid use inferred

## Original result

| SDK | canonical | differs | refused | rows |
|---|---:|---:|---:|---:|
| csharp | 6 | 18 | 3 | 27 |
| go | 9 | 18 | 0 | 27 |
| java | 13 | 14 | 0 | 27 |
| kotlin | 14 | 12 | 1 | 27 |
| php | 11 | 14 | 2 | 27 |
| python | 17 | 9 | 1 | 27 |
| ruby | 15 | 9 | 3 | 27 |
| rust | 17 | 7 | 3 | 27 |
| swift | 19 | 6 | 2 | 27 |
| typescript | 20 | 7 | 0 | 27 |

These are the original raw verdict buckets for all 27 inputs. Their meanings depend on the input profile. The historical workflow reports differences by default.

## Retained bodies

| Body | Source | Stored bytes |
|---|---|---:|
| [run.json](run.json) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/37944695894) | 13,570 |
| [jobs.json](jobs.json) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/runs/37944695894/jobs?per_page=100) | 22,777 |
| [workflow.yml](workflow.yml) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/16d6c5edc700fea2f22cda6044f90953e01d7d8e/.github/workflows/mcp-sdk-jcs.yml) | 2,856 |
| [source/interop/mcp-sdks/driver.py](source/interop/mcp-sdks/driver.py) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/16d6c5edc700fea2f22cda6044f90953e01d7d8e/interop/mcp-sdks/driver.py) | 11,418 |
| [source/interop/mcp-sdks/run-all.sh](source/interop/mcp-sdks/run-all.sh) | [Original source](https://raw.githubusercontent.com/probityai/agent-evidence-vectors/16d6c5edc700fea2f22cda6044f90953e01d7d8e/interop/mcp-sdks/run-all.sh) | 1,634 |
| [mcp-sdk-jcs-csharp.zip](mcp-sdk-jcs-csharp.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622679170/zip) | 1,929 |
| [mcp-sdk-jcs-go.zip](mcp-sdk-jcs-go.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622624078/zip) | 1,768 |
| [mcp-sdk-jcs-java.zip](mcp-sdk-jcs-java.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622318551/zip) | 1,779 |
| [mcp-sdk-jcs-kotlin.zip](mcp-sdk-jcs-kotlin.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622889095/zip) | 1,876 |
| [mcp-sdk-jcs-php.zip](mcp-sdk-jcs-php.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622903933/zip) | 1,839 |
| [mcp-sdk-jcs-python.zip](mcp-sdk-jcs-python.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622769171/zip) | 1,876 |
| [mcp-sdk-jcs-ruby.zip](mcp-sdk-jcs-ruby.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11623033985/zip) | 1,844 |
| [mcp-sdk-jcs-rust.zip](mcp-sdk-jcs-rust.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11623213741/zip) | 1,812 |
| [mcp-sdk-jcs-swift.zip](mcp-sdk-jcs-swift.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622023934/zip) | 1,773 |
| [mcp-sdk-jcs-typescript.zip](mcp-sdk-jcs-typescript.zip) | [Original source](https://api.github.com/repos/probityai/agent-evidence-vectors/actions/artifacts/11622228681/zip) | 1,785 |

Every body has a fixed SHA-256 in [provenance](provenance.json) and in the reader.
The retained original ZIP artifacts keep their original bytes.

## Check this packet

```sh
python3 experiments/ten-sdk-json-bytes-2026-10-09/validate_capsule.py
python3 tools/check_lab.py
```

The first command derives the full report from the retained bodies. It refuses
changed source, changed provenance, duplicate JSON keys and report substitutions.
It executes none of the captured source code. The original pinned workflow and
source keep the procedure for a separate native reproduction.

The [Lab record](https://probityai.github.io/agent-evidence-atlas/runs.html#record-ten-sdk-json-bytes-2026-10-09)
returns to this packet. New evidence uses the existing
[question and claim intake](https://probityai.github.io/agent-evidence-atlas/lab.html#choose-the-claim-you-are-submitting).
