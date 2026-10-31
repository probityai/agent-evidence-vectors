# Tool-shaped JSON remains insufficient for correct tool decisions

The authored CPU tool-argument study scored all 128 planned attempts. Every 24-token response reaches its cap before valid JSON. Every 96-token response satisfies its selected schema. At that longer cap, the smaller model scores 0/16 and the larger model 7/16 in each mode. Neither mode produces a correct abstention or fully correct contrast pair. All eight strict quality rows hold. [Claims P-51–P-56](claims.md) supply sources, read times, commands and limits.

These are exposed authored tool-argument and abstention cases, not a representative model benchmark. The run supports publishing this report within that scope. Task-quality gates stay held. Admitting a model action, dispatching it, recovering it and producing protected effects each need their own authority.

<a id="prospectively-selected-population"></a>

## Prospectively selected population

The study freezes sixteen original cases in eight one-field contrasts, cloned into two modes. The rules require a unique nonempty key, current integer revision evidence and the requested tool's permission. Writes also need a literal integer value and positive integer quota. Invalid records require explicit abstention.

Both modes request the same nested object and receive the same prompt. The control allows generic finite JSON values for arguments and any string tool. The tool-schema mode restricts the global catalog to `write_record`, `inspect_record` and `none`, with nullable string keys and nullable integer values. Its generic grammar contains no case-specific answer.

The prospective protocol commitment is `f62ded1a32862839da80a80f8e871ef6cda4acc8c30363367cccf6bec9e92c97` at [registration db429775](https://github.com/probityai/agent-evidence-observer/commit/db429775f139396df4028a9f4367e9bdfaa4ba17). The selected reader/source is [884814fe](https://github.com/probityai/agent-evidence-observer/commit/884814fe8cbc2e3b21d267fbaf86726c37892b14). The actual run uses protected main [51e0c125](https://github.com/probityai/agent-evidence-observer/commit/51e0c12551339cce5898d3bfae2ba9ef3d9607f5). These stages remain separate from Atlas retention.

The balanced serial order rotates all eight model/cap/mode cells within every original case. No failed response is retried, filtered from the denominator or used to retune a cap. A length-finished response retains its parsed format/schema scores, while strict correctness stays false under the frozen rubric.

<a id="every-original-quality-row"></a>

## Every original quality row

Each row contains sixteen cases, eight pairs and eight required abstentions. No row has a fully correct pair or correct abstention.

| Model      | Cap | Mode        | JSON/schema valid | Strict correct | Length-finished |
|------------|----:|-------------|------------------:|---------------:|----------------:|
| smol135-q4 |  24 | control     |              0/16 |           0/16 |           16/16 |
| smol135-q4 |  24 | tool-schema |              0/16 |           0/16 |           16/16 |
| smol135-q4 |  96 | control     |             16/16 |           0/16 |            0/16 |
| smol135-q4 |  96 | tool-schema |             16/16 |           0/16 |            0/16 |
| smol360-q4 |  24 | control     |              0/16 |           0/16 |           16/16 |
| smol360-q4 |  24 | tool-schema |              0/16 |           0/16 |           16/16 |
| smol360-q4 |  96 | control     |             16/16 |           7/16 |            0/16 |
| smol360-q4 |  96 | tool-schema |             16/16 |           7/16 |            0/16 |

The [native report](experiments/model-tool-arguments-cpu-2026-10-03/native-report.json) retains every attempt, original pair role, token count and resource observation. The larger model's seven correct cases in each longer-cap mode do not compensate for wrong abstentions or promote the held rows. The same-run comparison is finite and descriptive; it is not a general effect estimate.

<a id="whole-child-resources-and-archive-reuse"></a>

## Whole-child resources and archive reuse

An external observer measures the selected native child from spawn through reap, including source checks, model initialization, source retention and original child-terminal serialization. Its totals are 228.445554164 seconds wall, 430.234663 seconds CPU and 577,276 KiB lifetime peak RSS. Returned calls account for 29,992 prompt tokens and 3,468 completion tokens. Post-child model-free reconstruction is a separate consumer stage.

The new preparation charges 465,478,943 bytes for exactly one previously retained archive transfer. It extracts 66 selected files totalling 477,404,572 bytes, including the original payloads, compiled runtime, metadata and historical receipts. Preparation takes 13.785495131 seconds and offline installation 6.719390232 seconds. Installation transfers no dependencies, performs no native build and retains 1,088,340,047 bytes under its declared disk envelope.

The earlier six-preparation response-body aggregate remains 2,639,228,307 bytes in its original receipt. It is historical preparation, separate from this new archive charge. Reused model and dependency bytes are not presented as fresh Hugging Face or PyPI transfers. Paid provider calls, dollars and tool effects are zero. The frozen budgets and resource boundaries remain in the original protocol.

<a id="durable-original-retention-and-an-offline-refusal-gate"></a>

## Durable original retention and an offline refusal gate

The [exact native ZIP](experiments/model-tool-arguments-cpu-2026-10-03/original-artifact.zip) is 2,639,358 bytes and retains all 331 original members without omission. Its SHA-256 is `67ef1e638e814c71bbf354fe9895ea0faf5d9ef11eae2ff76b10b065bd7a7e54`. The [provenance](experiments/model-tool-arguments-cpu-2026-10-03/provenance.json) accounts for every native member and records the separate full preparation artifact's provider size, digest and expiry. The 1,051,848,146-byte full preparation archive is not retained in Atlas. Public hashes cannot reconstruct its omitted weights, wheels, original archive or installed environment. Provider artifacts expire at 2027-01-01T10:33:56Z; Git separately retains this complete compact native original. Observer also retains the [same original at its durable public source](https://github.com/probityai/agent-evidence-observer/blob/11389afe6d7c67874e63e4b4521d8a5c2a5dba81/interop/local-model-tool-arguments-2026-10-03/retained/native-37116827382.zip).

A fresh checkout can re-derive source selection, all raw-response semantic scores, complete row/pair/abstention denominators and whole-child measurements:

``` sh
python3 tools/check_lab.py
```

The checker refuses reselected archive/report/source substitutions and promotions of semantic quality, outside acceptance or custody. It reads data only and never imports retained model code. The normal pull-request test workflow repeats the retention controls without new inference.

This is the nineteenth bounded [Lab record](lab.md). All eighteen earlier literal record objects and artifact bytes remain unchanged. Producer acceptance, recurring outside operation, model-action authority and independently controlled keys, clock, target or effect custody remain unestablished.

[HTML view](tool-argument-findings.html) | [Agent guide](llms.txt)
