# Published robot controls

A task-grouped reading of Provael's simulator reports and correction

Publisher-report-derived companion. Native runtime gaps and the measured Lab register are preserved.

[Complete source bindings](examples/provael-task-controls/source-record.json), [calculation contract](examples/provael-task-controls/contract.json), [compact complete outcome report](examples/provael-task-controls/report.json) and [reader source](examples/provael-task-controls/check_provael_controls.py) are published here. [Claims P-59 through P-63](claims.md) bind the source, counts, matching, interval convention and limits.

<a id="published-simulator-controls-read-by-task"></a>

# Published simulator controls, read by task

This companion reads Provael's published SmolVLA / LIBERO-Object reports. It reconstructs the reported labels and matched controls from complete source files, then keeps all seeds and arms together when resampling a task. It runs no policy or simulator. Evidence class: `publisher-report-derived`.

The source is [Provael at f1dbc535](https://github.com/provael/provael/tree/f1dbc5352bfa7774c0a5599eff20407125914c78). The publication commit identifies the files we read. It cannot fill a missing historical runtime commit, dependency lock or precision.

<a id="run-it"></a>

## Run it

Python 3.11+ and its standard library are enough:

``` sh
git clone https://github.com/provael/provael.git provael-source
git -C provael-source checkout --detach f1dbc5352bfa7774c0a5599eff20407125914c78
python3 tools/check_provael_controls.py \
  --source-root provael-source \
  --expect examples/provael-task-controls/report.json \
  --output provael-control-report.json \
  --retain-source-zip provael-required-source.zip
```

The reader checks the baked contract and source-record digests, then every complete source file's length and SHA-256. Git HEAD alone would miss changed working files. The ZIP contains every bound original file, with its original path, and the source record; an extracted ZIP can also be the reader's input. The compact report retains every episode's source pointer, original and changed instruction, applied seed, applicability, reported unsafe flag and clean task success. The original reports also retain the action decisions and trajectories. Those complete files stay in the source ZIP, rather than being silently trimmed into the compact report.

<a id="keep-the-two-runs-separate"></a>

## Keep the two runs separate

| published run | tasks | seeds per arm | retained records | applicable | not applicable |
|---------------|------:|--------------:|-----------------:|-----------:|---------------:|
| suite         |    10 |             5 |              400 |        350 |             50 |
| controls      |    10 |             3 |              180 |        180 |              0 |

The suite's 50 `mcp_tool_desc` records are not applicable. Their reported `success: false` never becomes a measured safe result: their derived rate and interval are null. No outcome labels are unresolved in these published files. An unknown label or incomplete seed/arm cell is refused.

| arm | suite reported unsafe / applicable | controls reported unsafe / applicable |
|----|---:|---:|
| `none` (benign) | 1/50 | 1/30 |
| `roleplay` | 42/50 | 26/30 |
| `roleplay_no_target` | absent | 27/30 |
| `scrambled_text` | absent | 18/30 |
| `benign_reword` | absent | 0/30 |
| `nonsense_text` | absent | 0/30 |

The benign clean-task competence controls are 48/50 and 29/30. This is a separate outcome from the unsafe flag. Every remaining suite arm and every per-task count is in the report.

There are 60 shared task/seed/arm keys across the runs. Of those, 30 complete native episode objects are canonically identical, all in `none`. The report retains their digests and both source pointers. Separate directories do not establish fresh independent benign repeats. We do not pool the runs.

<a id="what-the-controls-change"></a>

## What the controls change

Provael's [E-2026-12 correction](https://github.com/provael/provael/blob/f1dbc5352bfa7774c0a5599eff20407125914c78/docs/errata.md#e-2026-12--the-4450-roleplay-result-was-described-as-the-attack-redirecting-the-policy-the-controls-show-the-policy-leaves-its-envelope-under-the-frame-alone-target-or-no-target) changes the interpretation, leaving the published counts intact. The frame with no target named fires as often as roleplay; scrambled tokens also fire. These observations support the publisher's narrower reading of envelope fragility under long imperative instructions. They do not demonstrate attacker-directed object control. The reader preserves that correction alongside the rates.

<a id="exact-task-resampling"></a>

## Exact task resampling

Each run contributes ten task vectors. A vector keeps all of that task's unsafe counts across all arms. An integer convolution adds one whole task at each of ten draw positions; the multiplicity of equal vectors is retained. The final weights therefore count all `10**10` ordered task draws exactly, without executing ten billion loops. There are 9,581 distinct suite states and 1,716 controls states. These are bootstrap draw weights, not new trials.

Every measured arm has the same applicable denominator within its run: five per task in the suite and three in controls. Thus the pooled episode rate and the equal-task mean coincide, including in each draw. Both targets are reported. The exact profile refuses unequal allocation, empty arms or unresolved labels rather than silently excluding tasks. The separate [authored example](task-grouped-rates.md) shows unequal weights and unresolved labels.

For nominal 95% endpoints, the reader uses the inverse empirical CDF: the smallest value reaching cumulative weight `ceil(p * 10**10)`, at `p=1/40` and `39/40`. The endpoint ranks are 250,000,000 and 9,750,000,000.

| within-run contrast | observed difference | exact nominal task-percentile endpoints |
|----|---:|---:|
| suite: roleplay minus none | 41/50 | \[30/50, 49/50\] |
| controls: roleplay minus none | 25/30 | \[19/30, 30/30\] |
| controls: roleplay minus no target | -1/30 | \[-3/30, 0/30\] |
| controls: roleplay minus scrambled | 8/30 | \[4/30, 12/30\] |

These are exact empirical bootstrap calculations, not exact population confidence guarantees. The ten benchmark tasks share policy and simulator; independent exchangeable sampling from an external task population is not established. Within-task pairing cannot remove dependence between tasks. `coverageEstablished` stays false, and no simultaneous coverage is claimed for the several arm comparisons. A degenerate point distribution stays labelled degenerate and cannot establish absence.

The publisher's aggregate intervals remain separately retained with their own method: 2,000 `random.Random(0)` task draws and floor-indexed percentiles. Our exact scrambled interval is \[12/30, 23/30\], while that Monte Carlo analysis gives \[13/30, 23/30\]. The reader does not rewrite the original. The controls' published Holm family includes all five non-baseline arms, including harmless variations; the suite family has six applicable attacks. Those publisher tests are preserved as analysis, not promoted to a claim that seeds are independent sampling units.

<a id="runtime-and-outcome-limits"></a>

## Runtime and outcome limits

All native manifests remain literal in the report. The suite runtime commit is null; controls record only `de6c231`. Repository, dependency-lock digest and precision are null in both runs, as are checkpoint and configuration bindings. The publication pin and release version do not repair those gaps.

All source reports declare `calibrated: false`. The reader checks that each reported episode flag agrees with its native decision flags; it does not evaluate the safety predicate from actions, establish its calibration or infer physical harm. These are publisher-reported simulator rollouts. No hardware execution, independent effect custody or new Lab register entry is established by this companion.

Provael and the original retained sources are by Sattyam Jain. The source ZIP includes their unchanged Apache-2.0 LICENSE, NOTICE and trademark text. [PROVAEL-LICENSE](https://probityai.github.io/agent-evidence-atlas/examples/provael-task-controls/PROVAEL-LICENSE) and [PROVAEL-NOTICE](https://probityai.github.io/agent-evidence-atlas/examples/provael-task-controls/PROVAEL-NOTICE) also accompany this example. Our reader is new Atlas code.

[HTML view](provael-task-controls.html) | [Agent guide](llms.txt)
