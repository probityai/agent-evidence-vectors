# Check whether readers find the right tool

Use this workflow to evaluate how a person or agent finds a component and a usable recipe. Keep the question, accessed sources, answer and review together. The local checker validates their retained bytes and reports declared outcomes.

<a id="start-with-the-fixed-prompts"></a>

## Start with the fixed prompts

From a new checkout, with Python 3.11 or later:

``` sh
git clone https://github.com/probityai/agent-evidence/tree/main/site
cd agent-evidence-atlas
git checkout 753a60ccd3ec84a80fd8ca84da283d8ec09a60fa
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements/discoverability.txt
.venv/bin/python tools/discovery_evaluation.py check
.venv/bin/python tools/discovery_evaluation.py prompts --mode navigation > prompts.json
.venv/bin/python tools/discovery_evaluation.py report \
  --session examples/discovery-evaluation/no-attempts.json \
  --evidence-root examples/discovery-evaluation
```

The saved example has no attempts. Its report preserves 25 tasks in each mode, all marked `not_executed`. Both navigation targets remain `not_established`. This checks the packet workflow; it does not run a client or search engine.

The [task definitions](https://github.com/probityai/agent-evidence-atlas/blob/753a60ccd3ec84a80fd8ca84da283d8ec09a60fa/data/discovery-tasks.json) contain the prompts, pinned source hashes and review criteria. They cover all current components, an installed native reader, an unreleased tool, a correction route and an original historical Lab run. The suite stays separate from research studies and does not change their tasks, source pins or results.

<a id="run-a-reader-session"></a>

## Run a reader session

Use one client, version, model and operator per session. Use separate sessions for different clients or versions. Record the operator relationship accurately.

| Mode | Starting point | Retain |
|----|----|----|
| `open_search` | The fixed user question | Actual queries, accessed public sources and the returned answer |
| `navigation` | The public organization or the published agent guide | The chosen start URL, each navigation choice, accessed sources and the returned answer |

Export the other mode with:

``` sh
.venv/bin/python tools/discovery_evaluation.py prompts --mode open_search > prompts-open-search.json
.venv/bin/python tools/discovery_evaluation.py prompts --mode navigation \
  --human-walkthroughs > prompts-human.json
```

Give the client the exported prompts, without the review criteria. The review key is public, so this export alone does not establish answer blindness. Record whether the key was exposed, whether the operator declares it unexposed, or whether access was not recorded.

The agent target is at least 90 percent reviewer-accepted first attempts in each complete mode. Missing attempts and pending answer reviews prevent a target result. Repeats show variation separately and never replace a failed first attempt.

The human walkthrough uses five fixed tasks. Its target is an accepted answer within two navigation choices for each task, with unfamiliarity declared by the reader. A declared role or familiarity value is not independently checked identity or proof of unfamiliarity.

<a id="retain-the-native-attempt"></a>

## Retain the native attempt

Copy the [empty session](https://github.com/probityai/agent-evidence-atlas/blob/753a60ccd3ec84a80fd8ca84da283d8ec09a60fa/examples/discovery-evaluation/no-attempts.json) and set its actual client and operator fields. Keep its suite digest. Append attempts using the closed [packet schema](https://github.com/probityai/agent-evidence-atlas/blob/753a60ccd3ec84a80fd8ca84da283d8ec09a60fa/data/discovery-evaluation.schema.json).

Each attempt needs:

- The task, mode and repetition, with the exact prompt bytes (no added newline).
- The native answer or client error and the declared start and end times.
- The actual query or navigation choices and a byte capture of each accessed source.
- The selected component and profile IDs, recipe URL and command, when applicable.
- A pending review, or the retained decision and all review checks.
- Separate stdout, stderr and exit code when a command actually ran.

Keep captures below one evidence directory. Each capture names its relative path, exact byte count and SHA-256. For example, after saving a native answer as `evidence/answer.txt`:

``` sh
.venv/bin/python - evidence/answer.txt <<'PY'
import hashlib
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
raw = path.read_bytes()
print(json.dumps({
    "path": str(path.relative_to("evidence")),
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
}))
PY
```

Do not edit native answers or source captures to agree with the rubric. Review component selection, recipe usability, claim accuracy and source support against the suite's pinned sources. A correct component name alone is not enough.

<a id="check-and-report"></a>

## Check and report

After recording the actual session and retained files:

``` sh
.venv/bin/python tools/discovery_evaluation.py check \
  --session session.json --evidence-root evidence
.venv/bin/python tools/discovery_evaluation.py report \
  --session session.json --evidence-root evidence > report.json
```

The checker refuses changed prompts, a different suite digest, duplicate task/mode/repetition records, missing files, substituted bytes, symlink escapes and contradictory review states. A repeated attempt needs its first attempt. Invalid input exits with code 2 and emits no report.

| Reported outcome | Meaning |
|----|----|
| `not_executed` | No first-attempt packet exists for this task and mode |
| `review_pending` | The answer is retained and its review is unfinished |
| `failed` | The client errored, the reviewer rejected the answer, or its component, profile or recipe binding disagrees |
| `review_accepted` | The retained packet passes mechanical checks and records an accepted review |

`author_check` packets remain separate from reported human or agent attempts. They cannot meet either navigation target. The checker never executes a recorded command or authenticates an operator, clock, accessed URL or reviewer decision. Actual first-run success, outside operation, host dependencies and independent custody need their own evidence.

Use a failed task to improve its public title, missing term, link or recipe. Retain the first result, change the surface, then record the next attempt without overwriting the original. Submit a source-linked [correction](https://github.com/probityai/agent-evidence/issues/new?template=evidence-correction.yml) when the documentation itself is wrong.

[HTML view](discovery-evaluation.html) | [Agent guide](llms.txt)
