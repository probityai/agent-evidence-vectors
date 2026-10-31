# Refund-connected vectors

Two retained runs of a connected refund pilot, judged offline from their bytes. Each run holds the inputs and trust files of its cases, the admission state, the signed handoffs and resolutions, the executor's four streams and the payment simulator's own record. The reference reader never opens `results.json`; it re-derives six verdicts per case (`input_pic`, `input_aps`, `admission`, `signature_trust`, `execution`, `observed_effect`) and four run-level checks.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)


Run it from a clone:

```
python3 vectors-refund-connected/check_vectors.py
python3 vectors-refund-connected/check_vectors.py vectors-refund-connected/source/j01-connected-20261028-r2
```

The first judges every case in `MANIFEST.json` against its recorded verdicts, prints how many it answered, and exits 0. The second judges one run and exits 0 only when every case ended as it should.

| Run | What it is | Reader result |
| --- | --- | --- |
| `r2` | every layer held, two effects, none from a negative case | exit 0 |
| `r1` | the run before the dispatch-window fix; the executor stopped before it dispatched | exit 1, `NOT_ESTABLISHED:no-dispatch-attempt` at `execution` for j01 and n4 |

Acceptance sentence for a pilot: the retained bundle passes the agent-evidence-vectors refund-connected family at version X.

The source runs had one operator, public test keys and an admission stand-in. They show that the layers compose; they are not a production deployment. Source: `examples/checkout-runner/connected/runs` at commit `dcc07c3cdde0ca4beab6f7b5afe6a7e15801eb58`, copied byte for byte. `MANIFEST.json` carries every file digest and the verdicts per case; `gen_vectors.py` regenerates it.

| Doc | Where |
| --- | --- |
| Corpus index | [docs/guides/corpora.md](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/guides/corpora.md) |
| Reader routes | [docs/reference/corpus-readers.md](https://github.com/probityai/agent-evidence-vectors/blob/main/docs/reference/corpus-readers.md) |
