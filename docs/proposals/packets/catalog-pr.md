# aos-standard/catalog: vendor the anchor-stream corpus and run it in CI

register: edelman
packet: true
ships: ../catalog-pr-body.md
inline_code_spans: 1
inline_code_spans_are: conformance/anchor-stream/

## Front matter

| field | value |
|---|---|
| **target** | a pull request against `https://github.com/aos-standard/catalog`, opened after the comment on issue 1 |
| **channel** | GitHub pull request, opened by the operator |
| **deadline** | none. The issue's rules of engagement treat 21 days of silence as no takers yet, and this is the second artifact in the same exchange |
| **audience** | the repository's maintainer, who wrote 15 of the 21 comments on issue 1 and has shipped 6 tags in response to reported findings |
| **identity** | Private individual, the operator's own name. The public suite is linked by URL. No company, product or site is named in the branch, the body, the vendored files or the workflow |

### Evidence status

| claim | status | locator |
|---|---|---|
| Their CI is one workflow, path-filtered to `census/**` | `verified_fact`, direct | `.github/workflows/census-diff.yml` in the clone at HEAD `71ad495`; it is the only file in `.github/workflows/` |
| That workflow already uses `actions/setup-python@v5` at 3.12 on ubuntu-latest | `verified_fact`, direct | same file |
| The two vendored scripts are stdlib-only Python 3 | `verified_fact`, direct | `run_verifier.py` and `gen_vectors.py` import only `argparse`, `base64`, `copy`, `hashlib`, `importlib`, `inspect`, `json`, `os`, `re`, `sys`, `unicodedata` |
| The corpus's own integrity check is the Go verifier | `verified_fact`, direct | `go build -o aee-verify ./cmd/aee-verify && ./aee-verify corpora/vectors-anchor-stream/` exits 0 and prints `members: 32`, `accept: 12`, `reject: 20` |
| The ratchet is green on the build it recorded and names 16 broken members against an older one | `verified_fact`, direct | `python3 run_verifier.py --verifier <v0.10> --expect recordings/anchors-verify-v0.10.json` exits 0; the same against v0.4 exits 1 with 16 `BROKE` lines |
| 27 of 32 members agree with `anchors-verify-v0.10` | `verified_fact`, direct | `recordings/anchors-verify-v0.10.json`, 32 members, 27 true |
| The vendored digest pins what was reviewed | `proposal` | this file |

### push_plan

1. The comment on issue 1 goes first and this pull request follows it, so the maintainer sees the findings before he sees a directory.
2. Open as a draft against `main`. One commit, one directory, one workflow.
3. Told next: nobody outside.
4. Follow-up: if he declines the vendoring, the corpus stays where it is and the run command in the comment still works, so nothing is lost. If he takes it, the recording is refreshed on each of his tags by re-running the write-expect command, which is the only maintenance the directory carries.

---

## The file layout

```
conformance/anchor-stream/
  VENDORED.json          source repository, commit, corpus digest, date, and the
                         command that reproduces the copy
  MANIFEST.json          expectations, conditions, counts, corpus digest
  INDEX.md               every member in one table
  README.md              what the corpus is and what it is not
  baseline/              the stream, sidecar and witness snapshots this tag published
  streams/  sidecars/  witness/
  reason-map/            the corpus stop-reason vocabulary mapped onto this
                         implementation's prose
  spec-vendored/         ANCHORS_VERIFY.md at anchors-verify-v0.4, pinned by digest
  recordings/anchors-verify-v0.10.json
  gen_vectors.py  run_verifier.py
.github/workflows/anchor-stream.yml
```

`VENDORED.json` carries the upstream commit and the corpus digest, so a reader can tell in one command whether the copy has drifted from what was reviewed, and re-vendoring is a diff rather than an act of faith.

## The workflow

```yaml
name: anchor-stream
# The vendored anchor-stream corpus, run against this repository's own verifier
# on every change to either. It is a RATCHET, not a conformance verdict: it
# refuses when a member that agreed in the recording stops agreeing, and says
# nothing about the members already recorded as disagreeing.
on:
  push:
    paths: ["anchors_verify.py", "conformance/anchor-stream/**", ".github/workflows/anchor-stream.yml"]
  pull_request:
    paths: ["anchors_verify.py", "conformance/anchor-stream/**", ".github/workflows/anchor-stream.yml"]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: The vendored copy is the copy that was reviewed
        run: python3 conformance/anchor-stream/gen_vectors.py --check
      - name: No member that agreed has stopped agreeing
        run: |
          python3 conformance/anchor-stream/run_verifier.py \
            --verifier anchors_verify.py \
            --label anchors-verify-v0.10 \
            --expect conformance/anchor-stream/recordings/anchors-verify-v0.10.json
```

Stdlib only, no network at run time, no install step, and it borrows the Python setup the census workflow already uses. The whole job is two commands.

---

## Paste-ready body

Paragraphs are single lines with a blank line between them, so GitHub renders prose.

---

This vendors the reject corpus from the issue-1 comment into `conformance/anchor-stream/`. One workflow runs it against anchors_verify.py on every push that touches either. It is a draft because the shape needs agreement before the corpus contents do.

The workflow is a ratchet rather than a conformance gate, and that distinction is the whole design. Today 27 of the 32 members agree with anchors-verify-v0.10. A gate demanding 32 would go red the moment it landed. A gate that goes red on arrival lasts a week. So the recording in recordings/anchors-verify-v0.10.json names which members agree right now. The job fails only when a member that agreed stops agreeing.

It stays silent about the 5 that already disagree: those are the findings in the comment, and they are yours to close or to decline on their own terms.

I checked that it discriminates before proposing it. Pointed at the build it recorded, the ratchet exits 0. Pointed at anchors-verify-v0.4, it exits 1 and names 16 members by identifier, each with the outcome that build now returns, so a change to line splitting, boundary rules or binding arithmetic surfaces in the job that ran it. Nobody on your side has to remember what the last tag did.

Two commands, stdlib only, no network at run time, no install step. gen_vectors.py --check asserts the vendored copy is byte-identical to what the generator emits, so a local edit to any vector cannot pass unnoticed.

Whether the corpus does what its manifest claims is answered in my repository rather than yours, by a Go verifier that reads every corpus by its manifest and needs nothing from your CI: go build -o aee-verify ./cmd/aee-verify && ./aee-verify corpora/vectors-anchor-stream/ exits 0 over 32 members, 12 accept and 20 reject, and exit 1 names the member whose bytes moved.

The second command is the ratchet described above. The job borrows the actions/setup-python@v5 at 3.12 that census-diff.yml already uses. Its path filter keeps it off every other push.

Two things about the vendored copy itself deserve a note. VENDORED.json carries the upstream commit and the corpus digest. Re-vendoring is then a diff against a named revision rather than a fresh act of trust. And spec-vendored/ holds ANCHORS_VERIFY.md at anchors-verify-v0.4, pinned by sha256. That is the contract text I wrote the members against, and a tag is a name that can move.

That text, as written, requires two of the ten conditions. The other eight are corrections the corpus proposes, and every member carries a contractBasis field saying which: nothing here reads as a conformance failure against what you have actually published.

reason-map/ is the contested part. Every reject member declares a stop reason as well as an outcome, and the runner scores both. That is your own rule from 20 August, turned on your own verifier. Scoring a reason means matching your prose, because the stream format publishes no reason codes: that file is a per-implementation map, and it goes stale the moment you reword a message. A reason code in the format deletes the file. Until there is one, somebody maintains it, and that somebody belongs with the format, not with the corpus.

If you would rather not carry a directory, say so and I will close this. The corpus stays where it is. The run command in the comment still works against any tag, and nothing about the findings depends on whether this lands.
