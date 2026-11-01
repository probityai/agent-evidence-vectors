Four constructions against anchors-verify-v0.10, and the first one is the copy-paste block at the top of ANCHORS_VERIFY.md. Run it today and it exits 1, not 3.

```
VERIFY FAILED: truncation vector 2: presented stream shorter than main branch (24 vs 49 lines)
```

I ran that block against all 7 published tags, v0.4 through v0.10, and recorded exit 1 from every one. The bundled stream has not changed and anchors_verify.py has not changed. main went from 24 lines to 49.

The cause, as best I can tell, is two lines in `verify_from_bytes` that have not changed since v0.4:

```python
if main_lines is None and query_repo:
    main_lines = fetch_repo_lines(query_repo, "main", "ANCHORS.jsonl")
```

That fetch has no condition on it, so the documented run reads a moving branch. Your own text beside the block says "The bundled files come from the same tag as the verifier. You can reproduce without referencing main." The verdict a reader gets from those commands is a function of what you pushed this week.

The remaining three run offline, because the alternative is a live fetch and a verdict that depends on one expires. Fetch anchors_verify.py, ANCHORS.jsonl and ANCHORS.jsonl.digests.json from the tag, add the two witness snapshots the stream names, and run the script below. It reproduces the outcome path of your main with the platform reads replaced by pinned bytes, and nothing else stubbed.

```
git show e000814f60f393469479df795114d5b595f7ff49:ANCHORS.jsonl > W-e000814.jsonl
git show 0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582:ANCHORS.jsonl > W-0eb69bf.jsonl
```

```python
import hashlib, inspect, json
import anchors_verify as av

REPO = "aos-standard/catalog"
ATTESTED = "e000814f60f393469479df795114d5b595f7ff49"
raw = open("ANCHORS.jsonl", "rb").read()
side = open("ANCHORS.jsonl.digests.json", "rb").read()
lines = [line + b"\n" for line in raw.split(b"\n")[:-1]]
witness = {(REPO, ATTESTED): av.bytes_to_lines(open("W-e000814.jsonl", "rb").read())}
active = av.bytes_to_lines(open("W-0eb69bf.jsonl", "rb").read())

def sidecar(stream):
    rows = [line + b"\n" for line in stream.split(b"\n")[:-1]]
    return json.dumps({"version": "1.0.0",
                       "line_sha256": [hashlib.sha256(r).hexdigest() for r in rows]}).encode()

def run(stream, presented_sidecar=None, main=None):
    kw = dict(check_witness_platform=True, expect_witness_repo=REPO,
              witness_lines_by_ref=witness, witness_lines=active,
              main_lines=av.bytes_to_lines(main if main is not None else stream))
    if "commit_reachability" in inspect.signature(av.verify_from_bytes).parameters:
        kw["commit_reachability"] = {(REPO, ATTESTED): True}
    try:
        result = av.verify_from_bytes(stream, presented_sidecar or side, **kw)
    except av.VerifyError as exc:
        return "exit 1  VERIFY FAILED: %s" % exc
    ckw = {"expect_witness_repo": REPO}
    if "presented_lines" in inspect.signature(av.classify_verification_outcome).parameters:
        ckw["presented_lines"] = av.bytes_to_lines(stream)
    code, _, message = av.classify_verification_outcome(result, **ckw)
    return "exit %d  %s" % (code, message.splitlines()[0])

short = json.loads(side)
digests = short["line_sha256"]
del digests[18:]
short = json.dumps(short).encode()
altered = b"".join(lines[:21] + [lines[21].replace(b'"note":""', b'"note":"x"')] + lines[22:])
binding = json.loads(lines[18])
attestation = binding["attestation"]
witness = attestation["witness"]
witness["repo"] = ""
norepo = b"".join(lines[:18] + [json.dumps(binding, separators=(",", ":")).encode() + b"\n"] + lines[19:])

for label, stream, presented_sidecar in (
    ("baseline", raw, None),
    ("final newline byte removed", raw[:-1], None),
    ("sidecar cut to 18 entries", raw, short),
    ("sidecar cut, line 22 altered", altered, short),
    ('binding witness repo set to ""', norepo, sidecar(norepo)),
):
    print("%-32s sha256 %s  %s" % (label, hashlib.sha256(stream).hexdigest()[:16],
                                   run(stream, presented_sidecar)))
```

```
baseline                         sha256 d0a5857384624bab  exit 3  VERIFY PARTIAL: lines=24 digests=24 ... attested_prefix_lines=18
final newline byte removed       sha256 c3c80b8a0b725331  exit 3  VERIFY PARTIAL: lines=24 digests=24 ... attested_prefix_lines=18
sidecar cut to 18 entries        sha256 d0a5857384624bab  exit 3  VERIFY PARTIAL: lines=24 digests=18 ... attested_prefix_lines=18
sidecar cut, line 22 altered     sha256 cb2c0208d0cd6d40  exit 3  VERIFY PARTIAL: lines=24 digests=18 ... attested_prefix_lines=18
binding witness repo set to ""   sha256 149032e9db4d8ce3  exit 3  VERIFY PARTIAL: lines=24 digests=24 ... attested_prefix_lines=18
```

Row 2 is the construction for H1 you asked for on 13 August: "If you have a construction for either, I will take it." Delete the final newline byte and keep the published sidecar.

The stream's sha256 moves from d0a5857384624bab to c3c80b8a0b725331, and the verifier prints the baseline's line word for word on all 7 tags. bytes_to_lines appends the missing terminator before hashing, so the digest that matched was computed over a line the file does not contain. ANCHORS_VERIFY.md says "Hashes cover the full stored line including the trailing newline byte." The last line of this stream has no such byte, and the hash that matched covered one anyway.

Rows 3 and 4 are the digest sidecar's coverage. verify_lines_against_digests fails closed when the sidecar is longer than the stream and iterates over digests when it is shorter, so 6 lines get no comparison at all.

Row 4 alters line 22 inside that gap. It returns the same outcome and the same exit code as the honest stream. Both rows present a sidecar covering 18 of the 24 lines, so lines 19 through 24 are compared against nothing at all, and the one field that moves between the honest run and either of these is the digests count inside the summary line, which is neither the verdict word nor the exit code a script branches on.

That field carries the whole signal, as I read it. You have to notice it, on a line whose verdict word and exit code are identical, before learning that a quarter of the stream went unchecked. Your limits section puts fork detection at the unattested tip out of scope. That is a different claim from this one, and nothing in it says the sidecar may cover part of the file.

Row 5 is _resolve_trust_repo. With --expect-witness-repo supplied, the comparison is guarded on the stream's repository being truthy. The empty string is not. So a binding that names no repository at all satisfies the pin.

ANCHORS_VERIFY.md says "If --expect-witness-repo is set and the stream names a different repository -> fail closed." The empty string is not a different repository, so that branch presumably never runs. I have not shown a witness substitution here. The query still goes to the pinned repository. What breaks is the comparison, not the fetch. It is the narrowest of the four and the cheapest to close.

The repairs, in the order I would land them. Compare the presented stream against the pinned witness commit and stop fetching main. Failing that, say in the outcome that the verdict was taken against a branch, and name the commit it stood at. Refuse a sidecar that does not cover every presented line, with its own stop reason, because "shorter" and "longer" are different failures and only one of them is caught today.

Split lines on the newline byte over raw bytes with no terminator appended, so a final line without one fails rather than being repaired into a line that hashes. Treat a falsy witness repository in a binding as absent and fail closed on it.

Every construction here carries a stop reason as well as a verdict, and the runner scores both, because of what you wrote on 20 August: "any branch that can emit a verdict without evaluating the property must say so in the verdict itself." And the operative half of it, in your words again: "assert on the stop reason, not the verdict column."

Scored that way, one member turns up an instance of exactly that in your own history. A binding whose byte_length is JSON JSON true is a type error, and from v0.4 through v0.8 the verifier reached the correct verdict from a value comparison instead:

```
position binding at line 19: witness prefix byte length 164 does not equal attested True
```

Right answer, and the type check it appears to be enforcing never ran. v0.9 stops at invalid byte_length. A run scoring the verdict column alone reports both tags as passes and cannot tell you which one closed anything.

All of this is a corpus rather than a list, and it is at https://github.com/probityai/agent-evidence-vectors under corpora/vectors-anchor-stream/. It runs against any tag with one command and no install, because it is stdlib Python for the same reason your verifier is a single file:

```
python3 run_verifier.py --verifier /path/to/anchors_verify.py --label v0.10
```

27 of its 32 members agree with v0.10. The 5 that do not are the findings above. It also carries a ratchet: --expect recordings/anchors-verify-v0.10.json refuses only when a member that agreed stops agreeing, and stays silent about the members already recorded as disagreeing, so it can sit in a build without going red on arrival. I have a draft pull request that vendors the directory into conformance/anchor-stream/ with one path-filtered workflow, borrowing the Python setup census-diff.yml already uses, so your own CI tells you when a change to anchors_verify.py breaks a member. Say the word and I will open it; say no and nothing above depends on it.

The four repairs turn streams that return PARTIAL today into FAILED, so by your own convention they ship as a new tag and v0.10 stays where it is.

Do you want the four separately, so each is a tag whose diff is one rule, or in one?
