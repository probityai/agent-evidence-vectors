# Run the pre-push gate on a build pool

Install the tracked hooks with `bash .githooks/install.sh`. The hook checks the
push history and every selected revision before Git sends any ref.

`AEV_PRE_PUSH_VENUE=local` is the default. It runs the complete committed workflow
gate on the machine that issues the push.

Set `AEV_PRE_PUSH_VENUE=pool` when that machine must send heavy work to a build
pool. Put the installed `box_run.sh` on `PATH`. Other venue values refuse the
push. The pool bridge does not push or need GitHub credentials.

```sh
AEV_PRE_PUSH_VENUE=pool git push origin my-reviewed-branch
```

The pool driver creates a separate job. The bridge restores the selected pushed
commit and checks its tree, tags, origin, hook, and gate before any workflow step.
It runs the same complete gate without workflow selection flags. Native steps
receive a defined environment without SSH agents or API tokens.

The bridge retains the original result, logs, source capture, and reports in a
compressed archive. It receives the archive through the pool driver's SSH route
and checks every member before the original Git push continues. A missing
runner, receipt, archive, source binding, or native result refuses the push.
Failure captures stay available at the printed evidence directory.

Archive and member hashes use 1 MiB read buffers. Gzip decoding feeds the tar
reader through a buffered stream, so a highly compressed member does not
expand into one allocation. The checker keeps the member metadata and four
JSON contracts in memory; it streams the other original files. It checks the
gzip footer and CRC. The archive validation record reports compressed bytes,
original file bytes, original file count and largest original file. These totals
exclude directory entries and the generated manifest. No size limit is imposed.
If archive storage itself refuses, the original native scratch stays available
at its printed location.

The native result lists steps that ran and steps that did not run locally.
Pool execution does not turn hosting-only steps into passes. Check the remote
workflows at the pushed commit after Git completes.

Timestamp captures keep the three fixed public validation inputs only when
their bytes match the selected public source and candidate manifest. Arbitrary
certificate or key files do not enter the archive through their suffix.
