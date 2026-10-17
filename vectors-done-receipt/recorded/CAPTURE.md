# Recorded runs

Twelve runs of an unmodified agent in a docker container under the observer's
launcher. The generators read these directories and never rebuild them: every
timestamp, digest and image id in them is what the launcher wrote.

- Launcher: `probity_observer.launch` of agent-evidence-observer, branch
  `lane/l2-launcher-sensors`, snapshot commit `6bca3d6f51f7f9589c437dda7970f37cbdb5ccc4`
  (parent `2b06aa2`), run with `capture.py` (in this directory) copied to
  `tests/launch/`.
- Host: a Linux gate box, docker 29.1.3, strace 6.13 inside the image
  `tests/launch/image` of that checkout. Captured on 2026-10-17.
- Workspaces were created under `/tmp/l5-capture/<run>/ws`; no other host path is
  recorded.
- Each directory holds the launch record, the launch receipt (the launcher's
  `receipt.json`), the observation, capability and tree records, the contract and
  the claims the run was checked against, the agent's transcript and the raw
  tracer output (`trace.txt`, whose digest the launch receipt carries). Four runs
  (`honest`, `protected-edit`, `spoofed-output`, `pth-injection`) also hold
  `grade.json`, from a fresh container that ran the acceptance command on the final
  tree after the protected paths were restored from the sealed start state.
- The contract's `adequacy` (`mutants: 1, killed: 1`) is fixed by `capture.py`, not
  measured.
- The `lost-events` run is the tracer killed from the host mid-run. The
  `direct-host-write` run is a write to a protected file from the host during the
  run, which the host sensor sees and the trace does not.

`MANIFEST.json` lists the SHA-256 of every file.
