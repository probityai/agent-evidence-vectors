#!/usr/bin/env bash
export UV_PYTHON=3.13
uv sync --locked --extra dev --extra generators > intake-sync.log 2>&1
uv run --locked --extra generators python scripts/gen-intake-records.py > intake-gen.log 2>&1
echo GEN_RC=$?
mkdir -p intakeout
git diff --stat > intakeout/diff.stat
git diff > intakeout/diff.patch
git status --short > intakeout/status.txt
tail -5 intake-gen.log
exit 0
