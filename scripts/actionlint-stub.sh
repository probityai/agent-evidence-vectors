#!/bin/sh
# Stand-in for actionlint in tests that run .githooks/pre-push. The hook aborts when
# actionlint is missing (correct, and kept); a runner image does not carry it, so the
# tests that are not about the workflow check put this in front of the hook.
exit 0
