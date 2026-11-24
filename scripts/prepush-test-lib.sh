#!/bin/bash
# Shared by every shell test that runs .githooks/pre-push. Source it, then call
# prepush_actionlint_stub: when actionlint is not on PATH it puts the stand-in
# scripts/actionlint-stub.sh in front, so the hook's workflow check can run. A real
# actionlint is left alone. The hook's own refusal when it is missing stays.

prepush_actionlint_stub() {
	local lib_dir stubdir
	lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
	command -v actionlint > /dev/null 2>&1 && return 0
	stubdir="$(mktemp -d "${TMPDIR:-/tmp}/actionlint-stub.XXXXXXXX")"
	cp "$lib_dir/actionlint-stub.sh" "$stubdir/actionlint"
	chmod +x "$stubdir/actionlint"
	PATH="$stubdir:$PATH"
	export PATH
}
