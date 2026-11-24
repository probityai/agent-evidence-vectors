#!/usr/bin/env bash
#
# Prove that .githooks/pre-push gates the REVISION BEING PUSHED and not the
# working tree.
#
# The case this exists for is the second one below, and it is the one the old
# hook waved through in silence: a commit that violates a gate, plus an
# uncommitted edit that repairs the violation. The old hook read the repaired
# working tree, went green, and let a red commit reach the remote. Nothing about
# that failure was visible from inside a push -- there was no output, no warning
# and no slow step, because the gate genuinely passed. It was just answering a
# question about a tree nobody was pushing.
#
# The hook under test is run against a throwaway repository, never against this
# one, and nothing is ever pushed anywhere: git's own hook protocol is fed on
# stdin and git's own hook environment is exported, which is all a real push
# does that the hook can observe.
#
#     scripts/prepush-isolation-test.sh                 # test this repo's hook
#     scripts/prepush-isolation-test.sh /path/to/hook   # test some other hook
#
# The second form is how the fix was verified: run it against the hook as it
# stood before the change and cases 1, 3, 4 and 5 fail; run it against the hook
# as it stands now and all six pass.

set -euo pipefail

# shellcheck source=scripts/prepush-test-lib.sh
. "$(dirname "$0")/prepush-test-lib.sh"
prepush_actionlint_stub

hook="${1:-$(cd "$(dirname "$0")/.." && pwd -P)/.githooks/pre-push}"
if [ ! -f "$hook" ]; then
	echo "prepush-isolation-test: no hook at $hook" >&2
	exit 1
fi
hook="$(cd "$(dirname "$hook")" && pwd -P)/$(basename "$hook")"

work="$(mktemp -d "${TMPDIR:-/tmp}/prepush-isolation-test.XXXXXXXX")"
repo="$work/repo"
trap 'rm -rf "$work"' EXIT

failures=0
ZERO="0000000000000000000000000000000000000000"

note() { printf '\n--- %s\n' "$1"; }

# ---------------------------------------------------------------------------
# A throwaway repository whose whole gate is one question: what does MARKER say?
# The stand-in gate resolves the repository from its own __file__, exactly as
# scripts/workflow-steps-gate.py does, so "which tree did the gate read" is
# answered by the tree the gate script was loaded from -- which is the property
# under test.
# ---------------------------------------------------------------------------
git init -q "$repo"
git -C "$repo" config user.email prepush-test@invalid
git -C "$repo" config user.name "Prepush Test"
git -C "$repo" config commit.gpgsign false
git -C "$repo" config core.hooksPath .githooks
mkdir -p "$repo/.githooks" "$repo/scripts"
cp "$hook" "$repo/.githooks/pre-push"
chmod +x "$repo/.githooks/pre-push"

cat >"$repo/scripts/workflow-steps-gate.py" <<'PY'
#!/usr/bin/env python3
"""Stand-in gate: passes when MARKER says OK, and says which tree it read."""
import pathlib
import sys

repo = pathlib.Path(__file__).resolve().parent.parent
marker = (repo / "MARKER").read_text().strip()
print(f"GATE-SAW: {marker}")
sys.exit(0 if marker == "OK" else 1)
PY

commit_marker() {
	printf '%s\n' "$1" >"$repo/MARKER"
	git -C "$repo" add -A
	git -C "$repo" commit -q -m "marker: $1"
	git -C "$repo" rev-parse HEAD
}

# Run the hook the way git runs it: at the top of the working tree, with the
# repository environment exported, the remote name and URL in argv, and one
# protocol line per ref on stdin. Exporting GIT_DIR and friends is not
# decoration -- they are what makes an isolated checkout answer with the wrong
# tree if the hook does not clear them.
run_hook() {
	local stdin_lines="$1"
	set +e
	out="$(
		cd "$repo" && printf '%s' "$stdin_lines" | \
			GIT_DIR="$repo/.git" \
			GIT_WORK_TREE="$repo" \
			GIT_INDEX_FILE="$repo/.git/index" \
			./.githooks/pre-push origin "file://$repo" 2>&1
	)"
	rc=$?
	set -e
}

check() {
	local label="$1" want_rc_zero="$2" want_saw="$3"
	local ok=1
	if [ "$want_rc_zero" = "yes" ] && [ "$rc" -ne 0 ]; then ok=0; fi
	if [ "$want_rc_zero" = "no" ] && [ "$rc" -eq 0 ]; then ok=0; fi
	# -none- is a sentinel meaning "the gate must not have run at all", and it
	# has to be tested BEFORE the literal-match branch. Written the other way
	# round it is itself a literal to search for, never found, and every case
	# using it fails while the hook is behaving correctly -- which is what the
	# first run of this file did to cases 3 and 4.
	if [ "$want_saw" = "-none-" ]; then
		if printf '%s' "$out" | grep -qF "GATE-SAW:"; then ok=0; fi
	elif [ -n "$want_saw" ]; then
		if ! printf '%s' "$out" | grep -qF "GATE-SAW: $want_saw"; then ok=0; fi
	fi
	if [ "$ok" -eq 1 ]; then
		echo "PASS  $label"
	else
		failures=$((failures + 1))
		echo "FAIL  $label  (exit $rc, wanted-zero=$want_rc_zero, wanted-saw=$want_saw)"
		printf '%s\n' "$out" | sed 's/^/      /'
	fi
}

# ---------------------------------------------------------------------------
# 1. FALSE PASS -- the reason this file exists.
#    The commit violates the gate. The working tree repairs it and is not
#    committed. The push must be REFUSED, and the gate must have read the
#    committed violation rather than the uncommitted repair.
# ---------------------------------------------------------------------------
note "1. committed state violates the gate, working tree repairs it"
broken_sha="$(commit_marker BROKEN)"
printf 'OK\n' >"$repo/MARKER" # uncommitted repair
run_hook "refs/heads/main $broken_sha refs/heads/main $ZERO
"
check "refuses a broken commit that an uncommitted edit repairs" no BROKEN

# ---------------------------------------------------------------------------
# 2. FALSE REFUSAL -- the visible half of the same defect.
#    The commit satisfies the gate. The working tree is broken and unrelated.
#    The push must be ALLOWED.
# ---------------------------------------------------------------------------
note "2. committed state is clean, working tree is broken"
git -C "$repo" checkout -q -- MARKER
clean_sha="$(commit_marker OK)"
printf 'BROKEN\n' >"$repo/MARKER"                    # uncommitted breakage
printf 'not valid anything\n' >"$repo/unrelated.txt" # and an unrelated one
run_hook "refs/heads/main $clean_sha refs/heads/main $ZERO
"
check "allows a clean commit while the working tree is broken" yes OK

# ---------------------------------------------------------------------------
# 3. A delete-only push names no revision, so there is nothing to gate.
# ---------------------------------------------------------------------------
note "3. delete-only push"
run_hook "(delete) $ZERO refs/heads/gone $clean_sha
"
check "skips a delete-only push without running the gate" yes -none-

# ---------------------------------------------------------------------------
# 4. Empty stdin is not a push. It must not be answered by reading whatever
#    tree happens to be lying around.
# ---------------------------------------------------------------------------
note "4. empty stdin"
run_hook ""
check "refuses when no revision was named" no -none-

# ---------------------------------------------------------------------------
# 5. A push can carry several refs. Every one of them is gated, not just the
#    first line on stdin.
# ---------------------------------------------------------------------------
note "5. two refs, the second one broken"
# The working tree is repaired first, on purpose. Left broken, a hook that reads
# the working tree refuses this case too and scores a pass it has not earned --
# the first version of this file did exactly that, and case 5 discriminated
# nothing. With the working tree clean, only a hook that actually reads the
# SECOND ref can find anything wrong.
printf 'OK\n' >"$repo/MARKER"
run_hook "refs/heads/main $clean_sha refs/heads/main $ZERO
refs/heads/topic $broken_sha refs/heads/topic $ZERO
"
check "gates every ref on stdin, not only the first" no BROKEN

# ---------------------------------------------------------------------------
# 6. Nothing is left behind. A leaked worktree registration poisons the next
#    run, and it is discovered far too late.
# ---------------------------------------------------------------------------
note "6. no leaked checkouts"
worktrees="$(git -C "$repo" worktree list | wc -l)"
# DIRECTORIES the hook itself creates, and only those. The first version of this
# counted `-name '*prepush.*'` with no type filter across the whole temp
# directory, so it matched any file any process had ever left there whose name
# contained the word -- including two scratch files from a debugging session
# three days earlier. It reported "2 stray directories" against a hook that had
# leaked nothing, and the hook was very nearly discarded as broken on the
# strength of it. A leak detector that fires on somebody else's litter cannot
# tell a leak from a neighbour.
strays="$(find "${TMPDIR:-/tmp}" "$(dirname "$repo")" -maxdepth 1 -type d \
	\( -name 'aee-prepush.*' -o -name '.*-prepush.*' \) 2>/dev/null | wc -l)"
if [ "$worktrees" -eq 1 ] && [ "$strays" -eq 0 ]; then
	echo "PASS  leaves no worktree registration and no checkout directory"
else
	failures=$((failures + 1))
	echo "FAIL  leaked state: $worktrees worktree entries (want 1), $strays stray directories (want 0)"
	git -C "$repo" worktree list | sed 's/^/      /'
fi

printf '\n%s\n' "-----------------------------------------------------------"
if [ "$failures" -eq 0 ]; then
	echo "prepush-isolation-test: all 6 cases passed for $hook"
	exit 0
fi
echo "prepush-isolation-test: $failures case(s) failed for $hook"
exit 1
