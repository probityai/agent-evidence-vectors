#!/usr/bin/env bash
#
# Prove that .githooks/pre-push runs the identity scanner, and the rules file
# the scanner reads, from the commit being pushed, and never from the main
# clone's working tree.
#
# Origin, 2026-10-21: a push from a linked worktree ran the scanner sitting in
# the main clone, which was 715 commits behind origin/main. That copy refused a
# vector family the branch's own scanner passes. The same stale copy would
# also pass a string a newer rule forbids, which is the direction nobody sees.
#
# The throwaway repository below plays both parts. Its main checkout holds an
# uncommitted scanner and rules file that disagree with the branch, and the
# push is made from a linked worktree, exactly as a lane pushes. A hook that
# reads the main checkout gets every case below wrong.
#
#     scripts/prepush-own-scanner-test.sh                 # test this repo's hook
#     scripts/prepush-own-scanner-test.sh /path/to/hook   # test another hook
#     scripts/prepush-own-scanner-test.sh --mutate        # also prove each case bites
#
# --mutate builds three broken copies of the hook (scanner read from the main
# checkout, rules file not extracted with the scanner, fallback made silent)
# and requires each of them to fail at least one case. Run it against the hook
# as it stood before this change and cases 1 and 2 fail.

set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd -P)"
mutate=0
if [ "${1:-}" = "--one" ]; then
	:
elif [ "${1:-}" = "--mutate" ]; then
	mutate=1
	shift
fi
if [ "${1:-}" = "--one" ]; then hook="$2"; else hook="${1:-$here/.githooks/pre-push}"; fi
hook="$(cd "$(dirname "$hook")" && pwd -P)/$(basename "$hook")"

run_cases() {
	local hook="$1"
	local work repo origin wt hooktmp failures=0 rc out
	work="$(mktemp -d "${TMPDIR:-/tmp}/prepush-own-scanner-test.XXXXXXXX")"
	# The hook's own temporary directories land here, so the leak check counts
	# only what the hook made.
	hooktmp="$work/hooktmp"
	mkdir -p "$hooktmp"
	repo="$work/repo"
	origin="$work/origin.git"
	wt="$work/lane"
	ZERO="0000000000000000000000000000000000000000"

	git init -q --bare "$origin"
	git init -q -b main "$repo"
	git -C "$repo" config user.email prepush-test@invalid
	git -C "$repo" config user.name "Prepush Test"
	git -C "$repo" config commit.gpgsign false
	mkdir -p "$repo/.githooks" "$repo/scripts"
	cp "$hook" "$repo/.githooks/pre-push"
	cp "$here/.githooks/commit-msg" "$repo/.githooks/commit-msg"
	chmod +x "$repo/.githooks/pre-push" "$repo/.githooks/commit-msg"
	printf 'import sys\nsys.exit(0)\n' >"$repo/scripts/push-hygiene.py"

	# A stand-in scanner: it prints which copy of the code ran and what the rules
	# file beside it says, and refuses unless the rules say ALLOW. It finds the
	# rules from its own __file__, as the real scanner finds its sidecars.
	write_scanner() {
		local dest="$1" label="$2"
		cat >"$dest/scripts/pre-push-identity-scan.py" <<PY
import pathlib
import sys

sys.stdin.read()
rules = pathlib.Path(__file__).resolve().parent.parent / ".githooks" / "scan-rules.txt"
if not rules.is_file():
    print("SCANNER-SAW: $label no-rules-file")
    sys.exit(2)
verdict = rules.read_text().strip()
print(f"SCANNER-SAW: $label {verdict}")
sys.exit(0 if verdict == "ALLOW" else 1)
PY
	}
	write_scanner "$repo" origin
	printf 'ALLOW\n' >"$repo/.githooks/scan-rules.txt"
	uv venv -q --python 3.13 "$repo/.venv"
	printf '.venv/\n' >"$repo/.gitignore"
	git -C "$repo" add -A
	git -C "$repo" commit -q -m "chore: add the hooks under test"
	git -C "$repo" remote add origin "$origin"
	git -C "$repo" push -q --no-verify origin main
	git -C "$repo" fetch -q origin
	git -C "$repo" worktree add -q -b lane "$wt" main

	# The main checkout goes stale: its working tree carries another scanner and
	# the opposite rules, uncommitted, which is all a hook reading it can see.
	set_main_checkout() {
		write_scanner "$repo" stale
		printf '%s\n' "$1" >"$repo/.githooks/scan-rules.txt"
	}

	lane_commit() {
		git -C "$wt" add -A
		git -C "$wt" commit -q --no-verify -m "$1"
		git -C "$wt" rev-parse HEAD
	}

	# Run the hook the way git runs it for a push from a linked worktree: at the
	# top of that worktree, with that worktree's repository environment exported.
	run_hook() {
		local sha="$1"
		set +e
		out="$(cd "$wt" && printf 'refs/heads/lane %s refs/heads/lane %s\n' "$sha" "$ZERO" |
			TMPDIR="$hooktmp" GIT_DIR="$repo/.git/worktrees/lane" GIT_WORK_TREE="$wt" \
				./.githooks/pre-push origin "file://$origin" 2>&1)"
		rc=$?
		set -e
	}

	check() {
		local label="$1" want_zero="$2"
		shift 2
		local ok=1 needle
		if [ "$want_zero" = yes ] && [ "$rc" -ne 0 ]; then ok=0; fi
		if [ "$want_zero" = no ] && [ "$rc" -eq 0 ]; then ok=0; fi
		for needle in "$@"; do
			printf '%s' "$out" | grep -qF -- "$needle" || ok=0
		done
		if [ "$ok" -eq 1 ]; then
			echo "PASS  $label"
		else
			failures=$((failures + 1))
			echo "FAIL  $label  (exit $rc, wanted zero=$want_zero, wanted text: $*)"
			printf '%s\n' "$out" | sed 's/^/      /'
		fi
	}

	# 1. The case that was reported: the pushed scanner passes, the main
	#    checkout's would refuse. The push must pass, judged by the lane's copy.
	echo "--- 1. pushed scanner passes, main checkout's scanner would refuse"
	set_main_checkout DENY
	write_scanner "$wt" branch
	printf 'case\n' >"$wt/family.txt"
	sha1="$(lane_commit "test: add a family the stale scanner refuses")"
	run_hook "$sha1"
	check "the pushed commit's scanner decides, not the main checkout's" yes \
		"SCANNER-SAW: branch ALLOW" "scanned by the scanner committed at $(printf '%.12s' "$sha1")"

	# 2. The silent direction: the pushed rules refuse, the main checkout's
	#    would pass. Only the rules file changes on the lane, so this also proves
	#    the rules come from the same tree as the scanner.
	echo "--- 2. pushed rules refuse, main checkout's rules would pass"
	set_main_checkout ALLOW
	printf 'DENY\n' >"$wt/.githooks/scan-rules.txt"
	sha2="$(lane_commit "test: tighten the scan rules")"
	run_hook "$sha2"
	check "the pushed commit's rules file decides, not the main checkout's" no \
		"SCANNER-SAW: branch DENY" "REFUSED -- a commit in refs/heads/lane"

	# 3. A pushed tree without a scanner is judged by origin/main's committed
	#    copy, and says so. It never falls back to the main checkout.
	echo "--- 3. pushed tree has no scanner"
	set_main_checkout DENY
	printf 'ALLOW\n' >"$wt/.githooks/scan-rules.txt"
	git -C "$wt" rm -q scripts/pre-push-identity-scan.py
	sha3="$(lane_commit "test: drop the scanner")"
	run_hook "$sha3"
	check "a missing scanner falls back to origin/main, visibly" yes \
		"SCANNER-SAW: origin ALLOW" "WARNING -- $(printf '%.12s' "$sha3") carries no scripts/pre-push-identity-scan.py" \
		"judged by the copy committed at origin/main"

	# 4. Neither the pushed tree nor origin/main has one: the push is refused.
	echo "--- 4. no scanner anywhere"
	origin_main="$(git -C "$repo" rev-parse refs/remotes/origin/main)"
	git -C "$repo" update-ref -d refs/remotes/origin/main
	run_hook "$sha3"
	git -C "$repo" update-ref refs/remotes/origin/main "$origin_main"
	check "no scanner in the pushed tree or origin/main refuses the push" no \
		"ABORT -- neither" "history guard is absent"

	# 5. Nothing the hook extracted is left behind.
	echo "--- 5. no leaked extraction"
	strays="$(find "$hooktmp" -mindepth 1 -maxdepth 1 | wc -l)"
	if [ "$strays" -eq 0 ]; then
		echo "PASS  leaves no extracted guard tree behind"
	else
		failures=$((failures + 1))
		echo "FAIL  $strays entries left in the hook's temporary directory"
		find "$hooktmp" -mindepth 1 -maxdepth 1 | sed 's/^/      /'
	fi

	rm -rf "$work"
	return "$failures"
}

# Each run is its own process, so set -e holds inside it (bash ignores set -e in
# a function called from an `||` or `if` context) and nothing it exports leaks.
if [ "${1:-}" = "--one" ]; then
	run_cases "$2"
	exit 0
fi

failures=0
bash "$0" --one "$hook" || failures=1
if [ "$failures" -ne 0 ]; then
	echo "prepush-own-scanner-test: $failures case(s) FAILED for $hook"
	exit 1
fi
echo "prepush-own-scanner-test: all 5 cases passed for $hook"

if [ "$mutate" -eq 1 ]; then
	mutdir="$(mktemp -d "${TMPDIR:-/tmp}/prepush-own-scanner-mutants.XXXXXXXX")"
	trap 'rm -rf "$mutdir"' EXIT
	# Each mutant must change the hook (a sed that matches nothing proves
	# nothing) and must fail at least one case.
	mutant() {
		local name="$1" expr="$2" file="$mutdir/$1"
		sed -e "$expr" "$hook" >"$file"
		if cmp -s "$hook" "$file"; then
			echo "MUTANT $name: the edit matched nothing in the hook; the check proves nothing" >&2
			exit 1
		fi
		if bash "$0" --one "$file" >"$file.log" 2>&1; then
			echo "MUTANT $name SURVIVED: every case passed" >&2
			exit 1
		fi
		echo "MUTANT $name killed ($(grep -c '^FAIL' "$file.log") case(s) failed)"
	}
	mutant reads-main-checkout \
		's#range_scan="$(require_guard "$local_sha" scripts/pre-push-identity-scan.py "history guard")" || exit 1#range_scan="$src_root/scripts/pre-push-identity-scan.py"#'
	mutant rules-not-extracted 's|for p in scripts .githooks .github; do|for p in scripts .github; do|'
	mutant silent-fallback 's|printf .pre-push: WARNING -- %.12s carries no %s; it is judged by the copy committed at origin/main (%.12s) instead.\\n. \\|: \\|'
	echo "prepush-own-scanner-test: all 3 mutants killed"
fi
