#!/usr/bin/env bash
#
# Prove that .githooks/pre-push lints the commit messages of the pushed range.
#
# The commit-msg hook is advisory: `git commit --no-verify`, or a clone whose
# core.hooksPath was never set, skips it. This test makes such a commit in a
# throwaway repository and feeds the hook git's pre-push protocol on stdin. The
# hook must refuse the push carrying the bad subject and pass the push carrying
# only good ones. Nothing is pushed anywhere.
#
#     scripts/prepush-commit-msg-test.sh                 # test this repo's hook
#     scripts/prepush-commit-msg-test.sh /path/to/hook   # test another hook
#
# The leak tier's other checks are replaced by stand-ins that always pass, so the
# only check that can refuse is the one under test.

set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd -P)"
hook="${1:-$here/.githooks/pre-push}"
hook="$(cd "$(dirname "$hook")" && pwd -P)/$(basename "$hook")"

work="$(mktemp -d "${TMPDIR:-/tmp}/prepush-commit-msg-test.XXXXXXXX")"
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
origin="$work/origin.git"
failures=0
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
for stub in pre-push-identity-scan.py push-hygiene.py; do
	printf 'import sys\nsys.stdin.read() if not sys.stdin.isatty() else None\nsys.exit(0)\n' \
		>"$repo/scripts/$stub"
done
# The venv bootstrap is the hook's own business; give it one so the test does
# not depend on network access.
uv venv -q --python 3.13 "$repo/.venv"

git -C "$repo" add -A
git -C "$repo" commit -q -m "chore: add the hooks under test"
git -C "$repo" remote add origin "$origin"
git -C "$repo" push -q --no-verify origin main
base="$(git -C "$repo" rev-parse HEAD)"

run_hook() {
	local sha="$1"
	set +e
	out="$(cd "$repo" && printf 'refs/heads/main %s refs/heads/main %s\n' "$sha" "$base" |
		./.githooks/pre-push origin "file://$origin" 2>&1)"
	rc=$?
	set -e
}

check() {
	local label="$1" want="$2" needle="$3"
	if [ "$rc" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
		echo "PASS  $label"
	else
		failures=$((failures + 1))
		echo "FAIL  $label  (exit $rc, wanted $want, wanted text: $needle)"
		printf '%s\n' "$out" | sed 's/^/      /'
	fi
}

# 1. A good subject passes the message check.
printf 'one\n' >"$repo/a.txt"
git -C "$repo" add -A
git -C "$repo" commit -q --no-verify -m "feat: add the first file"
good="$(git -C "$repo" rev-parse HEAD)"
run_hook "$good"
check "a range of good subjects passes" 0 "checked 1 commit message(s)"

# 2. A subject over 72 characters, committed past the commit-msg hook, is refused.
printf 'two\n' >"$repo/b.txt"
git -C "$repo" add -A
git -C "$repo" commit -q --no-verify \
	-m "fix(site): copy the invocation-binding schema into the navigation test fixture"
bad="$(git -C "$repo" rev-parse HEAD)"
run_hook "$bad"
check "a 78-character subject in the range is refused" 1 "REFUSED -- a commit message"

# 3. The refusal names the commit and the rule, not only an exit code.
check "the refusal names the rule" 1 "subject line is 78 chars; max is 72"

# 4. A range the gate cannot resolve aborts rather than passing.
run_hook "1111111111111111111111111111111111111111"
check "an unresolvable range aborts" 1 "ABORT -- the commit-message check could not run"

if [ "$failures" -ne 0 ]; then
	echo "prepush-commit-msg-test: $failures case(s) FAILED"
	exit 1
fi
echo "prepush-commit-msg-test: all 4 cases passed"
