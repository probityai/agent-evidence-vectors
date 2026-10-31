#!/usr/bin/env bash
# Developer Certificate of Origin check for one pull request.
#
# Every commit the pull request adds must carry a trailer of the form
#
#     Signed-off-by: Full Name <email>
#
# whose email is the commit author's email (compared without regard to case).
# CONTRIBUTING.md says what the sign-off certifies and how to add one. Three
# kinds of commit are not asked for a sign-off:
#
#   - merge commits, which add no authored change of their own;
#   - commits by GitHub bot accounts (a login ending in "[bot]"), which cannot
#     certify anything;
#   - commits by a maintainer: a login listed in DCO_MAINTAINERS (space
#     separated, set in the workflow on the base branch), or the pull request's
#     own author when GitHub reports that author as an owner, member or
#     collaborator. Maintainers license their own work under the repository
#     licence by publishing it, and their commits can reach an outside pull
#     request that was branched from unmerged maintainer work;
#   - history imported from another public repository: every commit reachable
#     from the second parent of a merge whose subject is
#     "chore(<dir>): import <owner>/<repo> with its history" and whose author
#     is a maintainer (scripts/consolidation/repo_import.py writes that merge).
#     Those commits were published, with their licence, in the source
#     repository before the import; the import adds no authored change.
#
# The commits are read with git from the pull request's head ref, which the
# script fetches, so a pull request of any size is checked (the pulls API
# lists at most 250 commits). Nothing from the pull request is run.
#
# Usage:
#   dco-check.sh OWNER/REPO PR_NUMBER   check a pull request (needs gh and jq,
#                                       authenticated through GH_TOKEN)
#   dco-check.sh --selftest             run the sign-off rule against fixtures
#
# Exit status: 0 every commit passes; 1 at least one commit lacks a valid
# sign-off; 2 the check could not run, so nothing was verified.

set -uo pipefail

# has_signoff EMAIL MESSAGE: succeed when MESSAGE has a Signed-off-by trailer
# naming EMAIL.
has_signoff() {
  local want
  want=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  [ -n "$want" ] || return 1
  printf '%s\n' "$2" | tr '[:upper:]' '[:lower:]' | awk -v want="<$want>" '
    /^signed-off-by: [^<]*[^<[:space:]][^<]* <[^>]+>[[:space:]]*$/ {
      sub(/[[:space:]]+$/, "")
      if (substr($0, length($0) - length(want) + 1) == want) found = 1
    }
    END { exit found ? 0 : 1 }'
}

selftest() {
  local failed=0
  expect() {
    local verdict=$1 email=$2 message=$3 label=$4 got=fail
    if has_signoff "$email" "$message"; then got=pass; fi
    if [ "$got" = "$verdict" ]; then
      echo "ok    $label"
    else
      echo "FAIL  $label: expected $verdict, got $got"
      failed=1
    fi
  }
  expect pass a@example.org $'Fix a typo\n\nSigned-off-by: Ada Lovelace <a@example.org>' \
    "trailer naming the author"
  expect pass A@Example.org $'Fix\n\nSigned-off-by: Ada Lovelace <a@EXAMPLE.org>  ' \
    "case and trailing space are ignored"
  expect pass a@example.org $'Fix\n\nCo-authored-by: B <b@example.org>\nSigned-off-by: Ada <a@example.org>' \
    "one of several trailers"
  expect fail a@example.org $'Fix a typo' \
    "no trailer"
  expect fail a@example.org $'Fix\n\nSigned-off-by: Bob Jones <b@example.org>' \
    "trailer naming someone else"
  expect fail a@example.org $'Fix\n\nSigned-off-by: <a@example.org>' \
    "trailer without a name"
  expect fail a@example.org $'Fix\n\nSigned-off-by: Ada <xa@example.org>' \
    "an email that only ends with the author email"
  expect fail a@example.org $'Fix\n\n  Signed-off-by: Ada <a@example.org>' \
    "an indented line is not a trailer"
  expect fail a@example.org $'Fix\n\nsigned-off-by Ada <a@example.org>' \
    "missing colon"
  expect fail "" $'Fix\n\nSigned-off-by: Ada <>' \
    "an author with no email"
  import_selftest || failed=1
  return "$failed"
}

# A maintainer's import merge exempts the history behind its second parent and
# nothing else; the same merge by someone else exempts nothing.
import_selftest() {
  local dir got want
  dir=$(mktemp -d) || return 1
  (
    set -e
    cd "$dir"
    git init -q -b main .
    git -c user.name=A -c user.email=a@example.org commit -q --allow-empty -m base
    git checkout -q --orphan src
    git -c user.name=B -c user.email=b@example.org commit -q --allow-empty -m "imported, unsigned"
    git checkout -q main
    git -c user.name=A -c user.email=a@example.org merge -q --allow-unrelated-histories --no-edit src       -m "chore(packages/x): import owner/x with its history"
    git -c user.name=C -c user.email=c@example.org commit -q --allow-empty -m "new, unsigned"
  ) || { rm -rf "$dir"; echo "FAIL  import fixture could not be built"; return 1; }
  commit_login() { if [ "$(git log -1 --format=%ae "$1")" = a@example.org ]; then echo maint; else echo other; fi; }
  want=$(git -C "$dir" rev-parse src)
  got=$(cd "$dir" && DCO_MAINTAINERS=maint imported_commits main~2 main 2>/dev/null)
  if [ "$got" = "$want" ]; then echo "ok    a maintainer's import merge exempts its imported history"
  else echo "FAIL  import exemption: expected $want, got '$got'"; rm -rf "$dir"; return 1; fi
  got=$(cd "$dir" && DCO_MAINTAINERS=someone imported_commits main~2 main 2>/dev/null)
  rm -rf "$dir"
  if [ -z "$got" ]; then echo "ok    an import merge by a non-maintainer exempts nothing"
  else echo "FAIL  a non-maintainer import merge exempted '$got'"; return 1; fi
}

IMPORT_SUBJECT='^chore\([^)]+\): import [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+ with its history$'

# commit_login SHA: the GitHub login of a commit's author, or "" when none.
commit_login() {
  gh api "repos/$DCO_REPO/commits/$1" --jq '.author.login // ""'
}

# is_maintainer LOGIN
is_maintainer() {
  local maintainers=" ${DCO_MAINTAINERS:-} "
  [ -n "$1" ] && [[ "$maintainers" == *" $1 "* ]]
}

# imported_commits BASE HEAD: every commit reachable from the second parent of
# a maintainer-authored import merge in BASE..HEAD, one per line.
imported_commits() {
  local base=$1 head=$2 merge subject login
  while read -r merge; do
    [ -n "$merge" ] || continue
    subject=$(git log -1 --format=%s "$merge")
    [[ "$subject" =~ $IMPORT_SUBJECT ]] || continue
    login=$(commit_login "$merge") || return 2
    if is_maintainer "$login"; then
      echo "import ${merge:0:12}  $subject (by $login)" >&2
      git rev-list "$merge^2" "^$base"
    else
      echo "::warning::${merge:0:12} looks like an import merge but its author '$login' is not a maintainer" >&2
    fi
  done < <(git rev-list --merges "$base..$head")
}

check_pr() {
  local repo=$1 pr=$2 pr_json pr_author association expected base head listed
  DCO_REPO=$repo
  if ! pr_json=$(gh api "repos/$repo/pulls/$pr"); then
    echo "::error::could not read pull request $repo#$pr; nothing was verified"
    return 2
  fi
  pr_author=$(jq -r '.user.login' <<<"$pr_json")
  association=$(jq -r '.author_association' <<<"$pr_json")
  expected=$(jq -r '.commits' <<<"$pr_json")
  base=$(jq -r '.base.sha' <<<"$pr_json")
  head=$(jq -r '.head.sha' <<<"$pr_json")
  if ! git fetch --quiet --no-tags origin "+refs/pull/$pr/head:refs/dco/head" "$base"; then
    echo "::error::could not fetch the commits of $repo#$pr; nothing was verified"
    return 2
  fi
  listed=$(git rev-list --count "$base..$head") || return 2
  if [ "$listed" != "$expected" ]; then
    echo "::error::$repo#$pr has $expected commits and git lists $listed between its base and head; nothing was verified"
    return 2
  fi

  local maintainer=0
  case "$association" in OWNER | MEMBER | COLLABORATOR) maintainer=1 ;; esac
  echo "pull request $repo#$pr by $pr_author ($association), $expected commits"

  local imported
  imported=$(imported_commits "$base" "$head") || {
    echo "::error::could not read an import merge's author; nothing was verified"
    return 2
  }
  declare -A skip_import=()
  local sha
  for sha in $imported; do skip_import[$sha]=1; done
  echo "${#skip_import[@]} commit(s) are imported history"

  local failures=0 login email parents short
  while read -r sha; do
    short=${sha:0:12}
    if [ -n "${skip_import[$sha]:-}" ]; then
      continue
    fi
    parents=$(git rev-list --parents -n 1 "$sha" | awk '{ print NF - 1 }')
    if [ "$parents" -gt 1 ]; then
      echo "skip  $short  merge commit"
      continue
    fi
    if ! login=$(commit_login "$sha"); then
      echo "::error::could not read the author of $short; nothing was verified"
      return 2
    fi
    email=$(git log -1 --format=%ae "$sha")
    if [[ "$login" == *'[bot]' ]]; then
      echo "skip  $short  bot account $login"
    elif is_maintainer "$login"; then
      echo "skip  $short  maintainer $login"
    elif [ "$maintainer" = 1 ] && [ "$login" = "$pr_author" ]; then
      echo "skip  $short  maintainer $login (the pull request's author)"
    elif has_signoff "$email" "$(git log -1 --format=%B "$sha")"; then
      echo "ok    $short  signed off by $email"
    else
      echo "::error::commit $short has no 'Signed-off-by: Name <$email>' trailer matching its author"
      failures=$((failures + 1))
    fi
  done < <(git rev-list --reverse "$base..$head")

  if [ "$failures" -gt 0 ]; then
    echo "$failures commit(s) lack a sign-off. Add one with 'git commit --amend --signoff'"
    echo "(or 'git rebase --signoff' for several), then force-push the branch."
    return 1
  fi
  echo "every commit that needs a sign-off has one"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") echo "usage: dco-check.sh OWNER/REPO PR_NUMBER | --selftest" >&2; exit 2 ;;
  *)
    if [ -z "${2:-}" ]; then
      echo "usage: dco-check.sh OWNER/REPO PR_NUMBER | --selftest" >&2
      exit 2
    fi
    check_pr "$1" "$2"
    ;;
esac
