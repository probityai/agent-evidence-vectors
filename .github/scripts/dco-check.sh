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
#     request that was branched from unmerged maintainer work.
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
  return "$failed"
}

check_pr() {
  local repo=$1 pr=$2 pr_json pr_author association expected commits listed
  if ! pr_json=$(gh api "repos/$repo/pulls/$pr"); then
    echo "::error::could not read pull request $repo#$pr; nothing was verified"
    return 2
  fi
  pr_author=$(jq -r '.user.login' <<<"$pr_json")
  association=$(jq -r '.author_association' <<<"$pr_json")
  expected=$(jq -r '.commits' <<<"$pr_json")
  if ! commits=$(gh api --paginate "repos/$repo/pulls/$pr/commits?per_page=100" \
      --jq '.[] | [.sha, (.author.login // ""), (.commit.author.email // ""),
                   (.parents | length), (.commit.message | @base64)] | @tsv'); then
    echo "::error::could not list the commits of $repo#$pr; nothing was verified"
    return 2
  fi
  listed=$(printf '%s' "$commits" | awk 'NF { n++ } END { print n + 0 }')
  if [ "$listed" != "$expected" ]; then
    echo "::error::$repo#$pr has $expected commits and the API listed $listed (it lists at most 250); nothing was verified"
    return 2
  fi

  local maintainer=0 maintainers=" ${DCO_MAINTAINERS:-} "
  case "$association" in OWNER | MEMBER | COLLABORATOR) maintainer=1 ;; esac
  echo "pull request $repo#$pr by $pr_author ($association), $expected commits"

  local failures=0 sha login email parents body short
  while IFS=$'\t' read -r sha login email parents body; do
    short=${sha:0:12}
    if [ "$parents" -gt 1 ]; then
      echo "skip  $short  merge commit"
    elif [[ "$login" == *'[bot]' ]]; then
      echo "skip  $short  bot account $login"
    elif [ -n "$login" ] && [[ "$maintainers" == *" $login "* ]]; then
      echo "skip  $short  maintainer $login"
    elif [ "$maintainer" = 1 ] && [ "$login" = "$pr_author" ]; then
      echo "skip  $short  maintainer $login (the pull request's author)"
    elif has_signoff "$email" "$(printf '%s' "$body" | base64 -d)"; then
      echo "ok    $short  signed off by $email"
    else
      echo "::error::commit $short has no 'Signed-off-by: Name <$email>' trailer matching its author"
      failures=$((failures + 1))
    fi
  done <<<"$commits"

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
