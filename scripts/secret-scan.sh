#!/usr/bin/env bash
#
# The one secret scan. The secret-scan workflow and the pre-push hook both call
# this file, so the version, the tarball hash, the flags and the config cannot
# drift apart between the two.
#
# Origin, 2026-10-25: CI's gitleaks reported four findings that a local run of
# the same version did not. The local run read a different binary (an unpinned
# build) and the hook ran no secret scan at all; CI also scanned every branch
# the checkout fetched, so a commit on an unmerged pull-request branch turned
# main red.
#
# Usage:
#   scripts/secret-scan.sh [--repo DIR] [--config FILE] [--range REVS]
#
#   --repo    repository to scan (default: the current directory)
#   --config  gitleaks config (default: DIR/.gitleaks.toml)
#   --range   revisions handed to git log (default: HEAD, its whole history)
#
# Exit status: 0 clean, 1 findings, 2 the scan could not run. A 2 never means
# "clean".

set -euo pipefail

version="8.30.1"
tgz_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"

repo="."
config=""
range="HEAD"
while [ "$#" -gt 0 ]; do
	case "$1" in
	--repo) repo="$2"; shift 2 ;;
	--config) config="$2"; shift 2 ;;
	--range) range="$2"; shift 2 ;;
	*) echo "secret-scan: unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ -n "$config" ] || config="$repo/.gitleaks.toml"
if [ ! -f "$config" ]; then
	echo "secret-scan: config $config does not exist; nothing was scanned." >&2
	exit 2
fi
if [ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]; then
	echo "secret-scan: only the linux x64 release is pinned; nothing was scanned." >&2
	exit 2
fi

# The verified tarball is cached; its hash is checked again on every run and
# the binary is unpacked fresh, so a cache someone edited is never trusted.
cache="${XDG_CACHE_HOME:-$HOME/.cache}/aev-gitleaks/$version"
mkdir -p "$cache"
tgz="$cache/gitleaks.tgz"
if [ ! -f "$tgz" ] || ! echo "$tgz_sha256  $tgz" | sha256sum -c --status -; then
	if ! curl -sSfL -o "$tgz.part" "$url"; then
		echo "secret-scan: could not download gitleaks $version; nothing was scanned." >&2
		exit 2
	fi
	mv "$tgz.part" "$tgz"
fi
if ! echo "$tgz_sha256  $tgz" | sha256sum -c --status -; then
	echo "secret-scan: gitleaks $version tarball fails its pinned hash; nothing was scanned." >&2
	exit 2
fi
bindir="$(mktemp -d "${TMPDIR:-/tmp}/aev-gitleaks.XXXXXXXX")"
trap 'rm -rf "$bindir"' EXIT
tar xzf "$tgz" -C "$bindir" gitleaks

# --exit-code 3 separates "findings" from every other failure, which gitleaks
# also reports as 1. The range is passed explicitly: gitleaks' own default is
# `git log --all`, which reads every ref in the clone, not the revision judged.
status=0
"$bindir/gitleaks" git --config "$config" --no-banner --redact --exit-code 3 \
	--log-opts="--full-history $range" "$repo" || status=$?
case "$status" in
0) exit 0 ;;
3) exit 1 ;;
*) echo "secret-scan: gitleaks exited $status; the scan did not complete." >&2; exit 2 ;;
esac
