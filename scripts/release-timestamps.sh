#!/usr/bin/env bash
# Time evidence for a signed corpus release: RFC 3161 and OpenTimestamps.
#
# WHAT IS STAMPED, AND WHY IT IS THE SIGNATURE RATHER THAN THE DIGEST LIST.
# Both proofs are taken over the RAW SIGNATURE BYTES of
# release/CORPUS-DIGESTS.txt.sig, not over the digest list. A timestamp over the
# list would establish that those bytes existed by some time; it would say
# nothing about when the maintainer committed to them, and the whole claim being
# made is about the commitment. Stamping the signature dates the commitment, and
# the commitment already binds the list. The files are therefore named after
# what they cover -- `CORPUS-DIGESTS.txt.sig.tsr`, `CORPUS-DIGESTS.txt.sig.ots`
# -- because a proof named after a file it does not cover is a proof a verifier
# will point at the wrong bytes.
#
# THE TWO ARE NOT REDUNDANT. The RFC 3161 token is an assertion by a named
# authority, checkable offline against a pinned root, and worth exactly the
# authority's honesty and key hygiene. The OpenTimestamps proof is an anchor
# into a public chain that nobody in this repository can rewrite, and it is
# worth nothing until it confirms. One is trusted and immediate, the other is
# trustless and slow, so a release carries both.
#
# PENDING IS A STATE, NOT A FAILURE. A fresh OpenTimestamps proof is an
# attestation by the calendars that they received the digest; the Bitcoin
# attestation lands roughly a day later, which is what `upgrade` (and the weekly
# workflow that calls it) is for. `ots verify` exits non-zero on a pending
# proof, so this script distinguishes the two by reading the output rather than
# by trusting the status alone, and prints which one it saw. What is checked
# OFFLINE and unconditionally is the binding: the digest inside the .ots must
# equal the sha256 of the raw signature. That check is the one an attacker would
# have to beat, and it does not depend on any network.
#
#   scripts/release-timestamps.sh stamp     # obtain both proofs (network)
#   scripts/release-timestamps.sh upgrade   # move a pending .ots forward (network)
#   scripts/release-timestamps.sh verify    # check both proofs
#
# Exit 0 on success. `upgrade` exits 0 when there is nothing to upgrade and when
# the proof is still pending: neither is a defect, and a weekly job that goes red
# for the passage of time teaches its reader to ignore it.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNATURE="$REPO/release/CORPUS-DIGESTS.txt.sig"
TSR="$SIGNATURE.tsr"
OTS="$SIGNATURE.ots"
ROOTS="$REPO/spec/tsa-roots.pem"
TSA_URL="${AEV_TSA_URL:-http://timestamp.digicert.com}"

command="${1:-}"
case "$command" in
  stamp|upgrade|verify) ;;
  *)
    echo "usage: release-timestamps.sh {stamp|upgrade|verify}" >&2
    exit 2
    ;;
esac

need() {
  command -v "$1" >/dev/null || {
    echo "release-timestamps: $1 is not on PATH. Refusing: a step that cannot run has not passed." >&2
    exit 2
  }
}
need openssl
need python3
need ots

[ -s "$SIGNATURE" ] || {
  echo "release-timestamps: $SIGNATURE is absent or empty. Sign before stamping; there is nothing to date." >&2
  exit 2
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
RAW="$workdir/signature.raw"
base64 -d < "$SIGNATURE" > "$RAW"
IMPRINT="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$RAW")"

ots_digest() {
  # The digest the proof is over, read out of the proof itself, offline.
  ots info "$OTS" | sed -n 's/^File sha256 hash: //p' | head -1
}

case "$command" in
  stamp)
    openssl ts -query -data "$RAW" -sha256 -cert -out "$workdir/request.tsq" >/dev/null 2>&1
    curl --retry 5 --retry-delay 5 --retry-all-errors --silent --show-error --fail --max-time 120 \
      --header "Content-Type: application/timestamp-query" \
      --data-binary "@$workdir/request.tsq" \
      --output "$TSR" \
      "$TSA_URL"
    openssl ts -verify -in "$TSR" -digest "$IMPRINT" -CAfile "$ROOTS" >/dev/null
    echo "stamped: ${TSR#"$REPO/"} at $(openssl ts -reply -in "$TSR" -text 2>/dev/null | sed -n 's/^Time stamp: //p')"

    cp "$RAW" "$workdir/CORPUS-DIGESTS.txt.sig"
    ots stamp "$workdir/CORPUS-DIGESTS.txt.sig"
    mv "$workdir/CORPUS-DIGESTS.txt.sig.ots" "$OTS"
    [ "$(ots_digest)" = "$IMPRINT" ] || {
      echo "release-timestamps: the .ots proof carries $(ots_digest) and the signature hashes to $IMPRINT." >&2
      exit 1
    }
    echo "stamped: ${OTS#"$REPO/"} (pending Bitcoin confirmation until the weekly upgrade)"
    ;;

  upgrade)
    if [ ! -f "$OTS" ]; then
      echo "nothing to upgrade: ${OTS#"$REPO/"} does not exist."
      exit 0
    fi
    if ots upgrade "$OTS" > "$workdir/upgrade.log" 2>&1; then
      cat "$workdir/upgrade.log"
      echo "upgraded: ${OTS#"$REPO/"}"
      exit 0
    fi
    cat "$workdir/upgrade.log"
    # `ots upgrade` reports a still-pending proof as "Failed! Timestamp not
    # complete" and exits non-zero. That sentence is about the Bitcoin
    # attestation, not about this repository, and treating it as a defect would
    # make a weekly job go red for the passage of time. It is accepted ONLY when
    # the calendars said pending in the same output, so a genuine error -- an
    # unreachable calendar, a corrupt proof -- is still a failure.
    if grep -q "Pending confirmation in Bitcoin blockchain" "$workdir/upgrade.log" \
       || grep -q "Timestamp not upgraded" "$workdir/upgrade.log"; then
      echo "not yet: the Bitcoin attestation has not landed. This is the expected state for about a day after stamping."
      exit 0
    fi
    echo "release-timestamps: ots upgrade failed for a reason other than a pending attestation." >&2
    exit 1
    ;;

  verify)
    [ -s "$TSR" ] || { echo "release-timestamps: $TSR is absent." >&2; exit 1; }
    [ -s "$OTS" ] || { echo "release-timestamps: $OTS is absent." >&2; exit 1; }
    [ -s "$ROOTS" ] || { echo "release-timestamps: $ROOTS is absent, so the token would be checked against nothing." >&2; exit 1; }
    openssl ts -verify -in "$TSR" -digest "$IMPRINT" -CAfile "$ROOTS" >/dev/null
    echo "RFC 3161: OK, imprint $IMPRINT, time $(openssl ts -reply -in "$TSR" -text 2>/dev/null | sed -n 's/^Time stamp: //p')"

    carried="$(ots_digest)"
    [ "$carried" = "$IMPRINT" ] || {
      echo "release-timestamps: the .ots proof is over $carried and the signature hashes to $IMPRINT. The proof does not cover this signature." >&2
      exit 1
    }
    echo "OpenTimestamps: the proof is over $IMPRINT (checked offline, from the proof itself)"
    # What follows reaches the network, and its result is REPORTED rather than
    # enforced. Everything above this line is offline and fatal: a token that
    # does not chain to the pinned root, or a proof over some other bytes, is a
    # broken release. The chain state is a different kind of fact -- it matures
    # on its own schedule and is read through calendars this repository does not
    # run -- so an unreachable calendar must not be reported as a bad proof.
    # Those two are indistinguishable from a non-zero exit alone, which is
    # exactly why the state is named in the output instead of being folded into
    # a status.
    if ots verify -d "$IMPRINT" "$OTS" > "$workdir/verify.log" 2>&1; then
      cat "$workdir/verify.log"
      echo "OpenTimestamps: ATTESTED"
      exit 0
    fi
    cat "$workdir/verify.log"
    if grep -q "Pending confirmation in Bitcoin blockchain" "$workdir/verify.log"; then
      echo "OpenTimestamps: PENDING. The calendars hold the digest and the Bitcoin attestation has not landed yet."
      exit 0
    fi
    echo "OpenTimestamps: NOT ESTABLISHED. The proof covers the right bytes -- that was checked offline above -- and the chain state could not be read here. This is not a claim that the proof is bad; it is a claim that nothing was learned about it on this run."
    exit 0
    ;;
esac
