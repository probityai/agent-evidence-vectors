"""Generate the deep-soundness ClusterImagePolicy from the canonical rego module.

The deep-soundness rego has to be wired into a DEPLOYED admission manifest
that actually enforces it — not a stub that trusts a self-declared result. sigstore
policy-controller runs a real OPA evaluator over the verified in-toto Statement, so
the enforcement vehicle is a ClusterImagePolicy whose `attestations[].policy` embeds
the ENTIRE ../rego/execution_evidence.rego module. Because policy-controller cannot
reference a rego file (the policy must be inline), this script embeds the canonical
module byte-for-byte so the deployed policy provably equals the module the offline
`opa test` gates — the CI opa job regenerates this file and `git diff --exit-code`s
it, so the deployed enforcement can never drift from the tested module.

Run: python3 policy-controller/gen_soundness_cip.py
     python3 policy-controller/gen_soundness_cip.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REGO = _HERE.parent / "rego" / "execution_evidence.rego"
_OUT = _HERE / "clusterimagepolicy-adversarial-execution-evidence-soundness.yaml"

_DATA_INDENT = " " * 14  # under `policy:` (10) -> `type/data:` (12) -> content (14)

_HEADER = """\
# adversarial-execution-evidence DEEP-SOUNDNESS admission policy
# (sigstore policy-controller) — the manifest that actually ENFORCES the rego.
#
# GENERATED FILE — do not edit by hand. Regenerate with:
#   python3 policy-controller/gen_soundness_cip.py
# The `attestations[].policy.data` below is ../rego/execution_evidence.rego embedded
# byte-for-byte, so the DEPLOYED enforcement is provably the same module `opa test`
# gates (the CI opa job regenerates this file and fails on any diff).
#
# In-cluster admission therefore re-derives the offline STRUCTURAL rules
# (coverage integrity at attack granularity, a corpus manifest that declares at least
# one attack identifier, the result recompute on the carried vocabulary, actualLayer,
# the run binding, the whole coverage-validity class match with its refs /
# referenced-payload / method-cap requirements, batchRoot presence, and
# record-signature presence) from the attested predicate bytes — it no longer trusts a
# self-declared `result`.
#
# "SOUNDNESS" IN THIS FILENAME IS A MISNOMER, retained because it is the deployed
# resource name. What the embedded module computes is a STRUCTURAL RE-DERIVATION over
# an already-decoded predicate body, never a cryptographic judgement. A verifier that
# evaluates coverage validity WITHOUT verifying the observation records' signatures
# cannot distinguish a substrate observation from an assembly-plane forgery: every
# record field the module reads comes out of a base64 payload whose signature nothing
# in this path checks. The evidence TIER is not computed anywhere in the
# policy-controller path — policy-controller verifies the DSSE ENVELOPE and hands the
# decoded payload to rego — so a consumer relying on this admission controller is
# extending FULL TRUST TO THE ENVELOPE SIGNER. Read the module header's
# "What this policy cannot know" block before deploying it as a security control.
#
# Four byte-pure gates narrow that gap without closing it: every observation record
# must carry a non-empty `signatures[]` (presence only — forged bytes pass); a clean
# row must be `basis: substrate` + `method: intercepted` unless the consumer DECLINES
# that obligation with `data.consumer.admit_unintercepted_clean_rows`, which governs
# the row check alone and never the admission threshold beside it; a clean row may not REFERENCE an
# `interception` record, because the substrate signed that it intercepted traffic and
# the row claims nothing was caught; and — the spec's own Coverage validity
# requirement — EVERY `basis: substrate` row must REFERENCE, through a non-empty
# in-range `observationRefs`, records matching the class its shape requires: a caught
# intercepted row an `interception` record, a `method: reconstructed` row an
# `examination` record, a clean intercepted row a valid `arming` record AND a COVERING
# `sealed` record (still armed, drops within a bound declared in the same payload,
# posture digest equal to the pinned one AND to every posture digest the row's other
# referenced arming records name, because the reference verifiers compare against the records
# the row REFERENCES, not the subset that ends up covering it). Every referenced
# payload must additionally be `+json` and carry the reserved members, and a row's
# `method` may be no stronger than the weakest `aeeMethod` across its covering records.
# All of it is read out of the base64 record payloads the module decodes. The last is a
# VALIDITY rule, so it sits in the structural re-derivation and the consumer opt-in
# does not relax it: a "nothing happened" claim with no evidence the vantage was ever
# armed is malformed under every consumer policy. It is still byte-pure, so a forged
# record set covers exactly as a real one does.
#
# vs. the binding-only sibling (clusterimagepolicy-adversarial-execution-evidence.yaml):
# that file embeds a classic-syntax STUB that checks only result=="pass" + the
# structural bindings; it is retained for policy-controller runtimes whose bundled OPA
# predates rego v1. THIS file is the recommended enforcement.
#
# Requirements / input contract:
#   - policy-controller with an OPA that supports rego v1 (`import rego.v1`, `if`,
#     `contains`, `every`) and the full stdlib (base64.decode, json.unmarshal,
#     json.marshal, crypto.sha256). Modern policy-controller (>= v0.10) satisfies this.
#   - `input` is the verified in-toto Statement {predicateType, predicate, subject};
#     the run-binding rule reads input.subject[0].digest.sha256 (absent -> "" ->
#     fail-closed). policy-controller passes the decoded attestation payload as `input`.
#   - The Ed25519 / RFC-6962 crypto and the RFC 8785 byte form stay offline (rego can
#     neither fold a Merkle root nor see the payload bytes); the per-record signature
#     BYTES, the batch root, and payload canonicality are validated by the offline
#     TS/Python verifiers, and the ATTESTATION envelope signature is verified by the
#     authority key below. In-policy, records are checked for signature PRESENCE only
#     (non-empty `signatures[]`), which needs no key and holds in every deployment; a
#     records-present bundle that withholds batchRoot is still rejected.
#   - The consumer admission threshold is data.consumer.accepted_results, whose absent
#     value is the spec's own default ["pass"] and whose only other admissible value
#     is ["pass", "pass_indirect"] — AND the default-safe clean-row provenance and
#     consistency gates AND the spec's out-of-band consumer anchors (isCompliant).
#     The threshold and the clean-row obligation are SEPARATE declarations: relaxing
#     the one never drops the other, and a document stating only one of the pair is
#     denied, because the spec requires a policy relaxed to admit pass_indirect to go
#     on keying on each clean row's basis and method. The optional REPLAY knobs ride
#     in data.consumer.{expected_catch_policy_digest, allowed_network_postures,
#     admit_unintercepted_clean_rows}; unset -> the safe default (those anchors
#     vacuously satisfied, unintercepted clean rows NOT admitted, the threshold at
#     "pass" alone).
#
# !!! THIS MANIFEST DENIES EVERY POD UNTIL YOU PIN THE CONSUMER ANCHORS !!!
#
# The spec's "Consumer policy obligations" require a consumer to pin, OUT OF BAND, the
# corpus digest and the substrate digest it expects, and to compare them at
# consumption. Everything else the embedded module checks about the corpus is
# SELF-CONSISTENCY, which is free to a party holding the envelope key: substituting a
# weaker corpus.manifest and re-hashing it needs no key, and the substituted statement
# then satisfies every recompute in the module. So the anchors are REQUIRED BY DEFAULT, and
# an absent pin DENIES rather than admitting -- the argument for that direction, and
# the cost of it, are in the embedded module's "THE ABSENT-ANCHOR DECISION" block.
#
# policy-controller has no consumer data document (the `data:` field below is the
# POLICY body, not a data document), so data.consumer cannot be mounted here. To pin,
# replace the right-hand side of the two `expected_*` rules in
# ../rego/execution_evidence.rego with the digest literals this deployment expects and
# re-run this generator. To decline the spec's MUST, set allow_unpinned_anchors the
# same way. Roll out with `mode: warn` first if you want the blast radius measured
# before it blocks.
#
# Identity references (verbatim, do NOT invent fields):
#   predicateType : https://in-toto.io/attestation/adversarial-execution-evidence/v0.7
#   public key    : the producer's published ed25519 SPKI public key
#   RFC-7638 keyid: 427a109244697aacd5075f0a36e3e4f3c16eb9176c41e3f43bd7bb9989e57a86
#
# No `ctlog:` block: This provenance is STATIC-KEY cosign with --tlog-upload=false
# (no Fulcio cert, no public Rekor) — the authority verifies by the
# embedded public key alone.
#
# Enforcement: spec.mode defaults to `enforce` (reject). Set `mode: warn` for an
# audit-first rollout (admit but surface a warning), then flip to enforce.
#
# Validate (no live cluster needed):
#   opa test ../rego/                          # the embedded module's own tests
#   kubeconform -strict clusterimagepolicy-adversarial-execution-evidence-soundness.yaml
apiVersion: policy.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: require-execution-evidence-soundness
spec:
  # mode: enforce   # default; reject Pods whose images fail the deep-soundness policy.
  # mode: warn      # audit-first variant: admit but surface a warning.
  mode: enforce
  images:
    - glob: "**"
  authorities:
    - name: producer-observation-key
      key:
        # ed25519 SPKI PEM, byte-identical to keys/observation-key.pub in this repository
        data: |
          -----BEGIN PUBLIC KEY-----
          MCowBQYDK2VwAyEAT2jLWVkBW84MmGahZlqmj1cxmA1ljoYa0dkp+gpUPnc=
          -----END PUBLIC KEY-----
      attestations:
        - name: must-be-sound-execution-evidence
          predicateType: "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
          policy:
            type: rego
            # >>> BEGIN generated from ../rego/execution_evidence.rego — do not edit <<<
            data: |
"""


def render() -> str:
    module = _REGO.read_text(encoding="utf-8").rstrip("\n")
    embedded = "\n".join(
        (_DATA_INDENT + line).rstrip() if line else "" for line in module.split("\n")
    )
    footer = "\n            # >>> END generated block <<<\n"
    return _HEADER + embedded + "\n" + footer


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "do not write; exit 1 when the manifest on disk differs from what "
            "this generator renders out of the module"
        ),
    )
    args = parser.parse_args(argv[1:])

    if not _REGO.is_file():
        print(f"gen_soundness_cip: missing {_REGO}", file=sys.stderr)
        return 2
    rendered = render()
    lines = _REGO.read_text(encoding="utf-8").rstrip("\n").count("\n") + 1

    if args.check:
        if not _OUT.is_file():
            print(f"gen_soundness_cip: {_OUT} does not exist", file=sys.stderr)
            return 2
        if _OUT.read_text(encoding="utf-8") != rendered:
            print(
                f"gen_soundness_cip: {_OUT.name} has drifted from "
                f"{_REGO.name}; regenerate it and commit the result",
                file=sys.stderr,
            )
            return 1
        print(f"check: {_OUT.name} embeds {_REGO.name} verbatim ({lines} rego lines)")
        return 0

    _OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {_OUT} ({lines} rego lines embedded)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
