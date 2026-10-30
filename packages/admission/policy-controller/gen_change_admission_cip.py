"""Generate the agent change admission ClusterImagePolicy from the rego module.

policy-controller runs OPA over the verified in-toto Statement, but it takes the
policy inline and gives it no data document. So this script embeds
../rego/agent_change_admission.rego whole, with two mechanical edits and nothing
else: the package line becomes `package sigstore`, the package policy-controller
evaluates, and three deployment rules are appended. Those three stand in for the
consumer document the module would otherwise read:

    engine_verified_envelope          true: the authority key below verified the
                                      envelope before the policy runs.
    engine_subject_binding            "image": cosign attaches the statement to the
                                      image, so its subject is the image digest.
    engine_expected_candidate_digest  the harness digest this deployment admits,
                                      left as a placeholder that admits nothing.

`--check` refuses a manifest that differs from what this script renders, and CI
runs it, so the deployed rule can never drift from the module `opa test` gates.

    python3 policy-controller/gen_change_admission_cip.py
    python3 policy-controller/gen_change_admission_cip.py --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REGO = _HERE.parent / "rego" / "agent_change_admission.rego"
_OUT = _HERE / "clusterimagepolicy-agent-change-admission.yaml"

PACKAGE_LINE = "package agent_change_admission"
PLACEHOLDER = "PIN-ME-REPLACE-WITH-THE-ADMITTED-HARNESS-DIGEST"
_DATA_INDENT = " " * 14

OVERRIDES = f"""
# Deployment rules appended by policy-controller/gen_change_admission_cip.py.
# Replace the placeholder digest with the harness this deployment admits.
engine_verified_envelope := true

engine_subject_binding := "image"

engine_expected_candidate_digest := "{PLACEHOLDER}"
"""

_HEADER = """\
# Agent change admission (sigstore policy-controller).
#
# GENERATED FILE. Do not edit by hand. Regenerate with:
#   python3 policy-controller/gen_change_admission_cip.py
# The `attestations[].policy.data` below is ../rego/agent_change_admission.rego with
# its package renamed to `sigstore` and three deployment rules appended; CI refuses
# a manifest that differs from what the generator renders.
#
# What it admits: a Pod whose image carries an agent-change-admission v1
# attestation, verified by the authority key below, whose decision admitted the
# harness digest pinned at the foot of the embedded module, with every gate in the
# closed set recorded once and passed and the admitted flag consistent with them.
#
# !!! THIS MANIFEST DENIES EVERY POD UNTIL YOU PIN TWO VALUES !!!
#   1. the issuer's Ed25519 public key under `authorities[].key.data`;
#   2. `engine_expected_candidate_digest`, the harness digest this deployment
#      admits. Edit it in this generator's OVERRIDES block, never in this file, and
#      regenerate.
#
# What neither this manifest nor the module establishes: that the evaluations the
# decision names ran, or that the reports it names are true. A valid receipt means
# the pinned key signed exactly this decision.
#
# Validate without a cluster:
#   opa test rego/
#   python3 conformance/run_change_admission_conformance.py
apiVersion: policy.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: require-agent-change-admission
spec:
  mode: enforce
  images:
    - glob: "**"
  authorities:
    - name: admission-issuer-key
      key:
        data: |
          -----BEGIN PUBLIC KEY-----
          PIN-ME-REPLACE-WITH-THE-ADMISSION-ISSUER-PUBLIC-KEY
          -----END PUBLIC KEY-----
      attestations:
        - name: must-carry-admitted-change
          predicateType: "https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/agent-change-admission-v1.md"
          policy:
            type: rego
            # >>> BEGIN generated from ../rego/agent_change_admission.rego, do not edit <<<
            data: |
"""


def embedded_module() -> str:
    """The module policy-controller evaluates: package renamed, overrides appended."""
    module = _REGO.read_text(encoding="utf-8")
    if module.count(PACKAGE_LINE + "\n") != 1:
        raise SystemExit(f"{_REGO.name} does not declare `{PACKAGE_LINE}` exactly once")
    return module.replace(PACKAGE_LINE + "\n", "package sigstore\n").rstrip("\n") + "\n" + OVERRIDES


def render() -> str:
    lines = embedded_module().rstrip("\n").split("\n")
    body = "\n".join((_DATA_INDENT + line).rstrip() if line else "" for line in lines)
    return _HEADER + body + "\n            # >>> END generated block <<<\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the manifest on disk has drifted")
    args = parser.parse_args(argv[1:])
    rendered = render()
    if args.check:
        if not _OUT.is_file() or _OUT.read_text(encoding="utf-8") != rendered:
            print(f"{_OUT.name} has drifted from {_REGO.name}; regenerate it and commit", file=sys.stderr)
            return 1
        print(f"check: {_OUT.name} embeds {_REGO.name} with the deployment rules")
        return 0
    _OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
