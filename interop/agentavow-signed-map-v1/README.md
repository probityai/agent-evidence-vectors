# Signed-map extraction for AgentAvow tool pins

This additive Probity candidate reads the producer's
[version-1 profile at b7c5cd2](https://github.com/AgentAvow/AgentAvow/tree/b7c5cd2fee080cfdd387683a9bcb3e0db20f8ee5/docs/standards/tool-manifest-digest-vectors-v1).
It verifies the compact Ed25519 JWS under a separately selected public key,
checks canonical payload bytes, selected issuer, MCP server, named tool,
definition digest and the half-open validity window, and emits the pin shape
consumed by the existing live-MCP definition reader. The historical literal-name
profile and definition digest implementation are unchanged.

Map lookup percent-encodes UTF-8 octets outside printable ASCII, plus `%` and
`=`, with uppercase hex. Bodies of at most 128 characters stay literal. Longer
bodies keep their first 96 characters, `~`, and the first 16 lowercase hex digits
of SHA-256 over the complete raw name. The cut can retain `%` or `%C` at its end.
No decoding, Unicode normalization or literal-name fallback occurs.

The native packet reproduction matches all thirteen name/key pairs, the three
original served-definition digests and all seven case verdicts, including
`boundary-fresh`, a gate time less than a millisecond inside the signed expiry.
The window compares instants at the payload's microsecond precision, so that
case reads fresh. The expected counts of pairs, tools and cases live in
`source-lock.json` beside the fixture digest, so selecting a later producer
revision is a lock change. Every
case retains the six producer axes plus its `rely` decision; selected issuer
matching is an additional axis. An absent tool leaves its digest axis
`not_evaluated`. A valid signature on noncanonical payload bytes cannot yield a
usable pin. The emitted pin is a static-definition input, not invocation
authorization, a runtime result or independent custody.

The native packet is supplied separately for source-available evaluation. No
producer source, signed packet or tool definitions are vendored here. New code
and synthetic tests are original Probity work. The selected native revision,
raw digest, license blob and shared-reader hashes are in `source-lock.json` (refresh the shared-reader hashes with `python3 lock_sources.py`; CI runs `--check`);
`selection.json` freezes the public packet key and issuer for this reproduction.
A production consumer must supply its own key-authority policy and current
reference time. Key URLs in the producer packet are never fetched by the reader.

Run from this directory with Python 3.13:

```sh
python -m pip install -r ../a2a-s3-retain-2026-10-01/requirements.txt
PYTHONPATH=. python -m pytest -q tests
python fetch_fixture.py --output /tmp/agentavow-native-packet.json
python run_agentavow.py --fixture /tmp/agentavow-native-packet.json > fresh-report.json
```

The fetch uses a fresh output path, a 256 KiB ceiling and one immutable source
digest. Retain its nonzero exit if downloading fails. The native verifier is
never imported or executed. `recorded-run.json` is the Probity-operated native
packet reproduction; the Ubuntu workflow produces and retains a fresh report.
Expected native outcomes are consulted after the independently implemented
checks have run. Synthetic signed controls cover trust/key confusion, malformed
and duplicate inputs, window boundaries, drift, Unicode/length rules, missing
tools, duplicate names and encoded-key collisions.

The 64-bit suffix does not prove injectivity of truncated keys. Duplicate or
colliding names in a supplied `tools/list` capture refuse. Capture uniqueness
does not establish completeness of unseen definitions or reveal the full
original name behind a producer's truncated key. This remains a candidate
consumer extraction policy, not AgentAvow or APS adoption.
