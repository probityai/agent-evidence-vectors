"""A canonicalizer that declares the integer-only profile: right on integers, refuses fractions.

    python integer_only_canonicalizer.py <target> <input.json>

It answers as the packaged reference canonicalizer does, except that an input
holding a number with a fraction or an exponent is refused (exit 1). Replayed
over the a2a-jcs corpus it fails exactly the float members, so the action passes
it with `profile: integer-only` and fails it without.
"""

import re
import sys

from agent_evidence_vectors import a2ajcs

STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
FRACTION = re.compile(
    r"(?<![0-9A-Za-z_.])-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)"
)

with open(sys.argv[2], encoding="utf-8", errors="surrogatepass") as handle:
    text = handle.read()
if FRACTION.search(STRING.sub('""', text)):
    sys.exit(1)
sys.exit(a2ajcs.main(sys.argv[1:]))
