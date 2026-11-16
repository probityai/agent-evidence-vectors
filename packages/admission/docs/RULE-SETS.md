# Rule sets: refuse a record before it is judged

`agent-evidence-admission admit <rule-set> <record>` runs one rule set on one record and prints
`ADMIT`, or one `REFUSE <code> at <pointer>` line per rule the record breaks. It exits 0 when the
record is admitted, 1 when it is refused, and 2 when the record, an option file or a passed file
could not be read. `--json` prints the verdict as an object; `rule-sets` lists every rule set with
its checks and options.

Admission decides whether a record is fit to be judged. It does not verify a signature, fetch a
URL, or say a record is true. Where a rule needs bytes the record names (an artifact, an
attestation), pass them with `--file <uri>=<path>`; where it needs what the consumer knows (its
resource URI, a clock), pass `--option <name>=<json>` or `--options <file>`. A rule that could not
run for want of an input refuses under a `*-not-evaluated` code. It never passes. A caller that
accepts a gap names the code with `--warn <code>`, and the verdict reports it as a warning.

## The rule sets

| Rule set | Reads | Refuses |
|---|---|---|
| `ijson` | any JSON record | the byte strings two decoders read as two documents (below) |
| `ijson-integer-only` | a record whose numbers are counts | the same, plus any fraction or exponent |
| `audit-freshness` | an audit record, bare or in DSSE | a time member outside the I-JSON range, a result later than the decision by more than the skew, a status the entries contradict |
| `catalog-attestations` | an ARD manifest or an AI Catalog document | an attestation not bound to the entry it sits in, a missing or wrong digest, a signed manifest whose subject is not the entry |
| `mcp-authz` | a decoded OAuth access token at an MCP server | an audience that is not this resource exactly, an unadvertised issuer, a passed lifetime, a bound token used as bearer |
| `co-signed-receipt` | a co-signed tool-call receipt | an unknown version, a missing member, a hash or signature in a lenient encoding, an outcome that contradicts itself |

Every rule set parses with the strict reader first. Its codes are those of the
agent-evidence-verify reader, plus four that only an admission profile refuses:

| Code | Refused |
|---|---|
| `not-utf8` | invalid UTF-8, a UTF-8 encoded surrogate, a byte-order mark |
| `not-parseable` | bytes that are not JSON |
| `non-json-number` | `NaN`, `Infinity`, `-Infinity` |
| `nesting-too-deep` | nesting past 64 levels |
| `lone-surrogate` | an escaped surrogate with no partner, in a name or a value |
| `noncharacter` | a Unicode noncharacter (RFC 7493 section 2.1) |
| `duplicate-member` | a repeated member at any depth, including one spelled with an escape |
| `case-fold-collision` | two names of one object equal under case folding, with U+0130, U+0131, U+017F and U+212A folded to ASCII |
| `number-token-too-long` | a number token over 64 characters |
| `unsafe-integer` | a number outside +-(2^53 - 1), integer or fraction |
| `value-not-representable` | `1e400`; under `integer-only`, any fraction or exponent |
| `negative-zero` | `-0` in any spelling |

## Time bounds

`audit-freshness` holds each `evaluation.inputs` entry to two bounds that are not symmetric. The
past bound is the entry's `maxAge`; an age equal to it is fresh. The future bound is the skew
tolerance alone (300 seconds; `--option skew=<seconds>`): a result produced an hour after the
decision it fed is refused, even with a day's `maxAge`, which is what a verifier checking
`|age| <= maxAge` admits. `maxAge` is range-checked before any arithmetic, so `2^53` and `2^64 - 1`
are refused and `2^53 - 1` is admitted.

The same rule is a function for other formats: `freshness.judge(produced, reference, max_age,
skew, uncertainty, max_uncertainty)`. A format that carries an uncertainty widens the past bound
by it, never the future bound, and the uncertainty is capped (3600 seconds by default) so a record
cannot widen its own window. `freshness.late(start, event, window, allowance)` is the bound on an
event that must follow a start within a window; each bound takes its own allowance (an
OpenTimestamps block time allows 7200 seconds, a clock reading the skew tolerance), and each has
its own boundary pair in the tests.

## Attestation transplantation

An attestation pinned only by its own digest proves the file was not swapped, and nothing about
which artifact it covers: copied into another publisher's entry, the pin checks out again.
`catalog-attestations` therefore refuses an entry delivered by `url` that carries attestations
and names no `digest` of its artifact (`entry_digest_missing_for_url`), and an attestation that is
not a signed statement whose subject names the entry or its digest (`attestation_unsigned`,
`attestation_subject_mismatch`). Both follow draft-bu-dawn-ard-discovery-00 sections 3.5.2 and
6.4 and the AI Catalog's Entry Release Coverage rules. A DSSE envelope counts as signed when it
carries a signature; whether the signature verifies is the verifier's question.

## Vectors and ablation

Each rule set's cases are in [`python/vectors/rules/`](../python/vectors/rules/), written by
`generate.py` from the rule each case tests (`generate.py --check` fails when a manifest drifts).
`agent-evidence-admission ablate <manifest>` drops each check in turn and reports the cases that
then reach the wrong verdict: it exits 1 when the full set misses a case, when a check is needed
by no case (a dead check, or a missing vector), or when switching a check on ever turns a refusal
into an admission. `--exhaustive` also lists the minimal sets of checks that reach every verdict.
The test suite runs it over every rule set, so a check without a vector fails CI.
