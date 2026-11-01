# What building this validator found in ACI Draft Specification v0.9

Read against `narko4u/aci-spec` at commit `9fb47bbb6b04d92270320786a5c16178e3fe1642`, whose
`SPEC.md` is 997 lines and whose `examples/` directory holds 18 manifest files across six
deployments. Every finding below is reproducible from this repository: the example deployments are members of
`vectors-aci/`, vendored at that commit, and `aee-verify vectors-aci/` prints the verdict each one
carries.

ACI (Agent Communication Interface) Draft Specification v0.9, Security Division, Empire Labs Pty Ltd, licensed CC BY 4.0, https://github.com/narko4u/aci-spec. Quoted specification text is used under that licence.

Sixteen findings. Four are ambiguities where two conforming implementations diverge, two are
defects in the reference validator, and ten are places the specification's own artifacts do not
satisfy its normative text.

---

## S-1. The score that gates Level 3 has no definition anywhere in the specification

Section 3.3 makes a number normative:

> All five manifests MUST pass ACI Validator checks with a score of 90 or above.

Section 18.2 raises it for a reference implementation:

> Pass ACI Validator checks with a score of 100/100

Section 17.3 publishes four bands (90-100 Full Compliance, 70-89 Partial, 50-69 Minimal, 0-49
Non-Compliant) and one sentence of arithmetic: "A score of 100 requires all checks to pass with no
warnings." No section says what a check is worth, how checks combine, what a warning costs, or how
absent manifests are counted. The arithmetic exists only in `validator/validate.py`, at lines
238-258 for a manifest and 304-311 for the deployment.

Two consequences, and the second is worse than the first.

The requirement is not reproducible by a second implementation, which is exactly the property the
specification asks for on line 8: "An ACI implementation SHOULD enable two independent autonomous
systems to reach substantially the same understanding of an organization without prior bilateral
agreement." Section 14.4 gates v1.0 on three independent implementations. A normative score with no
published algorithm is the one requirement a second implementer cannot write.

The reference arithmetic also contradicts section 3.4. `overall_score` is the mean of five
per-manifest scores plus a 10 point bonus when all five exist, so a deployment that publishes
Identity and Capability perfectly and nothing else is capped at 40. Section 3.4 says "An
organization MAY claim conformance at Level 1 or Level 2 without meeting higher levels", and
`validate.py` line 579 exits non-zero below 70. Measured against the specification's own examples,
served as `examples/README.md` documents:

| example | reference `overall_score` | reference `conformance_level` | exit |
|---|---|---|---|
| `minimal` | 18 | 0 | 1 |
| `level1` | 18 | 0 | 1 |
| `level2` | 58 | 0 | 1 |
| `level3` | 78 | 0 | 0 |
| `level4` | 74 | 0 | 0 |

A conformant Level 1 deployment scores 18 and fails. Suggested repair: publish the algorithm in
section 17.3, or replace the number in 3.3 with the check list it stands in for. This validator
prints no score, and `internal/aci/report.go` says why.

## S-2. `identifiers` carries objects while section 10.1 defines a string

Section 5.2 requires the field and points at section 10:

> `identifiers` | MUST be present. Array of canonical identifiers (§10) - at least one MUST be a stable, globally unique identifier (e.g., domain name, ABN, DUNS, LEI).

Section 10.1 then defines an identifier as a string:

```
identifier       = segment *( "." segment )
segment          = alphanum *( alphanum / "-" / "_" )
```

Every published manifest puts objects in that array instead, shaped
`{"id": "org.novadynamics", "type": "domain", "value": "novadynamics.example"}`. An implementer who
applies section 10.1 to the array elements rejects all 18 example manifests; one who follows the
examples never applies section 10.1 at all. Suggested repair: give the array element a schema in
section 5.2 and say that section 10.1 governs its `id` member. This validator accepts both shapes
and checks the grammar against the `id`.

The second half of that sentence is also unverifiable. Nothing marks which identifier is the stable,
globally unique one, so "at least one MUST be" has no machine-checkable subject.

## S-3. `last_updated` is required to be a timestamp and is published as a date

Section 5.2 and section 4.2 both ask for an "ISO 8601 timestamp", and section 16 says "All
timestamps MUST use ISO 8601". Appendix A.2 publishes `2026-07-19T04:00:00Z`. Appendix A.3 through
A.6 publish `2026-07-19`, and so does every one of the 18 example manifest files.

A date is a valid ISO 8601 date and is not a timestamp, so a strict validator rejects 18 of 18
examples and four of the five appendix manifests, and a lenient one accepts them. Suggested repair:
say date-time, or permit a date explicitly. This validator warns rather than failing, and names the
ambiguity in the warning.

## S-4. Section 12.2 requires an `x-` prefix that no published manifest uses

Section 12.2, rule 1:

> Extension fields MUST start with `x-` (e.g., `x-internal-rating`, `x-shipping-zones`)

Fields outside the normative vocabulary of sections 5 through 9 appear across the examples without
that prefix. Measured by `ACI-EXT-001`:

| deployment | undefined top-level fields |
|---|---|
| `level2`, `level3` | `relationships` (knowledge), `security` (trust) |
| `level4` | `aip_actions` (capability), `knowledge_domains`, `knowledge_graph`, `reference_libraries` (knowledge), `attestations`, `data_handling`, `privacy_policy`, `terms_of_service` (trust) |

`relationships` and `security` also appear in Appendix A, which the specification marks INFORMATIVE
at line 755, so they carry no normative definition from there. No example anywhere uses an `x-`
field, which leaves rule 1 and rule 2 ("The ACI Validator SHALL ignore `x-` fields") untested by any
published artifact. Suggested repair: promote the recurring fields into normative text with schema
entries, since `discovery`, `relationships`, `security` and `endpoints` are clearly intended, and
rename the rest in the examples.

## S-5. Nothing in a deployment states its claimed conformance level

Three normative sentences depend on a claim that no field carries.

> An organization MAY claim conformance at Level 1 or Level 2 without meeting higher levels. (3.4)

> This file MUST link to all manifests required by the organization's claimed conformance level. (4.1)

> At minimum, manifests required by the claimed conformance level MUST be present (4.2)

Neither the five manifests nor `/.well-known/aci` has a place to put the claim, so a validator has
to infer the level from which files it managed to fetch. That makes a Level 3 deployment whose agent
manifest is temporarily 404 indistinguishable from a complete Level 2 one, and it makes the
specification's own conformance claim ("We are ACI Level 2 compliant", section 3.4) something a
verifier cannot check against the deployment. Suggested repair: a `conformance_level` field in the
Identity Manifest and in the discovery file. This validator takes the level from `-level` and falls
back to inference, and reports both numbers so the difference is visible.

## S-6. Section 4.1 does not say whether a relative link satisfies it

The example in section 4.1 lists absolute URLs, and the reference deployment's `llms.txt` at
`https://empirelabs.com.au/llms.txt` uses absolute URLs. All five example `llms.txt` files use
relative targets:

```text
# AI manifests
- [Identity Manifest](identity.json)
- [Capability Manifest](capabilities.json)
```

The reference validator resolves neither. `parse_llms_txt` at `validator/validate.py` lines 180-206
keeps a target only when it begins with `http://`, `https://` or `/`, so it returns an empty list
for all five example files and discovery falls through to filename guessing without saying so.
Suggested repair: state that a relative target is resolved against the `llms.txt` URL, and resolve
it in the reference tool. This validator parses relative targets, matches them by basename, and
emits a note recording that the specification has not settled the question.

## S-7. The reference validator cannot find a capability manifest at the filename the specification uses

`schema/capability.yaml` sets:

```yaml
url_hints:
  - capabilit
  - product
  - offerings
```

The fallback probe at `validator/validate.py` lines 349-359 concatenates a hint with an extension,
so it requests `capabilit.json`, `capabilit.yaml`, `product.json`, `offerings.json` and never
`capabilities.json`, which is the filename section 4.1, section 4.2 and Appendix A.1 all use.
Because S-6 empties the `llms.txt` path as well, the two defects compose: the Capability Manifest is
never discovered in any of the five example deployments, scores 0 in each, and drags
`conformance_level` to 0 for `level3` and `level4`. `examples/README.md` documents that exact
invocation.

Two lines repair it: add `capabilities` to the hint list, and resolve relative `llms.txt` targets.

## S-8. Appendix A publishes two lifecycle states section 11.1 does not define

Section 11.1 defines four: `active`, `deprecated`, `superseded`, `withdrawn`. Appendix A.6 publishes
`"status": "pre-order"` at line 950 and `"status": "alpha"` at line 963, for the two agents of the
deployment section 18.1 calls the primary reference implementation. Section 11 says every named
entity "SHOULD declare a lifecycle state", which reads as a closed vocabulary. Suggested repair:
either widen 11.1 with the operational states real deployments need, or separate a lifecycle state
from a release stage and give the appendix the second field.

## S-9. One organization publishes two organization identifiers

Section 10.3:

> Identifiers SHALL NOT change once published.

Appendix A.2 publishes `org.empire-labs`. `examples/empirelabs/capabilities.json` publishes
`au.com.empirelabs`. Both carry `"publisher": "Empire Labs Pty Ltd"` and both are in the same
repository at the same commit. Section 10.2 gives the form as `org.<name>`, which the second does
not follow.

## S-10. Product identifiers and agent identifiers share one namespace

Section 10.2 gives Product ID and Agent ID the same form, `<org>.<product>` and `<org>.<agent>`.
Appendix A then uses `empire-labs.witnessos` as a product id in A.3 and as an agent id in A.6.
Nothing in section 10 separates the two namespaces, so an agent resolving a cross-reference cannot
tell which entity an identifier denotes without knowing which manifest it came from, and the
"navigate to the others via cross-references" promise of section 2 has no resolution rule behind it.

## S-11. The one example directory called a real-world implementation cannot reach Level 1

`examples/README.md` says "except `empirelabs/` which is a real-world implementation". That
directory holds one file, `capabilities.json`, so section 3.1's "Identity Manifest MUST be
published" is unmet and no conformance level is reachable. That capability manifest also carries
`identifiers`, `jurisdiction`, `contact`, `brand` and `description`, which section 5.3 assigns to
the Identity Manifest, and section 6 does not define for a capability manifest.

## S-12. "Cross-references MUST resolve" has no defined subject

Section 3.2 requires:

> Cross-references between all Level 2 manifests MUST resolve

Section 4.5 makes the mechanism a SHOULD: "Each manifest SHOULD include a `discovery` section
linking to the other manifests". `examples/level2/capabilities.json`, `knowledge.json` and
`trust.json` carry no `discovery` section and no other cross-reference, so either the example fails
its own level or "cross-reference" means something the specification never says. The term is not
defined and the MUST cannot be checked. Suggested repair: define a cross-reference as an entry in
the `discovery` object, and require it at Level 2 rather than recommending it in section 4.5.

## S-13. The first mechanism in the resolution order is published by nobody

Section 4.4 ranks `/.well-known/aci` first, "Fastest single-fetch resolution". No example deployment
includes the file, and `curl https://empirelabs.com.au/.well-known/aci` returns HTTP 404 (captured
2026-09-09). Section 4.2 is a SHOULD, so this is not a violation; it means the path an agent tries
first is exercised by no published deployment and illustrated only by the six-line snippet in 4.2.

## S-14. The discovery file and the manifests use different version syntaxes

Section 4.2 shows `"aci_version": "0.9"`. Every manifest uses `"manifest_version": "0.9.0"`, and
section 14.1 sets semantic versioning as `MAJOR.MINOR.PATCH`. Section 17.2's Version Consistency
check covers manifests only, so a discovery file may advertise a version the manifests it points at
do not carry, with nothing detecting it. Suggested repair: make `aci_version` the same three-part
string, and extend the consistency check to the discovery file.

## S-15. Three documents route through an adopters list that is not in the repository

`SPEC.md` section 18.4 asks organizations to "Register their implementation in the ACI Adopters
list". `CONTRIBUTING.md` gives the procedure: "Open a pull request adding your organization to the
adopters list (see ADOPTERS.md)". `CHANGE_PROCESS.md` step 3 makes it normative:

> If the ACI Adopters list contains three or more independent implementations, at least two of them MUST be consulted before the RFC can proceed.

`git ls-files ADOPTERS.md` returns nothing at commit `9fb47bb`. The word "adopters" appears in four
files and the file itself is in none of them. Section 14.4 gates v1.0 on three independent
implementations and the change process gates every RFC on consulting two of them, so both rules run
through a register that does not exist and an implementer who follows `CONTRIBUTING.md` has no file
to edit.

## S-16. The registration procedure requires the score S-1 says nobody can compute

`CONTRIBUTING.md`, under Submit an Implementation:

> 1. Ensure your implementation passes the ACI Validator
> 2. Open a pull request adding your organization to the adopters list (see ADOPTERS.md)
> 3. Include the validator output showing your score

Step 3 asks for a number no section of the specification defines, produced by a tool whose
arithmetic lives only in `validator/validate.py`. An independent implementation has nothing to
report there. Suggested repair: ask for the conformance level and the check results, which the
specification does define, and leave the score out until section 17.3 carries the algorithm.

---

## What this validator does about each finding

| finding | treatment here |
|---|---|
| S-1 | no score is printed; the verdict is the violation count |
| S-2 | both identifier shapes accepted; the grammar is checked against `id` |
| S-3 | a date-only value warns and the warning names the ambiguity |
| S-4 | `ACI-EXT-001` fails an undefined unprefixed field; the example results are pinned as corpus members |
| S-5 | `-level` sets the claim; the report prints claimed and detected levels separately |
| S-6 | relative targets parsed and matched; a note records the open question |
| S-7 | manifests are read by the filenames the specification uses |
| S-8 | an undefined state warns rather than failing, because section 11 is a SHOULD |
| S-9, S-10 | reported as unresolvable from one snapshot; noted, not checked |
| S-11 | pinned as the `spec-example-empirelabs` member, an expected reject at Level 1 |
| S-12 | not checked; the requirement has no definition to check against |
| S-13 | absence of the discovery file warns, with the resolution-order reason in the message |
| S-14 | `ACI-DIS-002` checks the required fields; the version syntax mismatch is not enforced |
| S-15, S-16 | out of scope for a checker; carried here because the register and the score are what an independent implementation is asked to file into |
