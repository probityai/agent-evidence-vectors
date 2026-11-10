# RFC: registering domain predicate types under predicate/v1

Status: open for comments until 20 Nov 2026. Discussion: the RFC issue that links this page.

## What the registry already says

The registry at <https://probityai.github.io/agent-evidence-vectors/predicate/> states two rules. A predicateType is
the one string a producer writes inside the bytes they sign, so a published URI never changes and never stops
resolving. Every entry says whether its field definitions are defined in this repository or registered here with the
definitions published elsewhere. What the registry lacks is a process by which someone outside this repository
registers a type for a record family from their own domain. This page proposes that process.

## Filing a "Registered here" entry

The person or project that emits the type files the entry, by pull request. The entry carries:

1. the URI under `predicate/v1/`;
2. the owner, by GitHub handle;
3. where the normative field definitions live;
4. the envelope: an in-toto Statement, in DSSE or bare;
5. one example record that validates;
6. the compatibility rule: a v2 is a new URI beside v1, never a change to v1;
7. `confirmed_at`: who confirmed which revision of the field definitions, with a link to that confirmation. An entry
   whose definitions live elsewhere names the revision its owner confirmed, and a later revision is a new
   confirmation, never an edit of the old one.

The page served at the URI states that the name is taken, by whom, and in what shape. It never presents itself as the
field definition. A superseded type keeps resolving with the status "addresses records already minted under it", as
the kernel-substrate v1 entry does today.

## Review checklist

A filed entry is merged when every item below holds, and each correction made during review is recorded in the pull
request so the history of the entry stays public:

- the URI resolves to the served page and the page names the owner and the confirmed revision;
- the example record validates against the published field definitions at that revision;
- the envelope named in the entry is the envelope the example uses;
- no existing entry, defined here or registered here, already covers the same records under another name;
- the entry adds no claim about a product beyond the shape of its records.

A pull request template that pre-fills the skeleton (entry, page, example, compatibility block, `confirmed_at`) is
planned for release 0.37.0, so filing becomes a review of filled fields.

## Families and how each becomes registered

Each family below has already been shown on #352 or in a pull request. The person who showed it can file its slot.

| Family | Source | Path |
| --- | --- | --- |
| `eip3009-payment-effect` | #347 | slot for its contributor to file |
| `refund-connected` | #432 (merged) | slot for its contributor to file |
| `paid-audit-record` | #247 | slot for its contributor to file |
| `privacy-access-request` | #423 | slot for its contributor to file |
| `rttp-refusal` | #453 | registered as `predicate/v1/refusal-reason-priority`, corpus `vectors-refusal-reason-priority` (#483); its owner confirmed revision 02 of the draft in #492 |
| `physical-completion` | #80 | this repository builds the `vectors-physical-completion` suite now from draft-noa-scitt-ai-agent-receipt-01 sections 8.1 to 8.3 (rejects) and 1.5 (indeterminate), crediting #80 in the suite manifest, and #80 closes with a link to it |

A slot is a reservation, not an entry. Demand seen on a thread is not settled semantics, and nothing is listed as
registered until its definition, example, page and confirmation exist. Credit in a manifest records who contributed
the case; it implies no endorsement of anyone's product.

## Suites and the corpus registry

A registered family usually also wants a conformance suite. Suites are listed in `corpora/REGISTRY.toml`, checked by
`scripts/corpus-registry.py` against `corpora/REGISTRY.schema.json`, so a new suite is one registry row plus its
corpus directory, and its records carry the registered URI. The suites roadmap ([suites-roadmap.md](suites-roadmap.md))
lists which families move first.

## What an emitter gets, and what it costs

An emitter gets a URI that is checked never to 404, listed beside the types this repository defines, and a row on
the Agent Evidence Conformance Board once a verifier replays their family ([conformance-badges.md](conformance-badges.md)).
It costs the artifacts above and the rule that the URI never moves. The first filed entry is merged as soon as its
artifacts resolve.
