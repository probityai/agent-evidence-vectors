# Predicate pages and their persistent identifiers

A predicate type URI of this project is a persistent identifier under `https://w3id.org/agent-evidence/predicate/v1/`. The w3id.org service redirects it, with HTTP 302, to `https://probityai.github.io/agent-evidence/predicate/v1/<name>/`, the Pages site of this repository, and the page there is the predicate's specification rendered to HTML. The redirect rules live in `ids/agent-evidence/.htaccess` of [perma-id/w3id.org](https://github.com/perma-id/w3id.org).

| Type URI | Page | Specification |
| --- | --- | --- |
| `https://w3id.org/agent-evidence/predicate/v1/done-contract` | `pages/predicate/v1/done-contract/` | `spec/predicates/done-contract.md` of agent-evidence-vectors |
| `https://w3id.org/agent-evidence/predicate/v1/done-receipt` | `pages/predicate/v1/done-receipt/` | `spec/predicates/done-receipt.md` of agent-evidence-vectors |

## Why the identifier and the page are separate

A producer writes the type URI inside the bytes it signs, so the URI can never change. The w3id identifier carries no host: if the pages move, one pull request to w3id.org repoints every identifier, and no signed statement changes. The page address is therefore not part of any record, and nothing should cite it in place of the type URI.

## Changing a page

`pages/` is generated. Rebuild it from the specification at a pinned commit, with pandoc 3.3:

```sh
python3 scripts/build_predicate_pages.py --spec-dir <agent-evidence-vectors>/spec/predicates --commit <sha>
python3 scripts/check_predicate_pages.py
```

The build writes each page's SHA-256 to `pages/predicate/v1/PAGES.sha256`, and the check (run by the `repository` job and before every deploy) refuses a page whose bytes differ from its pin, a page whose canonical link is not its type URI, and a link to a host outside its list. A page changes only when its specification changes, and the pin moves in the same commit.

Whatever later serves the Pages site of this repository must keep serving `pages/` at the same paths, because the w3id rules point there.

## Vocabulary term URIs

Every term of `packages/vocabulary/vocabulary.yaml` has the URI `https://w3id.org/agent-evidence/vocab/v1/<term>`, and each registered value is that URI with the value as its fragment, for example `https://w3id.org/agent-evidence/vocab/v1/observation_vantage#substrate`. The page behind each one is generated, never edited:

```sh
cd packages/vocabulary && python3 scripts/gen_registry_index.py && cd ../..
python3 scripts/build_vocabulary_pages.py
```

The first command writes `packages/vocabulary/registry.json`, which carries the SHA-256 of the exact `vocabulary.yaml` bytes (the `registryDigest` a record carries); the second writes `pages/vocab/v1/` and publishes those bytes at `pages/vocab/v1/registry/sha256-<hex>.yaml`.

`w3id/agent-evidence.htaccess` is the copy, kept here, of `ids/agent-evidence/.htaccess` in perma-id/w3id.org. `scripts/check_uris_resolve.py` applies it to every predicate type URI, term URI and value URI, and fails when one does not land on a page and anchor under `pages/`; the repository job runs it on every pull request. `--network` (the `uris-network` workflow) also compares the copy with the live rules and requests every identifier, so a rule added to the copy and not yet merged upstream shows there.

### Why the term URIs take this shape

Recorded so that later releases keep it. An outside review on 2026-10-27 attacked the first version of this decision; points 2, 3, 5, 6 and 7 carry its changes.

1. **One URI per term, made by a rule and never stored.** `https://w3id.org/agent-evidence/vocab/v1/<term>`, where `<term>` is the term's key in `vocabulary.yaml` (`[a-z0-9_]+`). The URI cannot disagree with the key, and a key is never reused for another meaning: a term whose meaning would change incompatibly gets a new key, and the old one keeps its URI and page, marked deprecated.
2. **A registered value is a fragment of its term**, `.../vocab/v1/observation_vantage#substrate`. A value means nothing apart from its term, so one page per term carries every value as an element whose `id` is the value key. The fragment never reaches the server, so one redirect rule serves every term. A value's spelling in the URI is its registry key; a document whose wire tokens are spelled differently states its own mapping to the value URIs.
3. **No release number in the URI; the release is pinned beside it.** The URI names the term. A record names the exact registry by `registryDigest`, the SHA-256 of the released `vocabulary.yaml` bytes, hashed as a file with no parsing or newline change. A document that cites terms pins the signed tag `agent-evidence-vocabulary-vX.Y.Z`, its commit, and that digest. Registration gives a value an identity; it does not make the value acceptable to a document that closes a set, which lists its own values.
4. **`v1` is a namespace, not a version.** It changes only if this rule changes. Adding a term or a value is a compatible change under the same URIs.
5. **w3id.org in front of GitHub Pages, for snapshots too.** No identifier names a host we run; one pull request to `ids/agent-evidence/.htaccess` in perma-id/w3id.org repoints all of them. Every published registry is reachable at `https://w3id.org/agent-evidence/vocab/v1/registry/sha256-<hex>.yaml`, and its bytes must hash to its name. `registry` is therefore reserved and is never a term key.
6. **Static HTML with the data embedded; no content negotiation.** GitHub Pages cannot vary a response by `Accept`. Each term page carries the same facts as JSON-LD with absolute `@id`s under w3id.org: the term is a `skos:Concept` in the `vocab/v1/` `skos:ConceptScheme`, and each value is a concept tied to its term by `rdfs:isDefinedBy`. A value is a value of the term, not a narrower kind of it, so `skos:narrower` is not used. A term page describes the current registry; a record is read against the registry its digest names.
7. **An issued URI is never withdrawn.** `scripts/build_vocabulary_pages.py` refuses to drop the page of a term that has one, and a published registry copy is never removed.
8. **Checked both ways.** `scripts/check_uris_resolve.py` fails a pull request when a term, value or snapshot URI does not land on a page, an anchor or matching bytes under `pages/` through `w3id/agent-evidence.htaccess`, or when a term takes a reserved key; the tests also parse each page's JSON-LD against `registry.json`. The weekly `uris-network` workflow compares that file with the live w3id.org rules and requests every identifier.

Rejected: identifiers at the Pages address (a host change would break every record), a per-release path such as `/vocab/0.8.0/<term>` (two URIs for one unchanged term, and records rewritten on every release), content negotiation through w3id `Accept` rules (a second representation per term to keep in step), and a page per value.
