# Layout of a signed-claims corpus

Some record families in this repository are not in-toto Statements. Each of their records is a small JSON object of
claims with one Ed25519 signature over it, and its corpus ships the records, the decision each case expects and two
readers that must agree. The revocation-fence and authority-epoch-fence corpora are the first of them; a new family of
this kind (an effect-chain receipt, a record-pipeline log, a twin reader in another language) takes the same layout,
so a verifier written for one already knows where everything is in the next.

## The wire form

| Part | Rule |
| --- | --- |
| Record | `{"claims": {...}, "sig": "<base64>"}`, exactly those two members |
| Claims | exactly the members the record type declares, with `"v": 1` |
| Signing input | `DOMAIN`, one zero byte, then the RFC 8785 serialisation of `claims` |
| Domain | the family's type URI, a `#`, and the record name, for example `.../predicate/v1/revocation-fence#effect-permit` |
| Signature | Ed25519, standard base64 with padding, and it must re-encode to the same string |
| Key id | lowercase hex SHA-256 of the raw 32-byte public key; it selects among keys the verifier pinned and never brings a key of its own |
| Times | nanoseconds as canonical decimal strings, because RFC 8785 numbers stop at 2^53 |
| Windows | half-open: `not_before <= t < not_after` |

Because the domain is the type URI, every record a producer signs carries the identifier this repository defines, and
the URI resolves to the family's specification.

## Where each part lives

| Part | Path |
| --- | --- |
| Corpus | `corpora/vectors-<family>/`: `README.md` (the specification), `gen_vectors.py`, `check_vectors.py`, `MANIFEST.json`, `cases/<id>/case.json` and the record files, `tests/test_corpus.py` |
| Registry row | one `[[corpus]]` row in `corpora/REGISTRY.toml`; `scripts/corpus-registry.py` writes the packaging block and the index from it |
| Type URI | one entry under "Defined here" in `spec/predicates/REGISTRY.md` whose document is the corpus README, built into `pages/` by `scripts/build_predicate_pages.py` |
| Python reader | `packaging/agent_evidence_vectors/<family>.py`: `SUITE`, `CHECKS` in the order applied, `verify(case_path, skip)`, `check`, `run`, `main` |
| Go reader | `corpusreaders/<family>.go`, registered with `init()` and run by `aee-verify <corpus-dir>` |

## Rules a new family keeps

- The generator writes every case file and the manifest, from published seed labels, and computes each expected value
  by calling the reader; `scripts/regenerability-gate.py` rebuilds it and compares bytes.
- Every entry of `CHECKS` is forced by at least one case: skipping it changes the decision of some case.
- A reader in another language is a twin: it must return the same decision, reason and status as the Python reader
  for every case in `MANIFEST.json`, and its test runs over the whole manifest.
- A case whose expected answer rests on a rule still under review carries `"status": "proposed"` in the manifest;
  every other case is `"normative"`.
- A state that is open, unresolved or unreadable never reads as closed. A family that reports a revocation status
  uses `closed`, `partial` or `unknown` for it, beside `live` and, where the family has suspension, `suspended`.
