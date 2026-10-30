"""Generate corpus_vectors.json for the OPA admission tests from the published
conformance corpus (a checkout of the vectors repository, `vectors/MANIFEST.json`).

The rego admission tests DRIVE from the real conformance corpus: this script is the
mechanical projection that makes the corpus loadable as OPA `data`. Each entry's
`statement` is the byte-for-byte parse of a v0.6 BARE in-toto Statement (the decoded
Statement the rego evaluates as `input`), so the security-relevant vectors are never
hand-copied into the test -- they are the published corpus.

`opa test rego/` loads every .json in the directory as `data`, so the
emitted document mounts at `data.corpus_vectors`. The CI opa job regenerates this file
and `git diff --exit-code`s it, so the test can never silently drift from the corpus.

The rego admission policy is a strict SUBSET verifier: it evaluates an already-parsed
Statement (mounted as `input`) and re-derives only the binding + coverage/soundness
contract it can see from the predicate body. Two scope boundaries are therefore
projected INTO this document so the wiring tests in execution_evidence_test.rego can
prove the split is exactly right (never reject-all, never over-denylisted):

  * reject vectors are split into `reject` (rego can evaluate: it trips
    `not (bindings_ok AND soundness_ok)`) and `reject_denylisted` (rego ADMITS them
    -- the defect lives in a layer rego cannot reach: the DSSE envelope, the base64
    record pre-image, the RFC-6962 Merkle fold, Ed25519 proof-of-observation, or a
    value-form rego does not validate). The `_OUTSIDE_REGO_REACH` families below were
    derived EMPIRICALLY (each reject run through the policy once; the denylist ==
    exactly the ids the policy admits) and each carries a per-family reason. The test
    `test_corpus_denylist_justified` asserts every denylisted reject really is
    admitted, so a future policy that GAINS power over one of these fails the gate
    loudly instead of silently hollowing the reject corpus.

  * accept vectors are all emitted in `accept`, each tagged `regoSound`. The ones
    tagged false exceed the rego subset's reach -- as of the vocabulary-scope
    correction that is one vector and one cause, an absent runEntropy the rego
    run-identity recompute cannot reproduce -- and they are declared in
    `_OUTSIDE_REGO_SOUNDNESS` below. EVERY accept satisfies `bindings_ok`; the excluded
    ones fail only `soundness_ok`, and they are still VALID per the offline TS/Python
    verifier (MANIFEST verdict "valid"). The test `test_corpus_accepts_scope_honest`
    asserts each `regoSound:false` accept binds but is NOT sound (the exclusion is
    justified, not hiding a bug), and every result=="pass" AND regoSound accept is
    asserted `isCompliant` (a reject-all bug fails these loudly -- the anti-hollow
    guarantee is the accept side).

HOW A BOUNDARY NAMES ITS VECTORS, AND WHY IT STOPPED NAMING THEM BY SLUG.
Both boundaries above used to be `dict[slug, reason]` tables keyed on the corpus's
authoring names. suiteRevision 28 deleted those names -- every vector is now
`statements/v<digest>.json`, and MANIFEST.json carries no trace of the old slugs,
because measured over the retired layout the identifier predicted accept-or-reject on
its own. Every key in both tables stopped matching in one commit. Nothing failed:
`v["id"] not in _TABLE` was true for every vector in the corpus, so the
denylist became the EMPTY SET, `reject_denylisted` was emitted empty, and
`every v in data.corpus_vectors.reject_denylisted { ... }` over an empty collection is
vacuously true. The gate that exists to prove each denylisted vector really is
admitted reported PASS while asserting nothing.

So a boundary is now a list of `ScopeFamily` (see corpus_scope.py), naming its vectors
by the manifest's own answer-neutral fields -- the `aee-c-NN` conditions the vector
forces and the exact `expected` object a conforming rail must produce -- plus a
predicate over the statement's own content wherever those two do not separate the
family from a sibling the rail genuinely reaches. NO DIGEST appears in a family
either: a content address substituted for a slug rebuilds the identical defect one
layer down, because the next regeneration moves every digest exactly as this one moved
every name. Each family declares how many vectors it covers, and a family that selects
a different number -- above all, a family that selects NOTHING -- REFUSES rather than
quietly narrowing the boundary.

The families were re-derived from the corpus generators in the vectors repository,
which mint every vector and write their own authoring-name-to-id maps
(`.build/aee-accept-ids.json`, `.build/aee-reject-ids.json`) on each run. That map is a
primary artifact rather than an inference; it is deliberately NOT vendored here,
because vendoring it would put the retired names back on the load-bearing path.

Run: python3 rego/gen_corpus_vectors.py --corpus <vectors checkout>
     python3 rego/gen_corpus_vectors.py --check --corpus <vectors checkout>

Exit codes:
    0  written, or under --check the vendored projection matches the corpus
    1  under --check, the vendored projection is stale against that corpus
    2  could not read: the checkout carries no vectors/MANIFEST.json, so nothing
       was measured. An unreadable corpus is never reported as an unchanged one.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from corpus_scope import (
    ScopeFamily,
    all_rows_substrate_basis,
    arming_without_assessed_attacks,
    env_without_substrate,
    resolve,
)

# Set from --corpus. There is no default: a default would let this script read
# whatever corpus happened to sit at a path and report the projection as current.
_VEC_DIR: Path = Path()
_OUT = Path(__file__).resolve().parent / "corpus_vectors.json"

# Reject vectors the rego rail ADMITS -- their defect is outside rego's evaluable
# scope (parsed-Statement binding + coverage/soundness only). DERIVED EMPIRICALLY:
# every reject was run through data.sigstore.bindings_ok && data.sigstore.soundness_ok;
# this set == exactly the ids the policy admitted. test_corpus_denylist_justified
# re-proves that equality inside `opa test`, so the boundary cannot silently rot.
#
# Whole families that USED to sit here and no longer do are worth stating, because the
# reason is a capability gain rather than a corpus move. The 1xx observationRefs class
# match, the 3xx aeeMethod-cap lattice, the 7xx record-class deep validation and the
# 0.7 attribution rules are all evaluated now; several entries that once claimed to
# need a SIGNED payload were reading a member this module already decodes, and were
# mis-denylisted from the start rather than correctly denylisted and later overtaken.
_OUTSIDE_REGO_REACH: tuple[ScopeFamily, ...] = (
    ScopeFamily(
        what="aeePayloadCommitment presence -- needs the signed interception payload",
        conditions=frozenset(["aee-c-104"]),
        expected={"codes": ["payload-missing-reserved"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "an unreferenced carried arming record missing aeeArmedAt -- outside "
            "rego's referenced-record scope"
        ),
        conditions=frozenset(["aee-c-108"]),
        expected={"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "an unreferenced carried examination record signed intercepted -- outside "
            "rego's referenced-record scope"
        ),
        conditions=frozenset(["aee-c-108"]),
        expected={"codes": ["examination-covers-nothing"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "unreferenced carried sealed records, each defective in its own member -- "
            "a missing or non-boolean aeeStillArmed, a missing or negative "
            "aeeDropCount, drops with no bound or past one, a mismatched posture, a "
            "reconstructed signing method, a missing aeeObservedSet or "
            "aeeObservedAttacks, an unknown observed attack, or covering nothing at "
            "all. GATE 1 requires every CARRIED covering-kind record to satisfy its "
            "own constraints whether or not a row references it, which closes the "
            "laundering path where a producer ships a defective signed record beside a "
            "clean one; the rego rail evaluates only the REFERENCED-record path, so an "
            "unreferenced carried record is outside its scope by construction"
        ),
        conditions=frozenset(["aee-c-108"]),
        expected={"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        count=14,
    ),
    ScopeFamily(
        what="record-internal JCS canonicality -- out of rego scope",
        conditions=frozenset(["aee-c-17"]),
        expected={
            "alsoEmits": ["caught-row-uncovered", "observed-set-mismatch"],
            "codes": ["payload-not-canonical"],
            "verdict": "invalid",
        },
        count=1,
    ),
    ScopeFamily(
        what=(
            "record-payload i-JSON and string-scalar faults -- a bignum, a duplicate "
            "member, a lone surrogate escape, CESU-8, a noncharacter, and nesting at "
            "or past the depth bound. All sit inside the base64 catch-record "
            "pre-image or in raw string bytes; rego reads the lenient parse of an "
            "already-decoded payload and bounds no nesting"
        ),
        conditions=frozenset(["aee-c-18"]),
        expected={
            "alsoCarries": ["observed-set-mismatch"],
            "alsoEmits": ["caught-row-uncovered"],
            "codes": ["payload-not-ijson"],
            "verdict": "invalid",
        },
        count=7,
    ),
    ScopeFamily(
        what=(
            "statement-wide raw-byte faults -- a duplicate member rego parses "
            "last-wins, a lone high or low surrogate escape, a reversed surrogate "
            "pair, and a noncharacter in a vocabulary label. Each lives in the bytes "
            "rather than in the parse rego is handed"
        ),
        conditions=frozenset(["aee-c-18"]),
        expected={"codes": ["statement-malformed"], "verdict": "invalid"},
        count=5,
    ),
    ScopeFamily(
        what="record base64 canonicality -- out of rego scope",
        conditions=frozenset(["aee-c-19"]),
        expected={
            "alsoCarries": ["observed-set-mismatch"],
            "alsoEmits": ["payload-not-canonical", "reconstructed-row-uncovered"],
            "codes": ["record-undecodable"],
            "verdict": "invalid",
        },
        count=1,
    ),
    ScopeFamily(
        what="RFC-6962 fold (domain separation) -- out of rego scope",
        conditions=frozenset(["aee-c-25"]),
        expected={"codes": ["batch-root-mismatch"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="RFC-6962 fold (padding) -- out of rego scope",
        conditions=frozenset(["aee-c-26"]),
        expected={"codes": ["batch-root-mismatch"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="RFC-6962 fold (leaf order) -- out of rego scope",
        conditions=frozenset(["aee-c-27"]),
        expected={"codes": ["batch-root-mismatch"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "record-hash dedup plus an undecodable record body -- both at the base64 "
            "record pre-image layer, the same boundary as the dedup family below"
        ),
        conditions=frozenset(["aee-c-29"]),
        expected={
            "codes": ["duplicate-record", "record-undecodable"],
            "verdict": "invalid",
        },
        count=1,
    ),
    ScopeFamily(
        what="record-hash dedup -- out of rego scope",
        conditions=frozenset(["aee-c-29"]),
        expected={"codes": ["duplicate-record"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="RFC-6962 fold (root tamper) -- out of rego scope",
        conditions=frozenset(["aee-c-30"]),
        expected={"codes": ["batch-root-mismatch"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="orphan batchRoot (no records) -- vacuously ok in rego",
        conditions=frozenset(["aee-c-31"]),
        expected={"codes": ["batch-root-orphaned"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="vocab caught-subset invariant -- out of rego scope",
        conditions=frozenset(["aee-c-52"]),
        expected={"codes": ["vocabulary-caught-not-subset"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "vocabulary canonical order, both as unsorted labels and as a duplicated "
            "caught label -- out of rego scope"
        ),
        conditions=frozenset(["aee-c-53"]),
        expected={"codes": ["vocabulary-not-canonical"], "verdict": "invalid"},
        count=2,
    ),
    ScopeFamily(
        what="vocab digest recompute -- out of rego scope",
        conditions=frozenset(["aee-c-54"]),
        expected={"codes": ["vocabulary-digest-mismatch"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "subject-array cardinality under a substrate row, under an artifact row, "
            "and under the mixed artifact-and-admission shape -- rego enforces "
            "cardinality only under substrate rows"
        ),
        conditions=frozenset(["aee-c-58"]),
        expected={"codes": ["subject-cardinality"], "verdict": "invalid"},
        count=3,
    ),
    ScopeFamily(
        what="outer _type (Statement/v0.9) -- rego ignores _type",
        conditions=frozenset(["aee-c-77"]),
        expected={"codes": ["statement-type-unsupported"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="missing substrate -- not in rego binding contract",
        conditions=frozenset(["aee-c-78"]),
        expected={"codes": ["environment-incomplete"], "verdict": "invalid"},
        count=1,
        shape=env_without_substrate,
        shape_says="the observationEnvironment carries no substrate at all",
    ),
    ScopeFamily(
        what="manifest cross-class dup attackId -- collapses under rego set-union",
        conditions=frozenset(["aee-c-80"]),
        expected={"codes": ["manifest-duplicate-attack"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="member spelling (snake_case) -- rego ignores; rows valid",
        conditions=frozenset(["aee-c-84"]),
        expected={"codes": ["member-spelling"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what=(
            "vocabulary label BMP-only profile -- rego does not scan for non-BMP code "
            "points"
        ),
        conditions=frozenset(["aee-c-86"]),
        expected={"codes": ["vocabulary-not-canonical"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="payload member-NAME BMP-only profile -- rego does not scan member names",
        conditions=frozenset(["aee-c-87"]),
        expected={
            "alsoEmits": ["caught-row-uncovered", "observed-set-mismatch"],
            "codes": ["payload-not-canonical"],
            "verdict": "invalid",
        },
        count=1,
    ),
    ScopeFamily(
        what="actualLayer decode-layer type -- rego does not type-check actualLayer",
        conditions=frozenset(["aee-c-88"]),
        expected={
            "alsoCarries": ["malformed-missing-actual-layer"],
            "codes": ["statement-malformed"],
            "verdict": "invalid",
        },
        count=1,
    ),
    ScopeFamily(
        what="a clean row resolving an interception -- needs the record's signed aeeKind",
        conditions=frozenset(["aee-c-94"]),
        expected={"codes": ["clean-row-contradicted"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="an interception no caught row resolves -- needs the record's signed aeeKind",
        conditions=frozenset(["aee-c-95"]),
        expected={"codes": ["interception-record-orphaned"], "verdict": "invalid"},
        count=1,
        shape=all_rows_substrate_basis,
        shape_says="every attackResults row rests on basis substrate",
    ),
    ScopeFamily(
        what="the seal's committed record set -- needs the record PAE leaf hashes",
        conditions=frozenset(["aee-c-97"]),
        expected={"codes": ["observed-set-mismatch"], "verdict": "invalid"},
        count=3,
    ),
    ScopeFamily(
        what="sealed-kind members -- needs the signed sealed payload",
        conditions=frozenset(["aee-c-97"]),
        expected={"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        count=1,
    ),
    ScopeFamily(
        what="sealed-kind members -- needs the signed sealed payload",
        conditions=frozenset(["aee-c-98"]),
        expected={"codes": ["sealed-covers-nothing"], "verdict": "invalid"},
        count=2,
    ),
    ScopeFamily(
        what="arming-kind members -- needs the signed arming payload",
        conditions=frozenset(["aee-c-99"]),
        expected={"codes": ["arming-covers-nothing"], "verdict": "invalid"},
        count=1,
        shape=arming_without_assessed_attacks,
        shape_says="a carried arming record omits aeeAssessedAttacks",
    ),
)

# Accept vectors the rego rail cannot fully vouch for (soundness_ok undefined) because
# they exercise v0.6 semantics broader than the rego subset. ALL still satisfy
# bindings_ok and are VALID per the offline verifier; rego is the subset. DERIVED
# EMPIRICALLY (each accept run through soundness_ok).
#
# THIS BOUNDARY USED TO CARRY FIVE MORE, AND ALL FIVE WERE A MISSING RULE. A
# fail-closed method, an out-of-vocabulary label, a retired basis, an absent method and
# a retired method were each annotated as exceeding rego's vocabulary scope. They did
# not: basis, method and containmentObserved are plain members of the parsed statement,
# and the rego rail was treating the spec's fail-closed-ROW semantics as a STATEMENT
# validity gate, so it called invalid what the spec calls valid-and-failing. The rules
# that did that (basis_method_ok, containment_vocab_ok) are gone; the recompute floors
# these statements at "fail" and result_recompute_ok requires the carried token to
# match. See the vocabulary block in execution_evidence.rego.
#
# What remains is the shape a REAL boundary has: an accept whose runEntropy is absent,
# so the run-identity pre-image rego derives cannot reproduce the producer's
# aeeRunBinding at all. Nothing rego could read would change that.
_OUTSIDE_REGO_SOUNDNESS: tuple[ScopeFamily, ...] = (
    ScopeFamily(
        what=(
            "runEntropy absent; the producer aeeRunBinding is not reproduced by rego's "
            "json.marshal run-identity recompute (result=pass_indirect, valid)"
        ),
        conditions=frozenset(
            ["aee-c-2", "aee-c-24", "aee-c-29", "aee-c-30", "aee-c-32"]
        ),
        expected={
            "verdict": "valid",
            "result": "pass_indirect",
            "tierWithPinnedKey": ["declared"],
            "tierWithoutKey": ["declared"],
        },
        count=1,
    ),
)


def _load_statement(rel: str) -> dict[str, Any]:
    """Parse a v0.6 bare in-toto Statement (= the rego `input`)."""
    data: dict[str, Any] = json.loads((_VEC_DIR / rel).read_text(encoding="utf-8"))
    return data


def _statement_or_none(vector: dict[str, Any]) -> dict[str, Any] | None:
    """The parsed statement, or None for bytes that are not JSON text.

    A shape predicate can never hold for a vector that does not parse, and a vector
    that does not parse is not an error at resolution time -- it is the byte-malformed
    family, excluded from the corpus below.
    """
    try:
        return _load_statement(vector["file"])
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _is_byte_malformed(rel: str) -> bool:
    """A byte-level-malformed reject vector (CESU-8, overlong UTF-8, a raw control
    byte) is not a well-formed sequence of Unicode scalar values, so it is not
    valid JSON text and can never be the rego `input`: the admission controller's
    base64/decode layer rejects it before OPA runs. Detect it so it is excluded
    from the rego corpus rather than crashing the generator."""
    try:
        _load_statement(rel)
        return False
    except (UnicodeDecodeError, json.JSONDecodeError):
        return True


def _predicate_type(stmt: dict[str, Any], manifest_pt: str) -> str:
    return str(stmt.get("predicateType", manifest_pt))


def _reject_reason(v: dict[str, Any]) -> str:
    codes = v.get("expected", {}).get("codes", [])
    conds = "; ".join(v.get("conditions", []))
    return f"{conds} | codes: {','.join(codes)}" if codes else conds


def main(argv: list[str]) -> int:
    global _VEC_DIR

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="a checkout of the vectors repository; the corpus is <corpus>/vectors",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv[1:])

    _VEC_DIR = args.corpus / "vectors"
    manifest_path = _VEC_DIR / "MANIFEST.json"
    if not manifest_path.is_file():
        print(f"gen_corpus_vectors: missing {manifest_path}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_pt = manifest["predicateType"]
    accepts = [v for v in manifest["vectors"] if v["kind"] == "accept"]
    rejects = [v for v in manifest["vectors"] if v["kind"] == "reject"]
    # Byte-level-malformed reject vectors are not JSON text and cannot be OPA
    # input; drop them from the rego corpus (they are caught pre-rego at the
    # base64/decode layer). Reported below so the exclusion is never silent.
    byte_malformed = [v for v in rejects if _is_byte_malformed(v["file"])]
    _bm_ids = {v["id"] for v in byte_malformed}
    rejects = [v for v in rejects if v["id"] not in _bm_ids]

    # Both boundaries resolve through the manifest HERE, before anything is emitted.
    # A family that selects a different number of vectors than it declares -- above
    # all a family that selects none -- raises rather than narrowing the boundary,
    # because a boundary nobody asserts reads exactly like one that holds.
    denylisted = resolve(
        _OUTSIDE_REGO_REACH,
        rejects,
        _statement_or_none,
        label="reject denylist",
    )
    not_sound = resolve(
        _OUTSIDE_REGO_SOUNDNESS,
        accepts,
        _statement_or_none,
        label="accept soundness scope",
    )

    accept_entries = sorted(
        (
            {
                "name": v["id"],
                "predicateType": _predicate_type(
                    stmt := _load_statement(v["file"]), manifest_pt
                ),
                "reason": "; ".join(v.get("conditions", [])),
                "regoSound": v["id"] not in not_sound,
                "regoScope": not_sound.get(v["id"], ""),
                "expected": v["expected"],
                "statement": stmt,
            }
            for v in accepts
        ),
        key=lambda e: e["name"],
    )

    reject_evaluable = sorted(
        (
            {
                "name": v["id"],
                "predicateType": _predicate_type(
                    _load_statement(v["file"]), manifest_pt
                ),
                "reason": _reject_reason(v),
                "expected": v["expected"],
                "statement": _load_statement(v["file"]),
            }
            for v in rejects
            if v["id"] not in denylisted
        ),
        key=lambda e: e["name"],
    )

    reject_denylisted = sorted(
        (
            {
                "name": v["id"],
                "predicateType": _predicate_type(
                    _load_statement(v["file"]), manifest_pt
                ),
                "reason": _reject_reason(v),
                "regoScope": denylisted[v["id"]],
                "expected": v["expected"],
                "statement": _load_statement(v["file"]),
            }
            for v in rejects
            if v["id"] in denylisted
        ),
        key=lambda e: e["name"],
    )

    doc = {
        "corpus_vectors": {
            "suite": manifest["suite"],
            "predicateType": manifest_pt,
            "accept": accept_entries,
            "reject": reject_evaluable,
            "reject_denylisted": reject_denylisted,
        }
    }
    rendered = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    sound = sum(1 for e in accept_entries if e["regoSound"])
    excluded = ",".join(sorted(v["id"] for v in byte_malformed)) or "none"
    census = (
        f"{len(accept_entries)} accept [{sound} rego-sound], "
        f"{len(reject_evaluable)} reject evaluable, {len(reject_denylisted)} "
        f"denylisted, {len(byte_malformed)} byte-malformed excluded: {excluded}"
    )

    if args.check:
        if not _OUT.is_file():
            print(f"gen_corpus_vectors: {_OUT} does not exist", file=sys.stderr)
            return 2
        if _OUT.read_text(encoding="utf-8") != rendered:
            print(
                f"gen_corpus_vectors: {_OUT.name} is stale against {args.corpus}; "
                f"regenerate it and commit the result",
                file=sys.stderr,
            )
            return 1
        print(f"check: {_OUT.name} is the current projection ({census})")
        return 0

    _OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {_OUT} ({census})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
