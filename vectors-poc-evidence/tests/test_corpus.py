"""Tests for the Proof-of-Control conformance corpus.

Standard library only (unittest), so they run on a box with no project environment:
    python3 -m unittest discover -s vectors-poc-evidence/tests -v
The builder and reference-comparison tests also need the cryptography library.
The corpus, the twin and the reference results are all committed, so nothing
here needs the network or the raw capture.
"""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "package"))

from poc_evidence_vectors import twin  # noqa: E402
from poc_evidence_vectors.run_vectors import judge_twin, load_cases, passes  # noqa: E402

PKG = ROOT / "package" / "poc_evidence_vectors"
SPEC = ROOT / "build" / "spec-93d0e28"
CASES = load_cases()
BY_ID = {c["id"]: c for c in CASES}


def run(script, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "build" / script), *args],
        capture_output=True,
        text=True,
        check=False,
    ).returncode


# ----------------------------------------------------------------- the corpus
def test_builder_is_byte_reproducible():
    assert run("proof-of-control-build.py", "--check") == 0


def test_manifest_matches_the_files():
    m = json.loads((PKG / "CORPUS-MANIFEST.json").read_text())
    files = {
        str(p.relative_to(PKG / "corpus")): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((PKG / "corpus").rglob("*.json"))
    }
    assert m["files"] == files
    assert m["case_count"] == len(CASES) == len(files)
    assert (
        m["corpus_sha256"]
        == hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    )


def test_every_case_names_real_requirements():
    ids = {r["id"] for r in csv.DictReader((SPEC / "poc-checklist.csv").open())}
    assert len(ids) == 127
    for c in CASES:
        assert c["requirements"], c["id"]
        assert set(c["requirements"]) <= ids, c["id"]


def test_every_negative_case_names_its_accepted_reasons():
    for c in CASES:
        if c["expect"]["result"] == "reject":
            assert c["expect"]["code"] and all(
                isinstance(x, str) for x in c["expect"]["code"]
            )


# ------------------------------------------------------- the twin is the check
def check_twin_agrees_with_the_case(case):
    got = judge_twin(case)
    assert passes(case, got), (
        f"{case['id']}: expected {case['expect']}, twin said {got}"
    )


def test_twin_ed25519_matches_rfc_8032():
    vectors = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ]
    for pk, msg, sig in vectors:
        assert twin.ed25519_verify(
            bytes.fromhex(pk), bytes.fromhex(sig), bytes.fromhex(msg)
        )
        assert not twin.ed25519_verify(
            bytes.fromhex(pk), bytes.fromhex(sig), bytes.fromhex(msg) + b"!"
        )


def test_twin_jcs_matches_the_specifications_published_canonical_digests():
    manifest = json.loads((SPEC / "schema" / "vectors" / "manifest.json").read_text())
    for entry in manifest["canonical"]:
        obj = twin.parse((SPEC / "schema" / "vectors" / entry["file"]).read_text())
        assert hashlib.sha256(twin.jcs(obj)).hexdigest() == entry["canonical_sha256"]


def test_twin_accepts_every_published_positive_and_rejects_every_negative_for_the_stated_reason():
    manifest = json.loads((SPEC / "schema" / "vectors" / "manifest.json").read_text())
    pk = manifest["public_key"]
    for e in manifest["positive"]:
        assert (
            twin.check_token((SPEC / "schema" / "vectors" / e["file"]).read_text(), pk)
            is None
        )
    for e in manifest["negative"]:
        got = twin.check_token(
            (SPEC / "schema" / "vectors" / e["file"]).read_text(), pk
        )
        assert got == e["expect_code"], (e["file"], got)


# ------------------------------------- one mutation per negative token (twin)
# The twin replaces a per-control test: for each negative token, the twin
# accepts the base, rejects the case, and the two differ at one claim path.
MULTI_PATH = {
    "TOK-N-tree-size-equals-step-index": "step_index and tree_size move together",
    "TOK-N-parse-lone-surrogate": "text edit",
}


def _paths(o, prefix=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, f"{prefix}/{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, f"{prefix}[{i}]")
    else:
        yield prefix, o


def _diff(a, b):
    pa, pb = dict(_paths(a)), dict(_paths(b))
    return {k for k in set(pa) | set(pb) if pa.get(k) != pb.get(k)} - {
        "/signature",
        "/iat",
    }


# a MODIFY fault is one mutation away from an accepted MODIFY record
BASE_OF = {"TOK-F-modify-same-as-proposed": "TOK-P-modify-dispatch-differs"}

TOKEN_NEG = [
    c for c in CASES if c["kind"] == "token" and c["expect"]["result"] == "reject"
]


def check_negative_token_is_one_mutation_from_an_accepted_base(case):
    base = BY_ID[BASE_OF.get(case["id"], "TOK-P-base")]
    assert twin.check_token(base["text"], base["public_key"]) is None
    try:
        tok = twin.parse(case["text"])
    except (
        Exception
    ):  # unparseable text: nothing to diff, the twin check above covers it
        return
    if (
        case["id"] in MULTI_PATH
        or "float" in case["id"]
        or "reference-time" in case["id"]
    ):
        return
    delta = _diff(twin.parse(base["text"]), tok)
    # a missing member shows as removed paths, which can be several leaves of a
    # nested member; require them to share one root member
    roots = {
        p.split("/")[1] + ("/" + p.split("/")[2] if p.startswith("/poc_claims") else "")
        for p in delta
    }
    assert len(roots) <= 1, (case["id"], sorted(delta))


# --------------------------------------- the Merkle negatives are not vacuous
def _sha(b):
    return hashlib.sha256(b).digest()


def naive_no_leaf_prefix_verify(index, size, record, proof, root):
    """A verifier that hashes leaves without the 0x00 prefix."""
    h = _sha(record)
    got = twin._root_from_path(index, size, h, list(proof))
    return got == root


def naive_duplicating_verify(index, size, record, proof, root):
    """A verifier for a tree that pairs an odd last node with itself."""
    h, i, n, p = twin.leaf_hash(record), index, size, list(proof)
    while n > 1:
        if i % 2 == 1:
            if not p:
                return False
            h = twin.node_hash(p.pop(0), h)
        elif i + 1 < n:
            if not p:
                return False
            h = twin.node_hash(h, p.pop(0))
        else:
            h = twin.node_hash(h, h)
        i //= 2
        n = (n + 1) // 2
    return not p and h == root


def _inc(case):
    return (
        case["index"],
        case["tree_size"],
        bytes.fromhex(case["record_hex"]),
        [bytes.fromhex(x) for x in case["proof"]],
        bytes.fromhex(case["root"]),
    )


def test_interior_node_case_fools_a_verifier_without_leaf_prefix():
    c = BY_ID["INC-N-interior-node-as-leaf"]
    assert naive_no_leaf_prefix_verify(*_inc(c)) is True
    assert judge_twin(c)["result"] == "reject"


def test_odd_leaf_case_fools_a_duplicating_tree_verifier():
    c = BY_ID["INC-N-odd-leaf-duplication"]
    assert naive_duplicating_verify(*_inc(c)) is True
    assert judge_twin(c)["result"] == "reject"


def test_size_is_not_bound_by_the_root():
    c = BY_ID["INC-O-size-not-bound-by-root"]
    assert judge_twin(c)["result"] == "accept"
    assert c["class"] == "observation"


# ------------------------------------- second-angle checks on the headline claim
RESULTS = json.loads((ROOT / "REFERENCE-RESULTS.json").read_text())


def test_reference_results_are_current():
    assert run("reference_compare.py", "--check") == 0


def test_every_divergence_is_a_token_case_and_the_classes_are_as_reported():
    d = RESULTS["divergences"]
    assert {x["kind"] for x in d} == {"token"}
    tally = {}
    for x in d:
        tally[x["class"]] = tally.get(x["class"], 0) + 1
    assert tally == {"finding": 3, "platform-fact": 2, "interop": 1, "robustness": 4}


def test_finding_quotes_appear_verbatim_in_the_pinned_specification():
    seen = 0
    for c in CASES:
        g = c.get("grounding")
        if not g:
            continue
        hits = [p for p in SPEC.rglob(g["file"])]
        assert hits, g
        flat = " ".join(hits[0].read_text(encoding="utf-8").split())
        assert " ".join(g["quote"].split()) in flat, (c["id"], g)
        seen += 1
    assert seen == 3


def test_finding_cases_are_accepted_only_because_of_the_stated_fault():
    # the reference accepts each finding case; it must also accept the base, and
    # the twin must accept the base: the single difference is the fault
    divergent = {x["id"] for x in RESULTS["divergences"]}
    for cid in (
        "TOK-F-modify-same-as-proposed",
        "TOK-F-reason-empty-string",
        "TOK-F-reference-values-uri-empty",
    ):
        assert cid in divergent
        assert BY_ID[cid]["class"] == "finding"
    assert "TOK-P-base" not in divergent


# ----------------------------------------------------------------- unittest glue
class CorpusTests(unittest.TestCase):
    def test_twin_agrees_with_every_case(self):
        for case in CASES:
            with self.subTest(case=case["id"]):
                check_twin_agrees_with_the_case(case)

    def test_every_negative_token_is_one_mutation_from_an_accepted_base(self):
        for case in TOKEN_NEG:
            with self.subTest(case=case["id"]):
                check_negative_token_is_one_mutation_from_an_accepted_base(case)


def _wrap(fn):
    def method(self):
        fn()

    method.__name__ = fn.__name__
    return method


for _name, _fn in list(globals().items()):
    if _name.startswith("test_") and callable(_fn) and _fn.__code__.co_argcount == 0:
        setattr(CorpusTests, _name, _wrap(_fn))
        del globals()[_name]

if __name__ == "__main__":
    unittest.main()
