"""The bound release's own test corpus, through the binding, two ways.

1. Against the corpus's expectations. Every pinned vector file the `jcs-admit`
   release ships in `tests/vectors/` is replayed through `jcs_admit` under
   the profile the crate's own Rust test uses, and must give the same accepted
   bytes and the same refusal classes. None of those expectations was produced
   by the crate (their provenance is `tests/vectors/PROVENANCE.md`).

2. Against the native crate. Every input from those files goes through the
   crate's own `wasm_oracle` example, built from the same registry source, and
   through the binding, under both `admit` and `admit_ijson`. The two must agree
   on every byte of output and on the variant, fields and message of every
   refusal, so the boundary loses nothing in either direction.

Each corpus asserts its own size: a differential that read nothing reports the
same clean run as one that found nothing wrong.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import bound_crate, data_lines
import jcs_admit as jcs

CRATE = bound_crate("jcs-admit")
VECTORS = CRATE.root / "tests/vectors"
TARGET = Path(__file__).resolve().parent.parent / "target" / "native-oracle"

# The profile the crate's attack and cross-rail tests run under:
# Options::ijson().integers_only(true).
CORPUS_PROFILE = {"safe_integers": True, "reject_noncharacters": True, "integers_only": True}


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.strip())


def rfc8785_reference() -> list[tuple[str, bytes, bytes]]:
    out = []
    for path in sorted((VECTORS / "rfc8785/input").glob("*.json")):
        out.append((path.stem, path.read_bytes(), (VECTORS / "rfc8785/output" / path.name).read_bytes()))
    assert len(out) == 6
    return out


def cross_rail() -> tuple[dict[str, bytes], dict[str, bytes], dict[str, str]]:
    inputs = {p.stem: p.read_bytes() for p in sorted((VECTORS / "cross-rail/input").glob("*.json"))}
    canonical = {p.stem: p.read_bytes() for p in sorted((VECTORS / "cross-rail/canonical").glob("*.json"))}
    refused = {}
    for line in data_lines(VECTORS / "cross-rail/refused.tsv"):
        vid, cls, *_ = line.split("\t")
        refused[vid] = cls
    assert (len(inputs), len(canonical), len(refused)) == (39, 30, 9)
    assert set(canonical) | set(refused) == set(inputs)
    assert not set(canonical) & set(refused)
    return inputs, canonical, refused


def attack() -> list[tuple[str, bytes, bytes | None]]:
    out = []
    for line in data_lines(VECTORS / "attack/strings-keys-members.tsv"):
        name, input_hex, expected, *_ = line.split("\t")
        if expected.startswith("ACCEPT "):
            out.append((name, unhex(input_hex), unhex(expected.removeprefix("ACCEPT "))))
        else:
            assert expected.startswith("REFUSE"), f"{name}: unreadable expectation {expected!r}"
            out.append((name, unhex(input_hex), None))
    assert len(out) == 317
    return out


def number_ties() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in data_lines(VECTORS / "es-number-ties.tsv"):
        left, right = line.split("\t")[:2]
        out.append((left, right))
    assert len(out) == 850
    return out


# ---- 1. against the corpus's own expectations ------------------------------


@pytest.mark.parametrize(("name", "data", "want"), rfc8785_reference(), ids=lambda v: v if isinstance(v, str) else "")
def test_rfc8785_reference_suite_byte_for_byte(name, data, want):
    assert jcs.admit(data) == want
    assert jcs.is_canonical(want)


def test_cross_rail_accepted_vectors_match_the_go_rails_bytes():
    inputs, canonical, _ = cross_rail()
    for vid, want in canonical.items():
        assert jcs.admit_with(inputs[vid], **CORPUS_PROFILE) == want, vid
        assert jcs.admit(want) == want, f"{vid}: the Go rail's output is not canonical under RFC 8785"


def test_cross_rail_refused_vectors_are_refused_in_the_same_class():
    inputs, _, refused = cross_rail()
    for vid, cls in refused.items():
        with pytest.raises(jcs.JcsError) as info:
            jcs.admit_with(inputs[vid], **CORPUS_PROFILE)
        assert info.value.variant == cls, vid


def test_attack_corpus_matches_the_independent_implementation():
    accepted = refused = 0
    for name, data, want in attack():
        if want is None:
            with pytest.raises(jcs.JcsError):
                jcs.admit_with(data, **CORPUS_PROFILE)
            refused += 1
        else:
            got = jcs.admit_with(data, **CORPUS_PROFILE)
            assert got == want, name
            assert jcs.is_canonical_with(got, **CORPUS_PROFILE), name
            accepted += 1
    # The split is pinned too, so turning a refusal into an acceptance cannot
    # pass by matching the other column.
    assert (accepted, refused) == (160, 157)


def test_every_number_tie_serializes_to_the_even_candidate():
    for token, want in number_ties():
        assert jcs.admit(token.encode()) == want.encode(), token


# ---- 2. against the native crate --------------------------------------------


@pytest.fixture(scope="module")
def oracle() -> Path:
    """The release's own `wasm_oracle` example, built from its registry source."""
    subprocess.run(
        [
            "cargo",
            "build",
            "--quiet",
            "--locked",
            "--manifest-path",
            str(CRATE.root / "Cargo.toml"),
            "--example",
            "wasm_oracle",
            "--features",
            "serde",
            "--target-dir",
            str(TARGET),
        ],
        check=True,
    )
    exe = TARGET / "debug" / "examples" / ("wasm_oracle.exe" if os.name == "nt" else "wasm_oracle")
    assert exe.is_file()
    return exe


def every_input() -> list[tuple[str, bytes]]:
    inputs, canonical, _ = cross_rail()
    out = [(f"rfc8785/{n}", d) for n, d, _ in rfc8785_reference()]
    out += [(f"rfc8785-out/{n}", w) for n, _, w in rfc8785_reference()]
    out += [(f"cross-rail/{k}", v) for k, v in inputs.items()]
    out += [(f"cross-rail-canonical/{k}", v) for k, v in canonical.items()]
    out += [(f"attack/{n}", d) for n, d, _ in attack()]
    out += [(f"ties/{t}", t.encode()) for t, _ in number_ties()]
    out += [(f"ties-out/{w}", w.encode()) for _, w in number_ties()]
    for line in data_lines(VECTORS / "rfc8785/appendix-b.tsv"):
        bits, expected, *_ = line.split("\t")
        if expected != "-":
            out.append((f"appendix-b/{bits}", expected.encode()))
    return out


def test_binding_and_native_crate_agree_on_the_whole_corpus(oracle):
    cases = every_input()
    assert len(cases) == 6 + 6 + 39 + 30 + 317 + 850 + 850 + 24
    profiles = {"admit": jcs.admit, "admit_ijson": jcs.admit_ijson}
    requests = [
        {"id": f"{i}:{profile}", "profile": profile, "bytes": list(data)}
        for i, (_, data) in enumerate(cases)
        for profile in profiles
    ]
    run = subprocess.run(
        [str(oracle)],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        # The oracle writes UTF-8 JSON; the locale's codec (cp1252 on Windows)
        # would turn a member name like U+1F600 into four wrong characters.
        encoding="utf-8",
        check=True,
    )
    responses = [json.loads(line) for line in run.stdout.splitlines()]
    assert len(responses) == len(requests)

    outcomes = {"accepted": 0, "refused": 0}
    for request, native in zip(requests, responses, strict=True):
        assert native["id"] == request["id"]
        name = cases[int(request["id"].split(":")[0])][0]
        fn = profiles[request["profile"]]
        try:
            got = fn(bytes(request["bytes"]))
        except jcs.JcsError as err:
            assert not native["ok"], f"{name} [{request['profile']}]: binding refused, crate accepted"
            want = native["error"]
            assert err.variant == want["variant"], name
            assert err.fields == want.get("fields"), name
            assert str(err) == want["message"], name
            outcomes["refused"] += 1
        else:
            assert native["ok"], f"{name} [{request['profile']}]: binding accepted, crate refused"
            assert got == bytes(native["output"]), name
            outcomes["accepted"] += 1
    # Both outcomes are exercised, so neither half of the comparison is vacuous.
    assert outcomes["accepted"] > 1000 and outcomes["refused"] > 100, outcomes
