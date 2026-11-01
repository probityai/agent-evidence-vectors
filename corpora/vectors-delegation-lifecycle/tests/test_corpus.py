"""The corpus regenerates byte for byte, its digest recomputes from the files, and
every case states one situation, one rule and an expected outcome."""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("delegation_lifecycle_generator", ROOT / "gen_vectors.py")


def _manifest() -> dict[str, Any]:
    return json.loads((ROOT / "MANIFEST.json").read_text())


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", ROOT / "INDEX.md", *(ROOT / "cases").rglob("*")]
                 if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_corpus_digest_recomputes_from_files() -> None:
    manifest = _manifest()
    assert generator.corpus_digest(manifest, str(ROOT)) == manifest["corpusDigest"]


def test_every_refused_case_names_an_accepted_twin_in_its_own_set() -> None:
    by_id = {e["id"]: e for e in _manifest()["vectors"]}
    for e in by_id.values():
        if e["expected"]["decision"] == "accept":
            assert "twin" not in e, e["id"]
            continue
        twin = by_id[e["twin"]]
        assert twin["expected"]["decision"] == "accept", e["id"]
        assert twin["set"] == e["set"], e["id"]


def test_every_case_states_its_situation_and_rule() -> None:
    prefix = {"delegation-tree": "tree-", "re-registration": "rereg-", "recovery": "recovery-",
              "sub-agent": "subagent-"}
    for e in _manifest()["vectors"]:
        assert e["id"].startswith(prefix[e["set"]])
        assert e["description"].endswith("."), e["id"]
        assert e["rule"].endswith("."), e["id"]


def test_both_sets_cover_the_situations_the_issue_names() -> None:
    ids = {e["id"]: e["expected"] for e in _manifest()["vectors"]}
    named = {
        "tree-parent-revoked-child-presented": "reject",
        "tree-child-presented-before-revocation": "accept",
        "tree-sibling-of-revoked-child": "accept",
        "tree-grandchild-under-revoked-parent": "reject",
        "tree-child-revocation-keeps-parent": "accept",
        "tree-dispute-open": "reject",
        "rereg-linked-successor": "accept",
        "rereg-no-link": "reject",
        "rereg-link-signed-by-wrong-key": "reject",
        "rereg-two-old-one-new": "reject",
        "rereg-link-after-old-revoked": "reject",
        "rereg-chain-old-middle-new": "accept",
        "recovery-regrant": "accept",
        "recovery-grant-not-carried": "reject",
        "recovery-registry-only": "reject",
        "recovery-after-compromise-no-revival": "reject",
        "recovery-history-follows": "accept",
        "recovery-unclaimed-succession": "accept",
        "recovery-unclaimed-unrecorded": "reject",
        "recovery-new-agent-asserted": "accept",
        "recovery-successor-responsible": "accept",
        "recovery-successor-responsible-unrecorded": "reject",
        "subagent-parent-active": "accept",
        "subagent-parent-retired": "reject",
        "subagent-respawned-after-parent-recovery": "accept",
        "subagent-not-carried-by-parent-recovery": "reject",
        "subagent-succession-history-only": "accept",
        "subagent-succession-grant-not-carried": "reject",
        "subagent-respawn-unrecorded": "reject",
    }
    assert {i: ids[i]["decision"] for i in named} == named


def _envelopes(case: Path) -> list[dict[str, Any]]:
    listed = json.loads((case / "case.json").read_text())
    out = []
    for name in [*listed["records"], listed["presentation"]]:
        try:
            out.append(json.loads((case / name).read_bytes()))
        except ValueError:
            continue
    return out


def test_every_signature_the_generator_wrote_is_a_real_ed25519_signature() -> None:
    """Every signature verifies under some published test key, so a refusal in the
    corpus comes from which key signed, never from a corrupt signature."""
    keys = {}
    for k in (generator.REGISTRY, generator.RELYING_PARTY, generator.INTRUDER):
        keys[generator.keyid(k)] = k
    for identifier in (generator.ORG, generator.PLANNER, generator.WORKER, generator.SUB,
                       generator.SIBLING, generator.V1, generator.V2, generator.V3,
                       generator.V2B, generator.B1, generator.OPERATOR,
                       generator.OPERATOR_2, generator.SA1, generator.SA2):
        k = generator._identity_key(identifier)
        keys[generator.keyid(k)] = k
    public = {kid: Ed25519PublicKey.from_public_bytes(generator.public_raw(k))
              for kid, k in keys.items()}
    for case in sorted((ROOT / "cases").iterdir()):
        for env in _envelopes(case):
            body = base64.b64decode(env["payload"])
            message = generator.pae(env["payloadType"], body)
            for sig in env["signatures"]:
                raw = base64.b64decode(sig["sig"])
                verified = False
                for k in public.values():
                    try:
                        k.verify(raw, message)
                        verified = True
                    except InvalidSignature:
                        continue
                tampered = case.name == "tree-grant-tampered"
                assert verified or tampered, (case.name, sig["keyid"])
