import base64
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import walk

HERE = Path(__file__).resolve().parent
RETAINED = HERE / "retained" / "2026-10-15-gate-horizonshield"
KEY = HERE / "walk-key.json"


def _copy(tmp_path: Path) -> Path:
    target = tmp_path / "walk"
    shutil.copytree(RETAINED, target)
    return target


def _envelope(directory: Path) -> dict:
    return json.loads((directory / "record.json").read_text(encoding="ascii"))


def _write(directory: Path, envelope: dict) -> None:
    (directory / "record.json").write_text(json.dumps(envelope), encoding="ascii")


def _resign(directory: Path, record: dict, tmp_path: Path) -> Path:
    seed = bytes(range(32))
    _write(directory, walk.sign(record, seed))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    key = tmp_path / "key.json"
    key.write_text(
        json.dumps({"public_key_ed25519_b64": base64.b64encode(public).decode()})
    )
    return key


def test_retained_walk_verifies_offline():
    record = walk.verify(RETAINED, KEY)
    assert record["card_signature"]["admitted"] is True
    assert [r["verified"] for r in record["card_signature"]["results"]] == [True, False]
    assert record["purpose"] == walk.PURPOSE + record["card"]["url"]


def test_main_verify_prints_the_signature_result(capsys):
    assert walk.main(["verify", str(RETAINED)]) == 0
    assert json.loads(capsys.readouterr().out)["kid"] == "hs-2026-09"


def test_verifier_copy_matches_its_pin():
    raw = (HERE / "retain_gate.py").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == walk.GATE_SHA256


def test_changed_card_byte_is_refused(tmp_path):
    directory = _copy(tmp_path)
    card = directory / "agent-card.json"
    card.write_bytes(card.read_bytes() + b" ")
    with pytest.raises(walk.WalkError, match="retained card"):
        walk.verify(directory, KEY)


def test_changed_jwks_byte_is_refused(tmp_path):
    directory = _copy(tmp_path)
    jwks = directory / "jwks.json"
    jwks.write_bytes(jwks.read_bytes() + b" ")
    with pytest.raises(walk.WalkError, match="retained JWKS"):
        walk.verify(directory, KEY)


def test_forged_record_signature_is_refused(tmp_path):
    directory = _copy(tmp_path)
    envelope = _envelope(directory)
    raw = base64.b64decode(envelope["record"]["signature_ed25519_b64"])
    flipped = bytes([raw[0] ^ 1]) + raw[1:]
    envelope["record"]["signature_ed25519_b64"] = base64.b64encode(flipped).decode()
    _write(directory, envelope)
    with pytest.raises(walk.WalkError, match="does not verify"):
        walk.verify(directory, KEY)


def test_edited_record_text_is_refused(tmp_path):
    directory = _copy(tmp_path)
    envelope = _envelope(directory)
    text = envelope["record"]["record_canonical"].replace(
        '"verified":false', '"verified":true'
    )
    envelope["record"]["record_canonical"] = text
    envelope["record"]["sha"] = hashlib.sha256(text.encode()).hexdigest()
    _write(directory, envelope)
    with pytest.raises(walk.WalkError, match="does not verify"):
        walk.verify(directory, KEY)


def test_record_hash_mismatch_is_refused(tmp_path):
    directory = _copy(tmp_path)
    envelope = _envelope(directory)
    envelope["record"]["sha"] = "0" * 64
    _write(directory, envelope)
    with pytest.raises(walk.WalkError, match="record hash"):
        walk.verify(directory, KEY)


def test_other_key_is_refused(tmp_path):
    other = tmp_path / "other.json"
    other.write_text(
        json.dumps({"public_key_ed25519_b64": base64.b64encode(b"\1" * 32).decode()})
    )
    with pytest.raises(walk.WalkError, match="pinned walk key"):
        walk.verify(RETAINED, other)


def test_a_signed_but_false_gate_result_is_refused(tmp_path):
    directory = _copy(tmp_path)
    record = walk.verify(RETAINED, KEY)
    record["card_signature"]["results"][1]["verified"] = True
    key = _resign(directory, record, tmp_path)
    with pytest.raises(walk.WalkError, match="gate result"):
        walk.verify(directory, key)


def test_a_signed_jwks_url_off_the_jku_is_refused(tmp_path):
    directory = _copy(tmp_path)
    record = walk.verify(RETAINED, KEY)
    record["jwks"]["url"] = "https://gate.horizonshield.dev/other.json"
    key = _resign(directory, record, tmp_path)
    with pytest.raises(walk.WalkError, match="jku"):
        walk.verify(directory, key)


def test_non_canonical_record_is_refused(tmp_path):
    directory = _copy(tmp_path)
    record = walk.verify(RETAINED, KEY)
    seed = bytes(range(32))
    raw = json.dumps(record, sort_keys=True).encode()
    key = Ed25519PrivateKey.from_private_bytes(seed)
    envelope = {
        "record": {
            "sha": hashlib.sha256(raw).hexdigest(),
            "record_canonical": raw.decode(),
            "signature_ed25519_b64": base64.b64encode(key.sign(raw)).decode(),
            "public_key_ed25519_b64": base64.b64encode(
                key.public_key().public_bytes_raw()
            ).decode(),
        }
    }
    _write(directory, envelope)
    pinned = tmp_path / "key.json"
    pinned.write_text(
        json.dumps(
            {"public_key_ed25519_b64": envelope["record"]["public_key_ed25519_b64"]}
        )
    )
    with pytest.raises(walk.WalkError, match="canonical"):
        walk.verify(directory, pinned)


def test_floats_are_refused_in_a_record():
    with pytest.raises(walk.WalkError):
        walk.canonical({"a": [1.5]})


def test_jku_on_another_host_is_refused():
    card = json.loads((RETAINED / "agent-card.json").read_bytes())
    with pytest.raises(walk.WalkError, match="host"):
        walk.jku_of(
            json.dumps(card).encode(), "https://example.org/.well-known/agent-card.json"
        )


def test_card_without_signatures_is_refused():
    jwks = (RETAINED / "jwks.json").read_bytes()
    with pytest.raises(walk.WalkError, match="no signatures"):
        walk.check_result(b'{"name": "x"}', jwks)


def test_jwks_without_the_kid_is_refused():
    card = (RETAINED / "agent-card.json").read_bytes()
    with pytest.raises(walk.WalkError, match="exactly one key"):
        walk.check_result(card, b'{"keys": []}')


def test_walk_signs_what_it_fetched(tmp_path, monkeypatch):
    pages = {
        "https://gate.horizonshield.dev/.well-known/agent-card.json": (
            RETAINED / "agent-card.json"
        ).read_bytes(),
        "https://gate.horizonshield.dev/.well-known/jwks.json": (
            RETAINED / "jwks.json"
        ).read_bytes(),
    }
    monkeypatch.setattr(walk, "_fetch", pages.__getitem__)
    out = tmp_path / "new"
    seed = bytes(range(32))
    envelope = walk.walk(next(iter(pages)), out, seed)
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    key = tmp_path / "key.json"
    key.write_text(
        json.dumps({"public_key_ed25519_b64": base64.b64encode(public).decode()})
    )
    record = walk.verify(out, key)
    assert (
        envelope["record"]["sha"]
        == hashlib.sha256(envelope["record"]["record_canonical"].encode()).hexdigest()
    )
    assert record["card_signature"] == walk.verify(RETAINED, KEY)["card_signature"]


def test_main_walk_needs_a_seed(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv(walk.SEED_ENV, raising=False)
    assert (
        walk.main(["walk", "https://example.org/card.json", str(tmp_path / "x")]) == 2
    )
    assert walk.SEED_ENV in capsys.readouterr().err


def test_main_verify_refuses_a_missing_directory(tmp_path):
    assert walk.main(["verify", str(tmp_path / "absent")]) == 2
