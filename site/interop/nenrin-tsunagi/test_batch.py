import json

import batch
import pytest
from reader import assess


def _raw(value) -> bytes:
    return json.dumps(value).encode()


def test_each_case_carries_the_reader_signature_unchanged():
    cases = [{"name": "empty", "bundle": {}}, {"name": "list", "bundle": []}]
    output = batch.answer(_raw(cases))
    assert list(output) == ["empty", "list"]
    for case in cases:
        assert output[case["name"]] == assess(case["bundle"])["signature"]


def test_unsupported_bundle_is_not_rewritten_as_a_verdict():
    output = batch.answer(_raw([{"name": "empty", "bundle": {}}]))
    assert output["empty"]["verdict"] == "unsupported"


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        [{"name": "a"}],
        [{"name": "a", "bundle": {}, "extra": 1}],
        [{"name": "", "bundle": {}}],
        [{"name": 1, "bundle": {}}],
        [{"name": "a", "bundle": {}}, {"name": "a", "bundle": {}}],
        ["a"],
    ],
)
def test_malformed_batch_is_refused(value):
    with pytest.raises(batch.BatchError):
        batch.answer(_raw(value))


def test_oversized_batch_is_refused():
    with pytest.raises(batch.BatchError):
        batch.answer(b" " * (batch.MAX_BATCH_BYTES + 1))


def test_duplicate_json_members_are_refused():
    with pytest.raises(ValueError):
        batch.answer(b'[{"name": "a", "name": "b", "bundle": {}}]')


def test_main_writes_the_output_file(tmp_path):
    source = tmp_path / "in.json"
    target = tmp_path / "out.json"
    source.write_bytes(_raw([{"name": "empty", "bundle": {}}]))
    assert batch.main([str(source), str(target)]) == 0
    written = json.loads(target.read_text(encoding="utf-8"))
    assert written == {"empty": assess({})["signature"]}


def test_main_refuses_without_writing(tmp_path, capsys):
    source = tmp_path / "in.json"
    target = tmp_path / "out.json"
    source.write_bytes(b"[]")
    assert batch.main([str(source), str(target)]) == 2
    assert not target.exists()
    assert "batch refused" in capsys.readouterr().err


def test_main_refuses_a_missing_file(tmp_path):
    assert batch.main([str(tmp_path / "absent"), str(tmp_path / "out.json")]) == 2


def test_main_needs_two_paths(capsys):
    assert batch.main([]) == 2
    assert "usage" in capsys.readouterr().err
