"""Check the actual installed consumer and refusal before process creation."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from tools import replay_vocabulary as consumer


def test_every_lab_claim_has_a_real_published_row_with_cadence() -> None:
    """Blank-separated pipe lines must not bypass ledger stamping as prose."""
    html = (consumer.ROOT / "docs/claims.html").read_text()
    for index in range(1, 51):
        identity = f"P-{index:02}"
        assert re.search(r'<tr\b[^>]*\bdata-read="[^"]+"[^>]*>\s*<td>'
                         + re.escape(identity) + r'</td>', html), identity


def test_actual_installed_reader_ignores_python_startup_injection(tmp_path, monkeypatch) -> None:
    marker = tmp_path / "startup-ran"
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(hostile))
    monkeypatch.setenv("PYTHONHOME", str(hostile))
    output = tmp_path / "output"
    receipt = consumer.replay(consumer.ROOT, output)
    assert not marker.exists()
    assert receipt["repeatStdoutExact"] is True
    assert receipt["nativeInferenceCalls"] == 0
    assert receipt["modelRuntimeInstalled"] is False
    assert {key: (value["exitCode"], value["consumerDecision"])
            for key, value in receipt["observations"].items()} == {
        "actual": (1, "hold-quality"), "actual-repeat": (1, "hold-quality"),
        "actual-evidence-only": (0, "hold-quality"),
        "changed-terminal": (1, "hold-evidence"),
    }
    assert (output / "actual.stdout.json").read_bytes() == (output / "actual-repeat.stdout.json").read_bytes()
    actual = json.loads((output / "actual.stdout.json").read_bytes())
    assert len(actual["report"]["attempts"]) == 128
    assert len(actual["qualityFailures"]) == 8


def test_changed_source_bytes_refused_before_output_or_environment(tmp_path, monkeypatch) -> None:
    selected = tmp_path / "selected"
    shutil.copytree(consumer.ROOT / "experiments" / consumer.IDENTITY,
                    selected / "experiments" / consumer.IDENTITY)
    (selected / "data").mkdir()
    shutil.copyfile(consumer.ROOT / "data/lab-register.json", selected / "data/lab-register.json")
    # Simulate a change after the first validation: the frozen read must recheck it.
    def change_after_validation(register, root):
        path = root / "experiments" / consumer.IDENTITY / "native-report.json"
        path.write_bytes(path.read_bytes() + b"\n")
    monkeypatch.setattr(consumer, "validate_register", change_after_validation)
    monkeypatch.setattr(consumer.venv.EnvBuilder, "create",
                        lambda *args: pytest.fail("untrusted source reached process creation"))
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="bytes changed after validation"):
        consumer.replay(selected, output)
    assert not output.exists()
