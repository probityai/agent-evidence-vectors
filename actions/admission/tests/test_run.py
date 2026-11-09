"""Tests for actions/admission/run.py, the logic behind the root action.yml.

The policy tests drive every vector this repository holds for the three rule sets through
the runner, so the Action answers each vector exactly as the rego suites say the rules do.
They need the pinned opa: set OPA to its path, or put it on PATH (CI installs it with
`run.py install-opa`). The digest tests run the checker from packages/admission/python.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import tomllib
import urllib.error
from collections import defaultdict
from pathlib import Path

import pytest

ACTION = Path(__file__).resolve().parents[1]
ROOT = ACTION.parents[1]
REGO = ROOT / "packages" / "admission" / "rego"
SAMPLES = ROOT / "packages" / "admission" / "samples"

_SPEC = importlib.util.spec_from_file_location("run", ACTION / "run.py")
run = importlib.util.module_from_spec(_SPEC)
sys.modules["run"] = run  # dataclasses resolves the module by name
_SPEC.loader.exec_module(run)

OPA = os.environ.get("OPA") or shutil.which("opa")

# The pins in README.md's quick start, which admit the sample statement.
SAMPLE_PINS = {"consumer": {
    "expected_corpus_digest": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
    "expected_substrate_digest": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb",
    "demanded_classes": ["XA"],
}}


@pytest.fixture(scope="module")
def opa() -> str:
    if not OPA:
        pytest.fail("no opa: set OPA or put the pinned opa on PATH (python3 run.py install-opa <dir>)")
    return OPA


def _write(path: Path, payload: object) -> str:
    path.write_text(json.dumps(payload))
    return str(path)


# --- the pins ---------------------------------------------------------------------------


def test_opa_pin_is_the_one_the_admission_ci_and_its_advisory_gate_use() -> None:
    workflow = (ROOT / ".github" / "workflows" / "package-admission.yml").read_text()
    version = re.search(r"^\s*OPA_VERSION: (\S+)$", workflow, re.MULTILINE)[1]
    sha = re.search(r"^\s*OPA_SHA256: (\S+)$", workflow, re.MULTILINE)[1]
    assert run.PINS["opa"]["version"] == version
    assert run.PINS["opa"]["assets"]["Linux-X64"] == {"file": "opa_linux_amd64_static", "sha256": sha}


def _version_key(version: str) -> tuple[int, ...]:
    assert re.fullmatch(r"\d+(\.\d+)*", version), f"not a plain release version: {version}"
    return tuple(int(part) for part in version.split("."))


def pin_is_a_published_release_not_ahead(requirement: str, name: str, version: str) -> bool:
    """A checker pin names the package and a version no newer than the package's own.

    The pin carries the wheel's SHA-256, which exists only after the release is published,
    so a release commit that bumps the package cannot also move the pin. The pin therefore
    trails the package by one release and follows in the next change. That the pinned
    version is on PyPI under that hash is proved by the Action's self-test, which installs
    the wheel from PyPI by hash.
    """
    match = re.fullmatch(r"(?P<name>[A-Za-z0-9._-]+)==(?P<version>\d+(\.\d+)*)", requirement)
    if match is None or match["name"] != name:
        return False
    return _version_key(match["version"]) <= _version_key(version)


def test_checker_pin_is_a_published_admission_release() -> None:
    project = tomllib.loads((ROOT / "packages" / "admission" / "python" / "pyproject.toml").read_text())["project"]
    assert pin_is_a_published_release_not_ahead(run.PINS["checker"]["requirement"], project["name"], project["version"])
    assert re.fullmatch(r"[0-9a-f]{64}", run.PINS["checker"]["sha256"])


@pytest.mark.parametrize(
    ("requirement", "expected"),
    [
        ("agent-evidence-admission==0.2.0", True),
        ("agent-evidence-admission==0.1.2", True),
        ("agent-evidence-admission==0.1.10", True),
        ("agent-evidence-admission==0.2.1", False),
        ("agent-evidence-admission==0.10.0", False),
        ("agent-evidence-admission>=0.1.2", False),
        ("agent-evidence-vectors==0.1.0", False),
        ("agent-evidence-admission", False),
    ],
)
def test_the_pin_may_trail_the_package_but_never_lead_it(requirement: str, expected: bool) -> None:
    assert pin_is_a_published_release_not_ahead(requirement, "agent-evidence-admission", "0.2.0") is expected


@pytest.mark.parametrize("name", sorted(run.PINS["rules"]))
def test_each_rule_set_names_a_module_that_declares_its_package(name: str) -> None:
    rule = run.PINS["rules"][name]
    text = (REGO / rule["module"]).read_text()
    assert re.search(rf"^package {rule['package']}$", text, re.MULTILINE)
    assert re.search(r"^default isCompliant := false$", text, re.MULTILINE)


def test_an_unpinned_runner_platform_is_refused_before_any_download(tmp_path: Path) -> None:
    with pytest.raises(run.SetupError, match="no pinned opa"):
        run.install_opa(tmp_path, "Windows-X64")
    assert not (tmp_path / "opa").exists()


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self) -> bytes:
        return self._body


class _FakeNet:
    """A stand-in for run._open that answers by URL and records every request."""

    def __init__(self, routes: dict) -> None:
        self.routes, self.calls = routes, []

    def __call__(self, request, timeout):
        self.calls.append((request.full_url, dict(request.header_items())))
        answer = self.routes[request.full_url]
        if isinstance(answer, list):
            answer = answer.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return _Response(answer)


@pytest.fixture
def opa_net(tmp_path: Path, monkeypatch):
    """Pin opa to known bytes, point the cache at tmp_path, never sleep, and return a route installer."""
    body = b"pretend opa"
    pins = json.loads(json.dumps(run.PINS))
    pins["opa"]["assets"]["Linux-X64"]["sha256"] = hashlib.sha256(body).hexdigest()
    monkeypatch.setattr(run, "PINS", pins)
    monkeypatch.setenv("AEV_ACTION_CACHE", str(tmp_path / "cache"))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(run, "_sleep", lambda seconds: None)
    tag, name = pins["opa"]["version"], pins["opa"]["assets"]["Linux-X64"]["file"]
    direct = f"https://github.com/open-policy-agent/opa/releases/download/{tag}/{name}"
    api = f"https://api.github.com/repos/open-policy-agent/opa/releases/tags/{tag}"
    asset = "https://api.github.com/repos/open-policy-agent/opa/releases/assets/77"

    def install(routes: dict) -> _FakeNet:
        net = _FakeNet(routes)
        monkeypatch.setattr(run, "_open", net)
        return net

    listing = json.dumps({"assets": [{"name": name, "id": 77}, {"name": "x", "id": 1}]}).encode()
    return type("Ctx", (), {"body": body, "direct": direct, "api": api, "asset": asset,
                            "install": staticmethod(install), "listing": listing})


def test_opa_bytes_that_miss_the_pinned_digest_are_refused_from_every_source(tmp_path: Path, opa_net) -> None:
    net = opa_net.install({opa_net.direct: b"not opa"})
    with pytest.raises(run.SetupError, match="not the pinned"):
        run.install_opa(tmp_path / "bin", "Linux-X64")
    assert not (tmp_path / "bin" / "opa").exists()
    assert [url for url, _ in net.calls] == [opa_net.direct], "a mismatch must not try another source"
    assert not (tmp_path / "cache").exists()


def test_opa_bytes_with_the_pinned_digest_are_kept_executable(tmp_path: Path, opa_net, capsys) -> None:
    opa_net.install({opa_net.direct: opa_net.body})
    target = run.install_opa(tmp_path / "bin", "Linux-X64")
    assert target.read_bytes() == opa_net.body and os.access(target, os.X_OK)
    assert "installed from direct" in capsys.readouterr().err


def test_a_direct_timeout_retries_and_then_the_api_endpoint_serves_the_pinned_bytes(
        tmp_path: Path, opa_net, monkeypatch, capsys) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t0ken")
    net = opa_net.install({opa_net.direct: [TimeoutError("The read operation timed out")] * run.ATTEMPTS,
                           opa_net.api: opa_net.listing, opa_net.asset: opa_net.body})
    target = run.install_opa(tmp_path / "bin", "Linux-X64")
    assert target.read_bytes() == opa_net.body
    assert [url for url, _ in net.calls] == [opa_net.direct] * run.ATTEMPTS + [opa_net.api, opa_net.asset]
    asset_headers = {k.lower(): v for k, v in net.calls[-1][1].items()}
    assert asset_headers["accept"] == "application/octet-stream"
    assert asset_headers["authorization"] == "Bearer t0ken"
    assert "installed from api" in capsys.readouterr().err


def test_a_transient_direct_failure_that_clears_is_retried_not_escalated(tmp_path: Path, opa_net) -> None:
    busy = urllib.error.HTTPError(opa_net.direct, 504, "Gateway Timeout", None, None)
    net = opa_net.install({opa_net.direct: [busy, busy, opa_net.body]})
    run.install_opa(tmp_path / "bin", "Linux-X64")
    assert len(net.calls) == 3


def test_a_direct_404_is_not_retried_and_falls_to_the_api(tmp_path: Path, opa_net) -> None:
    gone = urllib.error.HTTPError(opa_net.direct, 404, "Not Found", None, None)
    net = opa_net.install({opa_net.direct: gone, opa_net.api: opa_net.listing, opa_net.asset: opa_net.body})
    run.install_opa(tmp_path / "bin", "Linux-X64")
    assert [url for url, _ in net.calls] == [opa_net.direct, opa_net.api, opa_net.asset]


def test_every_route_failing_names_each_failure(tmp_path: Path, opa_net) -> None:
    down = TimeoutError("timed out")
    opa_net.install({opa_net.direct: [down] * run.ATTEMPTS, opa_net.api: down})
    with pytest.raises(run.SetupError, match=r"direct: .*api: "):
        run.install_opa(tmp_path / "bin", "Linux-X64")


def test_a_verified_cache_is_used_with_no_network(tmp_path: Path, opa_net, capsys) -> None:
    net = opa_net.install({opa_net.direct: opa_net.body})
    run.install_opa(tmp_path / "first", "Linux-X64")
    assert len(net.calls) == 1
    net.calls.clear()
    net.routes = {}
    target = run.install_opa(tmp_path / "second", "Linux-X64")
    assert target.read_bytes() == opa_net.body and net.calls == []
    assert "installed from cache" in capsys.readouterr().err


def test_a_corrupt_cache_entry_is_ignored_and_replaced(tmp_path: Path, opa_net) -> None:
    cached = tmp_path / "cache" / "agent-evidence-action" / "opa" / hashlib.sha256(opa_net.body).hexdigest()
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"tampered")
    opa_net.install({opa_net.direct: opa_net.body})
    target = run.install_opa(tmp_path / "bin", "Linux-X64")
    assert target.read_bytes() == opa_net.body and cached.read_bytes() == opa_net.body


def test_the_token_is_dropped_when_a_redirect_leaves_the_host() -> None:
    import urllib.request
    handler = run._KeepAuthOnSameHost()
    request = urllib.request.Request("https://api.github.com/x", headers={"Authorization": "Bearer t"})
    other = handler.redirect_request(request, None, 302, "Found", {}, "https://objects.example.net/blob")
    same = handler.redirect_request(request, None, 302, "Found", {}, "https://api.github.com/y")
    assert not other.has_header("Authorization") and same.has_header("Authorization")


# --- policy: the repository's own vectors -----------------------------------------------


def _vector_cases(file: str, key: str) -> list[dict]:
    return list(json.loads((REGO / file).read_text())[key]["cases"].values())


@pytest.mark.parametrize(("rules", "file", "key", "consumer_key"), [
    ("agent-change-admission", "agent_change_admission_vectors.json", "agent_change_admission_vectors",
     "change_admission_consumer"),
    ("verifier-isolation", "verifier_isolation_vectors.json", "verifier_isolation_vectors",
     "verifier_isolation_consumer"),
])
def test_every_vector_gets_the_decision_and_reasons_it_declares(opa: str, rules: str, file: str, key: str,
                                                                consumer_key: str) -> None:
    cases = _vector_cases(file, key)
    groups: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        groups[json.dumps(case["consumer"], sort_keys=True)].append(case)
    checked = 0
    for consumer, members in groups.items():
        decided = run.evaluate(opa, rules, [c["input"] for c in members], {consumer_key: json.loads(consumer)})
        for case, (compliant, reasons) in zip(members, decided):
            assert (compliant, reasons) == (not case["reasons"], sorted(case["reasons"])), case["name"]
            checked += 1
    assert checked == len(cases) > 0
    assert any(not c["reasons"] for c in cases) and any(c["reasons"] for c in cases)


def test_the_corpus_is_admitted_and_refused_as_the_rego_suite_says(opa: str, tmp_path: Path) -> None:
    corpus = json.loads((REGO / "corpus_vectors.json").read_text())["corpus_vectors"]
    # The rego suite's own corpus consumer: no single corpus or substrate pin fits every vector.
    consumer = {"consumer": {"allow_unpinned_anchors": True, "allow_unpinned_scope": True}}
    accept = corpus["accept"]
    decided = run.evaluate(opa, "execution-evidence", [v["statement"] for v in accept], consumer)
    for vector, (compliant, _) in zip(accept, decided):
        # Under the default accepted results only a sound pass is admitted.
        assert compliant == (vector["regoSound"] and vector["expected"]["result"] == "pass"), vector["name"]
    assert sum(c for c, _ in decided) > 0
    rejects = corpus["reject"]
    for i, vector in enumerate(rejects):
        _write(tmp_path / f"r{i}.json", vector["statement"])
    rows = run.check_policy(opa, "execution-evidence", [str(tmp_path / f"r{i}.json") for i in range(len(rejects))],
                            _write(tmp_path / "pins.json", consumer))
    assert len(rows) == len(rejects) > 0
    assert all(not row.admitted and row.reasons for row in rows)
    # reject_denylisted (rego admits them; their faults are in the signature and payload
    # bytes the offline verifiers check) is out of the rules' reach by design.


def test_a_refusal_always_carries_words_and_a_contradiction_is_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(run, "evaluate", lambda *a: [(False, []), (True, ["x"]), (True, []), (False, ["y"])])
    paths = [_write(tmp_path / f"s{i}.json", {}) for i in range(4)]
    rows = run.check_policy("opa", "execution-evidence", paths, None)
    assert [(r.admitted, r.reasons) for r in rows] == [
        (False, [run.NO_REASON]), (False, [run.CONTRADICTION, "x"]), (True, []), (False, ["y"])]


def test_the_sample_is_refused_until_the_consumer_pins_it(opa: str, tmp_path: Path) -> None:
    sample = str(SAMPLES / "adversarial-execution-evidence.pass.statement.json")
    [unpinned] = run.check_policy(opa, "execution-evidence", [sample], None)
    assert not unpinned.admitted and len(unpinned.reasons) == 3
    assert all(r.startswith("consumer anchor:") for r in unpinned.reasons)
    [pinned] = run.check_policy(opa, "execution-evidence", [sample], _write(tmp_path / "pins.json", SAMPLE_PINS))
    assert pinned.admitted and pinned.reasons == []


def test_main_exits_0_admitted_1_refused_and_writes_the_outputs(opa: str, tmp_path: Path, monkeypatch) -> None:
    out, summary = tmp_path / "out", tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    sample = str(SAMPLES / "adversarial-execution-evidence.pass.statement.json")
    pins = _write(tmp_path / "pins.json", SAMPLE_PINS)
    argv = ["policy", "--opa", opa, "--rules", "execution-evidence", "--statement"]
    assert run.main([*argv, f"{sample}\n{sample}\n", "--pins", pins]) == 0
    assert out.read_text() == "result=admitted\nrefusals=0\n"
    assert run.main([*argv, sample, "--pins", ""]) == 1
    assert out.read_text().endswith("result=refused\nrefusals=1\n")
    text = summary.read_text()
    assert "2 of 2 admitted" in text and "0 of 1 admitted" in text and "| refused | consumer anchor:" in text


def test_an_unreadable_statement_or_unknown_rules_exit_2(opa: str, tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert run.main(["policy", "--opa", opa, "--rules", "execution-evidence", "--statement", str(bad)]) == 2
    sample = str(SAMPLES / "adversarial-execution-evidence.pass.statement.json")
    assert run.main(["policy", "--opa", opa, "--rules", "no-such-rules", "--statement", sample]) == 2
    assert run.main(["policy", "--opa", opa, "--rules", "execution-evidence", "--statement", " \n"]) == 2


# --- digest -----------------------------------------------------------------------------


@pytest.fixture
def checker(monkeypatch) -> str:
    """The checker from this repository's source, run the way the Action runs the wheel."""
    source = str(ROOT / "packages" / "admission" / "python" / "src")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(filter(None, [source, os.environ.get("PYTHONPATH")])))
    return sys.executable


def _statement(tmp_path: Path, *artifacts: bytes) -> str:
    subject = [{"name": f"a{i}", "digest": {"sha256": hashlib.sha256(b).hexdigest()}} for i, b in enumerate(artifacts)]
    return _write(tmp_path / "statement.json", {"_type": "https://in-toto.io/Statement/v1", "subject": subject,
                                                "predicateType": "https://example.org/digest-demo/v1",
                                                "predicate": {}})


def test_digest_admits_each_artifact_the_document_names(checker: str, tmp_path: Path) -> None:
    document = _statement(tmp_path, b"one", b"two")
    (tmp_path / "one").write_bytes(b"one")
    (tmp_path / "two").write_bytes(b"two")
    rows = run.check_digests(checker, document, [str(tmp_path / "one"), str(tmp_path / "two")])
    assert [r.admitted for r in rows] == [True, True]


def test_digest_refuses_bytes_the_document_does_not_name(checker: str, tmp_path: Path) -> None:
    document = _statement(tmp_path, b"one")
    (tmp_path / "other").write_bytes(b"other")
    [row] = run.check_digests(checker, document, [str(tmp_path / "other")])
    assert not row.admitted and row.reasons[0].startswith("FAIL digest-mismatch")


def test_digest_main_exit_codes(checker: str, tmp_path: Path) -> None:
    document = _statement(tmp_path, b"one")
    (tmp_path / "one").write_bytes(b"one")
    (tmp_path / "other").write_bytes(b"other")
    base = ["digest", "--python", checker, "--document", document, "--artifact"]
    assert run.main([*base, str(tmp_path / "one")]) == 0
    assert run.main([*base, f"{tmp_path / 'one'}\n{tmp_path / 'other'}"]) == 1
    assert run.main([*base, str(tmp_path / "missing")]) == 2


COVERAGE_VECTORS = ROOT / "packages" / "admission" / "python" / "vectors" / "coverage"


def test_coverage_reports_one_row_per_required_class_and_refuses_a_missing_one(tmp_path: Path) -> None:
    document = str(COVERAGE_VECTORS / "cdx-1.6-baseline.json")
    required = _write(tmp_path / "required.json", ["library", "service", "machine-learning-model"])
    rows = run.check_coverage(document, required)
    assert [(r.subject, r.admitted) for r in rows] == [
        ("library ASSESSED", True), ("service COVERED-ELSEWHERE", True), ("machine-learning-model MISSING", False)]
    assert rows[2].reasons == ["no entry and no member"]


def test_coverage_main_exit_codes(tmp_path: Path) -> None:
    document = str(COVERAGE_VECTORS / "spdx-coverage-proposed.json")
    base = ["coverage", "--document", document, "--required"]
    assert run.main([*base, _write(tmp_path / "ok.json", ["library", "model", "data", "application"])]) == 0
    assert run.main([*base, _write(tmp_path / "missing.json", ["library", "tooling"])]) == 1
    assert run.main([*base, str(tmp_path / "absent.json")]) == 2


def test_coverage_runs_the_checker_of_this_checkout_without_an_installed_package() -> None:
    assert (run.CHECKER_SRC / "agent_evidence_admission" / "coverage_check.py").is_file()
