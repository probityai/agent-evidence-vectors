"""Tests for the Vanta connector, against a local fake HTTP server and never the live API.

Every request the connector would send is captured by the fake server, so the tests assert
the exact bytes: the token exchange, the bearer header, the full-state PUT body, the retry on
a throttled reply, the refusal to follow a redirect, and that a dry run sends nothing.
"""

from __future__ import annotations

import copy
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors.vanta_connector import cli as runner  # noqa: E402
from agent_evidence_vectors.vanta_connector import client, payloads  # noqa: E402

STAMP = "2026-10-29T00:00:00Z"
SECRET = "s3cret-value-never-printed"


def report(suite: str = "vectors", *, failing: tuple[str, ...] = ()) -> dict:
    vectors = [{"id": f"v{i}", "status": "PASS"} for i in range(5)]
    for i, name in enumerate(failing):
        vectors[i] = {"id": name, "status": "FAIL"}
    bad = len(failing)
    return {
        "suite": suite,
        "rail": "reference",
        "verifier": None,
        "corpus": {"suiteRevision": 7, "corpusDigest": "ab" * 32},
        "totals": {
            "vectors": 5,
            "pass": 5 - bad,
            "fail": bad,
            "notExercised": 0,
            "suiteRefusals": 0,
        },
        "vectors": vectors,
    }


def own_reader_report(*, failures: tuple = ()) -> dict:
    """The report shape the corpora with their own reader write."""
    return {
        "corpusDigest": "cd" * 32,
        "failures": list(failures),
        "rail": "own-reader",
        "suite": "test-tampering/v2",
        "totals": {
            "conform": 4 - len(failures),
            "fail": len(failures),
            "suiteRefusals": 0,
            "vectors": 4,
        },
        "verifier": {"command": None, "note": "reference", "vectorsExecuted": 4},
    }


class Fake:
    """A loopback HTTP server that records requests and answers from a script."""

    def __init__(self, replies: list[tuple[int, dict | None, dict]]) -> None:
        self.requests: list[dict] = []
        self.replies = list(replies)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "type": self.headers.get("Content-Type"),
                        "body": json.loads(self.rfile.read(length) or b"null"),
                    }
                )
                status, body, headers = outer.replies.pop(0)
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                payload = json.dumps(body).encode() if body is not None else b""
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_POST = do_PUT = do_GET = _handle

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_factory():
    made: list[Fake] = []

    def make(replies: list[tuple[int, dict | None, dict]]) -> Fake:
        fake = Fake(replies)
        made.append(fake)
        return fake

    yield make
    for fake in made:
        fake.close()


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv("VANTA_CLIENT_ID", "cid")
    monkeypatch.setenv("VANTA_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("VANTA_RESOURCE_ID", "res-1")


TOKEN_OK = (200, {"access_token": "vat_tok", "expires_in": 3600, "token_type": "Bearer"}, {})
PUT_OK = (200, {"results": {"accepted": 1, "rejected": 0}}, {})


def write_report(tmp_path: Path, data: dict, name: str = "r.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_record_for_a_passing_report():
    record = payloads.record_from_report(
        report(), run_timestamp=STAMP, package_version="1.2.3", external_url="https://x.test/"
    )
    props = record["customProperties"]
    assert record["uniqueId"] == "aev-vectors"
    assert props["allPass"] is True
    assert (props["vectors"], props["pass"], props["fail"]) == (5, 5, 0)
    assert props["failingVectors"] == ""
    assert props["lastRun"] == STAMP
    assert set(props) == set(payloads.JTD_SCHEMA["properties"])


def test_record_for_a_failing_report_names_the_vectors():
    record = payloads.record_from_report(
        report(failing=("vb", "va")), run_timestamp=STAMP, package_version="x", external_url="u"
    )
    props = record["customProperties"]
    assert props["allPass"] is False
    assert props["failingVectors"] == "va,vb"


def test_own_reader_report_shape_is_read():
    record = payloads.record_from_report(
        own_reader_report(), run_timestamp=STAMP, package_version="x", external_url="u"
    )
    props = record["customProperties"]
    assert record["uniqueId"] == "aev-test-tampering-v2"
    assert props["allPass"] is True and props["suiteVersion"] == "v2"
    assert (props["vectors"], props["pass"], props["notExercised"]) == (4, 4, 0)
    assert props["verifier"] == "own-reader" and props["corpusDigest"] == "cd" * 32


def test_own_reader_failures_are_named():
    data = own_reader_report(failures=({"id": "tt-9"}, "tt-1"))
    props = payloads.record_from_report(
        data, run_timestamp=STAMP, package_version="x", external_url="u"
    )["customProperties"]
    assert props["allPass"] is False and props["failingVectors"] == "tt-1,tt-9"


def test_executed_fewer_than_listed_counts_as_not_exercised():
    data = own_reader_report()
    data["verifier"]["vectorsExecuted"] = 3
    props = payloads.record_from_report(
        data, run_timestamp=STAMP, package_version="x", external_url="u"
    )["customProperties"]
    assert props["notExercised"] == 1 and props["allPass"] is False


def test_a_report_that_cannot_say_what_was_skipped_is_refused():
    data = own_reader_report()
    del data["verifier"]
    with pytest.raises(payloads.ReportError):
        payloads.record_from_report(
            data, run_timestamp=STAMP, package_version="x", external_url="u"
        )


def test_failing_list_is_bounded():
    data = report()
    data["vectors"] = [{"id": f"f{i:03d}", "status": "FAIL"} for i in range(30)]
    data["totals"].update({"vectors": 30, "pass": 0, "fail": 30})
    props = payloads.record_from_report(
        data, run_timestamp=STAMP, package_version="x", external_url="u"
    )["customProperties"]
    assert props["failingVectors"].endswith(",+10 more")
    assert props["failingVectors"].count(",") == payloads.MAX_FAILING_LISTED


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("totals"),
        lambda d: d["totals"].pop("fail"),
        lambda d: d["totals"].update({"pass": True}),
        lambda d: d["totals"].update({"pass": -1}),
        lambda d: d["corpus"].pop("corpusDigest"),
        lambda d: d.pop("suite"),
        lambda d: d.pop("vectors"),
    ],
)
def test_a_report_missing_a_member_is_refused_not_defaulted(mutate):
    data = copy.deepcopy(report())
    mutate(data)
    with pytest.raises(payloads.ReportError):
        payloads.record_from_report(
            data, run_timestamp=STAMP, package_version="x", external_url="u"
        )


@pytest.mark.parametrize(
    "change",
    [
        {"notExercised": 1},
        {"suiteRefusals": 1},
        {"pass": 4, "fail": 1},
    ],
)
def test_all_pass_needs_every_count_clean(change):
    data = report()
    data["totals"].update(change)
    props = payloads.record_from_report(
        data, run_timestamp=STAMP, package_version="x", external_url="u"
    )["customProperties"]
    assert props["allPass"] is False


def test_an_empty_corpus_does_not_pass():
    data = report()
    data["vectors"] = []
    data["totals"].update({"vectors": 0, "pass": 0})
    props = payloads.record_from_report(
        data, run_timestamp=STAMP, package_version="x", external_url="u"
    )["customProperties"]
    assert props["allPass"] is False


def test_two_records_with_one_corpus_name_are_refused():
    record = payloads.record_from_report(
        report(), run_timestamp=STAMP, package_version="x", external_url="u"
    )
    with pytest.raises(payloads.ReportError):
        payloads.resource_body("r", [record, record])


def test_dry_run_prints_exact_requests_and_sends_nothing(tmp_path, capsys, creds, fake_factory):
    fake = fake_factory([])
    code = runner.main(
        [
            "push",
            "--report",
            write_report(tmp_path, report()),
            "--api-base",
            fake.url,
            "--run-timestamp",
            STAMP,
        ]
    )
    out = capsys.readouterr().out
    assert code == 0 and fake.requests == []
    assert "dry run: nothing was sent" in out
    assert f"PUT {fake.url}/v1/resources/custom_resource" in out
    assert "Authorization: Bearer <access_token>" in out
    assert '"resourceId": "res-1"' in out
    assert SECRET not in out and "s3cret" not in out


def test_send_pushes_the_full_state_with_the_token(tmp_path, capsys, creds, fake_factory):
    fake = fake_factory([TOKEN_OK, PUT_OK])
    code = runner.main(
        [
            "push",
            "--report",
            write_report(tmp_path, report()),
            "--send",
            "--api-base",
            fake.url,
            "--run-timestamp",
            STAMP,
        ]
    )
    assert code == 0
    token_call, put_call = fake.requests
    assert token_call["path"] == "/oauth/token" and token_call["method"] == "POST"
    assert token_call["body"] == {
        "client_id": "cid",
        "client_secret": SECRET,
        "scope": "connectors.self:write-resource",
        "grant_type": "client_credentials",
    }
    assert put_call["method"] == "PUT" and put_call["path"] == "/v1/resources/custom_resource"
    assert put_call["auth"] == "Bearer vat_tok" and put_call["type"] == "application/json"
    assert put_call["body"]["resourceId"] == "res-1"
    assert put_call["body"]["resources"][0]["uniqueId"] == "aev-vectors"
    assert SECRET not in capsys.readouterr().out


def test_two_reports_go_in_one_put(tmp_path, creds, fake_factory):
    fake = fake_factory([TOKEN_OK, (200, {"results": {"accepted": 2, "rejected": 0}}, {})])
    args = ["push", "--send", "--api-base", fake.url, "--run-timestamp", STAMP]
    for name in ("alpha", "beta"):
        args += ["--report", write_report(tmp_path, report(name), f"{name}.json")]
    assert runner.main(args) == 0
    assert len(fake.requests) == 2
    ids = [r["uniqueId"] for r in fake.requests[1]["body"]["resources"]]
    assert ids == ["aev-alpha", "aev-beta"]


def test_a_throttled_put_is_retried(tmp_path, creds, fake_factory, monkeypatch):
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)
    fake = fake_factory([TOKEN_OK, (503, {"error": "busy"}, {}), PUT_OK])
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 0 and [r["method"] for r in fake.requests] == ["POST", "PUT", "PUT"]


def test_a_put_that_keeps_failing_stops_after_three_tries(
    tmp_path, creds, fake_factory, monkeypatch, capsys
):
    monkeypatch.setattr(client.time, "sleep", lambda _s: None)
    fake = fake_factory([TOKEN_OK] + [(503, {"error": "busy"}, {})] * 3)
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 1 and len(fake.requests) == 4
    assert "503" in capsys.readouterr().err


def test_an_auth_failure_is_not_retried(tmp_path, creds, fake_factory, capsys):
    fake = fake_factory([TOKEN_OK, (401, {"error": "expired"}, {})])
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 1 and len(fake.requests) == 2
    assert "401" in capsys.readouterr().err


def test_a_rejected_record_fails_the_push(tmp_path, creds, fake_factory, capsys):
    fake = fake_factory([TOKEN_OK, (200, {"results": {"accepted": 0, "rejected": 1}}, {})])
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 1
    assert "rejected 1" in capsys.readouterr().err


def test_a_token_reply_without_a_token_fails(tmp_path, creds, fake_factory):
    fake = fake_factory([(200, {"token_type": "Bearer"}, {})])
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 1 and len(fake.requests) == 1


def test_a_redirect_is_not_followed_so_the_token_stays_put(tmp_path, creds, fake_factory):
    fake = fake_factory([TOKEN_OK, (307, None, {"Location": "/elsewhere"})])
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 1 and len(fake.requests) == 2


def test_missing_credentials_send_nothing(tmp_path, monkeypatch, fake_factory, capsys):
    for name in runner.ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    fake = fake_factory([])
    code = runner.main(
        ["push", "--report", write_report(tmp_path, report()), "--send", "--api-base", fake.url]
    )
    assert code == 1 and fake.requests == []
    assert "VANTA_CLIENT_ID" in capsys.readouterr().err


@pytest.mark.parametrize("base", ["http://api.vanta.com", "ftp://127.0.0.1", "https://"])
def test_a_non_https_remote_base_is_refused(base):
    with pytest.raises(client.VantaError):
        client.check_base(base)


def test_loopback_http_is_allowed():
    assert client.check_base("http://127.0.0.1:9/") == "http://127.0.0.1:9"


def test_a_failing_corpus_still_pushes_and_exit_follows_the_flag(tmp_path, creds, fake_factory):
    data = report(failing=("va",))
    base = ["push", "--report", write_report(tmp_path, data), "--send"]
    fake = fake_factory([TOKEN_OK, PUT_OK, TOKEN_OK, PUT_OK])
    assert runner.main(base + ["--api-base", fake.url]) == 0
    assert fake.requests[1]["body"]["resources"][0]["customProperties"]["allPass"] is False
    assert runner.main(base + ["--api-base", fake.url, "--fail-on-fail"]) == 1


def test_an_unreadable_report_is_unusable(tmp_path, capsys):
    code = runner.main(["push", "--report", str(tmp_path / "absent.json")])
    assert code == 2 and "cannot read report" in capsys.readouterr().err


def test_schema_prints_the_dashboard_setup(capsys):
    assert runner.main(["schema"]) == 0
    out = capsys.readouterr().out
    assert payloads.CUSTOM_TEST_RULE in out and '"allPass"' in out and '"timestamp"' in out


def test_the_rail_runs_over_a_shipped_corpus_and_the_dry_run_matches_it(capsys):
    code = runner.main(
        ["push", "--corpus", "vectors-test-tampering", "--run-timestamp", STAMP, "--fail-on-fail"]
    )
    out = capsys.readouterr().out
    assert code == 0, out
    assert "aev-test-tampering-v2: allPass=True" in out


def test_a_bundle_directory_goes_through_the_same_rail(capsys):
    bundle = ROOT / "vectors-test-tampering"
    code = runner.main(["push", "--vectors", str(bundle), "--run-timestamp", STAMP])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "allPass=True" in out
