"""Tests for the client allowlist generator: the vector manifest, the golden files, the CLI, and
the corners the vectors leave."""

import copy
import json
from pathlib import Path

import pytest
from agent_evidence_admission import generate as g
from agent_evidence_admission.cli import main

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "generate"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())
CASES = MANIFEST["cases"]
BASE = json.loads((VECTORS / "admit-list.json").read_text())


def run(case: dict, out: Path, capsys) -> tuple[int, dict]:
    argv = ["generate", str(VECTORS / case["admit_list"]), "--out", str(out), "--json"]
    for client in case.get("clients", []):
        argv += ["--client", client]
    code = main(argv)
    captured = capsys.readouterr()
    return code, json.loads(captured.out) if captured.out else {}


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_vector(case, tmp_path, capsys):
    code, report = run(case, tmp_path / "out", capsys)
    assert code == case["exit"]
    if case["exit"] == 2:
        assert not (tmp_path / "out").exists()
        return
    assert [[r["client"], r["server"]] for r in report["refused"]] == case["refused"]
    assert report["ok"] is (case["exit"] == 0)
    written = sorted(str(p.relative_to(tmp_path / "out")) for p in (tmp_path / "out").rglob("*") if p.is_file())
    assert written == report["files"]
    if "expected" in case:
        expected = VECTORS / case["expected"]
        golden = sorted(str(p.relative_to(expected)) for p in expected.rglob("*") if p.is_file())
        assert written == golden
        for relative in golden:
            assert (tmp_path / "out" / relative).read_bytes() == (expected / relative).read_bytes(), relative


def test_the_manifest_holds_both_polarities_and_every_exit_code():
    assert {c["polarity"] for c in CASES} == {"positive", "negative"}
    assert {c["exit"] for c in CASES} == {0, 1, 2}
    assert {r[0] for c in CASES for r in c["refused"]} == {"cursor", "registry"}


def test_every_admit_list_in_the_directory_is_used_by_a_case():
    used = {c["admit_list"] for c in CASES}
    assert {p.name for p in VECTORS.glob("*.json")} - {"manifest.json"} == used


def test_no_client_binds_a_digest_and_the_report_says_so(tmp_path, capsys):
    code = main(["generate", str(VECTORS / "admit-list.json"), "--out", str(tmp_path)])
    text = capsys.readouterr().out
    assert code == 0
    assert text.count("UNBOUND ") == 3
    assert text.rstrip().endswith("PASS every server rendered for every client")
    settings = json.loads((tmp_path / "claude-code/managed-settings.json").read_text())
    assert settings["allowManagedMcpServersOnly"] is True
    assert all("serverName" not in e for e in settings["allowedMcpServers"])


def test_latest_is_the_last_version_listed_and_the_list_holds_one_entry_per_name():
    result = g.generate(g.parse_admit_list(BASE), ("registry",))
    latest = json.loads(result.files["registry/v0.1/servers/io.github.example%2Ffiles/versions/latest.json"])
    assert latest["server"]["version"] == "1.4.2"
    listing = json.loads(result.files["registry/v0.1/servers.json"])
    assert listing["metadata"]["count"] == 2
    assert latest["_meta"][g.META_KEY]["digest"] == "sha256:" + "2" * 64


def test_claude_code_writes_one_entry_for_two_servers_with_one_url():
    doc = copy.deepcopy(BASE)
    doc["admitted"].append({**doc["admitted"][2], "name": "com.example/search-mirror", "key": "mirror"})
    result = g.generate(g.parse_admit_list(doc), ("claude-code",))
    allowed = json.loads(result.files["claude-code/managed-settings.json"])["allowedMcpServers"]
    assert allowed.count({"serverUrl": "https://mcp.example.com/v2/mcp"}) == 1
    assert len(result.binds) == 4


def test_windsurf_patterns_match_only_the_literal_value():
    doc = copy.deepcopy(BASE)
    doc["admitted"][0]["stdio"]["args"] = ["a.b", "(x)|[y]*+?{1}^$\\"]
    config = g.generate(g.parse_admit_list(doc), ("windsurf",)).files["windsurf/allowlist.json"]
    args = json.loads(config)["entries"][0]["serverConfig"]["args"]
    assert args == ["a\\.b", "\\(x\\)\\|\\[y\\]\\*\\+\\?\\{1\\}\\^\\$\\\\"]


def test_cursor_refuses_a_wildcard_in_an_argument():
    doc = copy.deepcopy(BASE)
    doc["admitted"][0]["stdio"]["args"][2] = "/srv/*"
    result = g.generate(g.parse_admit_list(doc), ("cursor",))
    assert [r[:2] for r in result.refused] == [("cursor", "io.github.example/files@1.4.1")]


def mutate(path: str, value):
    doc = copy.deepcopy(BASE)
    target = doc
    *head, last = path.split(".")
    for part in head:
        target = target[int(part)] if part.isdigit() else target[part]
    if value is KeyError:
        del target[last]
    else:
        target[int(last) if last.isdigit() else last] = value
    return doc


@pytest.mark.parametrize(
    "doc, message",
    [
        ([], "non-empty admitted array"),
        ({"admitted": "x"}, "non-empty admitted array"),
        ({"admitted": ["x"]}, "must be an object"),
        (mutate("admitted.0.description", KeyError), "description must be a non-empty string"),
        (mutate("admitted.0.description", " padded"), "no outer whitespace"),
        (mutate("admitted.0.key", "has space"), "key must be"),
        (mutate("admitted.0.package", "npm"), "package must be an object"),
        (mutate("admitted.0.package", {"registryType": 1}), "package must be an object"),
        (mutate("admitted.0.stdio.args", "-y"), "args must be a list"),
        (mutate("admitted.0.stdio.args", [""]), "args must be a list"),
        (mutate("admitted.0.stdio.command", "${HOME}/npx"), "expands on the user's machine"),
        (mutate("admitted.0", {**BASE["admitted"][0], "stdio": None}), "must be an object"),
        (mutate("admitted.2.remote.type", "websocket"), "type must be one of"),
        (mutate("admitted.2.remote.url", "https:///mcp"), "https URL with a host"),
        (mutate("admitted.2.remote", {}), "url must be a non-empty string"),
        (mutate("admitted.2.remote", "not-an-object"), "remote: must be an object"),
    ],
)
def test_an_invalid_admit_list_is_refused_with_its_reason(doc, message):
    with pytest.raises((TypeError, ValueError), match=message.replace("$", "\\$").replace("{", "\\{")):
        g.parse_admit_list(doc)


def test_an_unreadable_admit_list_and_an_unwritable_out_exit_2(tmp_path, capsys):
    assert main(["generate", str(tmp_path / "absent.json"), "--out", str(tmp_path / "o")]) == 2
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert main(["generate", str(VECTORS / "admit-list.json"), "--out", str(blocker)]) == 2
    assert "could not write" in capsys.readouterr().err


def test_the_other_commands_still_dispatch(capsys):
    with pytest.raises(SystemExit):
        main(["generate", "--help"])
    assert "--client" in capsys.readouterr().out
