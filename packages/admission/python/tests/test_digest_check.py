"""Tests for the digest check: a document names a digest, the artifact must have it."""

import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_admission import digest_check
from agent_evidence_admission.cli import main

ARTIFACT = b"log4j-core-2.26.1.jar bytes\n"
SHA256 = hashlib.sha256(ARTIFACT).hexdigest()
SHA512 = hashlib.sha512(ARTIFACT).hexdigest()


def write(tmp_path: Path, name: str, payload: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return path


def tea_document(value: str = SHA256) -> dict:
    return {
        "uuid": "6bb5d2c1-0000-4000-8000-000000000001",
        "formats": [
            {
                "mediaType": "application/java-archive",
                "url": "https://example.org/log4j-core-2.26.1.jar",
                "checksums": [{"algType": "SHA-256", "algValue": value}],
            }
        ],
    }


def test_declared_digests_reads_tea_checksums():
    assert digest_check.declared_digests(tea_document()) == [("sha256", SHA256)]


def test_declared_digests_reads_the_cyclonedx_subject_component():
    bom = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "log4j-core", "hashes": [{"alg": "SHA-512", "content": SHA512.upper()}]}},
    }
    assert digest_check.declared_digests(bom) == [("sha512", SHA512)]


def test_a_dependency_hash_in_a_bom_does_not_name_the_artifact():
    # A BOM lists its dependencies' hashes too. Matching one of those says the artifact IS that
    # dependency, not that the BOM covers it, so only the subject component counts.
    bom = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "log4j-core"}},
        "components": [{"name": "log4j-api", "hashes": [{"alg": "SHA-256", "content": SHA256}]}],
    }
    assert digest_check.declared_digests(bom) == []
    assert digest_check.check(bom, ARTIFACT).reason == "no-digest-named"


def test_declared_digests_reads_cyclonedx_xml():
    xml = (
        '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"><metadata>'
        '<tools><components><component><hashes><hash alg="SHA-256">' + "a" * 64 + "</hash></hashes>"
        "</component></components></tools>"
        '<component type="library"><name>log4j-core</name><hashes><hash alg="SHA-256">'
        + SHA256
        + "</hash></hashes></component></metadata>"
        '<components><component><hashes><hash alg="SHA-512">' + SHA512 + "</hash></hashes></component></components></bom>"
    )
    assert digest_check.declared_digests(digest_check.parse_document(xml.encode())) == [("sha256", SHA256)]


def test_parse_document_refuses_xml_with_a_doctype():
    with pytest.raises(ValueError, match="DOCTYPE"):
        digest_check.parse_document(b'<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY a "b">]><bom/>')


def test_parse_document_refuses_bytes_that_are_neither_json_nor_xml():
    with pytest.raises(ValueError):
        digest_check.parse_document(b"not a document")


def test_declared_digests_reads_in_toto_subjects():
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "a", "digest": {"sha256": SHA256}}],
        "predicate": {"materials": [{"name": "dep", "digest": {"sha256": "b" * 64}}]},
    }
    assert digest_check.declared_digests(statement) == [("sha256", SHA256)]


def test_declared_digests_ignores_unknown_algorithms():
    doc = {"checksums": [{"algType": "MD5", "algValue": "0" * 32}, {"algType": "SHA-1", "algValue": "0" * 40}]}
    assert digest_check.declared_digests(doc) == []


def test_check_passes_when_the_artifact_has_a_named_digest():
    result = digest_check.check(tea_document(), ARTIFACT)
    assert result.ok
    assert result.matched == ("sha256", SHA256)


def test_check_rejects_a_swapped_artifact():
    result = digest_check.check(tea_document(), b"a different jar\n")
    assert not result.ok
    assert result.reason == "digest-mismatch"


def test_check_rejects_a_document_that_names_no_digest():
    result = digest_check.check({"formats": [{"url": "https://example.org/x.jar"}]}, ARTIFACT)
    assert not result.ok
    assert result.reason == "no-digest-named"


def test_check_passes_on_any_matching_entry_among_several():
    doc = {"checksums": [{"algType": "SHA-256", "algValue": "f" * 64}, {"algType": "SHA-512", "algValue": SHA512}]}
    assert digest_check.check(doc, ARTIFACT).ok
    assert digest_check.check(doc, ARTIFACT).matched == ("sha512", SHA512)


def test_cli_exit_codes(tmp_path, capsys):
    artifact = tmp_path / "artifact.jar"
    artifact.write_bytes(ARTIFACT)
    good = write(tmp_path, "good.json", tea_document())
    bad = write(tmp_path, "bad.json", tea_document("0" * 64))
    empty = write(tmp_path, "empty.json", {"formats": []})

    assert main(["digest-check", str(good), str(artifact)]) == 0
    assert "PASS" in capsys.readouterr().out
    assert main(["digest-check", str(bad), str(artifact)]) == 1
    assert "digest-mismatch" in capsys.readouterr().out
    assert main(["digest-check", str(empty), str(artifact)]) == 1
    assert "no-digest-named" in capsys.readouterr().out


def test_cli_could_not_read_is_exit_2(tmp_path, capsys):
    assert main(["digest-check", str(tmp_path / "missing.json"), str(tmp_path / "missing.jar")]) == 2
    assert "ERROR" in capsys.readouterr().err


def test_cli_rejects_a_document_that_is_not_json(tmp_path, capsys):
    doc = tmp_path / "doc.json"
    doc.write_text("not json")
    artifact = tmp_path / "a.jar"
    artifact.write_bytes(ARTIFACT)
    assert main(["digest-check", str(doc), str(artifact)]) == 2


def test_read_source_fetches_http_urls(monkeypatch):
    class Response:
        def __init__(self):
            self.body = b"payload"

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return Response()

    monkeypatch.setattr(digest_check.urllib.request, "urlopen", fake_urlopen)
    assert digest_check.read_source("https://example.org/doc.json") == b"payload"
    assert seen == {"url": "https://example.org/doc.json", "timeout": digest_check.FETCH_TIMEOUT_SECONDS}


def test_read_source_refuses_plain_http():
    with pytest.raises(ValueError, match="https"):
        digest_check.read_source("http://example.org/doc.json")


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip().startswith("agent-evidence-admission ")


def test_declared_digests_reads_a_dsse_envelope():
    import base64

    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "a", "digest": {"sha256": SHA256}}]}
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "signatures": [],
    }
    assert digest_check.declared_digests(envelope) == [("sha256", SHA256)]
    assert digest_check.declared_digests({"payloadType": "x", "payload": "!!not base64"}) == []


def test_declared_digests_of_a_non_object_is_empty():
    assert digest_check.declared_digests(["not", "an", "object"]) == []


def test_parse_document_refuses_malformed_xml():
    with pytest.raises(ValueError, match="well-formed"):
        digest_check.parse_document(b"<bom><metadata></bom>")
