"""Adverse controls for signed actions, signer keys and corpus completeness."""

import base64
import copy
import hashlib
import json

import pytest
import reader
import run_corpus
from agent_evidence_vectors import run_vectors


def did_key(raw):
    number = int.from_bytes(b"\xed\x01" + raw, "big")
    digits = ""
    while number:
        number, digit = divmod(number, 58)
        digits = reader.BASE58[digit] + digits
    return "did:key:z" + digits


SEEDS = {
    name: hashlib.sha256(("probity-action-control/" + name).encode()).digest()
    for name in ("caller", "provider", "witness")
}
KEYS = {
    name: did_key(run_vectors.ed25519_public_key(seed)) for name, seed in SEEDS.items()
}


def signed(record, kind, signer):
    record = copy.deepcopy(record)
    id_field, sig_field = {
        "grant": ("grant_ref", "caller_sig"),
        "receipt": ("receipt_id", "provider_sig"),
        "intent": ("intent_id", "intent_sig"),
        "observation": ("evidence_id", "witness_sig"),
    }[kind]
    preimage = reader.preimage(record, kind)
    record[id_field] = hashlib.sha256(reader.canonical(preimage)).hexdigest()
    record[sig_field] = base64.b64encode(
        run_vectors.ed25519_sign(SEEDS[signer], reader.canonical(preimage))
    ).decode()
    return record


def bundle(action, *, intent=reader.MISSING):
    grant = {
        "schema": "task-execution-bind-v0/grant",
        "task_id": "own-control",
        "caller_id": KEYS["caller"],
        "provider_id": KEYS["provider"],
        "not_before": "2026-10-11T00:00:00Z",
        "not_after": "2026-10-11T01:00:00Z",
        "nonce": "control-1",
    }
    if action is not reader.MISSING:
        grant["action"] = action
    grant = signed(grant, "grant", "caller")
    receipt = {
        "schema": "task-execution-bind-v0/receipt",
        "task_id": "own-control",
        "grant_ref": grant["grant_ref"],
        "provider_id": KEYS["provider"],
        "executed_at": "2026-10-11T00:30:00Z",
        "outcome": {
            "status": "completed",
            "evidence": {
                "kind": "document_sha256",
                "ref": "a" * 64,
                "system": "synthetic-control",
            },
        },
    }
    if action is not reader.MISSING:
        receipt["executed_action"] = action
    receipt = signed(receipt, "receipt", "provider")
    observation = {
        "task_id": "own-control",
        "hop": {"seq": 0, "from": KEYS["caller"], "to": KEYS["provider"]},
        "prev_evidence_id": None,
        "witness_id": KEYS["witness"],
        "observed_at": "2026-10-11T00:40:00Z",
        "conduct": {
            "verdict": "ok",
            "detail_ref": "nenrin-exec://" + receipt["receipt_id"],
        },
    }
    observation = signed(observation, "observation", "witness")
    observation["edge_sig"] = base64.b64encode(
        run_vectors.ed25519_sign(
            SEEDS["caller"],
            reader.canonical({"task_id": "own-control", "hop": observation["hop"]}),
        )
    ).decode()
    result = {
        "task_id": "own-control",
        "grant": grant,
        "receipt": receipt,
        "observations": [observation],
    }
    if intent is not reader.MISSING:
        record = {
            "schema": "task-execution-bind-v0/intent",
            "task_id": "own-control",
            "grant_ref": grant["grant_ref"],
            "provider_id": KEYS["provider"],
            "declared_at": "2026-10-11T00:20:00Z",
            "proposed_action": intent,
        }
        result["intent"] = signed(record, "intent", "provider")
    return result


@pytest.mark.parametrize("value", [reader.MISSING, None, False, 0, 0.0, -0.0, ""])
def test_equal_degenerate_actions_still_refuse(value):
    result = reader.assess(bundle(value))
    assert result["signature"] == {
        "verdict": "refused",
        "refusals": ["execution_invalid"],
        "findings": ["evidence_bound_unchecked"],
    }
    assert result["recordSignatures"] == {"grant": True, "receipt": True}
    assert result["receiptReconciled"] is True
    assert result["reasons"]["execution_invalid"] == ["action_diverged"]


@pytest.mark.parametrize(
    "value", [{}, [], True, 1, "0", "false", " ", {"tool": "read"}]
)
def test_present_actions_do_not_use_python_truthiness(value):
    result = reader.assess(bundle(value, intent=value))
    assert result["signature"] == {
        "verdict": "accepted",
        "refusals": [],
        "findings": ["evidence_bound_unchecked"],
    }
    assert result["liveEvidenceLookupExecuted"] is False
    assert result["executionObserved"] is False


@pytest.mark.parametrize("value", [None, 0, False, ""])
def test_degenerate_intent_and_receipt_are_not_a_match(value):
    item = bundle({"tool": "read"}, intent=value)
    item["receipt"]["executed_action"] = value
    item["receipt"] = signed(item["receipt"], "receipt", "provider")
    item["observations"] = []
    result = reader.assess(item)
    assert result["signature"]["refusals"] == ["execution_invalid", "preflight_invalid"]
    assert "declared_executed_divergence" in result["signature"]["findings"]


@pytest.mark.parametrize(
    "record,field,code",
    [
        ("grant", "caller_sig", "execution_signature_invalid"),
        ("receipt", "provider_sig", "execution_signature_invalid"),
        ("intent", "intent_sig", "preflight_signature_invalid"),
    ],
)
def test_each_record_signature_is_checked(record, field, code):
    item = bundle({}, intent={})
    raw = bytearray(base64.b64decode(item[record][field]))
    raw[0] ^= 1
    item[record][field] = base64.b64encode(raw).decode()
    assert code in reader.assess(item)["signature"]["refusals"]


@pytest.mark.parametrize("field", ["witness_sig", "edge_sig"])
def test_each_observation_signature_is_checked(field):
    item = bundle({})
    item["observations"][0][field] = base64.b64encode(bytes(64)).decode()
    assert (
        "delegation_observation_invalid" in reader.assess(item)["signature"]["refusals"]
    )


def test_signed_changed_action_still_differs():
    item = bundle({"tool": "read"})
    item["receipt"]["executed_action"] = {"tool": "write"}
    item["receipt"] = signed(item["receipt"], "receipt", "provider")
    item["observations"] = []
    result = reader.assess(item)
    assert result["recordSignatures"]["receipt"] is True
    assert result["reasons"]["execution_invalid"] == ["action_diverged"]


def test_unsigned_changed_action_does_not_keep_authentication():
    item = bundle({"tool": "read"})
    item["grant"]["action"] = {"tool": "write"}
    result = reader.assess(item)
    assert "execution_signature_invalid" in result["signature"]["refusals"]
    assert result["reasons"]["execution_invalid"] == ["grant_recompute_mismatch"]


def test_identity_key_forgery_is_refused_before_signature_check():
    identity = b"\x01" + bytes(31)
    forged = identity + bytes(32)
    message = reader.canonical({"action": {}})
    # The primitive's equation alone accepts this. The profile needs a prime-order key.
    assert run_vectors.ed25519_verify(identity, message, forged) is True
    assert (
        reader.signature_valid(
            did_key(identity), base64.b64encode(forged).decode(), {"action": {}}
        )
        is False
    )


@pytest.mark.parametrize(
    "key",
    [
        bytes(31),
        reader.PRIME.to_bytes(32, "little"),
        (reader.PRIME - 1).to_bytes(32, "little"),
        (2**255 + 1).to_bytes(32, "little"),
    ],
)
def test_noncanonical_and_nonprime_keys_do_not_resolve(key):
    assert reader.prime_order_key(key) is False


@pytest.mark.parametrize(
    "change",
    [
        lambda text: text + "\n",
        lambda text: text[:-1],
        lambda text: text.replace("+", "-") if "+" in text else "_" + text[1:],
    ],
)
def test_noncanonical_base64_is_not_a_signature(change):
    item = bundle({})
    grant = item["grant"]
    assert (
        reader.signature_valid(
            grant["caller_id"],
            change(grant["caller_sig"]),
            reader.preimage(grant, "grant"),
        )
        is False
    )


def test_booleans_are_not_numeric_actions():
    assert reader.actions_equal(True, 1) is False
    assert reader.canonical(True) != reader.canonical(1)
    assert reader.action_shape(False) == "false"
    assert reader.action_shape(0) == "zero"


@pytest.mark.parametrize(
    "value", [1.5, float("nan"), 2**53, 10**1000, {"\x01": 1}, object()]
)
def test_unsupported_canonical_values_fail(value):
    with pytest.raises(reader.Unsupported):
        reader.canonical(value)


def test_canonical_profile_keeps_significant_bytes():
    assert reader.canonical("\ud83d\ude00") == reader.canonical("😀")
    assert (
        reader.canonical({"b": -0.0, "a": "é\u2028\ud800"})
        == b'{"a":"\xc3\xa9\xe2\x80\xa8\\ud800","b":0}'
    )
    item = bundle({})
    item["grant"]["future"] = "signed extension"
    result = reader.assess(item)
    assert result["reasons"]["execution_invalid"] == ["grant_recompute_mismatch"]
    assert "execution_signature_invalid" in result["signature"]["refusals"]


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(require_signatures=False),
        lambda value: value.update(receipts=[]),
        lambda value: value.update(grant=False),
        lambda value: value.update(intent=[]),
        lambda value: value.update(observations=[1]),
    ],
)
def test_unsupported_profiles_never_accept(change):
    item = bundle({})
    change(item)
    assert reader.assess(item)["signature"]["verdict"] == "unsupported"


def corpus(tmp_path):
    directory = tmp_path / "corpus"
    (directory / "fixtures").mkdir(parents=True)
    item = bundle({})
    (directory / "fixtures" / "case.json").write_text(json.dumps(item))
    (directory / "expected.json").write_text(
        json.dumps(
            {
                "cases": {
                    "case": {
                        "expect": {
                            "verdict": "accepted",
                            "refusals": [],
                            "findings": ["evidence_bound_unchecked"],
                        }
                    }
                }
            }
        )
    )
    manifest = {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [directory / "expected.json", directory / "fixtures" / "case.json"]
    }
    (directory / "SHA256.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    return directory


def replay(directory):
    pins = directory / "SHA256.json"
    return run_corpus.replay(
        directory, pins, hashlib.sha256(pins.read_bytes()).hexdigest()
    )


def test_replay_retains_input_and_source_pins(tmp_path):
    result = replay(corpus(tmp_path))
    assert result["passed"] == result["total"] == 1
    assert len(result["readerSourceSHA256"]) == 64
    assert len(result["cases"][0]["inputSHA256"]) == 64


def test_replay_refuses_missing_fixture(tmp_path):
    directory = corpus(tmp_path)
    (directory / "fixtures" / "case.json").unlink()
    with pytest.raises(ValueError, match="populations differ"):
        replay(directory)


def test_replay_refuses_extra_fixture(tmp_path):
    directory = corpus(tmp_path)
    (directory / "fixtures" / "extra.json").write_text("{}")
    with pytest.raises(ValueError, match="populations differ"):
        replay(directory)


def test_replay_refuses_empty_population(tmp_path):
    directory = corpus(tmp_path)
    (directory / "expected.json").write_text('{"cases": {}}')
    with pytest.raises(ValueError, match="population is empty"):
        replay(directory)


def test_replay_refuses_case_path_escape(tmp_path):
    directory = corpus(tmp_path)
    (directory / "expected.json").write_text('{"cases": {"../escape": {}}}')
    with pytest.raises(ValueError, match="safe file basename"):
        replay(directory)


def without_observations(item):
    item["observations"] = []
    return item


@pytest.mark.parametrize(
    "value,reason",
    [
        ("2026-10-11T00:30:00+00:00", "invalid_timestamp"),
        ("2026-02-30T00:30:00Z", "invalid_timestamp"),
        ("2026-10-11T01:00:01Z", "outside_authorization_window"),
        ("2026-10-10T23:59:59Z", "outside_authorization_window"),
    ],
)
def test_authenticated_receipt_still_checks_authorization_time(value, reason):
    item = without_observations(bundle({}))
    item["receipt"]["executed_at"] = value
    item["receipt"] = signed(item["receipt"], "receipt", "provider")
    result = reader.assess(item)
    assert result["recordSignatures"]["receipt"] is True
    assert result["reasons"]["execution_invalid"] == [reason]


def test_timestamp_precision_is_milliseconds():
    left = reader._timestamp("2026-10-11T00:30:00.1239999Z")
    right = reader._timestamp("2026-10-11T00:30:00.123Z")
    assert left == right
    assert reader._timestamp(None) is None


@pytest.mark.parametrize("bound", ["not_before", "not_after"])
def test_invalid_grant_time_bound_cannot_authorize(bound):
    item = without_observations(bundle({}))
    item["grant"][bound] = "bad time"
    item["grant"] = signed(item["grant"], "grant", "caller")
    item["receipt"]["grant_ref"] = item["grant"]["grant_ref"]
    item["receipt"] = signed(item["receipt"], "receipt", "provider")
    assert reader.assess(item)["reasons"]["execution_invalid"] == ["invalid_timestamp"]


def action_binding(action):
    return {
        "type": "canonical_request_digest",
        "canonicalization": "musubi-canonical-v0",
        "preimage_profile": "task-execution-bind-v0/action",
        "digest": {
            "alg": "sha-256",
            "value": hashlib.sha256(reader.canonical(action)).hexdigest(),
        },
    }


@pytest.mark.parametrize(
    "binding,reason",
    [
        (None, "action_binding_malformed"),
        ({"type": "wrong"}, "action_binding_malformed"),
        (
            {"type": "canonical_request_digest", "digest": []},
            "action_binding_malformed",
        ),
        (
            {
                "type": "canonical_request_digest",
                "digest": {"alg": "wrong", "value": "a"},
            },
            "action_binding_malformed",
        ),
        (
            {
                "type": "canonical_request_digest",
                "digest": {"alg": "sha-256", "value": 1},
            },
            "action_binding_malformed",
        ),
        (
            {
                "type": "canonical_request_digest",
                "digest": {"alg": "sha-256", "value": "a"},
            },
            "action_binding_unknown_profile",
        ),
    ],
)
def test_supplied_binding_is_validated(binding, reason):
    item = bundle({})
    item["grant"]["action_binding"] = binding
    assert reader.assess(item)["reasons"]["execution_invalid"] == [reason]


def test_valid_binding_does_not_change_signed_preimage():
    item = bundle({}, intent={})
    for name, field in (
        ("grant", "action"),
        ("receipt", "executed_action"),
        ("intent", "proposed_action"),
    ):
        item[name]["action_binding"] = action_binding(item[name][field])
    result = reader.assess(item)
    assert result["signature"]["verdict"] == "accepted"
    assert all(result["recordSignatures"].values())
    item["receipt"]["action_binding"]["digest"]["value"] = "0" * 64
    assert reader.assess(item)["reasons"]["execution_invalid"] == [
        "action_binding_mismatch"
    ]


def test_grant_binding_does_not_qualify_intent_binding():
    item = bundle({}, intent={})
    item["grant"]["action_binding"] = None
    result = reader.assess(item)
    assert result["reasons"]["execution_invalid"] == ["action_binding_malformed"]
    assert "preflight_invalid" not in result["signature"]["refusals"]


@pytest.mark.parametrize(
    "record,field", [("receipt", "receipt_id"), ("intent", "intent_id")]
)
def test_record_identifier_does_not_follow_a_claimed_digest(record, field):
    item = bundle({}, intent={})
    item[record][field] = "0" * 64
    result = reader.assess(item)
    code = "execution_invalid" if record == "receipt" else "preflight_invalid"
    assert result["reasons"][code] == [record + "_recompute_mismatch"]


def test_authentic_unbound_receipt_cannot_reconcile():
    item = without_observations(bundle({}))
    item["receipt"]["grant_ref"] = "0" * 64
    item["receipt"] = signed(item["receipt"], "receipt", "provider")
    result = reader.assess(item)
    assert result["recordSignatures"]["receipt"] is True
    assert result["reasons"]["execution_invalid"] == ["receipt_unbound"]
    assert result["receiptReconciled"] is False


def test_authentic_other_provider_is_not_authorized():
    item = without_observations(bundle({}))
    item["receipt"]["provider_id"] = KEYS["caller"]
    item["receipt"] = signed(item["receipt"], "receipt", "caller")
    result = reader.assess(item)
    assert result["recordSignatures"]["receipt"] is True
    assert result["reasons"]["execution_invalid"] == ["provider_not_authorized"]


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        {},
        {"kind": []},
        {"kind": "document_sha256", "ref": "a" * 64, "system": ""},
    ],
)
def test_evidence_shape_does_not_claim_live_resolution(evidence):
    item = without_observations(bundle({}))
    item["receipt"]["outcome"]["evidence"] = evidence
    item["receipt"] = signed(item["receipt"], "receipt", "provider")
    result = reader.assess(item)
    assert result["liveEvidenceLookupExecuted"] is False
    if evidence is None:
        assert "no_evidence_bound" in result["signature"]["findings"]
    else:
        assert "evidence_invalid" in result["signature"]["refusals"]


def resign_observation(row):
    row = signed(row, "observation", "witness")
    row["edge_sig"] = base64.b64encode(
        run_vectors.ed25519_sign(
            SEEDS["caller"],
            reader.canonical({"task_id": row["task_id"], "hop": row["hop"]}),
        )
    ).decode()
    return row


@pytest.mark.parametrize("seq", [True, -1, "0", 1])
def test_delegation_sequence_is_a_contiguous_integer(seq):
    item = bundle({})
    item["observations"][0]["hop"]["seq"] = seq
    item["observations"][0] = resign_observation(item["observations"][0])
    assert "delegation_chain_broken" in reader.assess(item)["signature"]["refusals"]


@pytest.mark.parametrize("seq,link", [(0, "wrong"), (1, {}), (1, "wrong")])
def test_malformed_delegation_links_refuse_without_crashing(seq, link):
    item = bundle({})
    item["observations"][0].update(prev_evidence_id=link)
    item["observations"][0]["hop"]["seq"] = seq
    item["observations"][0] = resign_observation(item["observations"][0])
    assert "delegation_chain_broken" in reader.assess(item)["signature"]["refusals"]


def test_authenticated_witness_disagreement_remains_a_finding():
    item = bundle({})
    other = copy.deepcopy(item["observations"][0])
    other["conduct"]["verdict"] = "refused"
    item["observations"].append(resign_observation(other))
    result = reader.assess(item)
    assert "witness_disagreement" in result["signature"]["findings"]
    assert "delegation_observation_invalid" not in result["signature"]["refusals"]


@pytest.mark.parametrize("link", [None, "nenrin-exec://" + "0" * 64])
def test_receipt_linkage_needs_the_authenticated_digest(link):
    item = bundle({})
    item["observations"][0]["conduct"]["detail_ref"] = link
    item["observations"][0] = resign_observation(item["observations"][0])
    result = reader.assess(item)
    if link is None:
        assert "no_digest_link" in result["signature"]["findings"]
    else:
        assert "linkage_receipt_mismatch" in result["signature"]["refusals"]


@pytest.mark.parametrize(
    "identifier",
    [
        None,
        "did:key:wrong",
        "did:key:z",
        "did:key:z!",
        "did:key:z" + "1" * 65,
        "did:key:z1",
    ],
)
def test_nonresolving_key_identifiers_never_authenticate(identifier):
    assert reader.public_key(identifier) is None


def test_canonical_depth_is_bounded():
    value = None
    for _ in range(66):
        value = [value]
    with pytest.raises(reader.Unsupported, match="depth"):
        reader.canonical(value)


def test_replay_refuses_changed_dependency(tmp_path, monkeypatch):
    monkeypatch.setattr(run_corpus.importlib.metadata, "version", lambda name: "0.0.0")
    with pytest.raises(ValueError, match="version differs"):
        replay(corpus(tmp_path))


def test_replay_refuses_oversized_case(tmp_path):
    directory = corpus(tmp_path)
    (directory / "fixtures" / "case.json").write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match="one MiB"):
        replay(directory)


def test_replay_command_writes_the_raw_report(tmp_path, capsys):
    directory = corpus(tmp_path)
    output = tmp_path / "nested" / "report.json"
    assert (
        run_corpus.main(
            [
                "--corpus",
                str(directory),
                "--pins",
                str(directory / "SHA256.json"),
                "--pins-sha256",
                hashlib.sha256((directory / "SHA256.json").read_bytes()).hexdigest(),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(output.read_text())["passed"] == 1
    assert json.loads(capsys.readouterr().out)["total"] == 1


def test_reader_command_returns_refusal_as_diagnostic(tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle(None)))
    assert reader.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["signature"]["verdict"] == "refused"


@pytest.mark.parametrize(
    "raw",
    [b"not JSON", b" " * (1024 * 1024 + 1), b"[" * 1001 + b"]" * 1001],
    ids=["invalid-json", "oversized", "too-deep"],
)
def test_reader_command_reports_unreadable_input(tmp_path, capsys, raw):
    path = tmp_path / "bundle.json"
    path.write_bytes(raw)
    assert reader.main([str(path)]) == 2
    assert json.loads(capsys.readouterr().out)["signature"]["verdict"] == "unsupported"


def test_replay_refuses_changed_fixture_before_comparison(tmp_path):
    directory = corpus(tmp_path)
    path = directory / "fixtures" / "case.json"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(ValueError, match="input digest differs"):
        replay(directory)


def test_replay_refuses_changed_expectation_before_comparison(tmp_path):
    directory = corpus(tmp_path)
    path = directory / "expected.json"
    path.write_text(path.read_text() + "\n")
    with pytest.raises(ValueError, match="input digest differs"):
        replay(directory)


def test_replay_refuses_changed_pin_manifest(tmp_path):
    directory = corpus(tmp_path)
    with pytest.raises(ValueError, match="pin manifest digest differs"):
        run_corpus.replay(directory, directory / "SHA256.json", "0" * 64)


def test_replay_refuses_incomplete_pin_manifest(tmp_path):
    directory = corpus(tmp_path)
    (directory / "SHA256.json").write_text("{}")
    with pytest.raises(ValueError, match="pin manifest population differs"):
        replay(directory)


@pytest.mark.parametrize(
    "expect,reason",
    [
        (
            {"verdict": "unsupported", "refusals": [], "findings": []},
            "unsupported is not",
        ),
        (
            {"verdict": "accepted", "refusals": [], "findings": ["a", "a"]},
            "sorted and unique",
        ),
        ({"verdict": "accepted", "refusals": {}, "findings": []}, "list is malformed"),
        (
            {"verdict": "accepted", "refusals": [True], "findings": []},
            "list is malformed",
        ),
        ({"verdict": "accepted"}, "shape is malformed"),
        (None, "shape is malformed"),
    ],
)
def test_replay_does_not_qualify_a_malformed_or_unsupported_expectation(
    tmp_path, expect, reason
):
    directory = corpus(tmp_path)
    (directory / "expected.json").write_text(
        json.dumps({"cases": {"case": {"expect": expect}}})
    )
    with pytest.raises(ValueError, match=reason):
        replay(directory)


def test_reader_command_reports_a_missing_file(tmp_path, capsys):
    assert reader.main([str(tmp_path / "missing.json")]) == 2
    assert json.loads(capsys.readouterr().out)["signature"]["verdict"] == "unsupported"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"action":null,"action":{}}',
        b'{"action":null,"\\u0061ction":{}}',
        b'{"nested":[{"action":null,"action":{}}]}',
    ],
    ids=["duplicate", "escaped-duplicate", "nested-duplicate"],
)
def test_json_parser_refuses_duplicate_members_before_hashing(raw):
    with pytest.raises(reader.Unsupported, match="duplicate JSON member"):
        reader.decode_json(raw)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_json_parser_refuses_non_json_numeric_constants(constant):
    with pytest.raises(reader.Unsupported, match="non-JSON numeric constant"):
        reader.decode_json(("{" + '"value":' + constant + "}").encode())


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_json_parser_requires_utf8_bytes(encoding):
    with pytest.raises((UnicodeError, ValueError)):
        reader.decode_json('{"value":1}'.encode(encoding))


def test_signed_record_with_duplicate_action_never_authenticates(tmp_path, capsys):
    raw = json.dumps(bundle({})).replace(
        '"action": {}', '"action": null, "action": {}', 1
    )
    assert reader.assess(json.loads(raw))["signature"]["verdict"] == "accepted"
    path = tmp_path / "bundle.json"
    path.write_text(raw)
    assert reader.main([str(path)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["signature"]["verdict"] == "unsupported"
    assert report["unsupported"] == "duplicate JSON member"


@pytest.mark.parametrize(
    "target", ["expected.json", "fixtures/case.json", "SHA256.json"]
)
def test_replay_refuses_duplicate_members_in_every_input(tmp_path, target):
    directory = corpus(tmp_path)
    path = directory / target
    value = json.loads(path.read_bytes())
    first = next(iter(value))
    duplicate = json.dumps(first) + ":" + json.dumps(value[first]) + ","
    path.write_text("{" + duplicate + path.read_text()[1:])
    if target != "SHA256.json":
        pins = directory / "SHA256.json"
        manifest = json.loads(pins.read_bytes())
        manifest[target] = hashlib.sha256(path.read_bytes()).hexdigest()
        pins.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    with pytest.raises(reader.Unsupported, match="duplicate JSON member"):
        replay(directory)
