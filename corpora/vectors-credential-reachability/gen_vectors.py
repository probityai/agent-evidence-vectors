"""Build the deterministic credential-reachability cases.

    uv run --extra generators python corpora/vectors-credential-reachability/gen_vectors.py

Each member is one signed credential-reachability/v1 statement: the result of a
probe that ran inside an agent's environment and tried every ambient credential
class of a closed list, with the verifier policy that judges it. Four members are
accepted as issued; every other member is one scripted mutation away from an
accepted twin, and the mutation is the only difference. Every envelope is signed
here with the published test keys below, so every byte in the corpus is a
function of this file alone.

TEST KEYS ONLY. Each seed is the SHA-256 of a public label, so anyone can
re-derive the private key. Never trust these keys for anything else.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
_DIGEST = importlib.util.spec_from_file_location("credential_reachability_digest",
                                                 ROOT / "digest.py")
assert _DIGEST is not None and _DIGEST.loader is not None
_digest_module = importlib.util.module_from_spec(_DIGEST)
_DIGEST.loader.exec_module(_digest_module)
corpus_digest = _digest_module.corpus_digest

SUITE = "credential-reachability/v1"
PREDICATE = ("https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
             "credential-reachability")
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT = "https://in-toto.io/Statement/v1"
CLASS_SET = "credential-reachability/v1"
CLASSES = ("ssh-agent", "ssh-key-file", "cloud-metadata", "cloud-config-file",
           "registry-config-file", "browser-cookie-store", "environment-token",
           "cluster-service-account", "git-credential", "host-keyring")

HOST_LABEL = "credential-reachability/v1 test environment-host key"
AGENT_LABEL = "credential-reachability/v1 test key the agent holds"
OTHER_LABEL = "credential-reachability/v1 test key that no policy pins"

ENVIRONMENT = "environment/run-0042"
AUDIENCE = "https://auditor.example.org"
PROBED_AT = "2026-11-21T18:00:00Z"
JUDGED_AT = "2026-11-21T18:05:00Z"
MAX_AGE_SECONDS = 3600
# A service-account home outside /home: a /home/<name>/ path reads as a person's home
# directory, and the push-range identity scan refuses one inside a signed payload.
HOME = "/srv/agent-home"
PLACEHOLDER = "BROKER_PLACEHOLDER_"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(label: str) -> str:
    return _sha(label.encode())


def _prefix(label: str) -> str:
    """The 12-hex prefix a probe records for a credential, here of a public label."""
    return _hex(label)[:12]


CONTRACT_DIGEST = _hex("environment contract run-0042")
CHALLENGE = _hex("verifier challenge 0042")
PROBE_DIGEST = _hex("credential-probe 1.0.0 binary")
MARKED_PREFIX = _prefix("agent token issued to agent-0042")


def canonical(value: object) -> bytes:
    """The issuer's canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public_raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def keyid(k: Ed25519PrivateKey) -> str:
    """The SHA-256 of the raw 32-byte public key, lowercase hex."""
    return _sha(public_raw(k))


HOST, AGENT, OTHER = key(HOST_LABEL), key(AGENT_LABEL), key(OTHER_LABEL)


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def signature(k: Ed25519PrivateKey, payload_type: str, body: bytes,
              kid: str | None = None) -> dict[str, str]:
    return {"keyid": kid or keyid(k), "sig": _b64(k.sign(pae(payload_type, body)))}


def _a(locator: str, outcome: str, prefix: str | None = None,
       detail: str | None = None) -> dict[str, str]:
    attempt = {"locator": locator, "outcome": outcome}
    if prefix is not None:
        attempt["digestPrefix"] = prefix
    if detail is not None:
        attempt["detail"] = detail
    return attempt


def _contained_attempts() -> dict[str, list[dict[str, str]]]:
    """What a probe records in an environment that holds no unmarked credential."""
    return {
        "ssh-agent": [_a("env:SSH_AUTH_SOCK", "absent"),
                      _a("glob:/tmp/ssh-*/agent.*", "absent")],
        "ssh-key-file": [_a(f"file:{HOME}/.ssh/id_ed25519", "absent"),
                         _a(f"file:{HOME}/.ssh/id_rsa", "absent"),
                         _a("dir:/root/.ssh", "denied")],
        "cloud-metadata": [
            _a("http://169.254.169.254/latest/api/token", "absent", detail="connection refused"),
            _a("http://metadata.google.internal/computeMetadata/v1/", "absent",
               detail="name does not resolve"),
            _a("http://169.254.169.254/metadata/instance", "absent", detail="connection refused")],
        "cloud-config-file": [_a(f"file:{HOME}/.aws/credentials", "absent"),
                              _a(f"file:{HOME}/.config/gcloud/credentials.db", "absent"),
                              _a(f"file:{HOME}/.azure/msal_token_cache.json", "absent")],
        "registry-config-file": [_a(f"file:{HOME}/.npmrc", "absent"),
                                 _a(f"file:{HOME}/.pypirc", "absent"),
                                 _a(f"file:{HOME}/.docker/config.json", "absent"),
                                 _a(f"file:{HOME}/.cargo/credentials.toml", "absent")],
        "browser-cookie-store": [_a(f"glob:{HOME}/.config/google-chrome/*/Cookies", "absent"),
                                 _a(f"glob:{HOME}/.mozilla/firefox/*/cookies.sqlite", "absent")],
        "environment-token": [_a("env:GITHUB_TOKEN", "placeholder"),
                              _a("env:OPENAI_API_KEY", "placeholder")],
        "cluster-service-account": [
            _a("file:/var/run/secrets/kubernetes.io/serviceaccount/token", "absent"),
            _a(f"file:{HOME}/.kube/config", "absent")],
        "git-credential": [_a("git-config:credential.helper", "absent"),
                           _a(f"file:{HOME}/.git-credentials", "absent"),
                           _a(f"file:{HOME}/.netrc", "absent")],
        "host-keyring": [_a("env:DBUS_SESSION_BUS_ADDRESS", "absent"),
                         _a("socket:/run/user/1000/keyring/control", "absent"),
                         _a(f"socket:{HOME}/.gnupg/S.gpg-agent", "absent")],
    }


def derive_verdict(attempts: list[dict[str, str]]) -> str:
    outcomes = {a["outcome"] for a in attempts}
    if "found" in outcomes:
        return "reachable"
    if outcomes & {"error", "not_run"}:
        return "could_not_test"
    return "not_reachable"


def derive_result(verdicts: list[str]) -> str:
    if "reachable" in verdicts:
        return "exposed"
    if "could_not_test" in verdicts:
        return "incomplete"
    return "contained"


def predicate(attempts: dict[str, list[dict[str, str]]],
              marked: list[dict[str, str]] | None = None) -> dict[str, Any]:
    classes = [{"class": c, "verdict": derive_verdict(attempts[c]), "attempts": attempts[c]}
               for c in CLASSES]
    return {
        "classSet": CLASS_SET,
        "audience": AUDIENCE,
        "challenge": CHALLENGE,
        "probedAt": PROBED_AT,
        "vantage": "agent-process",
        "probe": {"name": "credential-probe", "version": "1.0.0",
                  "digest": {"sha256": PROBE_DIGEST}},
        "placeholders": [{"prefix": PLACEHOLDER}],
        "markedCredentials": marked or [],
        "classes": classes,
        "result": derive_result([c["verdict"] for c in classes]),
    }


def statement(pred: dict[str, Any]) -> dict[str, Any]:
    return {"_type": STATEMENT,
            "subject": [{"name": ENVIRONMENT, "digest": {"sha256": CONTRACT_DIGEST}}],
            "predicateType": PREDICATE, "predicate": pred}


def contained() -> dict[str, Any]:
    return statement(predicate(_contained_attempts()))


def exposed() -> dict[str, Any]:
    """A positive control: a developer's home mounted into a plain container."""
    attempts = _contained_attempts()
    attempts["ssh-key-file"][0] = _a(f"file:{HOME}/.ssh/id_ed25519", "found",
                                     _prefix("developer ed25519 private key"))
    attempts["environment-token"] = [
        _a("env:AWS_SECRET_ACCESS_KEY", "found", _prefix("developer cloud secret key"))]
    attempts["git-credential"][1] = _a(f"file:{HOME}/.git-credentials", "found",
                                       _prefix("developer stored git credentials"))
    attempts["browser-cookie-store"][0] = _a(
        f"file:{HOME}/.config/google-chrome/Default/Cookies", "found",
        _prefix("developer browser cookie database"))
    return statement(predicate(attempts))


def incomplete() -> dict[str, Any]:
    attempts = _contained_attempts()
    attempts["cloud-metadata"][1] = _a("http://metadata.google.internal/computeMetadata/v1/",
                                       "error", detail="resolver did not answer")
    return statement(predicate(attempts))


def contained_marked() -> dict[str, Any]:
    attempts = _contained_attempts()
    attempts["environment-token"].append(_a("env:AGENT_TOKEN", "marked", MARKED_PREFIX))
    return statement(predicate(attempts, [{"id": "agent-token-0042",
                                           "digestPrefix": MARKED_PREFIX}]))


BASES: dict[str, Callable[[], dict[str, Any]]] = {
    "contained": contained, "exposed": exposed, "incomplete": incomplete,
    "contained-marked": contained_marked,
}


def default_policy() -> dict[str, Any]:
    return {
        "payload_type": PAYLOAD_TYPE,
        "trusted_signers": {keyid(HOST): _b64(public_raw(HOST))},
        "agent_keys": {keyid(AGENT): _b64(public_raw(AGENT))},
        "environment": {"name": ENVIRONMENT, "sha256": CONTRACT_DIGEST},
        "audience": AUDIENCE,
        "challenge": CHALLENGE,
        "judged_at": JUDGED_AT,
        "max_age_seconds": MAX_AGE_SECONDS,
        "probe_digests": [PROBE_DIGEST],
    }


class Member:
    """One case before it is written: the statement, the envelope edits and the policy."""

    def __init__(self, base: str) -> None:
        self.body: Any = BASES[base]()
        self.policy = default_policy()
        self.payload_type = PAYLOAD_TYPE
        self.signers: list[tuple[Ed25519PrivateKey, str]] = [(HOST, keyid(HOST))]
        self.raw_payload: bytes | None = None
        self.post: Callable[[dict[str, Any]], None] | None = None
        self.raw_envelope: bytes | None = None

    def payload(self) -> bytes:
        return self.raw_payload if self.raw_payload is not None else canonical(self.body)

    def envelope_bytes(self) -> bytes:
        if self.raw_envelope is not None:
            return self.raw_envelope
        body = self.payload()
        env = {"payload": _b64(body), "payloadType": self.payload_type,
               "signatures": [signature(k, self.payload_type, body, kid)
                              for k, kid in self.signers]}
        if self.post is not None:
            self.post(env)
        return canonical(env)


Mutation = Callable[[Member], None]


def _pred(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    def mutate(m: Member) -> None:
        edit(m.body["predicate"])
    return mutate


def _stmt(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    def mutate(m: Member) -> None:
        edit(m.body)
    return mutate


def _policy(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    def mutate(m: Member) -> None:
        edit(m.policy)
    return mutate


def _class(name: str, m: dict[str, Any]) -> dict[str, Any]:
    return next(c for c in m["classes"] if c["class"] == name)


def _tamper_payload(m: Member) -> None:
    forged = copy.deepcopy(m.body)
    _class("ssh-key-file", forged["predicate"])["attempts"][0]["outcome"] = "absent"

    def post(env: dict[str, Any]) -> None:
        env["payload"] = _b64(canonical(forged))
    m.post = post


def _signers(*pairs: tuple[Ed25519PrivateKey, str]) -> Mutation:
    def mutate(m: Member) -> None:
        m.signers = list(pairs)
    return mutate


def _payload_type(value: str) -> Mutation:
    def mutate(m: Member) -> None:
        m.payload_type = value
    return mutate


def _raw_envelope(data: bytes) -> Mutation:
    def mutate(m: Member) -> None:
        m.raw_envelope = data
    return mutate


def _duplicate_member(m: Member) -> None:
    text = canonical(m.body).decode()
    m.raw_payload = text.replace('"result":"contained"',
                                 '"result":"exposed","result":"contained"', 1).encode()


def _not_object(m: Member) -> None:
    m.body = [m.body]


def _set_attempt(cls: str, index: int, **fields: Any) -> Mutation:
    def edit(p: dict[str, Any]) -> None:
        attempt = _class(cls, p)["attempts"][index]
        for name, value in fields.items():
            if value is None:
                attempt.pop(name, None)
            else:
                attempt[name] = value
    return _pred(edit)


def _drop_class(name: str) -> Mutation:
    return _pred(lambda p: p.__setitem__("classes",
                                         [c for c in p["classes"] if c["class"] != name]))


def _duplicate_class(name: str) -> Mutation:
    return _pred(lambda p: p["classes"].append(copy.deepcopy(_class(name, p))))


def _second_subject(s: dict[str, Any]) -> None:
    s["subject"].append({"name": "environment/run-0043",
                         "digest": {"sha256": _hex("environment contract run-0043")}})


SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")

# (id, base, mutation or None, decision, reason, what the mutation does)
MEMBERS: tuple[tuple[str, str, Mutation | None, str, str, str], ...] = (
    ("contained", "contained", None, SUPPORTED, "contained_verified",
     "every class tried and not reachable; two broker placeholders in the environment"),
    ("exposed", "exposed", None, SUPPORTED, "exposed_verified",
     "a positive control: a key file, a cloud secret, stored git credentials and a cookie "
     "database are reachable"),
    ("incomplete", "incomplete", None, SUPPORTED, "incomplete_verified",
     "one metadata attempt failed, so that class could not be tested and the result is "
     "incomplete"),
    ("contained-marked", "contained-marked", None, SUPPORTED, "contained_verified",
     "an agent token that carries an agent marker is reachable, and nothing else"),
    ("contained-unpinned-cosigner", "contained",
     _signers((OTHER, keyid(OTHER)), (HOST, keyid(HOST))), SUPPORTED, "contained_verified",
     "a first signature by a key no policy names is ignored; the host's verifies"),
    ("contained-no-probe-pin", "contained", _policy(lambda p: p.__setitem__("probe_digests", [])),
     SUPPORTED, "contained_verified", "the verifier pins no probe digest"),
    ("malformed-envelope", "contained", _raw_envelope(b'{"payload": '), NO_VERDICT,
     "malformed_envelope", "the envelope bytes are not JSON"),
    ("malformed-signature", "contained",
     lambda m: setattr(m, "post", lambda env: env["signatures"][0].__setitem__("sig", "%%%")),
     NO_VERDICT, "malformed_envelope", "a signature is not base64"),
    ("payload-type-other", "contained", _payload_type("application/json"), NOT_ESTABLISHED,
     "unsupported_payload_type", "signed under a payload type the policy does not pin"),
    ("signed-by-agent-key", "contained", _signers((AGENT, keyid(AGENT))), CONTRADICTED,
     "signed_by_agent_key", "the agent signed its own result under its own keyid"),
    ("agent-key-names-host-keyid", "contained", _signers((AGENT, keyid(HOST))), CONTRADICTED,
     "signed_by_agent_key", "the agent signed its own result and labelled it with the host's "
     "keyid"),
    ("agent-cosigned", "contained", _signers((HOST, keyid(HOST)), (AGENT, keyid(AGENT))),
     CONTRADICTED, "signed_by_agent_key",
     "the host signed and the agent added its own signature to the envelope"),
    ("forged-payload", "exposed", _tamper_payload, CONTRADICTED, "signature_invalid",
     "the found key file was rewritten as absent after signing"),
    ("untrusted-signer", "contained", _signers((OTHER, keyid(OTHER))), CONTRADICTED,
     "untrusted_key", "signed by a key the policy does not name, under its own keyid"),
    ("swapped-key-names-host-keyid", "contained", _signers((OTHER, keyid(HOST))), CONTRADICTED,
     "signature_invalid", "signed by a key the policy does not name, labelled with the host's "
     "keyid"),
    ("payload-duplicate-member", "contained", _duplicate_member, NOT_ESTABLISHED,
     "payload_not_json_object", "the signed payload repeats the result member"),
    ("payload-not-object", "contained", _not_object, NOT_ESTABLISHED,
     "payload_not_json_object", "the signed payload is a JSON array holding the statement"),
    ("statement-type-old", "contained",
     _stmt(lambda s: s.__setitem__("_type", "https://in-toto.io/Statement/v0.1")),
     NOT_ESTABLISHED, "unsupported_statement_type", "the statement names a superseded type"),
    ("predicate-type-other", "contained",
     _stmt(lambda s: s.__setitem__("predicateType",
                                   "https://in-toto.io/attestation/test-result/v0.1")),
     NOT_ESTABLISHED, "unsupported_predicate", "the statement names another predicate type"),
    ("subject-two-members", "contained", _stmt(_second_subject), NOT_ESTABLISHED,
     "subject_malformed", "the statement names two environments"),
    ("another-environment-name", "contained",
     _stmt(lambda s: s["subject"][0].__setitem__("name", "environment/run-0043")),
     CONTRADICTED, "environment_mismatch", "the record is for another environment"),
    ("another-environment-contract", "contained",
     _stmt(lambda s: s["subject"][0]["digest"].__setitem__(
         "sha256", _hex("environment contract run-0042, widened"))),
     CONTRADICTED, "environment_mismatch",
     "the record is for the same environment name under another contract"),
    ("predicate-not-object", "contained", _stmt(lambda s: s.__setitem__("predicate", "contained")),
     NOT_ESTABLISHED, "predicate_field_invalid:predicate", "the predicate is a string"),
    ("predicate-extra-member", "contained",
     _pred(lambda p: p.__setitem__("secrets", [])), NOT_ESTABLISHED,
     "predicate_field_invalid:members", "the predicate carries a member outside its list"),
    ("predicate-member-missing", "contained", _pred(lambda p: p.pop("markedCredentials")),
     NOT_ESTABLISHED, "predicate_field_invalid:members", "markedCredentials is absent"),
    ("class-set-downgrade", "contained",
     _pred(lambda p: p.__setitem__("classSet", "credential-reachability/v0")), NOT_ESTABLISHED,
     "class_set_unsupported", "the record claims an older, shorter class list"),
    ("audience-empty", "contained", _pred(lambda p: p.__setitem__("audience", "")),
     NOT_ESTABLISHED, "predicate_field_invalid:audience", "the audience is empty"),
    ("vantage-not-text", "contained", _pred(lambda p: p.__setitem__("vantage", None)),
     NOT_ESTABLISHED, "predicate_field_invalid:vantage", "the vantage is null"),
    ("placeholder-prefix-empty", "contained",
     _pred(lambda p: p.__setitem__("placeholders", [{"prefix": ""}])), NOT_ESTABLISHED,
     "predicate_field_invalid:placeholders", "a declared placeholder prefix is empty"),
    ("marked-prefix-long", "contained-marked",
     _pred(lambda p: p["markedCredentials"][0].__setitem__("digestPrefix", MARKED_PREFIX + "0")),
     NOT_ESTABLISHED, "predicate_field_invalid:markedCredentials",
     "a declared marked credential carries 13 hex digits"),
    ("challenge-malformed", "contained", _pred(lambda p: p.__setitem__("challenge", "0042")),
     NOT_ESTABLISHED, "predicate_field_invalid:challenge", "the challenge is not 64 hex"),
    ("probed-at-offset", "contained",
     _pred(lambda p: p.__setitem__("probedAt", "2026-11-21T13:00:00-05:00")), NOT_ESTABLISHED,
     "predicate_field_invalid:probedAt", "the probe time carries a zone offset, not Z"),
    ("probe-digest-missing", "contained", _pred(lambda p: p["probe"].pop("digest")),
     NOT_ESTABLISHED, "predicate_field_invalid:probe", "the probe names no digest"),
    ("class-unknown", "contained",
     _pred(lambda p: _class("host-keyring", p).__setitem__("class", "host-keychain")),
     NOT_ESTABLISHED, "predicate_field_invalid:classes", "a class term outside the list"),
    ("class-without-attempts", "contained",
     _pred(lambda p: _class("cloud-metadata", p).__setitem__("attempts", [])),
     NOT_ESTABLISHED, "predicate_field_invalid:classes",
     "a class reported with no attempt: the probe did not run for it"),
    ("outcome-unknown", "contained", _set_attempt("ssh-agent", 0, outcome="clean"),
     NOT_ESTABLISHED, "predicate_field_invalid:classes", "an attempt outcome outside the list"),
    ("result-unknown", "contained", _pred(lambda p: p.__setitem__("result", "safe")),
     NOT_ESTABLISHED, "predicate_field_invalid:result", "a result outside the list"),
    ("attempt-carries-value", "exposed",
     _set_attempt("environment-token", 0, value="not-a-real-credential-0042"),
     CONTRADICTED, "attempt_fields", "a found attempt carries the credential's value"),
    ("attempt-full-digest", "exposed",
     _set_attempt("ssh-key-file", 0, digestPrefix=_hex("developer ed25519 private key")),
     CONTRADICTED, "attempt_fields", "a found attempt carries a full digest, not a prefix"),
    ("found-without-prefix", "exposed", _set_attempt("ssh-key-file", 0, digestPrefix=None),
     CONTRADICTED, "attempt_fields", "a found attempt carries no digest prefix"),
    ("absent-with-prefix", "contained",
     _set_attempt("ssh-agent", 0, digestPrefix=_prefix("nothing")), CONTRADICTED,
     "attempt_fields", "an absent attempt carries a digest prefix"),
    ("vantage-host", "contained", _pred(lambda p: p.__setitem__("vantage", "host-process")),
     NOT_ESTABLISHED, "vantage_not_agent", "the probe ran on the host, outside the agent's view"),
    ("audience-other", "contained",
     _pred(lambda p: p.__setitem__("audience", "https://other-verifier.example.org")),
     CONTRADICTED, "audience_mismatch", "the record was made for another verifier"),
    ("challenge-replayed", "contained",
     _pred(lambda p: p.__setitem__("challenge", _hex("verifier challenge 0041"))),
     CONTRADICTED, "challenge_mismatch", "a record made under an earlier challenge is replayed"),
    ("probed-in-future", "contained",
     _pred(lambda p: p.__setitem__("probedAt", "2026-11-21T18:06:00Z")), CONTRADICTED,
     "probed_in_future", "the probe time is after the time the verifier judges at"),
    ("result-stale", "contained",
     _pred(lambda p: p.__setitem__("probedAt", "2026-11-21T17:04:59Z")), NOT_ESTABLISHED,
     "result_stale", "the record is one second older than the oldest the verifier accepts"),
    ("probe-not-pinned", "contained",
     _pred(lambda p: p["probe"]["digest"].__setitem__("sha256",
                                                      _hex("credential-probe 0.9.0 binary"))),
     NOT_ESTABLISHED, "probe_not_pinned", "the probe is not one the verifier pins"),
    ("class-duplicate", "contained", _duplicate_class("ssh-agent"), CONTRADICTED,
     "class_duplicate:ssh-agent", "one class is reported twice"),
    ("class-omitted", "contained", _drop_class("host-keyring"), CONTRADICTED,
     "class_missing:host-keyring", "the host keyring class is left out"),
    ("marked-undeclared", "contained-marked",
     _pred(lambda p: p.__setitem__("markedCredentials", [])), CONTRADICTED,
     "marked_undeclared", "a credential is called marked that the record does not declare"),
    ("placeholder-undeclared", "contained", _pred(lambda p: p.__setitem__("placeholders", [])),
     CONTRADICTED, "placeholder_undeclared",
     "values are called placeholders while the record declares no placeholder prefix"),
    ("found-reported-clean", "exposed",
     _pred(lambda p: _class("ssh-key-file", p).__setitem__("verdict", "not_reachable")),
     CONTRADICTED, "reachable_reported_clean:ssh-key-file",
     "a class with a found key file is reported not reachable"),
    ("not-run-reported-clean", "contained",
     _pred(lambda p: _class("cloud-metadata", p)["attempts"].__setitem__(
         0, _a("http://169.254.169.254/latest/api/token", "not_run"))),
     CONTRADICTED, "untested_reported_clean:cloud-metadata",
     "a metadata attempt did not run and the class is still reported not reachable"),
    ("error-reported-clean", "incomplete",
     _pred(lambda p: _class("cloud-metadata", p).__setitem__("verdict", "not_reachable")),
     CONTRADICTED, "untested_reported_clean:cloud-metadata",
     "a metadata attempt failed and the class is reported not reachable"),
    ("verdict-overcautious", "contained",
     _pred(lambda p: _class("ssh-agent", p).__setitem__("verdict", "reachable")),
     CONTRADICTED, "class_verdict_mismatch:ssh-agent",
     "a class is reported reachable that no attempt found"),
    ("result-overstates-incomplete", "incomplete",
     _pred(lambda p: p.__setitem__("result", "contained")), CONTRADICTED, "result_overstates",
     "a class could not be tested and the result is reported contained"),
    ("result-overstates-exposed", "exposed",
     _pred(lambda p: p.__setitem__("result", "incomplete")), CONTRADICTED, "result_overstates",
     "classes are reachable and the result is reported incomplete"),
    ("result-understates", "contained", _pred(lambda p: p.__setitem__("result", "exposed")),
     CONTRADICTED, "result_mismatch", "no class is reachable and the result is reported exposed"),
)


def _write_case(root: Path, name: str, m: Member) -> dict[str, str]:
    directory = root / "cases" / name
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.iterdir():
        stale.unlink()
    files = {"envelope.json": m.envelope_bytes(),
             "case.json": _pretty({"envelope": "envelope.json", "policy": m.policy})}
    for file, data in files.items():
        (directory / file).write_bytes(data)
    return {file: _sha(data) for file, data in sorted(files.items())}


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# Credential reachability vectors", "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.", "",
        f"Suite: `{SUITE}`. Predicate: {PREDICATE}", "",
        f"Environment-host test keyid: `{keyid(HOST)}`", "",
        f"Agent test keyid: `{keyid(AGENT)}`", "",
        f"Corpus digest: `{digest}`", "",
        "| id | decision | reason | twin | mutation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        lines.append(f"| `{e['id']}` | {x['decision']} | `{x['reason']}` | "
                     f"{e.get('twin', '')} | {e['description']} |")
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the manifest and the index."""
    entries = []
    for name, base, mutate, verdict, reason, description in MEMBERS:
        m = Member(base)
        if mutate is not None:
            mutate(m)
        entry: dict[str, Any] = {
            "id": name, "path": f"cases/{name}", "files": _write_case(root, name, m),
            "description": description, "expected": {"decision": verdict, "reason": reason},
        }
        if verdict != SUPPORTED:
            entry["twin"] = base
        entries.append(entry)
    stale = {p.name for p in (root / "cases").iterdir() if p.is_dir()} - {e["id"] for e in entries}
    for name in stale:
        for file in (root / "cases" / name).iterdir():
            file.unlink()
        (root / "cases" / name).rmdir()
    digest = _sha(_pretty(entries))
    manifest = {"suite": SUITE, "predicateType": PREDICATE, "vectors": entries,
                "hostKeyid": keyid(HOST), "agentKeyid": keyid(AGENT),
                "verifierContract": "verifier case.json --json", "corpusDigest": digest}
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_pretty(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
