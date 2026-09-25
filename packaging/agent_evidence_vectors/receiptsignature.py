"""Judge vectors-receipt-signature/, and run a named verifier over it.

Two jobs, in the words the Go reader in ``corpora/receiptsignature.go`` prints,
so the two rails can be diffed:

``judge``
    The corpus judges itself. Every member is run through a reference
    verification of draft-farley-acta-signed-receipts-03 twice, against the
    external key set with and without its validity windows, and each outcome
    must be the one the manifest declares. The grading is held to the text: a
    member whose only defect is the window tests a SHOULD, so it must be
    indeterminate, and a reject must cite a MUST.

``run_external``
    A named verifier is run through the contract in the corpus README: once per
    member per key set, the receipt path as its last argument, the key set's path
    in ``AEV_RECEIPT_JWKS``, and its answer read from its exit status and the
    last line of its stdout. A member counts as executed only when both of its
    invocations answered.

Ed25519 and RFC 8785 are borrowed from the reference rail, which owns the one
implementation of each in this distribution.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime
from typing import Any

SUITE = "receipt-signature-conformance"
KEYS_ENV = "AEV_RECEIPT_JWKS"
VALID, INVALID, UNDECIDABLE = "valid", "invalid", "undecidable"
EXIT_VERDICTS = {0: VALID, 1: INVALID, 2: UNDECIDABLE}

_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")
_RAIL_PRIMITIVES = ("ed25519_verify", "jcs_dumps")


def _rail() -> Any:
    """The rail module, resolved at call time: the rail imports this module to
    dispatch the suite, so a module-level import would be a cycle. The rule is
    the one ``observedeffect`` documents."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if all(hasattr(module, p) for p in _RAIL_PRIMITIVES):
            return module
    raise ImportError(
        f"the reference rail is importable as neither {_RAIL_NAMES[0]} nor "
        f"{_RAIL_NAMES[1]}, so the Ed25519 verification and RFC 8785 this module "
        "borrows from it are unavailable"
    )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(directory: str, rel: str) -> bytes | None:
    try:
        with open(os.path.join(directory, rel), "rb") as handle:
            return handle.read()
    except OSError:
        return None


def outcome_text(verdict: str, code: str | None) -> str:
    return verdict if code is None else f"{verdict} {code}"


def _declared(outcome: Any) -> str:
    if not isinstance(outcome, dict):
        return "absent"
    return outcome_text(str(outcome.get("verdict")), outcome.get("code"))


# --------------------------------------------------------------------------
# Reference verification
# --------------------------------------------------------------------------


class _Object(dict[str, Any]):
    """A decoded object that remembers whether it repeated a member name.

    Go's decoder keeps the last of two repeated members, and so does this one;
    RFC 8785 refuses them, which the Go reader learns when it canonicalizes the
    payload. The mark carries that fact to the same step here.
    """

    repeated = False


def _objects(pairs: list[tuple[str, Any]]) -> _Object:
    out = _Object()
    for key, value in pairs:
        if key in out:
            out.repeated = True
        out[key] = value
    return out


def _repeats(value: Any) -> bool:
    if isinstance(value, _Object) and value.repeated:
        return True
    if isinstance(value, dict):
        return any(_repeats(item) for item in value.values())
    if isinstance(value, list):
        return any(_repeats(item) for item in value)
    return False


def parse_envelope(body: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """The envelope shape of Section 2.1, or the outcome that stops at the shape."""
    try:
        top = json.loads(body, object_pairs_hook=_objects)
    except ValueError:
        return None, outcome_text(UNDECIDABLE, "not_envelope_shape")
    if not isinstance(top, dict) or set(top) != {"payload", "signature"}:
        return None, outcome_text(UNDECIDABLE, "not_envelope_shape")
    signature = top["signature"]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"alg", "kid", "sig"}
        or not all(isinstance(signature[k], str) and signature[k] for k in signature)
    ):
        return None, outcome_text(UNDECIDABLE, "bad_signature_object")
    if not isinstance(top["payload"], dict):
        return None, outcome_text(UNDECIDABLE, "payload_not_an_object")
    return top, None


def _public_key(key: dict[str, Any]) -> bytes | None:
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return None
    x = key.get("x")
    if not isinstance(x, str):
        return None
    try:
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    except ValueError:
        return None
    return raw if len(raw) == 32 else None


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _precheck(payload: dict[str, Any], signature: dict[str, str]) -> str | None:
    if any(field not in payload for field in ("type", "issued_at", "issuer_id")):
        return outcome_text(UNDECIDABLE, "missing_required_field")
    if "signature" in payload:
        return outcome_text(INVALID, "signature_in_signing_input")
    if signature["alg"] != "EdDSA":
        return outcome_text(UNDECIDABLE, "unsupported_alg")
    if payload["issuer_id"] != signature["kid"]:
        return outcome_text(INVALID, "issuer_kid_mismatch")
    return None


def _window(issued: Any, key: dict[str, Any]) -> str:
    """valid_from included, valid_until excluded; an absent bound is open."""
    at = _instant(issued)
    if at is None:
        return outcome_text(UNDECIDABLE, "window_not_applicable")
    bounds = {member: _instant(key[member]) for member in ("valid_from", "valid_until")
              if member in key}
    if any(bound is None for bound in bounds.values()):
        return outcome_text(UNDECIDABLE, "window_not_applicable")
    start, end = bounds.get("valid_from"), bounds.get("valid_until")
    if (start is not None and at < start) or (end is not None and at >= end):
        return outcome_text(INVALID, "key_outside_validity_window")
    return VALID


def verify(body: bytes, keys: dict[str, dict[str, Any]]) -> str:
    """Sections 2.1, 2.2, 5.2, 6.6 and 9.2 of draft-03, the key resolved only from
    the external key set (Section 9.5), in the order the Go reader checks them."""
    top, stop = parse_envelope(body)
    if top is None:
        return stop or outcome_text(UNDECIDABLE, "not_envelope_shape")
    payload, signature = top["payload"], top["signature"]
    stop = _precheck(payload, signature)
    if stop is not None:
        return stop
    key = keys.get(signature["kid"])
    if key is None:
        return outcome_text(UNDECIDABLE, "unknown_kid")
    public = _public_key(key)
    if public is None:
        return outcome_text(UNDECIDABLE, "bad_key")
    try:
        sig = bytes.fromhex(signature["sig"])
    except ValueError:
        sig = b""
    if len(sig) != 64:
        return outcome_text(INVALID, "bad_signature_encoding")
    rail = _rail()
    try:
        if _repeats(payload):
            raise ValueError("a repeated member name")
        canonical = rail.jcs_dumps(payload)
    except ValueError:
        return outcome_text(UNDECIDABLE, "payload_not_canonicalizable")
    if not rail.ed25519_verify(public, canonical, sig):
        return outcome_text(INVALID, "signature_invalid")
    return _window(payload["issued_at"], key)


# --------------------------------------------------------------------------
# The corpus judge
# --------------------------------------------------------------------------


class Judged:
    """One corpus, judged: members with their findings, and corpus findings."""

    def __init__(self) -> None:
        self.members: list[tuple[str, str, list[str]]] = []
        self.findings: list[str] = []

    def ok(self) -> bool:
        return not self.findings and all(not findings for _, _, findings in self.members)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, kind, _ in self.members:
            counts[kind] = counts.get(kind, 0) + 1
        return counts


class _Corpus:
    def __init__(self, directory: str, manifest: dict[str, Any]) -> None:
        self.directory = directory
        self.manifest = manifest
        self.findings: list[str] = []
        self.levels: dict[str, str] = {}
        self.with_windows: dict[str, dict[str, Any]] = {}
        self.without_windows: dict[str, dict[str, Any]] = {}

    def check_text(self) -> None:
        m = self.manifest
        spec, pinned = str(m.get("specVendored", "")), str(m.get("specDigest", ""))
        body = _read(self.directory, spec)
        if body is None:
            self.findings.append(
                f"the vendored specification {spec} is missing, so nothing records what "
                "this corpus certifies against"
            )
        elif _sha(body) != pinned:
            self.findings.append(
                f"the vendored specification {spec} does not match its pinned digest "
                f"(pinned {pinned[:12]}, on disk {_sha(body)[:12]}). Re-vendor from upstream "
                "instead of editing the copy."
            )
        contract = str(m.get("contract", ""))
        if not os.path.isfile(os.path.join(self.directory, contract)):
            self.findings.append(
                f"the manifest names the verifier contract at {contract} and no such file is there"
            )
        text = re.sub(r"\s+", " ", body.decode("utf-8")) if body is not None else ""
        for req in m.get("requirements") or []:
            self._check_requirement(req, text)

    def _check_requirement(self, req: dict[str, Any], text: str) -> None:
        rid, level, sentence = str(req.get("id")), str(req.get("level")), str(req.get("sentence"))
        if rid in self.levels:
            self.findings.append(f"requirement {rid} is declared twice")
        self.levels[rid] = level
        if sentence not in text:
            self.findings.append(
                f"requirement {rid} quotes a sentence the vendored specification does not contain"
            )
        if _sha(sentence.encode("utf-8")) != req.get("sentenceDigest"):
            self.findings.append(
                f"requirement {rid} has a sentenceDigest that is not the digest of its sentence"
            )
        if level not in ("MUST", "SHOULD"):
            self.findings.append(f"requirement {rid} declares level {json.dumps(level)}")
        elif level not in sentence:
            self.findings.append(
                f"requirement {rid} declares level {level} and its sentence does not say {level}"
            )

    def check_key_sets(self) -> None:
        sets = self.manifest.get("keySets") or {}
        self.with_windows = self._load_keys(sets.get("withWindows") or {}, "withWindows")
        self.without_windows = self._load_keys(sets.get("withoutWindows") or {}, "withoutWindows")
        windowed = False
        for kid in sorted(self.with_windows):
            key = self.with_windows[kid]
            bare = self.without_windows.get(kid)
            if bare is None or bare.get("x") != key.get("x"):
                self.findings.append(f"the key sets disagree on key {kid} beyond its window")
            windowed = windowed or "valid_from" in key or "valid_until" in key
        if len(self.with_windows) != len(self.without_windows):
            self.findings.append(
                f"the key sets carry {len(self.with_windows)} and "
                f"{len(self.without_windows)} keys"
            )
        for kid in sorted(self.without_windows):
            key = self.without_windows[kid]
            if "valid_from" in key or "valid_until" in key:
                self.findings.append(f"the windowless key set carries a window on key {kid}")
        if not windowed:
            self.findings.append(
                "the windowed key set carries no window, so the two passes are the same pass"
            )

    def _load_keys(self, spec: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
        rel = str(spec.get("file", ""))
        body = _read(self.directory, rel)
        if body is None:
            self.findings.append(f"the {name} key set {rel} cannot be read")
            return {}
        if _sha(body) != spec.get("sha256"):
            self.findings.append(f"the {name} key set {rel} does not match its pinned digest")
        try:
            keys = json.loads(body)["keys"]
        except (ValueError, KeyError, TypeError) as e:
            self.findings.append(f"the {name} key set {rel} does not parse: {e}")
            return {}
        out: dict[str, dict[str, Any]] = {}
        for key in keys:
            kid = str(key.get("kid"))
            if kid in out:
                self.findings.append(f"the {name} key set names key {kid} twice")
            out[kid] = key
        return out

    def judge_member(self, v: dict[str, Any]) -> list[str]:
        findings = self.check_declaration(v)
        body = _read(self.directory, str(v.get("file", "")))
        if body is None:
            return [*findings, "the manifest names a receipt file that does not exist"]
        if "v" + _sha(body)[:16] != v.get("id"):
            findings.append("identifier does not recompute from the receipt's own bytes")
        with_w = verify(body, self.with_windows)
        if with_w != _declared(v.get("expected")):
            findings.append(
                f"with the windowed key set the reference verification is {with_w} and the "
                f"manifest declares {_declared(v.get('expected'))}"
            )
        without_w = verify(body, self.without_windows)
        if without_w != _declared(v.get("expectedWithoutWindows")):
            findings.append(
                f"without the windows the reference verification is {without_w} and the "
                f"manifest declares {_declared(v.get('expectedWithoutWindows'))}"
            )
        return [*findings, *self.check_signed_input(v, body)]

    def check_declaration(self, v: dict[str, Any]) -> list[str]:
        conditions = v.get("conditions") or []
        if not conditions:
            return ["cites no condition"]
        findings: list[str] = []
        levels: set[str] = set()
        defined = self.manifest.get("conditions") or {}
        for c in conditions:
            if c not in defined:
                findings.append(f"cites condition {c} the manifest does not define")
                continue
            levels.update(self.levels.get(r, "") for r in defined[c].get("requirements") or [])
        registry = self.manifest.get("codeRegistry") or {}
        for key in ("expected", "expectedWithoutWindows"):
            code = (v.get(key) or {}).get("code")
            if code is not None and code not in registry:
                findings.append(f"expects code {code} the code registry does not define")
        kind = v.get("kind")
        checks = {"accept": _check_accept, "reject": _check_reject,
                  "indeterminate": _check_indeterminate}
        if kind not in checks:
            return [*findings, f"declares kind {json.dumps(kind)}"]
        return [*findings, *checks[str(kind)](v, levels)]

    def check_signed_input(self, v: dict[str, Any], body: bytes) -> list[str]:
        top, _ = parse_envelope(body)
        if top is None:
            return []
        signature = top["signature"]
        if signature["kid"] != v.get("keyId"):
            return ["keyId is not the kid the receipt's signature names"]
        try:
            signed = bytes.fromhex(str(v.get("signedInputHex", "")))
        except ValueError:
            return ["signedInputHex is not hex"]
        try:
            sig = bytes.fromhex(signature["sig"])
        except ValueError:
            sig = b""
        public = _public_key(self.with_windows.get(signature["kid"], {}))
        rail = _rail()
        if public is None or len(sig) != 64 or not rail.ed25519_verify(public, signed, sig):
            return [
                "the signature does not verify over signedInputHex, so the manifest does "
                "not say what was signed"
            ]
        if v.get("kind") == "reject":
            return []
        try:
            canonical = rail.jcs_dumps(top["payload"])
        except ValueError:
            canonical = b""
        if canonical != signed:
            return ["is not a signing-input defect and its signedInputHex is not JCS(payload)"]
        return []

    def check_corpus(self) -> None:
        m = self.manifest
        vectors: list[dict[str, Any]] = m.get("vectors") or []
        accepted: set[str] = set()
        refused: set[str] = set()
        measured = {"accept": 0, "indeterminate": 0, "reject": 0}
        for v in vectors:
            if v.get("kind") in measured:
                measured[str(v["kind"])] += 1
            for c in v.get("conditions") or []:
                (accepted if v.get("kind") == "accept" else refused).add(c)
        orphan = sorted(refused - accepted)
        if orphan:
            self.findings.append(
                f"conditions that are refused and never accepted: [{' '.join(orphan)}]. A "
                "verifier that refuses every receipt would score full marks on them."
            )
        idle = sorted(set(m.get("conditions") or {}) - accepted - refused)
        if idle:
            self.findings.append(
                f"conditions declared and carried by no member: [{' '.join(idle)}]"
            )
        self._check_requirements_cited()
        declared = m.get("counts") or {}
        if declared != measured:
            self.findings.append(
                f"counts disagree: manifest {_render_counts(declared)}, measured "
                f"{_render_counts(measured)}"
            )
        ordered = sorted(vectors, key=lambda v: str(v.get("id")))
        digest = hashlib.sha256()
        for v in ordered:
            digest.update(_read(self.directory, str(v.get("file", ""))) or b"")
        if digest.hexdigest() != m.get("corpusDigest"):
            self.findings.append("corpusDigest does not match the receipt files on disk")
        self._check_origin(vectors)

    def _check_requirements_cited(self) -> None:
        cited: set[str] = set()
        for name, cond in sorted((self.manifest.get("conditions") or {}).items()):
            for req in cond.get("requirements") or []:
                if req not in self.levels:
                    self.findings.append(
                        f"condition {name} cites requirement {req} the manifest does not declare"
                    )
                cited.add(req)
        idle = sorted(set(self.levels) - cited)
        if idle:
            self.findings.append(
                f"requirements declared and cited by no condition: [{' '.join(idle)}]"
            )

    def _check_origin(self, vectors: list[dict[str, Any]]) -> None:
        files = {str(v.get("id")): str(v.get("file", "")) for v in vectors}
        for o in (self.manifest.get("origin") or {}).get("members") or []:
            rel = files.get(str(o.get("id")))
            if rel is None:
                self.findings.append(
                    f"origin names {o.get('upstreamFile')} as member {o.get('id')} and the "
                    "manifest has no such member"
                )
                continue
            body = _read(self.directory, rel)
            if body is None or _sha(body) != o.get("sha256"):
                self.findings.append(
                    f"member {o.get('id')} is not the upstream bytes of {o.get('upstreamFile')}"
                )


def _render_counts(counts: dict[str, Any]) -> str:
    return "{" + ", ".join(f"{k}={counts[k]}" for k in sorted(counts)) + "}"


def _verdict(outcome: Any) -> Any:
    return outcome.get("verdict") if isinstance(outcome, dict) else None


def _check_accept(v: dict[str, Any], _levels: set[str]) -> list[str]:
    findings = []
    if _verdict(v.get("expected")) != VALID or _verdict(v.get("expectedWithoutWindows")) != VALID:
        findings.append("is an accept member expecting something other than valid")
    if v.get("expectedIfNotHonoured") is not None:
        findings.append(
            "is an accept member carrying expectedIfNotHonoured, which only a SHOULD member has"
        )
    return findings


def _check_reject(v: dict[str, Any], levels: set[str]) -> list[str]:
    findings = []
    if (
        _verdict(v.get("expected")) != INVALID
        or _verdict(v.get("expectedWithoutWindows")) != INVALID
    ):
        findings.append("is a reject member not expected invalid in both passes")
    if "MUST" not in levels:
        findings.append(
            "is a reject member citing no MUST, so a conformant verifier may decline to refuse it"
        )
    if v.get("expectedIfNotHonoured") is not None:
        findings.append(
            "is a reject member carrying expectedIfNotHonoured, which only a SHOULD member has"
        )
    return findings


def _check_indeterminate(v: dict[str, Any], levels: set[str]) -> list[str]:
    findings = []
    if "MUST" in levels or "SHOULD" not in levels:
        findings.append(
            "is an indeterminate member whose conditions do not cite only SHOULD-level requirements"
        )
    if v.get("expectedIfNotHonoured") is None:
        return [*findings, "is an indeterminate member with no expectedIfNotHonoured"]
    if (
        _verdict(v.get("expected")) != INVALID
        or _verdict(v.get("expectedIfNotHonoured")) != VALID
    ):
        findings.append(
            "is an indeterminate member whose two outcomes are not invalid when honoured and "
            "valid when not"
        )
    if _verdict(v.get("expectedWithoutWindows")) != VALID:
        findings.append(
            "is an indeterminate member expected invalid without the windows, which no rule "
            "it cites decides"
        )
    return findings


def _load(directory: str) -> dict[str, Any]:
    with open(os.path.join(directory, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest: dict[str, Any] = json.load(handle)
    return manifest


def judge(directory: str) -> Judged:
    manifest = _load(directory)
    corpus = _Corpus(directory, manifest)
    corpus.check_text()
    corpus.check_key_sets()
    judged = Judged()
    seen: set[str] = set()
    for v in manifest.get("vectors") or []:
        vid, kind = str(v.get("id")), str(v.get("kind"))
        findings = ["duplicate identifier"] if vid in seen else []
        seen.add(vid)
        findings.extend(corpus.judge_member(v))
        judged.members.append((vid, kind, findings))
    corpus.check_corpus()
    judged.findings.extend(corpus.findings)
    return judged


def render(judged: Judged, suite: str) -> str:
    """The lines ``aee-verify`` prints from the Go reader."""
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts = judged.counts()
    for kind in sorted(counts):
        lines.append(f"  {kind}: {counts[kind]}")
    failed = 0
    for member_id, _, findings in judged.members:
        if findings:
            failed += 1
        for finding in findings:
            lines.append(f"FAIL {member_id}: {finding}")
    for finding in judged.findings:
        lines.append(f"FAIL corpus: {finding}")
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} corpus-level claim(s) "
            "do not hold"
        )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# A named verifier, through the contract
# --------------------------------------------------------------------------


def ask(cmd: list[str], receipt: str, keys: str) -> tuple[str | None, str | None]:
    """One invocation: (the answer, or None; the reason it is not an answer)."""
    env = dict(os.environ)
    env[KEYS_ENV] = keys
    try:
        proc = subprocess.run(
            [*cmd, receipt], capture_output=True, timeout=120, env=env, check=False
        )
    except subprocess.TimeoutExpired:
        return None, "the verifier did not terminate"
    except OSError as e:
        return None, f"the verifier could not run: {e}"
    verdict = EXIT_VERDICTS.get(proc.returncode)
    if verdict is None:
        return None, f"the verifier exited {proc.returncode}, which the contract gives no meaning"
    lines = [ln for ln in proc.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]
    if not lines:
        return None, "the verifier wrote no answer line"
    try:
        line = json.loads(lines[-1])
    except ValueError:
        return None, "the verifier's last stdout line is not JSON"
    if not isinstance(line, dict) or line.get("verdict") != verdict:
        return None, (
            f"the verifier's exit status says {verdict} and its answer line says "
            f"{line.get('verdict') if isinstance(line, dict) else line!r}"
        )
    code = line.get("code")
    return outcome_text(verdict, code if isinstance(code, str) and code else None), None


def score(v: dict[str, Any], with_w: str, without_w: str) -> tuple[str, list[str]]:
    """PASS, NOT-HONOURED or FAIL for one member, with the reasons."""
    expected = _declared(v.get("expected"))
    without_expected = _declared(v.get("expectedWithoutWindows"))
    reasons = []
    if without_w != without_expected:
        reasons.append(f"without the windows: expected {without_expected}, answered {without_w}")
    if with_w == expected:
        return ("FAIL", reasons) if reasons else ("PASS", [])
    if v.get("kind") == "indeterminate" and with_w == _declared(v.get("expectedIfNotHonoured")):
        if reasons:
            return "FAIL", reasons
        return "NOT-HONOURED", [
            f"with the windows: answered {with_w}, which does not honour the SHOULD this "
            "member tests (expected when honoured: " + expected + ")"
        ]
    reasons.append(f"with the windows: expected {expected}, answered {with_w}")
    return "FAIL", reasons


def _member_row(directory: str, cmd: list[str], v: dict[str, Any],
                keys: tuple[str, str]) -> dict[str, Any]:
    receipt = os.path.abspath(os.path.join(directory, str(v.get("file", ""))))
    with_w, why_w = ask(cmd, receipt, keys[0])
    without_w, why_n = ask(cmd, receipt, keys[1])
    row: dict[str, Any] = {
        "id": v.get("id"), "kind": v.get("kind"),
        "withWindows": with_w, "withoutWindows": without_w,
        "verifierRan": with_w is not None and without_w is not None,
    }
    if with_w is None or without_w is None:
        row["status"] = "FAIL"
        row["reasons"] = [f"with the windows: {why_w}" if why_w else "",
                          f"without the windows: {why_n}" if why_n else ""]
        row["reasons"] = [r for r in row["reasons"] if r]
        return row
    row["status"], row["reasons"] = score(v, with_w, without_w)
    return row


def run_external(directory: str, cmd: list[str], report_path: str, rail_note: str) -> int:
    """Run a named verifier over every member, write the report, return the exit."""
    manifest = _load(directory)
    judged = judge(directory)
    notes = [] if judged.ok() else [
        "the corpus does not judge clean:", *render(judged, SUITE).splitlines()
    ]
    sets = manifest["keySets"]
    keys = tuple(
        os.path.abspath(os.path.join(directory, sets[name]["file"]))
        for name in ("withWindows", "withoutWindows")
    )
    rows = [_member_row(directory, cmd, v, (keys[0], keys[1])) for v in manifest["vectors"]]
    executed = sum(1 for r in rows if r["verifierRan"])
    if executed != len(rows):
        notes.append(
            f"the verifier {shlex.join(cmd)!r} ran on {executed} of {len(rows)} vectors; "
            f"{len(rows) - executed} were never answered by it"
        )
    refusals = (0 if judged.ok() else 1) + (0 if executed == len(rows) else 1)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    not_honoured = sum(1 for r in rows if r["status"] == "NOT-HONOURED")
    failed = sum(1 for r in rows if r["status"] == "FAIL")
    report = {
        "suite": os.path.basename(os.path.normpath(directory)),
        "rail": "external",
        "railNote": rail_note,
        "verifier": {"command": shlex.join(cmd), "vectorsExecuted": executed, "vectors": len(rows)},
        "totals": {
            "vectors": len(rows),
            "pass": passed,
            "fail": failed,
            "conform": passed + not_honoured,
            "notHonoured": not_honoured,
            "reasonParityMismatch": 0,
            "suiteRefusals": refusals,
            "notExercised": 0,
        },
        "grading": "README.md, How a SHOULD is graded",
        "notes": notes,
        "vectors": rows,
    }
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    for r in rows:
        print(f"{str(r['id']):<20} {str(r['kind']):<14} {r['status']:<13} "
              f"windows: {r['withWindows']}; no windows: {r['withoutWindows']}")
        for reason in r["reasons"]:
            print(f"    {'!' if r['status'] == 'FAIL' else '-'} {reason}")
    for note in notes:
        print(f"note: {note}")
    print(f"totals: {len(rows)} vectors, {passed} pass, {not_honoured} not honouring a SHOULD, "
          f"{failed} fail; report written to {report_path}")
    print(f"verifier: {shlex.join(cmd)} ran on {executed} of {len(rows)} vectors")
    if executed == 0:
        return 2
    return 1 if failed or refusals else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="receiptsignature",
        description="judge vectors-receipt-signature/, or run a named verifier over it",
    )
    parser.add_argument("directory", help="a corpus directory carrying MANIFEST.json")
    parser.add_argument("--verifier", help="the verifier command, run through the contract")
    parser.add_argument("--report", default="receipt-signature-report.json")
    args = parser.parse_args(argv)
    if args.verifier:
        return run_external(args.directory, shlex.split(args.verifier), args.report,
                            f"external verifier: {args.verifier}")
    judged = judge(args.directory)
    sys.stdout.write(render(judged, SUITE))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    if __package__ in (None, ""):
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    raise SystemExit(main())
