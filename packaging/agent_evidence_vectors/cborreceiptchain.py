"""Judge a stream of signed CBOR receipts as one whole, ordered chain.

A class of authorization systems writes one signed receipt per decision as a CBOR map and links each
receipt to the one before it by the SHA-256 of its bytes. Every receipt can verify while the stream is
not the one that was written: a receipt repeated, an authorization recorded twice, two receipts swapped,
the tail cut, a gap hidden by a restart, a record re-signed under a key the consumer never trusted. The
format is a pinned profile (``profile.json``) and every trust input comes from the consumer's case,
never from the stream.

The reader checks in a fixed order and names the first check that fails (decision ``contradicted``):

1. ``receipt_shape``: every line is a well formed four-member receipt;
2. ``signature``: every signature verifies under the key the receipt carries;
3. ``signer_pinned``: every signing key is one the consumer pinned;
4. ``no_duplicate_receipt``: no receipt appears twice;
5. ``single_use``: no signed request proof is allowed by two receipts;
6. ``chain_order``: each receipt names the one before it, and the first names the pinned predecessor;
7. ``head_anchor``: the last receipt and the count match the head the consumer kept outside the stream.

A stream that passes all seven is ``supported`` (``receipt_chain_holds``) unless the bytes cannot show
completeness, in which case it is ``not_established``: ``chain_reset`` (a receipt names no predecessor
after the first), ``head_not_anchored`` (no head pinned) or ``effect_not_recorded`` (an effect was
required and the format carries none).

The external-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one JSON object
carrying ``decision`` and ``reason``, and exits 0 for ``supported``, 1 for ``contradicted`` and 3 for
``not_established``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from agent_evidence_vectors.anchoredchain import _rail
from agent_evidence_vectors.monitorcoverage import (
    _fixture_error,
    _validated_entries,
    cli,
    run_corpus,
)

SUITE = "cbor-receipt-chain/v1"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED = "supported", "contradicted", "not_established"
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 3}
CHECKS = (
    "receipt_shape",
    "signature",
    "signer_pinned",
    "no_duplicate_receipt",
    "single_use",
    "chain_order",
    "head_anchor",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-cbor-receipt-chain" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-cbor-receipt-chain")
OUTER = ("version", "payload", "signer_key", "signature")


class Malformed(ValueError):
    """A defect in carried bytes."""


def _take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if n < 0 or pos + n > len(buf):
        raise Malformed("truncated")
    return buf[pos:pos + n], pos + n


def _item(buf: bytes, pos: int, depth: int, budget: list[int]) -> tuple[Any, int]:
    budget[0] -= 1
    if depth > 16 or budget[0] < 0:
        raise Malformed("too deep or too large")
    head, pos = _take(buf, pos, 1)
    major, info = head[0] >> 5, head[0] & 31
    if major == 7:
        if info in (20, 21, 22):
            return {20: False, 21: True, 22: None}[info], pos
        raise Malformed("float or simple value")
    if major == 6 or info > 27:
        raise Malformed("tag, reserved or indefinite")
    arg = info
    if info >= 24:
        raw, pos = _take(buf, pos, 1 << (info - 24))
        arg = int.from_bytes(raw, "big")
    if major in (0, 1):
        return (arg if major == 0 else -1 - arg), pos
    if major in (2, 3):
        raw, pos = _take(buf, pos, arg)
        try:
            return (raw if major == 2 else raw.decode("utf-8")), pos
        except UnicodeDecodeError as exc:
            raise Malformed("text is not UTF-8") from exc
    if arg > len(buf):
        raise Malformed("length past the end")
    if major == 4:
        items = []
        for _ in range(arg):
            value, pos = _item(buf, pos, depth + 1, budget)
            items.append(value)
        return items, pos
    out: dict[Any, Any] = {}
    for _ in range(arg):
        key, pos = _item(buf, pos, depth + 1, budget)
        if not isinstance(key, (int, str)) or isinstance(key, bool) or key in out:
            raise Malformed("map key is not an integer or text, or repeats")
        out[key], pos = _item(buf, pos, depth + 1, budget)
    return out, pos


def decode(data: bytes) -> Any:
    """Decode exactly one CBOR item, strictly."""
    value, pos = _item(data, 0, 0, [4096])
    if pos != len(data):
        raise Malformed("trailing bytes")
    return value


def _bytes(value: Any, form: str, size: int) -> bytes:
    if form == "pair":
        if not isinstance(value, list) or len(value) != 2:
            raise Malformed("expected an [alg, bytes] pair")
        value = value[1]
    if not isinstance(value, bytes) or len(value) != size:
        raise Malformed(f"expected {size} bytes")
    return value


def parse(wire: str, profile: dict[str, Any]) -> dict[str, Any]:
    """One receipt: shape, signature under its embedded key, then payload members."""
    try:
        raw = bytes.fromhex(wire)
    except ValueError as exc:
        raise Malformed("not hex") from exc
    outer, names, fields = decode(raw), profile["outer"], profile["fields"]
    if not isinstance(outer, dict) or set(outer) != {names[m] for m in OUTER}:
        raise Malformed("outer receipt is not the profile's four-member map")
    version, payload = outer[names["version"]], outer[names["payload"]]
    if isinstance(version, bool) or not isinstance(version, int) or not 0 <= version < 256:
        raise Malformed("version is not a byte")
    if not isinstance(payload, bytes):
        raise Malformed("payload is not a byte string")
    key = _bytes(outer[names["signer_key"]], profile["key_form"], 32)
    sig = _bytes(outer[names["signature"]], profile["key_form"], 64)
    message = bytes.fromhex(profile["signature_context_hex"]) + bytes([version]) + payload
    if not _rail().ed25519_verify(key, message, sig):
        raise ValueError("signature does not verify")
    body = decode(payload)
    if not isinstance(body, dict) or body.get(fields["version"]) != version:
        raise Malformed("payload is not a map carrying the receipt's version")
    prev = body.get(fields["prev_hash"])
    if prev is not None and (not isinstance(prev, bytes) or len(prev) != 32):
        raise Malformed("predecessor hash is not 32 bytes")
    return {"signer": key.hex(), "digest": hashlib.sha256(raw).hexdigest(),
            "prev": None if prev is None else prev.hex(),
            **{role: body.get(num) for role, num in fields.items()
               if role not in ("version", "prev_hash")}}


def judge_stream(lines: list[str], case: dict[str, Any], profile: dict[str, Any],
                 skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference decision and reason for one stream against the consumer's inputs."""

    def fail(check: str) -> dict[str, str]:
        return {"decision": CONTRADICTED, "reason": check}

    parsed: list[dict[str, Any]] = []
    for wire in lines:
        try:
            parsed.append(parse(wire, profile))
        except Malformed:
            if "receipt_shape" not in skip:
                return fail("receipt_shape")
        except ValueError:
            if "signature" not in skip:
                return fail("signature")
    if not parsed:
        return fail("receipt_shape")
    pinned = {k.lower() for k in case["signer_keys"]}
    if "signer_pinned" not in skip and any(p["signer"] not in pinned for p in parsed):
        return fail("signer_pinned")
    digests = [p["digest"] for p in parsed]
    if "no_duplicate_receipt" not in skip and len(set(digests)) != len(digests):
        return fail("no_duplicate_receipt")
    seen: set[tuple[Any, Any]] = set()
    for p in parsed:
        if "proof" in p and p.get("outcome") == profile["allow_outcome"] and p["proof"] is not None:
            token = (p.get("request_hash"), p["proof"])
            if "single_use" not in skip and token in seen:
                return fail("single_use")
            seen.add(token)
    resets = False
    for i, p in enumerate(parsed):
        if "chain_order" in skip:
            break
        if i == 0 and p["prev"] != case.get("first_prev"):
            return fail("chain_order")
        if i > 0 and p["prev"] is None:
            resets = True
        elif i > 0 and p["prev"] != digests[i - 1]:
            return fail("chain_order")
    head = case.get("head")
    if "head_anchor" not in skip and head is not None and (
            digests[-1] != head or len(parsed) != case["count"]):
        return fail("head_anchor")
    if resets:
        return {"decision": NOT_ESTABLISHED, "reason": "chain_reset"}
    if head is None:
        return {"decision": NOT_ESTABLISHED, "reason": "head_not_anchored"}
    if case.get("require_effect") and "effect" not in profile["fields"]:
        return {"decision": NOT_ESTABLISHED, "reason": "effect_not_recorded"}
    return {"decision": SUPPORTED, "reason": "receipt_chain_holds"}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one case file."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    profile = json.loads((case_path.parent / case["profile"]).read_text(encoding="utf-8"))
    lines = [x.strip() for x in (case_path.parent / case["chain"]).read_text("ascii").splitlines()
             if x.strip()]
    return judge_stream(lines, case, profile, skip)


def external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    """Run one external verifier on one case and read its decision, which its exit code must repeat."""
    try:
        result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(verifier: str | list[str] | None = None, root: Path = ROOT,
          skip: frozenset[str] = frozenset()) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
        pinned = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))["profile"]["sha256"]
        profile_ok = hashlib.sha256((root / "profile.json").read_bytes()).hexdigest() == pinned
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    if not profile_ok:
        return 0, ["profile digest mismatch"]
    command = verifier.split() if isinstance(verifier, str) else verifier
    errors, answered = [], 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        problem = _fixture_error(directory, entry)
        if problem:
            errors.append(f"{name}: {problem}")
            continue
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory / "case.json", skip)
        else:
            ran, observed = external_answer(command, directory / "case.json")
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    return cli(argv, __doc__, verify, check, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
