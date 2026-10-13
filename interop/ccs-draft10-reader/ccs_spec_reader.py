"""A CCS receipt reader written from draft-correctover-ccs-10, not from any CCS checker.

Every check cites the section of draft-correctover-ccs-10 it comes from. Where the
draft says nothing a corpus case depends on, the check reports SILENT rather than
guessing. Where a check needs a reading the draft does not state (the signed field
set beyond fields 1-21, the encoding of the embedded key), the reading is named in
the result so a reader can see exactly which sentence the draft would need.

Canonical bytes come from agent-evidence-vectors (agent_evidence_vectors.a2ajcs,
RFC 8785). When JCS_ADMIT is set to a jcs-admit check binary, every canonical
byte string is also produced by jcs-admit and the two must agree byte for byte.

Usage: python ccs_spec_reader.py <corpus-dir> <out-dir>
Writes cases.jsonl (one line per case, every check kept), summary.json and
controls.json. Exit 0 when the run completed, whatever the verdicts are; exit 2
when the run itself could not complete.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from agent_evidence_vectors.a2ajcs import Refusal, canonicalize, parse
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PASS, FAIL, SILENT = "PASS", "FAIL", "SILENT"

# draft-10 section 4.1 and section 16: fields 1-22 in table order.
FIELDS_1_21 = [
    "trace_id",
    "verdict",
    "timestamp",
    "tool",
    "params_hash",
    "rule_summary",
    "receipt",
    "verified_at",
    "block_reason",
    "request_hash",
    "config_hash",
    "response_hash",
    "runtime_context_hash",
    "action",
    "issuer",
    "audience",
    "nonce",
    "sequence",
    "issued_at",
    "expires_at",
    "max_clock_skew",
]
# section 4.1, Required = MUST.
REQUIRED = [
    "trace_id",
    "verdict",
    "timestamp",
    "tool",
    "params_hash",
    "rule_summary",
    "receipt",
    "verified_at",
    "request_hash",
    "action",
    "config_hash",
    "issuer",
    "audience",
    "nonce",
    "issued_at",
    "expires_at",
    "signature",
]
# section 7.2 item 3 (new in draft-10): these MUST be covered by the signature.
KEY_FIELDS = ["public_key", "public_key_fingerprint", "signing_algorithm"]
NUMBERS = ["timestamp", "verified_at", "issued_at", "expires_at", "max_clock_skew"]
HEX = re.compile(r"[0-9a-f]+")
URI = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:.+")

JCS_ADMIT = os.environ.get("JCS_ADMIT")


def jcs(value: Any) -> bytes:
    out = canonicalize(value)
    if JCS_ADMIT:
        second = subprocess.run(
            [JCS_ADMIT], input=json.dumps(value).encode(), capture_output=True, check=False
        )
        if second.returncode != 0 or second.stdout != out:
            raise RuntimeError(
                f"canonicalizers disagree: aev={out[:80]!r} "
                f"jcs-admit rc={second.returncode} {second.stdout[:80]!r}"
            )
    return out


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(name: str, section: str, result: str, detail: str = "") -> dict[str, str]:
    return {"check": name, "section": section, "result": result, "detail": detail}


def decode_sig(text: Any, hex_only: bool) -> bytes | None:
    if not isinstance(text, str):
        return None
    if re.fullmatch(r"[0-9a-f]{128}", text):
        return bytes.fromhex(text)
    if hex_only:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 64 else None


def decode_key(text: Any) -> bytes | None:
    # The draft never states the encoding of the embedded key (section 7.2). Base64 is
    # what the corpus carries; the reader records that it inferred it.
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def verify(key: bytes | None, sig: bytes | None, msg: bytes) -> bool:
    if key is None or sig is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, msg)
    except (InvalidSignature, ValueError):
        return False
    return True


SIGNED_SETS = {
    # section 4.2 step 1, literally: fields 1-21, signature as 128 lowercase hex (step 4).
    "sig-4.2-literal": (lambda r: {k: r[k] for k in FIELDS_1_21 if k in r}, True),
    # section 4.2 plus section 7.2 item 3, signature in whatever encoding the record uses.
    "sig-4.2+7.2": (lambda r: {k: r[k] for k in FIELDS_1_21 + KEY_FIELDS if k in r}, False),
    # Not stated by draft-10: every member except the signature.
    "sig-all-but-signature": (lambda r: {k: v for k, v in r.items() if k != "signature"}, False),
}


def signature_checks(r: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, bytes]]:
    out, signed = [], {}
    key = decode_key(r.get("public_key"))
    for name, (select, hex_only) in SIGNED_SETS.items():
        body = jcs(select(r))
        signed[name] = body
        sig = decode_sig(r.get("signature"), hex_only)
        if sig is None:
            out.append(check(name, "4.2/7.2", FAIL, "signature not decodable under this reading"))
        else:
            out.append(
                check(
                    name,
                    "4.2/7.2",
                    PASS if verify(key, sig, body) else FAIL,
                    f"{len(select(r))} members signed",
                )
            )
    return out, signed


def structure_checks(r: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    missing = [k for k in REQUIRED if k not in r]
    out.append(check("required-fields", "4.1", FAIL if missing else PASS, ",".join(missing)))
    # The same list without field 7 (the HMAC receipt), which section 4.2 confines to Level 0.
    missing_b = [k for k in missing if k != "receipt"]
    out.append(
        check(
            "required-fields-b",
            "4.1 less field 7",
            FAIL if missing_b else PASS,
            ",".join(missing_b),
        )
    )
    extra = sorted(set(r) - set(FIELDS_1_21) - {"signature"} - set(KEY_FIELDS))
    out.append(check("fields-outside-draft", "4.1/16", SILENT if extra else PASS, ",".join(extra)))
    t = r.get("trace_id")
    out.append(
        check(
            "trace_id-16-hex",
            "4.1/16",
            PASS if isinstance(t, str) and re.fullmatch(r"[0-9a-f]{16}", t) else FAIL,
            repr(t)[:40],
        )
    )
    v = r.get("verdict")
    out.append(
        check(
            "verdict-enum", "4.1/4.5", PASS if v in ("allow", "deny", "escalate") else FAIL, repr(v)
        )
    )
    p = r.get("params_hash")
    out.append(
        check(
            "params_hash-hex",
            "4.1/6.5",
            PASS if isinstance(p, str) and re.fullmatch(r"[0-9a-f]{16}|[0-9a-f]{64}", p) else FAIL,
            repr(p)[:30],
        )
    )
    for k in ("issuer", "audience"):
        x = r.get(k)
        out.append(
            check(
                f"{k}-uri",
                "6.6/6.7",
                PASS if isinstance(x, str) and URI.fullmatch(x) else FAIL,
                repr(x),
            )
        )
    n = r.get("nonce")
    out.append(
        check(
            "nonce-hex",
            "4.1/6.8",
            PASS if isinstance(n, str) and HEX.fullmatch(n) else FAIL,
            repr(n),
        )
    )
    if "nonce" in r:
        out.append(
            check("nonce-nonempty", "6.8", PASS if isinstance(n, str) and n else FAIL, repr(n))
        )
    s = r.get("sequence")
    if "sequence" in r:
        ok = isinstance(s, int) and not isinstance(s, bool) and s >= 0
        out.append(check("sequence-integer", "4.1", PASS if ok else FAIL, repr(s)))
    bad = [
        k
        for k in NUMBERS
        if k in r and (isinstance(r[k], bool) or not isinstance(r[k], (int, float)))
    ]
    out.append(check("numeric-fields", "4.1", FAIL if bad else PASS, ",".join(bad)))
    sig = r.get("signature")
    out.append(
        check(
            "signature-128-hex",
            "4.2 step 4",
            PASS if isinstance(sig, str) and re.fullmatch(r"[0-9a-f]{128}", sig) else FAIL,
            (sig or "")[:12] if isinstance(sig, str) else repr(sig),
        )
    )
    alg = r.get("signing_algorithm")
    if "signing_algorithm" in r:
        out.append(
            check(
                "signing_algorithm-ed25519",
                "4.2/7.1",
                PASS if alg == "Ed25519" else FAIL,
                repr(alg),
            )
        )
    return out


def prefixed(declared: Any, digest: str) -> str:
    if declared == "sha256:" + digest:
        return PASS
    return FAIL


def binding_checks(r: dict[str, Any], d: Path, idx: str) -> list[dict[str, str]]:
    out = []
    body = d / f"response-body{idx}.json"
    if body.exists() and "response_hash" in r:
        dig = sha(jcs(parse(body.read_text())))
        bare = r["response_hash"] == dig
        out.append(
            check(
                "response_hash-6.2",
                "6.2",
                prefixed(r["response_hash"], dig),
                "bare hex matches, draft requires sha256: prefix"
                if bare
                else "no match with or without prefix",
            )
        )
        out.append(
            check(
                "response_hash-value",
                "6.2 (prefix ignored)",
                PASS if bare or r["response_hash"] == "sha256:" + dig else FAIL,
                "",
            )
        )
    if r.get("verdict") == "deny" or r.get("verdict") == "block":
        empty = r.get("response_hash", "") == ""
        out.append(
            check(
                "deny-response_hash-empty",
                "4.2 lifecycle",
                PASS if empty else FAIL,
                f"verdict={r.get('verdict')}",
            )
        )
    args = d / f"tool-args{idx}.json"
    if args.exists() and "params_hash" in r:
        params = json.loads(args.read_text())
        # section 6.5's own code: json.dumps(sort_keys, compact), default ensure_ascii.
        full = sha(json.dumps(params, sort_keys=True, separators=(",", ":")).encode())
        p = r["params_hash"]
        out.append(
            check(
                "params_hash-6.5",
                "6.5",
                PASS if p in (full, full[:16]) else FAIL,
                "full" if p == full else ("16" if p == full[:16] else "none"),
            )
        )
        if "action" in r and "tool" in r:
            want = f"ccs:tool-invoke:{r['tool']}:{full}"
            out.append(
                check("action-6.4", "6.4", PASS if r["action"] == want else FAIL, repr(r["action"]))
            )
    rc = d / f"runtime-context{idx}.json"
    if rc.exists() and "runtime_context_hash" in r:
        ctx = json.loads(rc.read_text())
        dig = sha(json.dumps(ctx, sort_keys=True, separators=(",", ":")).encode())
        out.append(
            check(
                "runtime_context_hash-6.3",
                "6.3",
                prefixed(r["runtime_context_hash"], dig),
                "bare hex matches" if r["runtime_context_hash"] == dig else "no match",
            )
        )
    if "request_hash" in r:
        out.append(
            check(
                "request_hash-6.1",
                "6.1",
                SILENT,
                "no Command (agent_id, tool, params, timestamp, trace_id) is carried",
            )
        )
    if "config_hash" in r:
        out.append(
            check(
                "config_hash-5.3",
                "5.1/5.3",
                SILENT,
                "no canonical config with the 5.1 MUST members is carried",
            )
        )
    key = decode_key(r.get("public_key"))
    if key is not None and "public_key_fingerprint" in r:
        f = r["public_key_fingerprint"]
        full = sha(key)
        out.append(
            check(
                "fingerprint-7.2",
                "7.2 item 2",
                PASS if f == full else FAIL,
                "first 8 bytes" if f == full[:16] else ("full" if f == full else "none"),
            )
        )
    return out


def freshness_checks(r: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    try:
        ia, ea = float(r["issued_at"]), float(r["expires_at"])
        skew = float(r.get("max_clock_skew") or 30.0)
        now = float(r["verified_at"])
    except (KeyError, TypeError, ValueError):
        return [check("freshness-6.9", "6.9", SILENT, "a time field is missing or not a number")]
    # The corpus pins no evaluation time; verified_at is used as local_time, and that
    # choice is the reader's.
    ok = (ia - skew) <= now <= (ea + skew)
    out.append(
        check(
            "freshness-6.9-at-verified_at",
            "6.9/12.2",
            PASS if ok else FAIL,
            f"issued={ia} expires={ea} at={now} skew={skew}",
        )
    )
    return out


def receipt_checks(
    r: dict[str, Any], d: Path, idx: str
) -> tuple[list[dict[str, str]], dict[str, bytes]]:
    if "receipt_type" in r:
        sigs, signed = signature_checks(r)
        return sigs + [
            check("receipt-type", "none", SILENT, f"{r['receipt_type']} is not defined by draft-10")
        ], signed
    sigs, signed = signature_checks(r)
    return sigs + structure_checks(r) + binding_checks(r, d, idx) + freshness_checks(r), signed


def chain_checks(receipts: list[dict[str, Any]], d: Path) -> list[dict[str, str]]:
    out = []
    seqs: list[Any] = [r.get("sequence") for r in receipts]
    if all(isinstance(s, int) for s in seqs):
        inc = all(b > a for a, b in zip(seqs, seqs[1:], strict=False))
        out.append(check("sequence-monotonic", "6.8", PASS if inc else FAIL, repr(seqs)))
    nonces = [(r.get("issuer"), r.get("nonce")) for r in receipts]
    out.append(
        check(
            "nonce-replay", "6.8/12.2 step 4", FAIL if len(set(nonces)) < len(nonces) else PASS, ""
        )
    )
    chain = d / "chain.json"
    if chain.exists():
        out.append(
            check(
                "previous-receipt-hash",
                "11.2/11.5",
                SILENT,
                "draft names previous_receipt_hash but not the bytes it is computed over",
            )
        )
    if len(receipts) == 1 and chain.exists():
        declared = json.loads(chain.read_text())
        if declared.get("expects_predecessor"):
            out.append(
                check(
                    "zero-hop",
                    "11.1.1",
                    SILENT,
                    "chain.json declares expects_predecessor, a member draft-10 does not define",
                )
            )
        else:
            out.append(
                check("zero-hop", "11.1.1", PASS, "a single receipt is a valid zero-hop chain")
            )
    return out


def load_receipts(d: Path) -> list[tuple[str, dict[str, Any]]]:
    if (d / "receipt.json").exists():
        return [("", parse((d / "receipt.json").read_text()))]
    if (d / "receipt-tampered.json").exists():
        return [("", parse((d / "receipt-tampered.json").read_text()))]
    out = []
    for i in range(1, 10):
        p = d / f"receipt-{i}.json"
        if p.exists():
            out.append((f"-{i}", parse(p.read_text())))
    return out


def judge(checks: list[dict[str, str]], decisive: set[str] | None) -> tuple[str, list[str]]:
    grounds = [
        c["check"]
        for c in checks
        if c["result"] == FAIL and (decisive is None or c["check"] in decisive)
    ]
    return ("invalid" if grounds else "valid"), grounds


# Reading A: everything draft-10 states, literally. Reading B: VERIFIED as section 7.2 defines it
# (signature over every signed field against the embedded key), plus only the semantic rules the
# draft states that a corpus case can be tested on, with the signed set the draft does not state.
READING_B = {
    "sig-all-but-signature",
    "deny-response_hash-empty",
    "response_hash-value",
    "freshness-6.9-at-verified_at",
    "sequence-monotonic",
    "nonce-replay",
    "numeric-fields",
    "sequence-integer",
    "signing_algorithm-ed25519",
    "verdict-enum-b",
    "required-fields-b",
    "nonce-nonempty",
}
# Reading A keeps only the literal checks: the two signed-set readings the draft does not state,
# the prefix-tolerant hash comparison, the block-as-deny enum and the byte comparison are left out.
NOT_READING_A = {
    "sig-4.2+7.2",
    "sig-all-but-signature",
    "response_hash-value",
    "verdict-enum-b",
    "our-bytes-equal-corpus-signing-input",
    "required-fields-b",
}


def run_case(d: Path, root: Path) -> dict[str, Any]:
    expected = json.loads((d / "expected.json").read_text())
    rec = load_receipts(d)
    checks: list[dict[str, str]] = []
    signed_bytes: dict[str, str] = {}
    for idx, r in rec:
        cs, signed = receipt_checks(r, d, idx)
        for c in cs:
            c["receipt"] = idx or "receipt"
        checks += cs
        corpus_input = d / (
            f"signing-input{idx}.jcs"
            if (d / f"signing-input{idx}.jcs").exists()
            else "signing-input-tampered.jcs"
        )
        if corpus_input.exists():
            same = corpus_input.read_bytes() == signed["sig-all-but-signature"]
            checks.append(
                check(
                    "our-bytes-equal-corpus-signing-input",
                    "none",
                    PASS if same else FAIL,
                    corpus_input.name,
                )
                | {"receipt": idx or "receipt"}
            )
        signed_bytes[idx or "receipt"] = sha(signed["sig-all-but-signature"])
        v = r.get("verdict")
        if "receipt_type" not in r:
            checks.append(
                check(
                    "verdict-enum-b",
                    "4.1/4.5",
                    PASS if v in ("allow", "deny", "escalate", "block") else FAIL,
                    "block counted as deny",
                )
                | {"receipt": idx or "receipt"}
            )
    if len(rec) > 1 or (d / "chain.json").exists():
        checks += [c | {"receipt": "chain"} for c in chain_checks([r for _, r in rec], d)]
    a, ga = judge([c for c in checks if c["check"] not in NOT_READING_A], None)
    b, gb = judge(checks, READING_B)
    exp = expected.get("verdict")
    silent = sorted({c["check"] for c in checks if c["result"] == SILENT})
    return {
        "case": str(d.relative_to(root)),
        "expected": exp,
        "expected_reason": expected.get("reason", ""),
        "reading_a": a,
        "reading_a_grounds": ga,
        "reading_b": b,
        "reading_b_grounds": gb,
        "silent": silent,
        "signed_sha256": signed_bytes,
        "checks": checks,
    }


def controls(root: Path) -> dict[str, Any]:
    """Mutation controls on 01-allow: each must flip reading B to invalid."""
    d = root / "01-allow"
    base = parse((d / "receipt.json").read_text())
    out = {}
    muts = {
        "signature-byte-flipped": lambda r: r.__setitem__(
            "signature",
            base64.b64encode(
                bytes([base64.b64decode(r["signature"])[0] ^ 1])
                + base64.b64decode(r["signature"])[1:]
            ).decode(),
        ),
        "signed-field-changed-verified_at": lambda r: r.__setitem__(
            "verified_at", r["verified_at"] + 1
        ),
        "embedded-key-substituted": lambda r: r.__setitem__(
            "public_key", base64.b64encode(bytes(32)).decode()
        ),
        "unsigned-member-added": lambda r: r.__setitem__("x_extra", 1),
    }
    for name, fn in muts.items():
        r = copy.deepcopy(base)
        fn(r)
        cs, _ = receipt_checks(r, d, "")
        verdict, grounds = judge(cs, READING_B)
        out[name] = {"reading_b": verdict, "grounds": grounds, "refused": verdict == "invalid"}
    return out


def relaxed(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Criterion 11 pairing: each invalid-expected case with the signature check relaxed."""
    out = []
    for c in cases:
        if c["expected"] != "invalid":
            continue
        others = [g for g in c["reading_b_grounds"] if g != "sig-all-but-signature"]
        out.append(
            {
                "case": c["case"],
                "baseline": c["reading_b"],
                "baseline_grounds": c["reading_b_grounds"],
                "signature_relaxed": "invalid" if others else "valid",
                "relaxed_grounds": others,
            }
        )
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    root, out = Path(argv[1]), Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((root / "manifest.json").read_text())
    dirs = sorted({(root / f).parent for f in manifest["files"] if f.endswith("expected.json")})
    on_disk = sorted(p.parent for p in root.rglob("expected.json"))
    cases = [run_case(d, root) for d in dirs]
    with (out / "cases.jsonl").open("w") as fh:
        for c in cases:
            fh.write(json.dumps(c, sort_keys=True) + "\n")
    tally: dict[str, dict[str, int]] = {}
    for c in cases:
        for c2 in c["checks"]:
            t = tally.setdefault(c2["check"], {PASS: 0, FAIL: 0, SILENT: 0})
            t[c2["result"]] += 1
    summary = {
        "manifest_cases": len(dirs),
        "on_disk_cases": len(on_disk),
        "manifest_equals_disk": [str(p) for p in dirs] == [str(p) for p in on_disk],
        "reading_a_matches_expected": sum(c["reading_a"] == c["expected"] for c in cases),
        "reading_b_matches_expected": sum(c["reading_b"] == c["expected"] for c in cases),
        "reading_b_disagreements": [
            {
                "case": c["case"],
                "expected": c["expected"],
                "reader": c["reading_b"],
                "grounds": c["reading_b_grounds"],
                "expected_reason": c["expected_reason"],
            }
            for c in cases
            if c["reading_b"] != c["expected"]
        ],
        "check_tally": tally,
        "jcs_admit_cross_check": bool(JCS_ADMIT),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "controls.json").write_text(
        json.dumps(
            {"mutations": controls(root), "relaxed_signature": relaxed(cases)},
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                k: summary[k]
                for k in (
                    "manifest_cases",
                    "on_disk_cases",
                    "manifest_equals_disk",
                    "reading_a_matches_expected",
                    "reading_b_matches_expected",
                )
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except (OSError, Refusal, RuntimeError, KeyError) as exc:
        print(f"RUN DID NOT COMPLETE: {exc!r}", file=sys.stderr)
        sys.exit(2)
