#!/usr/bin/env python3
"""ACS-Core wire probes: one reproduction per Guardian obligation.

Drives a running ACS v0.1.0 Guardian over HTTP and checks what a host adapter
can see on the wire: request signatures (Specification section 10), replay and
timestamp windows (10.3), the published chain head under a response signature
(8.6), system/ping (13), handshake negotiation and its enforcement (4), the
six-hook minimum and wrapped MCP (conformance.md), and the reason code for a
tool the deployment does not govern.

The probe ids D1 to D10 follow the defect table of
GenAI-Security-Project/agent-control-standard issue 184.

Standard library only. It imports nothing from any Guardian implementation;
envelopes are built from specification/v0.1.0/*.json.

Key derivation: section 10 says the per-session HMAC key is HKDF-derived from
deployment input keying material "together with the session_id" and does not
fix the HKDF salt or info. The defaults (empty salt, info = session_id,
key_id = session_id) match the AGT reference Guardian; --hkdf-salt and
--key-id-mode cover other readings.

  ACS_HMAC_SECRET=$(head -c 32 /dev/urandom | base64) bun run guardian &
  python3 acs_wire_probes.py --guardian http://127.0.0.1:8787/acs \\
      --ikm-b64 "$ACS_HMAC_SECRET" --out run

Replay across a restart (D2c) takes two invocations around the restart:
  ... --replay-save run/replay.json      (before stopping the Guardian)
  ... --replay-send run/replay.json      (after starting it again)

With --expect FILE the exit status compares each probe's status with the
recorded one, so CI stays green while a known gap is open and goes red the
moment behaviour changes in either direction. Without it: 0 when every MUST
probe passes, 1 when one fails. Either way, 2 when the Guardian is unreachable.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib import error, request

ACS_VERSION = "0.1.0"
AGENT_ID = "acs-wire-probes"
Json = dict[str, Any]
BASH_LS: Json = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}},
                 "raw_command": "ls"}
BASH_RM: Json = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}},
                 "raw_command": "rm -rf /"}
ALL_METHODS = ["steps/toolCallRequest", "steps/toolCallResult", "steps/sessionStart",
               "steps/userMessage", "steps/agentResponse", "steps/sessionEnd",
               "protocols/MCP/tools/call", "system/ping"]


def jcs(obj: Any) -> bytes:
    """RFC 8785 for the value domain built here (no floats)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def now_iso(offset_s: float = 0.0) -> str:
    t = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=offset_s)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def new_sid() -> str:
    return str(uuid.uuid4())


class Probe:
    def __init__(self, guardian: str, ikm: bytes, salt: bytes, key_id_mode: str, out: Path):
        self.url = guardian
        self.ikm = ikm
        self.salt = salt
        self.key_id_mode = key_id_mode
        self.wire = out / "wire"
        self.wire.mkdir(parents=True, exist_ok=True)
        self.n = len(list(self.wire.iterdir()))
        self.rows: list[Json] = []

    def key(self, sid: str) -> bytes:
        return hkdf_sha256(self.ikm, self.salt, sid.encode())

    def envelope(self, method: str, sid: str, payload: Json, *, ts: str | None = None,
                 meta: Json | None = None) -> Json:
        rid = new_sid()
        m: Json = {"agent_id": AGENT_ID, "session_id": sid}
        m.update(meta or {})
        return {"jsonrpc": "2.0", "method": method, "id": rid,
                "params": {"acs_version": ACS_VERSION, "request_id": rid,
                           "timestamp": ts or now_iso(), "metadata": m, "payload": payload}}

    def sign(self, env: Json, *, corrupt: bool = False, drop: str | None = None) -> Json:
        """HMAC-SHA256 over JCS of the envelope without params.signature (section 10).
        corrupt inverts every MAC byte; drop leaves one params member out of the
        signed input so the signature covers a subset."""
        env = json.loads(json.dumps(env))
        env["params"].pop("signature", None)
        view = json.loads(json.dumps(env))
        if drop:
            view["params"].pop(drop, None)
        sid = env["params"]["metadata"]["session_id"]
        mac = hmac.new(self.key(sid), jcs(view), hashlib.sha256).digest()
        if corrupt:
            mac = bytes(b ^ 0xFF for b in mac)
        kid = sid if self.key_id_mode == "session_id" else "k1"
        env["params"]["signature"] = {"algorithm": "HMAC-SHA256",
                                      "value": base64.b64encode(mac).decode(), "key_id": kid}
        return env

    def hello(self, sid: str, *, versions: list[str] | None = None,
              methods: list[str] | None = None, profiles: list[str] | None = None) -> Json:
        payload = {"acs_versions_supported": versions or [ACS_VERSION],
                   "methods_implemented": methods or ALL_METHODS,
                   "transports_supported": ["http"], "provenance_producer": "none",
                   "profiles_supported": profiles or ["acs-core"]}
        return self.sign(self.envelope("handshake/hello", sid, payload))

    def post(self, name: str, env: Json) -> Json:
        self.n += 1
        rec: Json = {"request": env}
        req = request.Request(self.url, data=jcs(env), method="POST",
                              headers={"content-type": "application/json"})
        text: str | None = None
        try:
            with request.urlopen(req, timeout=15) as resp:
                text, rec["http_status"] = resp.read().decode(), resp.status
        except error.HTTPError as e:
            text, rec["http_status"] = e.read().decode(errors="replace"), e.code
        except OSError as e:
            rec["transport_error"] = repr(e)
        if text is not None:
            try:
                rec["response"] = json.loads(text)
            except json.JSONDecodeError:
                rec["response_text"] = text
        path = self.wire / f"{self.n:03d}-{name}.json"
        path.write_text(json.dumps(rec, indent=2))
        rec["_file"] = path.name
        return rec

    def response_signature_ok(self, rec: Json, sid: str) -> bool:
        resp = rec.get("response") or {}
        side = "result" if isinstance(resp.get("result"), dict) else "error"
        carrier = resp.get(side)
        if not isinstance(carrier, dict) or not isinstance(carrier.get("signature"), dict):
            return False
        view = json.loads(json.dumps(resp))
        value = view[side].pop("signature").get("value", "")
        mac = hmac.new(self.key(sid), jcs(view), hashlib.sha256).digest()
        try:
            return hmac.compare_digest(mac, base64.b64decode(value))
        except (ValueError, TypeError):
            return False

    def check(self, pid: str, probe: str, level: str, expected: str, rec: Json, ok: bool,
              observed: str) -> None:
        self.rows.append({"id": pid, "probe": probe, "level": level, "expected": expected,
                          "observed": observed, "status": "PASS" if ok else "FAIL",
                          "wire": rec.get("_file")})


def summary(rec: Json) -> Json:
    resp = rec.get("response") or {}
    res = resp.get("result") if isinstance(resp.get("result"), dict) else {}
    err = resp.get("error") if isinstance(resp.get("error"), dict) else {}
    return {"code": err.get("code"), "message": err.get("message"),
            "decision": res.get("decision"), "reason_codes": res.get("reason_codes") or [],
            "chain_hash": res.get("chain_hash"), "result": res,
            "transport_error": rec.get("transport_error")}


def describe(s: Json) -> str:
    if s["transport_error"]:
        return f"transport error {s['transport_error']}"
    if s["code"] is not None:
        return f"error {s['code']} {s['message']}"
    return f"decision={s['decision']} reason_codes={s['reason_codes']}"


def expect_code(p: Probe, pid: str, probe: str, level: str, code: int, rec: Json) -> None:
    s = summary(rec)
    p.check(pid, probe, level, f"error {code}", rec, s["code"] == code, describe(s))


def probe_control(p: Probe) -> bool:
    sid = new_sid()
    p.post("control-hello", p.hello(sid))
    rec = p.post("control-allow", p.sign(p.envelope("steps/toolCallRequest", sid, BASH_LS)))
    s = summary(rec)
    p.check("C0", "signed fresh Bash ls after handshake", "control", "decision allow", rec,
            s["decision"] == "allow", describe(s))
    return not s["transport_error"]


def probe_d1(p: Probe) -> None:
    sid = new_sid()
    p.post("D1-hello", p.hello(sid))
    step = p.envelope("steps/toolCallRequest", sid, BASH_LS)
    expect_code(p, "D1a", "request with no signature", "MUST", -32004, p.post("D1a", step))
    step = p.envelope("steps/toolCallRequest", sid, BASH_LS)
    expect_code(p, "D1b", "HMAC with every byte inverted", "MUST", -32004,
                p.post("D1b", p.sign(step, corrupt=True)))
    step = p.envelope("steps/toolCallRequest", sid, BASH_LS)
    expect_code(p, "D1c", "signature that does not cover params.payload", "MUST", -32004,
                p.post("D1c", p.sign(step, drop="payload")))


def probe_d2(p: Probe) -> None:
    sid = new_sid()
    p.post("D2-hello", p.hello(sid))
    env = p.sign(p.envelope("steps/toolCallRequest", sid, BASH_LS))
    p.post("D2a-first", env)
    expect_code(p, "D2a", "same request_id twice in one session", "MUST", -32005,
                p.post("D2a-replay", env))
    nonce = base64.b64encode(os.urandom(16)).decode()
    rec: Json = {}
    for i in (1, 2):
        step = p.envelope("steps/toolCallRequest", sid, BASH_LS)
        step["params"]["nonce"] = nonce
        rec = p.post(f"D2b-nonce{i}", p.sign(step))
    expect_code(p, "D2b", "same nonce under a fresh request_id", "SHOULD", -32005, rec)


def probe_d3(p: Probe) -> None:
    sid = new_sid()
    hello = p.post("D3-hello", p.hello(sid))
    sh = summary(hello)["result"]
    p.check("D3a", "ServerHello declares skew_window_ms", "MUST", "skew_window_ms present",
            hello, "skew_window_ms" in sh, f"ServerHello keys={sorted(sh)}")
    for pid, off in (("D3b", -3600), ("D3c", 3600)):
        step = p.envelope("steps/toolCallRequest", sid, BASH_LS, ts=now_iso(off))
        expect_code(p, pid, f"timestamp {off:+d} s", "MUST", -32006, p.post(pid, p.sign(step)))


def probe_d4(p: Probe) -> None:
    sid = new_sid()
    p.post("D4-hello", p.hello(sid))
    rec = p.post("D4a", p.sign(p.envelope("steps/toolCallRequest", sid, BASH_LS)))
    first = summary(rec)["chain_hash"]
    sig = p.response_signature_ok(rec, sid)
    ok = isinstance(first, str) and len(first) == 64 and sig
    p.check("D4a", "allow carries chain_hash under a verifying response signature", "MUST",
            "64-hex chain_hash, signature verifies", rec, ok,
            f"chain_hash={'present' if first else 'absent'} signature_verifies={sig}")
    rec = p.post("D4b", p.sign(p.envelope("steps/toolCallRequest", sid, BASH_RM)))
    s = summary(rec)
    advanced = s["chain_hash"] not in (None, first)
    sig = p.response_signature_ok(rec, sid)
    p.check("D4b", "deny advances chain_hash under a verifying response signature", "MUST",
            "chain head advances, signature verifies", rec, advanced and sig,
            f"decision={s['decision']} chain_advanced={advanced} signature_verifies={sig}")
    meta = {"session_state": {"chain_hash": "f" * 64}}
    rec = p.post("D4c", p.sign(p.envelope("steps/toolCallRequest", sid, BASH_LS, meta=meta)))
    s = summary(rec)
    p.check("D4c", "client chain_hash that cannot match", "MAY",
            "deny chain_mismatch or error -32007", rec,
            s["code"] == -32007 or "chain_mismatch" in s["reason_codes"], describe(s))


def probe_d5(p: Probe) -> None:
    rec = p.post("D5", p.envelope("system/ping", new_sid(), {"echo": "probe"}))
    s = summary(rec)
    p.check("D5", "system/ping", "MUST", "decision allow, no ACS error", rec,
            s["decision"] == "allow" and s["code"] is None, describe(s))


def probe_d6(p: Probe) -> None:
    expect_code(p, "D6a", "ClientHello offering only 9.9.9", "MUST", -32001,
                p.post("D6a", p.hello(new_sid(), versions=["9.9.9"])))
    rec = p.post("D6b", p.hello(new_sid(), profiles=["acs-core", "acs-audit"]))
    got = summary(rec)["result"].get("profiles_accepted")
    p.check("D6b", "ServerHello profiles_accepted", "MUST", "profiles_accepted == [acs-core]",
            rec, got == ["acs-core"], f"profiles_accepted={got}")
    sid = new_sid()
    p.post("D6c-hello", p.hello(sid, methods=["steps/toolCallRequest"]))
    step = p.envelope("protocols/MCP/tools/call", sid, BASH_LS)
    expect_code(p, "D6c", "method outside the negotiated methods_implemented", "MUST", -32003,
                p.post("D6c", p.sign(step)))
    rec = p.post("D6d", p.sign(p.envelope("steps/toolCallRequest", new_sid(), BASH_LS)))
    s = summary(rec)
    p.check("D6d", "step in a session that never sent handshake/hello", "MUST",
            "an error, not a decision", rec, s["code"] is not None, describe(s))


def probe_d7(p: Probe) -> None:
    sid = new_sid()
    p.post("D7-hello", p.hello(sid))
    hooks: list[tuple[str, Json]] = [
        ("sessionStart", {"policy_mode": "strict"}),
        ("userMessage", {"content": [{"type": "text", "value": "hello"}]}),
        ("agentResponse", {"content": [{"type": "text", "value": "hi"}]}),
        ("sessionEnd", {"reason": "completed"}),
    ]
    for hook, payload in hooks:
        rec = p.post(f"D7-{hook}", p.sign(p.envelope(f"steps/{hook}", sid, payload)))
        s = summary(rec)
        ok = s["decision"] is not None and "envelope_invalid" not in s["reason_codes"]
        p.check(f"D7-{hook}", f"steps/{hook} with a schema-valid payload", "MUST",
                "a decision", rec, ok, describe(s))


def probe_d8(p: Probe) -> None:
    sid = new_sid()
    p.post("D8-hello", p.hello(sid))
    rec = p.post("D8", p.sign(p.envelope("protocols/MCP/tools/call", sid, BASH_RM)))
    s = summary(rec)
    p.check("D8", "protocols/MCP/tools/call reaches policy", "MUST",
            "decision deny for rm -rf /", rec, s["decision"] == "deny", describe(s))


def probe_d10(p: Probe) -> None:
    sid = new_sid()
    p.post("D10-hello", p.hello(sid))
    payload: Json = {"tool": {"name": "records.lookup"}, "arguments": {"id": {"value": "1"}}}
    rec = p.post("D10", p.sign(p.envelope("steps/toolCallRequest", sid, payload)))
    s = summary(rec)
    p.check("D10", "tool the deployment does not govern", "low", "deny tool_unregistered", rec,
            s["decision"] == "deny" and "tool_unregistered" in s["reason_codes"], describe(s))


def replay_save(p: Probe, path: Path) -> None:
    sid = new_sid()
    p.post("D2c-hello", p.hello(sid))
    env = p.sign(p.envelope("steps/toolCallRequest", sid, BASH_LS))
    rec = p.post("D2c-first", env)
    path.write_text(json.dumps(env))
    s = summary(rec)
    p.check("D2c-save", "request accepted before the restart", "control", "decision allow",
            rec, s["decision"] == "allow", describe(s))


def replay_send(p: Probe, path: Path) -> None:
    expect_code(p, "D2c", "same request bytes after a Guardian restart", "MUST", -32005,
                p.post("D2c-after-restart", json.loads(path.read_text())))


def exit_status(rows: list[Json], expect: Path | None) -> int:
    if any(r["observed"].startswith("transport error") for r in rows):
        return 2
    if expect is None:
        return 1 if any(r["status"] == "FAIL" and r["level"] in ("MUST", "control")
                        for r in rows) else 0
    want: dict[str, str] = json.loads(expect.read_text())["status"]
    drift = [(r["id"], want.get(r["id"]), r["status"]) for r in rows
             if want.get(r["id"]) != r["status"]]
    for pid, was, now in drift:
        print(f"DRIFT {pid}: expected {was}, observed {now}", file=sys.stderr)
    return 1 if drift else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--guardian", required=True, help="e.g. http://127.0.0.1:8787/acs")
    ap.add_argument("--ikm-b64", required=True, help="deployment HMAC keying material, base64")
    ap.add_argument("--hkdf-salt", default="", help="HKDF salt as text (default: empty)")
    ap.add_argument("--key-id-mode", choices=["session_id", "static"], default="session_id")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--expect", type=Path, help="JSON {status: {probe id: PASS|FAIL}}")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--replay-save", type=Path, help="D2c, part one: send and save a request")
    mode.add_argument("--replay-send", type=Path, help="D2c, part two: resend after a restart")
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    p = Probe(a.guardian, base64.b64decode(a.ikm_b64), a.hkdf_salt.encode(), a.key_id_mode,
              a.out)
    if a.replay_save:
        replay_save(p, a.replay_save)
    elif a.replay_send:
        replay_send(p, a.replay_send)
    elif probe_control(p):
        for fn in (probe_d1, probe_d2, probe_d3, probe_d4, probe_d5, probe_d6, probe_d7,
                   probe_d8, probe_d10):
            fn(p)
    name = "results-replay-save" if a.replay_save else (
        "results-replay-send" if a.replay_send else "results")
    (a.out / f"{name}.json").write_text(json.dumps(p.rows, indent=2))
    print("| id | probe | level | expected | observed | status |")
    print("|---|---|---|---|---|---|")
    for r in p.rows:
        print(f"| {r['id']} | {r['probe']} | {r['level']} | {r['expected']} | "
              f"{r['observed']} | {r['status']} |")
    return exit_status(p.rows, a.expect)


if __name__ == "__main__":
    sys.exit(main())
