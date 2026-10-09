#!/usr/bin/env python3
"""Run the JCS byte corpus through an MCP SDK's own JSON-RPC codec.

Every harness under this directory speaks one line protocol. It reads
newline-delimited JSON-RPC messages on stdin, decodes each one with the SDK's
message decoder, encodes the decoded message with the SDK's wire encoder, and
writes one line per input: ``OK <base64 of the encoded message>`` or
``ERR <reason>``. The driver wraps each corpus input as the ``v`` member of a
response result, ``{"jsonrpc":"2.0","id":1,"result":{"v":INPUT}}``, then cuts the
re-encoded ``v`` value out of the SDK's bytes and compares it with the RFC 8785
bytes the corpus pins.

    driver.py run NAME -- CMD [ARGS...]   write results/NAME.json
    driver.py admit -- CMD [ARGS...]      write results/jcs-admit.json
    driver.py table                       print the markdown table
    driver.py gate NAME                   exit 1 when NAME diverges anywhere

The corpus is corpora/jcs-byte-vectors/cases.json of agent-evidence-vectors at
a release tag, fetched by URL and checked against a pinned SHA-256, plus the
supplementary extra-cases.json in this directory. Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
CORPUS_TAG = "v0.17.5"
CORPUS_URL = (
    "https://raw.githubusercontent.com/probityai/agent-evidence-vectors/"
    f"{CORPUS_TAG}/corpora/jcs-byte-vectors/cases.json"
)
CORPUS_SHA256 = "b07c54bc8d72d6cb79e9e249df973a01c70a456e5e1820bd00b4e6ca4903a29f"

CLASSES = {
    "ordinary-unicode": "string",
    "utf16-nested-key-order": "key order",
    "exponent-switch": "number",
    "largest-safe-integer": "number",
    "first-unsafe-integer": "number",
    "duplicate-member": "admission",
    "lone-surrogate": "admission",
    "rounded-unsafe-integer": "admission",
    "negative-zero": "number",
    "one-point-zero": "number",
    "integer-valued-1e20": "number",
    "exponent-1e21": "number",
    "point-three-ulp": "number",
    "min-subnormal": "number",
    "max-double": "number",
    "non-finite-1e400": "admission",
    "control-char-escape": "string",
    "short-escapes": "string",
    "escaped-solidus": "string",
    "html-characters": "string",
    "nfd-combining-mark": "string",
    "nbsp-and-line-separator": "string",
    "astral-value": "string",
    "ascii-key-order": "key order",
    "insignificant-whitespace": "structure",
    "depth-64": "structure",
    "depth-129": "admission",
}
CLASS_ORDER = ["number", "string", "key order", "structure", "admission"]


def load_corpus() -> list[dict]:
    """Return every case: the tagged corpus first, then the supplementary set."""
    local = os.environ.get("JCS_CORPUS_PATH")
    if local:
        raw = Path(local).read_bytes()
    else:
        with urllib.request.urlopen(CORPUS_URL, timeout=60) as resp:
            raw = resp.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CORPUS_SHA256:
        raise SystemExit(f"corpus sha256 {digest} != pinned {CORPUS_SHA256}")
    cases = []
    for source, doc in (
        (f"agent-evidence-vectors {CORPUS_TAG}", json.loads(raw)),
        ("extra-cases.json", json.loads((HERE / "extra-cases.json").read_text())),
    ):
        for c in doc["canonicalCases"]:
            cases.append({**c, "source": source, "expect": "canonical"})
        for c in doc["rejectCases"]:
            # A reject case with no jcsError is refused only by the bounded
            # safe-integer profile; RFC 8785 itself serializes the rounded double.
            expect = "reject" if c.get("jcsError") else "bounded-reject"
            cases.append({**c, "source": source, "expect": expect})
    return cases


def envelope(case_input: str) -> str:
    return '{"jsonrpc":"2.0","id":1,"result":{"v":' + case_input + "}}"


_START = re.compile(rb'"result"\s*:\s*\{\s*"v"\s*:\s*')


def cut_value(message: bytes) -> bytes | None:
    """Return the bytes of result.v inside an encoded message, or None."""
    m = _START.search(message)
    if not m:
        return None
    i = m.end()
    depth = 0
    in_str = False
    esc = False
    start = i
    while i < len(message):
        b = message[i]
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
        elif b == 0x22:
            in_str = True
        elif b in (0x5B, 0x7B):
            depth += 1
        elif b in (0x5D, 0x7D):
            depth -= 1
            if depth == 0:
                return message[start : i + 1]
        i += 1
    return None


def run_lines(cmd: list[str], lines: list[str]) -> list[str]:
    proc = subprocess.run(
        cmd,
        input=("\n".join(lines) + "\n").encode(),
        capture_output=True,
        check=False,
    )
    # Split on LF only: str.splitlines would also split on U+2028 and other
    # separators a harness may echo inside an ERR line.
    out = proc.stdout.decode("utf-8", "replace").split("\n")
    if out and out[-1] == "":
        out.pop()
    if proc.returncode != 0 or len(out) != len(lines):
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        for extra in out:
            if not extra.startswith(("OK ", "ERR")):
                sys.stderr.write(f"stray stdout line: {extra[:300]!r}\n")
        raise SystemExit(
            f"harness exited {proc.returncode} with {len(out)} lines for {len(lines)} inputs"
        )
    return out


def cmd_run(name: str, cmd: list[str]) -> None:
    cases = load_corpus()
    out = run_lines(cmd, [envelope(c["input"]) for c in cases])
    rows = []
    for case, line in zip(cases, out):
        row = {"id": case["id"], "expect": case["expect"]}
        if line.startswith("ERR"):
            row.update(verdict="refused", detail=line[4:].strip()[:160])
        elif line.startswith("OK "):
            message = base64.b64decode(line[3:])
            value = cut_value(message)
            row["message"] = message.decode("utf-8", "replace")
            if value is None:
                row.update(verdict="dropped", detail="result.v absent from the encoded message")
            else:
                row["bytes"] = value.decode("utf-8", "replace")
                want = bytes.fromhex(case["canonicalHex"]) if "canonicalHex" in case else None
                row["verdict"] = "canonical" if value == want else "differs"
        else:
            raise SystemExit(f"{name}: unparseable harness line {line!r}")
        rows.append(row)
    meta = json.loads(os.environ.get("HARNESS_META", "{}"))
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"{name}.json").write_text(
        json.dumps({"sdk": name, "meta": meta, "rows": rows}, indent=1, ensure_ascii=False) + "\n"
    )
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"{name}: {counts}")


def cmd_admit(cmd: list[str]) -> None:
    cases = load_corpus()
    out = run_lines(cmd, [c["input"] for c in cases])
    rows = []
    for case, line in zip(cases, out):
        rfc, ijson = line.split("\t")
        row = {"id": case["id"], "expect": case["expect"], "rfc8785": rfc[:3].strip(), "ijson": ijson[:3].strip()}
        if rfc.startswith("ERR"):
            row["rfc8785_error"] = rfc[4:]
        elif "canonicalHex" in case:
            row["matches_pin"] = base64.b64decode(rfc[3:]) == bytes.fromhex(case["canonicalHex"])
        if ijson.startswith("ERR"):
            row["ijson_error"] = ijson[4:]
        rows.append(row)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "jcs-admit.json").write_text(json.dumps({"rows": rows}, indent=1) + "\n")
    bad = [
        r["id"]
        for r in rows
        if r.get("matches_pin") is False
        or (r["expect"] == "canonical" and r["rfc8785"] != "OK")
        or (r["expect"] == "reject" and r["rfc8785"] == "OK")
    ]
    print(f"jcs-admit: {len(rows)} cases, disagreements with the pins: {bad}")
    if bad:
        raise SystemExit(1)


def short(text: str, limit: int = 34) -> str:
    text = text.replace("|", "\\|").replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def cell(row: dict) -> str:
    v = row["verdict"]
    if v == "canonical":
        return "= JCS"
    if v == "refused":
        return "**refused**"
    if v == "dropped":
        return "**dropped**"
    if row["expect"] == "reject":
        return f"**accepted** `{short(row['bytes'])}`"
    return f"`{short(row['bytes'])}`"


def cmd_table() -> None:
    admit = {r["id"]: r for r in json.loads((RESULTS / "jcs-admit.json").read_text())["rows"]}
    sdks = sorted(p.stem for p in RESULTS.glob("*.json") if p.stem != "jcs-admit")
    data = {s: json.loads((RESULTS / f"{s}.json").read_text()) for s in sdks}
    by_id = {s: {r["id"]: r for r in data[s]["rows"]} for s in sdks}
    ids = list(admit)
    print("| Class | Vector | jcs-admit (RFC 8785 / I-JSON) | " + " | ".join(sdks) + " |")
    print("|---|---|---|" + "---|" * len(sdks))
    for klass in CLASS_ORDER:
        for cid in ids:
            if CLASSES.get(cid) != klass:
                continue
            a = admit[cid]
            av = "admit" if a["rfc8785"] == "OK" else f"refuse ({a['rfc8785_error']})"
            iv = "admit" if a["ijson"] == "OK" else f"refuse ({a['ijson_error']})"
            cells = [cell(by_id[s][cid]) for s in sdks]
            print(f"| {klass} | `{cid}` | {av} / {iv} | " + " | ".join(cells) + " |")
    print()
    print("| SDK | canonical | differs | refused | dropped | reject accepted |")
    print("|---|---|---|---|---|---|")
    for s in sdks:
        rows = data[s]["rows"]
        def n(pred):
            return sum(1 for r in rows if pred(r))
        print(
            f"| {s} | {n(lambda r: r['verdict'] == 'canonical')} | "
            f"{n(lambda r: r['verdict'] == 'differs' and r['expect'] == 'canonical')} | "
            f"{n(lambda r: r['verdict'] == 'refused')} | {n(lambda r: r['verdict'] == 'dropped')} | "
            f"{n(lambda r: r['expect'] == 'reject' and r['verdict'] == 'differs')} |"
        )


def cmd_gate(name: str) -> None:
    rows = json.loads((RESULTS / f"{name}.json").read_text())["rows"]
    bad = [
        r["id"]
        for r in rows
        if (r["expect"] == "canonical" and r["verdict"] != "canonical")
        or (r["expect"] == "reject" and r["verdict"] != "refused")
    ]
    print(f"{name}: {len(bad)} of {len(rows)} vectors diverge: {bad}")
    if bad:
        raise SystemExit(1)


def main(argv: list[str]) -> None:
    if not argv:
        raise SystemExit(__doc__)
    if argv[0] == "table":
        cmd_table()
        return
    if argv[0] == "gate" and len(argv) == 2:
        cmd_gate(argv[1])
        return
    if "--" not in argv:
        raise SystemExit(__doc__)
    sep = argv.index("--")
    if argv[0] == "admit":
        cmd_admit(argv[sep + 1 :])
    elif argv[0] == "run" and sep == 2:
        cmd_run(argv[1], argv[sep + 1 :])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
