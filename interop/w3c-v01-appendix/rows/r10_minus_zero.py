#!/usr/bin/env python3
"""R10: the bytes each reference reader writes for the integer -0.

    python rows/r10_minus_zero.py <work dir> <result.json>

The input is the document {"v": -0}, the token parsed from the wire, as in
0038. At v0.17.4 the Python reader's compact form and the Go reader's
pythonCompactJSON are measured; at v0.18.1 both readers' jcs-sha256 bytes.
The Python reader comes from PyPI at the release's version, the Go reader from
the tagged commit, called from a test file added to a scratch copy. Also
counts -0 number tokens in the vectors-w3c-report files at v0.17.4.

Exits 0 only when every hex string equals the value posted in 0038 and 0079.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402

DOCUMENT = b'{"v":-0}'
PYTHON = {
    "v0.17.4": "import json\nfrom agent_evidence_vectors import w3creport as w\n"
               "print(w.compact(json.loads(%r)).hex())",
    "v0.18.1": "from agent_evidence_vectors import w3creport as w\n"
               "print(w.jcs_sha256(w.load_json(%r)).hex())",
}
GO_FUNCTION = {"v0.17.4": "pythonCompactJSON", "v0.18.1": "jcsSHA256Bytes"}
GO_TEST = """package corpora

import (
\t"bytes"
\t"encoding/hex"
\t"encoding/json"
\t"fmt"
\t"testing"
)

func TestAppendixMinusZero(t *testing.T) {
\tdec := json.NewDecoder(bytes.NewReader([]byte(`{"v":-0}`)))
\tdec.UseNumber()
\tvar v any
\tif err := dec.Decode(&v); err != nil {
\t\tt.Fatal(err)
\t}
\tout, err := %s(v)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tfmt.Printf("HEX %%s\\n", hex.EncodeToString(out))
}
"""
TOKEN = re.compile(rb"(?<=[:\[,\s])-0(?![\w.])")


def main() -> int:
    work, result = Path(sys.argv[1]), Path(sys.argv[2])
    log = work / "log.txt"
    expect = rerun.ROWS["rows"]["R10"]["expect"]
    out: dict = {"input": DOCUMENT.decode(), "releases": {}}
    ok = True
    for tag, posted in expect.items():
        tree = rerun.aev_tree(tag, work / f"aev-{tag}", log,
                              ["/go.mod", "/go.sum", "/corpora/", "/aee/", "/observedeffect/",
                               "/vectors-w3c-report/"])
        py_out = work / f"python-{tag}.txt"
        code_py = rerun.run(["uv", "run", "-q", "--no-project", "--python", "3.13", "--with",
                             f"agent-evidence-vectors=={tag.lstrip('v')}", "python", "-c",
                             PYTHON[tag] % DOCUMENT], work, log, stdout=py_out)
        (tree / "corpora" / "appendix_minus_zero_test.go").write_text(
            GO_TEST % GO_FUNCTION[tag], encoding="utf-8")
        go_out = work / f"go-{tag}.txt"
        code_go = rerun.run(["go", "test", "-count=1", "-run", "TestAppendixMinusZero", "-v",
                             "./corpora/"], tree, log, env={"GOWORK": "off", "GOFLAGS": "-mod=mod"},
                            stdout=go_out)
        go_hex = [line.split()[1] for line in go_out.read_text(encoding="utf-8").splitlines()
                  if line.startswith("HEX ")]
        release = {
            "commit": rerun.ROWS["aev_tags"][tag],
            "python": {"posted": posted["python"], "observed": py_out.read_text().strip(),
                       "exit": code_py},
            "go": {"posted": posted["go"], "observed": go_hex[0] if go_hex else None,
                   "exit": code_go, "function": GO_FUNCTION[tag]},
        }
        ok = (ok and release["python"]["observed"] == posted["python"]
              and release["go"]["observed"] == posted["go"])
        if "minus_zero_tokens" in posted:
            files = [p for p in sorted((tree / "vectors-w3c-report").rglob("*")) if p.is_file()]
            hits = {str(p.relative_to(tree)): len(TOKEN.findall(p.read_bytes())) for p in files}
            found = sum(hits.values())
            release["text_search"] = {"files": len(files), "posted": posted["minus_zero_tokens"],
                                      "observed": found,
                                      "in": sorted(k for k, v in hits.items() if v)}
            ok = ok and found == posted["minus_zero_tokens"]
        out["releases"][tag] = release
    out["ok"] = ok
    result.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
