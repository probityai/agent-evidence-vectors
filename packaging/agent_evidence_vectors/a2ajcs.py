"""Judge the a2a Agent Card canonicalization corpus, vendored from a2a-tck.

The corpus is a2aproject/a2a-tck ``conformance-vectors/a2a-jcs-v01``, carried
byte for byte under ``vectors-a2a-jcs-v01/`` and pinned by commit and corpus
digest in that directory's ``source-lock.json``. Its MANIFEST names two
functions, and each vector is scored against the functions that own it:

``rfc8785``
    One JSON value to its RFC 8785 canonical bytes: the A3 to A6 vectors.
``card-signing-input``
    The bytes an Agent Card signature covers: the card without its top-level
    ``signatures`` member, canonicalized. Every vector; the A2 vectors
    test that exclusion, which RFC 8785 has no notion of.

External-verifier contract. The harness runs ``<verifier> <target> <input>``
once per vector, where ``<target>`` is one of the two names above and
``<input>`` is a file holding the vector's input as UTF-8 JSON text. The
verifier answers on the last nonempty stdout line with one JSON object:

- exit 0 and ``{"canonical_utf8_hex": "<hex>"}`` when it produced bytes;
- exit 1 when it refuses the input (it has no canonical form), with any or no
  JSON on stdout.

Any other exit, a missing or malformed answer, or a timeout is ``errored``.
Each vector gets the outcome the upstream runners give it, and only ``pass``
passes: on MUST-ACCEPT, ``diverged`` (other bytes) and ``refused``; on
MUST-REJECT, ``accepted`` (bytes for input with no canonical form, or signing
bytes that still carry ``signatures``). The target is ``card-signing-input``
unless ``A2A_JCS_TARGET`` names ``rfc8785``, so a canonicalizer that only
implements the primitive is scored on the vectors it owns.

With no verifier named, this module's own canonicalizer answers every vector
for both targets, which is how the shipped corpus is checked clean.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
from decimal import Decimal
from pathlib import Path
from typing import Any

SUITE = "a2a-agent-card-canonicalization-conformance"
CORPUS_DIR = "vectors-a2a-jcs-v01"
TARGETS = ("rfc8785", "card-signing-input")
DEFAULT_TARGET = "card-signing-input"
TARGET_ENV = "A2A_JCS_TARGET"
SIGNATURES_EXCLUSION_CLAUSE = "a2a-spec-8.4.1-rule-3"
RFC8785_CLAUSE_PREFIX = "RFC8785-"
TIMEOUT_S = 30
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / CORPUS_DIR
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / CORPUS_DIR
)


class Refusal(ValueError):
    """The input has no RFC 8785 canonical form."""


# ---------------------------------------------------------------------------
# RFC 8785, the general profile: any I-JSON value, numbers as IEEE 754 doubles.


def _number(value: float) -> str:
    """ECMAScript Number::toString of a finite double (RFC 8785 section 3.2.2.3).

    ``repr`` gives the shortest digit string that round-trips, which is the
    digit string ECMAScript picks; only the placement of the point and the
    exponent differ, and those follow the specification's four cases.
    """
    if not math.isfinite(value):
        raise Refusal("NaN and Infinity have no JSON number form")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + _number(-value)
    _, digit_tuple, exponent = Decimal(repr(value)).as_tuple()
    if not isinstance(exponent, int):
        raise Refusal("NaN and Infinity have no JSON number form")
    every = "".join(str(d) for d in digit_tuple)
    digits = every.rstrip("0")
    exponent += len(every) - len(digits)
    k = len(digits)
    n = k + exponent
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"


_CONTROL = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _string(text: str) -> str:
    """RFC 8785 section 3.2.2.2, refusing a lone surrogate (not Unicode text)."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise Refusal(f"lone surrogate U+{code:04X} is not a Unicode scalar value")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append(_CONTROL.get(code, f"\\u{code:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _value(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        try:
            return _number(float(value))
        except OverflowError as exc:
            raise Refusal("integer outside the IEEE 754 double range") from exc
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, list):
        return "[" + ",".join(_value(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(key) + ":" + _value(value[key]) for key in keys) + "}"
    raise Refusal(f"{type(value).__name__} is not a JSON value")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in pairs:
        if key in out:
            raise Refusal(f"duplicate member {key!r} is not I-JSON")
        out[key] = item
    return out


def parse(text: str) -> Any:
    """Parse JSON text as RFC 8785 input. NaN and Infinity parse, and refuse later."""
    return json.loads(text, object_pairs_hook=_no_duplicates)


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 canonical bytes of one parsed JSON value."""
    return _value(value).encode("utf-8")


def signing_input(card: Any) -> bytes:
    """The bytes an Agent Card signature covers (a2a spec 8.4.1 rules 2 and 3)."""
    if isinstance(card, dict):
        card = {key: item for key, item in card.items() if key != "signatures"}
    return canonicalize(card)


FUNCTIONS = {"rfc8785": canonicalize, "card-signing-input": signing_input}


# ---------------------------------------------------------------------------
# The corpus: its digest, its members, and which target owns each.


def corpus_digest(manifest_bytes: bytes) -> str:
    """The upstream corpus digest, from the MANIFEST file's own bytes.

    Upstream hashes ``json.dumps(body, indent=2)`` where ``body`` is the
    manifest without ``corpusDigest``, then writes the manifest with the digest
    appended as its last member. Removing that last member from the file bytes
    restores the preimage exactly, so no re-serialization (whose escaping rules
    differ between languages) stands between the file and its digest.
    """
    text = manifest_bytes.decode("utf-8")
    declared = json.loads(text)["corpusDigest"]
    tail = f',\n  "corpusDigest": "{declared}"\n}}\n'
    if not text.endswith(tail):
        raise ValueError(
            "MANIFEST.json does not end with its corpusDigest member as upstream writes it"
        )
    return hashlib.sha256((text[: -len(tail)] + "\n}").encode("utf-8")).hexdigest()


def owns(target: str, clause: str) -> bool:
    if target == "rfc8785":
        return clause.startswith(RFC8785_CLAUSE_PREFIX)
    return clause.startswith(RFC8785_CLAUSE_PREFIX) or clause == SIGNATURES_EXCLUSION_CLAUSE


def load(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """The manifest, its vectors in manifest order, and every integrity finding."""
    raw = (root / "MANIFEST.json").read_bytes()
    manifest = json.loads(raw)
    findings: list[str] = []
    if manifest.get("suite") != SUITE:
        findings.append(f"MANIFEST.json declares suite {manifest.get('suite')!r}, not {SUITE!r}")
    try:
        if corpus_digest(raw) != manifest.get("corpusDigest"):
            findings.append("corpusDigest does not match the MANIFEST body")
    except ValueError as exc:
        findings.append(str(exc))
    vectors: list[dict[str, Any]] = []
    listed = set()
    for entry in manifest.get("vectors", []):
        path = root / entry["path"]
        listed.add(entry["path"])
        try:
            body = path.read_bytes()
        except OSError:
            findings.append(f"{entry['path']} is listed and missing")
            continue
        if hashlib.sha256(body).hexdigest() != entry["sha256"]:
            findings.append(f"{entry['path']} does not match its manifest sha256")
        vectors.append(json.loads(body))
    on_disk = {
        p.relative_to(root).as_posix() for p in root.glob("*/*.json") if p.parent.name != "tests"
    }
    for extra in sorted(on_disk - listed):
        findings.append(f"{extra} is on disk and not in the manifest")
    for target in TARGETS:
        declared = manifest.get("targets", {}).get(target, {}).get("vectors")
        counted = sum(1 for v in vectors if owns(target, v["clause"]))
        if declared != counted:
            findings.append(f"target {target} declares {declared} vectors and owns {counted}")
    return manifest, vectors, findings


def input_text(vector: dict[str, Any]) -> str:
    """The vector's input as JSON text: ``input_raw`` verbatim, or ``input`` serialized.

    ``json.dumps`` writes every double as its shortest round-tripping form and
    escapes nothing a JSON parser reads differently, so the value a verifier
    parses is the value the vector holds.
    """
    if "input_raw" in vector:
        return str(vector["input_raw"])
    return json.dumps(vector["input"], ensure_ascii=True, allow_nan=False)


def outcome(vector: dict[str, Any], answer: str, produced: bytes | None) -> tuple[str, str]:
    """Score one answer (``bytes``, ``refused`` or ``errored``) as upstream does."""
    if vector["disposition"] == "MUST-ACCEPT":
        if answer != "bytes":
            return answer, f"{answer} on input that has a canonical form"
        want = bytes.fromhex(vector["expected"]["canonical_utf8_hex"])
        if produced != want:
            return "diverged", f"got {produced!r} want {want!r}"
        return "pass", "ok"
    if vector["clause"] == SIGNATURES_EXCLUSION_CLAUSE:
        if answer != "bytes":
            return answer, "the signing path did not answer a well-formed card"
        if produced == input_text(vector).encode("utf-8"):
            return "accepted", "recomputed signing bytes still carry 'signatures'"
        return "pass", "the presented bytes are not this card's signing bytes"
    if answer == "bytes":
        return "accepted", f"produced {produced!r} for input with no canonical form"
    if answer == "refused":
        return "pass", "refused"
    return answer, "errored rather than refusing"


def reference_answer(target: str, text: str) -> tuple[str, bytes | None]:
    try:
        return "bytes", FUNCTIONS[target](parse(text))
    except (Refusal, ValueError):
        return "refused", None


# ---------------------------------------------------------------------------
# The two routes the rail dispatches to.


def judge(root: str | Path = ROOT) -> int:
    """Answer every vector for both targets with this module's canonicalizer."""
    directory = Path(root)
    _, vectors, findings = load(directory)
    for target in TARGETS:
        owned = [v for v in vectors if owns(target, v["clause"])]
        failed = 0
        for vector in owned:
            result, detail = outcome(vector, *reference_answer(target, input_text(vector)))
            if result != "pass":
                failed += 1
                findings.append(f"{target} {vector['id']}: {result}: {detail}")
        print(f"{SUITE} target {target}: {len(owned) - failed} of {len(owned)} pass")
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"{SUITE}: {'clean' if not findings else f'{len(findings)} finding(s)'}")
    return 1 if findings else 0


def _ask(command: list[str], target: str, path: str) -> tuple[str, bytes | None, str]:
    try:
        proc = subprocess.run(
            [*command, target, path], capture_output=True, text=True, timeout=TIMEOUT_S, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "notrun", None, f"the verifier did not run: {exc}"
    if proc.returncode == 1:
        return "refused", None, "exit 1"
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if proc.returncode != 0 or not lines:
        return "errored", None, f"exit {proc.returncode} with no answer"
    try:
        answer = json.loads(lines[-1])
        return "bytes", bytes.fromhex(answer["canonical_utf8_hex"]), "exit 0"
    except (ValueError, KeyError, TypeError) as exc:
        return "errored", None, f"exit 0 without a canonical_utf8_hex answer: {exc}"


def run_external(root: str, verifier: list[str], report_path: str, rail_note: str) -> int:
    """Run the named verifier over every vector its target owns and write the report."""
    directory = Path(root)
    target = os.environ.get(TARGET_ENV, DEFAULT_TARGET)
    if target not in TARGETS:
        print(
            f"{TARGET_ENV}={target!r} names no target of this corpus; use one of {TARGETS}",
            file=sys.stderr,
        )
        return 2
    manifest, vectors, findings = load(directory)
    owned = [v for v in vectors if owns(target, v["clause"])]
    rows: list[dict[str, Any]] = []
    executed = 0
    with tempfile.TemporaryDirectory(prefix="a2a-jcs-") as tmp:
        for vector in owned:
            path = os.path.join(tmp, f"{vector['id']}.json")
            with open(path, "w", encoding="utf-8", errors="surrogatepass") as handle:
                handle.write(input_text(vector))
            answer, produced, how = _ask(verifier, target, path)
            if answer != "notrun":
                executed += 1
                result, detail = outcome(vector, answer, produced)
            else:
                result, detail = "errored", how
            rows.append(
                {
                    "id": vector["id"],
                    "kind": vector["disposition"],
                    "target": target,
                    "outcome": result,
                    "status": "PASS" if result == "pass" else "FAIL",
                    "reasons": [] if result == "pass" else [f"{result}: {detail} ({how})"],
                }
            )
    if not executed:
        print("no report written: the named verifier did not answer a vector", file=sys.stderr)
        return 2
    failed = sum(1 for row in rows if row["status"] == "FAIL")
    report = {
        "suite": SUITE,
        "rail": "external",
        "railNote": rail_note,
        "target": target,
        "verifier": {"command": verifier, "vectorsExecuted": executed},
        "corpus": {
            "corpusDigest": manifest.get("corpusDigest"),
            "manifestSha256": hashlib.sha256(
                (directory / "MANIFEST.json").read_bytes()
            ).hexdigest(),
        },
        "totals": {
            "vectors": len(owned),
            "pass": len(owned) - failed,
            "fail": failed,
            "conform": len(owned) - failed,
            "reasonParityMismatch": 0,
            "suiteRefusals": len(findings),
        },
        "notes": findings,
        "vectors": rows,
    }
    Path(report_path).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for row in rows:
        if row["status"] == "FAIL":
            print(f"FAIL {row['id']}: {row['reasons'][0]}")
    for finding in findings:
        print(f"FAIL {finding}")
    print(
        f"{SUITE} target {target}: executed {executed} of {len(owned)}, "
        f"{len(owned) - failed} pass; report {report_path}"
    )
    return 1 if failed or findings or executed != len(owned) else 0


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """The rail's route: the named verifier under the contract, or this reader."""
    if verifier is None:
        return judge(root)
    return run_external(root, verifier, report_path, rail_note)


# ---------------------------------------------------------------------------
# This module is also a verifier under the contract above, so the contract has a
# known-good implementation to run against: python -m agent_evidence_vectors.a2ajcs


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] not in TARGETS:
        print(
            f"usage: python -m agent_evidence_vectors.a2ajcs {{{'|'.join(TARGETS)}}} <input.json>",
            file=sys.stderr,
        )
        return 2
    with open(args[1], encoding="utf-8", errors="surrogatepass") as handle:
        answer, produced = reference_answer(args[0], handle.read())
    if answer != "bytes" or produced is None:
        print(json.dumps({"refused": True}))
        return 1
    print(json.dumps({"canonical_utf8_hex": produced.hex()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
