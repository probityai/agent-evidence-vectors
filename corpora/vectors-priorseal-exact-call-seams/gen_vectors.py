"""Build the PriorSeal exact-call seam cases byte-identically.

Every case is one input of the exact-call envelope matrix in imokokok/PriorSeal
at 2ff89d86611257b4440232e5c2793926b3d52043: the matrix's signed source record,
unchanged, and an observed envelope that is the matrix's case-00 with one field
changed (or, for one control, the matrix's case-05). The source files are
vendored in source/ and checked against their pinned digests before anything is
written. Three cases are the seams G9 to G11 recorded in issue 352 and are open,
each listing the answer under every reading of the one question it turns on;
the others are decided by the 1.0.1 text under every reading, and keep a reader
from passing the seams by ignoring time or chain identity. Every case is
synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / "source"
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import priorsealseams as reader  # noqa: E402

SUITE = reader.SUITE
MATRIX = "examples/open-evidence-lab-exact-call-matrix-v1"
COMMIT = "2ff89d86611257b4440232e5c2793926b3d52043"
ISSUE = "https://github.com/probityai/agent-evidence-vectors/issues/352"
#: Vendored file, its path in imokokok/PriorSeal at COMMIT, and its sha256 there.
PINNED = {
    "INPUT-CONTRACT.md": (
        f"{MATRIX}/INPUT-CONTRACT.md",
        "7454ab478cd8bac6108dbf6376acc8df30582102de4dfdbd00347165bc1861d8",
    ),
    "expected.json": (
        f"{MATRIX}/expected.json",
        "34560ef158d94e2b2108ffdf15c70b1b78da1cc32c230ecb75f44e93cfbe9113",
    ),
    "signed-authorization.json": (
        f"{MATRIX}/fixture/signed-authorization.json",
        "38cebf301c47a63fd3f308b6b7e7e6b6bd0fd166c81857276059650f828fdccb",
    ),
    "case-00-exact-call-observed-match.json": (
        f"{MATRIX}/fixture/observed/case-00-exact-call-observed-match.json",
        "960ebbe8ea7a1c756732da379a93778f67d1d830fa56533de00e2d088e58ac19",
    ),
    "case-05-time-window-expired.json": (
        f"{MATRIX}/fixture/observed/case-05-time-window-expired.json",
        "b94856739a21399ce26ee4b38d384a46c52b6249b7c45c5b2f39c0f4df78e377",
    ),
    "LICENSE": ("LICENSE", "635fdb5f2c6ccc4d7e251db23f18970ab39294ff2b6f2b48d728b09fff8a029f"),
}
SPEC = {
    "contract": "exact-call envelope matrix v1, INPUT-CONTRACT.md",
    "contractVersion": "1.0.1",
    "repository": "https://github.com/imokokok/PriorSeal",
    "commit": COMMIT,
    "unchangedAt": "b39d217e2b81df79ad11e589d8593f4f4dc2a326",
    "files": {name: {"path": path, "sha256": digest} for name, (path, digest) in PINNED.items()},
    "owner": "imokokok, who maintains the contract and decides G9 to G11",
    "license": "MIT, copyright imokokok; source/LICENSE",
}
SOURCE = {
    "seams": f"piiiico, {ISSUE}#issuecomment-6529875972",
    "reproductions": [
        f"ogasurfproject-jpg, {ISSUE}#issuecomment-6529876210 (priorseal-reader-v0), "
        f"{ISSUE}#issuecomment-6529876371 (commit 1bdbebc5)",
        f"Tetsurohhori, {ISSUE}#issuecomment-6529877263 (a reader of the 1.0.0 text)",
    ],
    "recorded": f"imokokok, {ISSUE}#issuecomment-6529876820 and "
    f"{ISSUE}#issuecomment-6529877400, as candidate gaps G9 to G11",
    "note": "The answers each reader and the profile gave are quoted from the comments named "
    "in reportedAnswers, not re-run here. This corpus decides none of the three questions: "
    "the contract's owner does.",
}

#: The 1.0.1 sentences the cases rest on, by key: (section, quote).
SENTENCES = {
    "case-00": ("7", "`case-00` | `bound: true`, no mismatch codes"),
    "case-05": (
        "7",
        "`case-05` | `OUTSIDE_TIME_WINDOW` and `OUTSIDE_AUTHORIZATION_WINDOW` | The observed "
        "execution falls outside both time windows (added in 1.0.1)",
    ),
    "time-row": (
        "4",
        "`intent.validUntil` | `executedAt` (fallback `observedAt`) | observed time greater "
        "than `validUntil` | `OUTSIDE_TIME_WINDOW`",
    ),
    "window-row": (
        "4",
        "`authorization.notBefore` / `authorization.expiresAt` | `executedAt` (fallback "
        "`observedAt`) | observed time earlier than `notBefore` or greater than `expiresAt` | "
        "`OUTSIDE_AUTHORIZATION_WINDOW`",
    ),
    "chain-row": (
        "4",
        "`intent.chainId` | `chainId` | strict equality of the integer values | "
        "`CHAIN_MISMATCH`",
    ),
    "coercion": (
        "4",
        "The shipped implementations compare values after JavaScript `String()` coercion: a "
        "JSON integer participates through its canonical decimal string (`8453` → "
        '`"8453"`), a missing or null value through the empty string, and string comparison '
        "is ASCII-case-insensitive.",
    ),
    "nonce-same": (
        "4",
        'Under these rules a numeric nonce `7` and the string `"7"` are the same value.',
    ),
    "not-settled": (
        "4",
        "The contract states this coercion rather than tightening it; whether the producer "
        "should reject non-canonical forms is an open question, deliberately not settled in "
        "1.0.1.",
    ),
    "instants": (
        "2.1",
        "`issuedAt`, `notBefore` and `expiresAt` are **JSON numbers** (Unix seconds)",
    ),
    "bound": (
        "4",
        "`bound` is decided by the mismatch set of this section only: `bound = (mismatch "
        "codes is empty)`.",
    ),
}
_DROP = object()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _source(name: str) -> Any:
    data = (SOURCE_DIR / name).read_bytes()
    if _sha(data) != PINNED[name][1]:
        raise SystemExit(f"source/{name} is not the pinned PriorSeal file")
    return json.loads(data)


def basis(*keys: str) -> list[dict[str, str]]:
    return [{"quote": SENTENCES[key][1], "section": SENTENCES[key][0]} for key in keys]


def observed(**change: Any) -> dict[str, Any]:
    """The matrix's case-00 envelope with the named fields changed or dropped."""
    envelope: dict[str, Any] = copy.deepcopy(_source("case-00-exact-call-observed-match.json"))
    for key, value in change.items():
        if value is _DROP:
            envelope.pop(key, None)
        else:
            envelope[key] = value
    return envelope


def _decided() -> list[dict[str, Any]]:
    return [
        {
            "id": "control-case-00",
            "observed": observed(),
            "edit": "none: the matrix's case-00 envelope unchanged",
            "basis": basis("case-00", "bound"),
        },
        {
            "id": "control-case-05",
            "observed": _source("case-05-time-window-expired.json"),
            "edit": "none: the matrix's case-05 envelope (executedAt 2001, after both windows)",
            "basis": basis("case-05", "time-row", "window-row"),
        },
        {
            "id": "decided-observedat-fallback-inside",
            "observed": observed(executedAt=_DROP),
            "edit": "executedAt removed; observedAt 1101 stays, inside both windows",
            "basis": basis("time-row", "window-row"),
        },
        {
            "id": "decided-observedat-fallback-late",
            "observed": observed(executedAt=_DROP, observedAt=2002),
            "edit": "executedAt removed; observedAt 2002, after both windows",
            "basis": basis("time-row", "window-row"),
            "note": "The twin of the G9 case: the fallback still holds a time, so a reader "
            "that ignores the windows when executedAt is absent fails here.",
        },
        {
            "id": "decided-chainid-other-integer",
            "observed": observed(chainId=8454),
            "edit": "chainId 8454 (a JSON integer) against the signed 8453",
            "basis": basis("chain-row", "coercion"),
            "note": "The twin of the G11 case: a different chain mismatches under every "
            "reading of the representation question.",
        },
        {
            "id": "decided-nonce-json-number",
            "observed": observed(nonce=7),
            "edit": 'nonce 7 (a JSON number) against the signed "7"',
            "basis": basis("nonce-same"),
            "note": "The paragraph settles the representation question for nonce in so many "
            "words; it is the same question as G11 asked of a field the paragraph names.",
        },
    ]


def _seams() -> list[dict[str, Any]]:
    c = f"{ISSUE}#issuecomment-"
    return [
        {
            "id": "open-g9-missing-time",
            "observed": observed(executedAt=_DROP, observedAt=_DROP),
            "edit": "executedAt and observedAt both removed",
            "basis": basis("time-row", "window-row", "coercion"),
            "note": "The window rows name an observed time and no rule covers its absence. The "
            "paragraph's missing-to-empty-string rule is stated for comparisons of values, and "
            "the window rows are order comparisons. AUTHORIZATION_AFTER_EXECUTION, which the "
            "shipped profile also emits here, is not in the section 4 map.",
            "readings": {
                "skip": "no observed time, so neither window row applies and the case is bound",
                "zero": "the missing time is coerced to the empty string, which an order "
                "comparison reads as 0: earlier than notBefore, not later than validUntil",
                "outside": "a missing time is outside both windows, so both window codes apply",
            },
            "reportedAnswers": [
                f"reader.mjs: bound true ({c}6529875972)",
                "shipped profile (buildAuthorizedReceipt): OUTSIDE_AUTHORIZATION_WINDOW and "
                f"AUTHORIZATION_AFTER_EXECUTION, NON_COMPLIANT ({c}6529875972)",
                f"priorseal-reader-v0 at bfde94be9d80: bound true ({c}6529876210)",
                f"priorseal-reader-v0 at 1bdbebc5: bound false, outside both windows "
                f"({c}6529876371)",
                f"Tetsurohhori's 1.0.0-text reader: bound true, no window code ({c}6529877263)",
            ],
        },
        {
            "id": "open-g10-executedat-not-a-number",
            "observed": observed(executedAt="late"),
            "edit": 'executedAt "late"; observedAt 1101 stays',
            "basis": basis("time-row", "window-row", "instants", "not-settled"),
            "note": "Section 2.1 types the authorization's instants as JSON numbers; no sentence "
            "types the observed executedAt, and the fallback to observedAt applies only when "
            "executedAt is missing. A reader that stops without an answer matches no reading.",
            "readings": {
                "comparison-false": "a time that is not a number makes each window comparison "
                "false, so neither row fires and the case is bound",
                "outside": "a time that is not a number is outside both windows",
            },
            "reportedAnswers": [
                f"reader.mjs: bound true ({c}6529875972)",
                f"shipped profile: bound true, COMPLIANT ({c}6529875972)",
                f"piiiico's JavaScript reader: bound true ({c}6529875972)",
                f"priorseal-reader-v0 at bfde94be9d80: no answer, ValueError ({c}6529876210)",
                f"priorseal-reader-v0 at 1bdbebc5: bound false, outside both windows "
                f"({c}6529876371)",
                f"Tetsurohhori's 1.0.0-text reader: no answer, TypeError, exit 1 ({c}6529877263)",
            ],
        },
        {
            "id": "open-g11-chainid-decimal-string",
            "observed": observed(chainId="8453"),
            "edit": 'chainId "8453" (a JSON string) against the signed 8453',
            "basis": basis("chain-row", "coercion", "nonce-same", "not-settled"),
            "note": "The paragraph, read as written, makes the two the same value; the row's "
            "word strict, the matrix's expected.json (rule strict-equality for chainId beside "
            "strict-string-equality-default-0 for nonce) and both shipped paths keep the JSON "
            "type. The 1.0.0 row said strict equality alone.",
            "readings": {
                "decimal-string": "values compare through their decimal strings, as the "
                "paragraph states, so the chain matches and the case is bound",
                "json-type": "strict equality keeps the JSON type, so a string is not the "
                "integer and CHAIN_MISMATCH applies",
            },
            "reportedAnswers": [
                f"reader.mjs: CHAIN_MISMATCH ({c}6529875972)",
                f"shipped profile: CHAIN_MISMATCH ({c}6529875972)",
                f"piiiico's JavaScript reader: bound true ({c}6529875972)",
                f"priorseal-reader-v0: bound true, chain row mismatch false ({c}6529876210)",
                f"Tetsurohhori's 1.0.0-text reader: CHAIN_MISMATCH ({c}6529877263)",
            ],
        },
    ]


def cases() -> list[dict[str, Any]]:
    """Every case, decided controls first, then the three seams."""
    return [*_decided(), *_seams()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _entry(spec: dict[str, Any], data: bytes, case: dict[str, Any]) -> dict[str, Any]:
    name = spec["id"]
    answer = reader.judge(case)
    texts = spec.get("readings")
    if (answer["decision"] == reader.OPEN) != (texts is not None):
        raise SystemExit(f"{name}: the reader answers {answer}, the case says otherwise")
    entry: dict[str, Any] = {
        key: spec[key] for key in ("basis", "edit", "note", "reportedAnswers") if key in spec
    }
    entry.update(
        {
            "expected": answer,
            "files": {"case.json": _sha(data)},
            "id": name,
            "path": f"cases/{name}",
        }
    )
    if texts is not None:
        answers = reader.reading_answers(case, answer["question"])
        if set(answers) != set(texts):
            raise SystemExit(f"{name}: readings {sorted(texts)} are not {sorted(answers)}")
        entry["readings"] = [
            {"answer": answers[reading], "reading": reading, "text": texts[reading]}
            for reading in reader.QUESTIONS[answer["question"]]
        ]
    return entry


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    authorization = _source("signed-authorization.json")
    entries = []
    for spec in cases():
        directory = root / "cases" / spec["id"]
        directory.mkdir(parents=True)
        case = {"contractVersion": "1.0.1", "observed": spec["observed"], "source": authorization}
        data = _json(case)
        (directory / "case.json").write_bytes(data)
        entries.append(_entry(spec, data, case))
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "provenance": SOURCE,
        "spec": SPEC,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier case.json --json; exit 0 bound, 1 not_bound, 2 open",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
