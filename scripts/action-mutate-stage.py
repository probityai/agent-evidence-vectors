#!/usr/bin/env python3
"""The action's mutation stage: every mutant of every accept member, judged by two verifiers.

This is the body of the "Check mutants against the reference verifier" step of
`action.yml`, run when the `mutate` input is `structural` or `bytes`. For each
member the corpus says must be accepted it writes mutants and asks both the
verifier under test (the `verifier` input, `<verifier> <file>`, exit 0 valid)
and the reference verifier (agent-evidence-verify) for a verdict on each.

* `bytes` flips every bit of every DSSE payload in the member, after decoding,
  and does not re-sign: the signature covers those bytes, so every mutant must
  be rejected. A member with no DSSE envelope has its file bytes flipped.
* `structural` drops each member of the signed payload (or of the statement's
  predicate), moves each scalar by one unit, moves each number to 2^53 and to
  2^64 - 1 and swaps each digest, then RE-SIGNS each changed envelope with the
  corpus's published test key and recomputes the batch root, so the refusal a
  verifier gives is the semantic one and not a broken signature. A corpus that
  publishes no key recipe has its envelope members refused by name.

A mutant passes the stage only when both verifiers reject it. A mutant both
accept is a SURVIVOR: a change no rule binds, named in the summary. A mutant
the two judge differently is a DISAGREEMENT. The stage prints

    mutation-checked N of M

where M is every mutant judged and N the ones both rejected. A corpus with no
reference route reads `0 of M` and fails: a mutation run that compared nothing
is never a pass. When the full set is larger than `MUTATE_LIMIT`, an evenly
spaced, deterministic sample is judged and the summary gives both numbers.

The report gains `mutation` (`checked`, `total`, `generated`, `agreement`,
`survivors`, `disagreements`, `mode`) and keeps `reference.verifier.id`.

Variables: MUTATE, VERIFIER, CORPUS_DIR, REPORT, GITHUB_STEP_SUMMARY,
GITHUB_OUTPUT (required); MUTATE_LIMIT (default 2000).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import action_checks  # noqa: E402

HERE = Path(__file__).resolve().parent
STAGE = HERE / "action-reference-stage.py"
MAX_ROWS = 20
TIMEOUT_S = 60
AEE_KEY_LABEL = "in-toto-aee-test-key/substrate-observation-test/v1"

Path_ = list[Any]  # a JSON path: keys and indexes


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(f"action-mutate-stage: ${name} is not set; refusing to report nowhere.")
    return value


# ---------------------------------------------------------------- JSON paths


def get_at(doc: Any, path: Path_) -> Any:
    for step in path:
        doc = doc[step]
    return doc


def set_at(doc: Any, path: Path_, value: Any) -> None:
    get_at(doc, path[:-1])[path[-1]] = value


def is_envelope(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("payload"), str)
        and isinstance(value.get("payloadType"), str)
        and isinstance(value.get("signatures"), list)
    )


def envelopes(doc: Any, path: Path_ | None = None) -> Iterator[Path_]:
    """The path of every DSSE envelope in a document, outermost first."""
    path = path or []
    if is_envelope(doc):
        yield path
        return
    if isinstance(doc, dict):
        for key, value in doc.items():
            yield from envelopes(value, [*path, key])
    elif isinstance(doc, list):
        for index, value in enumerate(doc):
            yield from envelopes(value, [*path, index])


def scalars(doc: Any, path: Path_ | None = None, depth: int = 0) -> Iterator[tuple[Path_, Any]]:
    path = path or []
    if depth > 6:
        return
    if isinstance(doc, dict):
        for key, value in doc.items():
            yield from scalars(value, [*path, key], depth + 1)
    elif isinstance(doc, list):
        for index, value in enumerate(doc):
            yield from scalars(value, [*path, index], depth + 1)
    else:
        yield path, doc


# ---------------------------------------------------------------- structural edits

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def nudged(value: Any) -> list[tuple[str, Any]]:
    """The one-unit moves of a scalar, each with its name."""
    if isinstance(value, bool):
        return [("negated", not value)]
    if isinstance(value, int):
        return [("plus one", value + 1), ("to 2^53", 2**53), ("to 2^64-1", 2**64 - 1)]
    if isinstance(value, float):
        return [("plus one", value + 1.0), ("to 2^53", 2**53), ("to 2^64-1", 2**64 - 1)]
    if isinstance(value, str):
        if HEX64.match(value):
            return [("digest swapped", hashlib.sha256(value.encode()).hexdigest())]
        if not value:
            return [("emptied string filled", "x")]
        return [("last character moved", value[:-1] + chr((ord(value[-1]) + 1) % 0x110000 or 0x21))]
    return []


def structural_edits(target: Any) -> Iterator[tuple[str, Path_, Any]]:
    """(description, path, new value or DROP) for each structural mutation of an object."""
    if isinstance(target, dict):
        for key in list(target):
            yield f"dropped {key}", [key], DROP
    for path, value in scalars(target):
        for name, new in nudged(value):
            yield f"{'/'.join(map(str, path))} {name}", path, new


DROP = object()


def apply_edit(target: Any, path: Path_, value: Any) -> Any:
    mutant = copy.deepcopy(target)
    if value is DROP:
        del get_at(mutant, path[:-1])[path[-1]]
    else:
        set_at(mutant, path, value)
    return mutant


# ---------------------------------------------------------------- signing


def key_seed(manifest: dict[str, Any]) -> bytes | None:
    """The corpus's published test-key seed, from its manifest's recipe."""
    recipe = manifest.get("keyRecipe")
    if isinstance(recipe, str):
        match = re.search(r"sha-?256\(\s*\"([^\"]+)\"\s*\)", recipe, re.IGNORECASE)
        if match:
            label = match.group(1)
            role = re.search(r"role ([A-Za-z0-9_-]+)", recipe)
            if "<role>" in label and role:
                label = label.replace("<role>", role.group(1))
            if "<" not in label:
                return hashlib.sha256(label.encode()).digest()
    # The AEE corpus publishes its recipe in vectors/keys/README.md; the reference
    # stage holds the same recipe (aee_test_key).
    if manifest.get("predicateType") == AEE_PREDICATE:
        return hashlib.sha256(AEE_KEY_LABEL.encode()).digest()
    return None


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d " % (len(pt), pt, len(payload)) + payload


def sign(seed: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


def merkle_root_hex(leaves: list[bytes]) -> str:
    def node(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 1:
            return hashlib.sha256(b"\x00" + leaves[lo]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + node(lo, lo + k) + node(lo + k, hi)).digest()

    return node(0, len(leaves)).hex()


def reseal(document: Any, seed: bytes, changed: Path_) -> None:
    """Re-sign the envelope at `changed` and recompute the predicate's batch root."""
    env = get_at(document, changed)
    payload = base64.b64decode(env["payload"])
    signature = base64.b64encode(sign(seed, pae(env["payloadType"], payload))).decode()
    env["signatures"] = [{**s, "sig": signature} for s in env["signatures"]] or [{"sig": signature}]
    predicate = document.get("predicate") if isinstance(document, dict) else None
    if isinstance(predicate, dict) and isinstance(predicate.get("batchRoot"), str):
        records = predicate.get("observationRecords")
        if isinstance(records, list) and records and all(is_envelope(r) for r in records):
            leaves = [pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records]
            predicate["batchRoot"] = merkle_root_hex(leaves)


# ---------------------------------------------------------------- mutants


def mutants(raw: bytes, mode: str, seed: bytes | None) -> Iterator[tuple[str, bytes | str]]:
    """(description, mutant bytes) for one member; a str in place of bytes is a refusal."""
    try:
        document = json.loads(raw)
    except ValueError:
        document = None
    paths = list(envelopes(document)) if document is not None else []
    if mode == "bytes":
        if not paths:
            for index in range(len(raw) * 8):
                flipped = bytearray(raw)
                flipped[index // 8] ^= 1 << (index % 8)
                yield f"file bit {index}", bytes(flipped)
            return
        for path in paths:
            env = get_at(document, path)
            payload = base64.b64decode(env["payload"])
            for index in range(len(payload) * 8):
                flipped = bytearray(payload)
                flipped[index // 8] ^= 1 << (index % 8)
                mutant = copy.deepcopy(document)
                get_at(mutant, path)["payload"] = base64.b64encode(bytes(flipped)).decode()
                yield f"{'/'.join(map(str, path))} payload bit {index}", json.dumps(mutant).encode()
        return
    if document is None:
        yield "member", "the member is not JSON, so it has no structure to mutate"
        return
    if paths:
        if seed is None:
            yield "member", "the corpus publishes no key recipe, so a structural mutant cannot be re-signed"
            return
        for path in paths:
            env = get_at(document, path)
            try:
                inner = json.loads(base64.b64decode(env["payload"]))
            except ValueError:
                continue
            for name, sub, value in structural_edits(inner):
                mutant = copy.deepcopy(document)
                get_at(mutant, path)["payload"] = base64.b64encode(
                    json.dumps(apply_edit(inner, sub, value), separators=(",", ":")).encode()
                ).decode()
                reseal(mutant, seed, path)
                yield f"{'/'.join(map(str, path))}: {name}", json.dumps(mutant).encode()
    target_path: Path_ = ["predicate"] if isinstance(document, dict) and isinstance(document.get("predicate"), dict) else []
    target = get_at(document, target_path)
    skip = {tuple(p[len(target_path):]) for p in paths}
    for name, sub, value in structural_edits(target):
        if any(tuple(sub[: len(s)]) == s for s in skip if s):
            continue
        mutant = copy.deepcopy(document)
        if target_path:
            set_at(mutant, target_path, apply_edit(target, sub, value))
        else:
            mutant = apply_edit(target, sub, value)
        yield f"{'/'.join(map(str, target_path + sub))}: {name}", json.dumps(mutant).encode()


def sample(total: int, limit: int) -> set[int]:
    """Evenly spaced indexes, deterministic, `limit` of `total`."""
    if total <= limit:
        return set(range(total))
    return {int(i * total / limit) for i in range(limit)}


# ---------------------------------------------------------------- verdicts

AEE_PREDICATE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"


def load_stage() -> Any:
    spec = importlib.util.spec_from_file_location("aev_reference_stage", STAGE)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {STAGE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def reference_route(manifest: dict[str, Any]) -> tuple[Any, str] | None:
    """A function judging one mutant's bytes, and the verifier id; None when there is no route."""
    if manifest.get("predicateType") != AEE_PREDICATE:
        return None
    stage = load_stage()
    if stage.reference_missing():
        return None

    def judge(entry: dict[str, Any], root: Path) -> str:
        return str(stage.aee_decide(entry, root, [])["verdict"])

    return judge, stage.reference_id()


def candidate(verifier: list[str], path: Path) -> str:
    try:
        done = subprocess.run(  # noqa: S603 -- the consumer's verifier, as in the replay
            [*verifier, str(path)], capture_output=True, text=True, timeout=TIMEOUT_S, check=False,
            env={k: v for k, v in os.environ.items() if k != "AEE_SUBSTRATE_KEYS"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"notrun ({exc})"
    return "valid" if done.returncode == 0 else "invalid" if done.returncode == 1 else f"errored (exit {done.returncode})"


def run(mode: str, verifier: list[str], corpus_dir: Path, limit: int) -> dict[str, Any]:
    manifest = action_checks.manifest_of(corpus_dir) or {}
    members = [m for m in action_checks.listed_members(manifest)
               if str(m["entry"].get("kind") or m["entry"].get("disposition")) in action_checks.ACCEPT_KINDS]
    seed = key_seed(manifest)
    route = reference_route(manifest)
    refusals: list[str] = []
    planned: list[tuple[dict[str, Any], str, bytes]] = []
    for member in members:
        raw = (corpus_dir / member["path"]).read_bytes()
        for name, body in mutants(raw, mode, seed):
            if isinstance(body, str):
                refusals.append(f"{member['id']}: {body}")
                break
            planned.append((member, name, body))
    chosen = sample(len(planned), limit)
    survivors: list[str] = []
    disagreements: list[str] = []
    unjudged: list[str] = []
    checked = agreed = 0
    with tempfile.TemporaryDirectory(prefix="aev-mutants-") as tmp:
        root = Path(tmp)
        for index, (member, name, body) in enumerate(planned):
            if index not in chosen:
                continue
            path = root / f"{member['id']}-m{index:06d}.json"
            path.write_bytes(body)
            label = f"{member['id']} #{index} ({name})"
            mine = candidate(verifier, path)
            theirs = None
            if route is not None:
                try:
                    theirs = route[0]({"id": member["id"], "file": path.name}, root)
                except Exception as exc:  # noqa: BLE001 -- one mutant must not hide the rest
                    theirs = f"errored ({exc!r})"
            if theirs is None:
                unjudged.append(label)
                continue
            if mine == theirs:
                agreed += 1
                if mine == "invalid":
                    checked += 1
                else:
                    survivors.append(f"{label}: both verifiers say {mine}")
            else:
                disagreements.append(f"{label}: verifier under test {mine}, reference {theirs}")
    judged = len(chosen)
    notes = []
    if route is None:
        notes.append("no reference route into this corpus, so no mutant was compared")
    return {
        "mode": mode,
        "checked": checked,
        "total": judged,
        "generated": len(planned),
        "sampled": judged < len(planned),
        "agreement": agreed,
        "survivors": survivors,
        "disagreements": disagreements,
        "refusals": refusals,
        "notes": notes,
        "referenceVerifierId": route[1] if route else None,
        "pass": bool(judged) and checked == judged and not refusals,
    }


def main() -> int:
    mode = required("MUTATE")
    report_path = Path(required("REPORT"))
    corpus_dir = Path(required("CORPUS_DIR"))
    summary_path = required("GITHUB_STEP_SUMMARY")
    output_path = required("GITHUB_OUTPUT")
    verifier = shlex.split(os.environ.get("VERIFIER", ""), posix=os.name != "nt")
    limit = int(os.environ.get("MUTATE_LIMIT") or 2000)
    if mode not in ("structural", "bytes"):
        sys.exit(f"action-mutate-stage: mutate must be none, structural or bytes, not {mode!r}")
    if not verifier:
        result: dict[str, Any] = {"mode": mode, "checked": 0, "total": 0, "generated": 0, "sampled": False,
                                  "agreement": 0, "survivors": [], "disagreements": [], "refusals": [],
                                  "notes": ["mutate needs the `verifier` input"], "referenceVerifierId": None,
                                  "pass": False}
    else:
        result = run(mode, verifier, corpus_dir, limit)
    line = f"mutation-checked {result['checked']} of {result['total']}"
    print(line)
    for item in result["refusals"] + result["notes"] + result["survivors"] + result["disagreements"]:
        print(item)
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["mutation"] = {k: v for k, v in result.items() if k != "referenceVerifierId"}
        if result["referenceVerifierId"]:
            report.setdefault("reference", {}).setdefault("verifier", {"id": result["referenceVerifierId"]})
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rows = [f"## agent-evidence-vectors: {line} ({mode})\n\n"]
    if result["sampled"]:
        rows.append(f"A deterministic sample of {result['total']} of {result['generated']} mutants was judged.\n\n")
    rows.append(
        f"Both rejected {result['checked']}; the verdicts agree on {result['agreement']}; "
        f"{len(result['survivors'])} survived both; {len(result['disagreements'])} disagree.\n\n"
    )
    for title, items in (("refused", result["refusals"]), ("note", result["notes"]),
                         ("survivor", result["survivors"]), ("disagreement", result["disagreements"])):
        if items:
            rows.append(f"| {title} |\n| --- |\n")
            rows.extend(f"| {item[:300]} |\n" for item in items[:MAX_ROWS])
            rows.append("\n")
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("".join(rows))
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(
            f"mutation-checked={result['checked']}\nmutation-total={result['total']}\n"
            f"mutation-agreement={result['agreement']}\nmutation-survivors={len(result['survivors'])}\n"
            f"mutation-result={'pass' if result['pass'] else 'fail'}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
