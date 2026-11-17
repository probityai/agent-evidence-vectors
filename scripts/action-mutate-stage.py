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
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
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
    """The one-unit moves of a scalar that change it, each with its name.

    A move that lands on the value it started from (2^53 moved to 2^53, a float
    past 2^53 plus one) is not a mutant: it is the accepted member again, and
    both verifiers accepting it would be filed as a survivor no rule could bind.
    """
    return [(name, new) for name, new in _moves(value) if new != value]


def _moves(value: Any) -> list[tuple[str, Any]]:
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
SKIP = "skip: "


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


#: A mutant is built only when the sample picks it: the full set of an AEE
#: corpus in bytes mode is over half a million documents.
Build = Callable[[], bytes]


def _flip(document: Any, path: Path_, payload: bytes, index: int) -> Build:
    def build() -> bytes:
        flipped = bytearray(payload)
        flipped[index // 8] ^= 1 << (index % 8)
        mutant = copy.deepcopy(document)
        get_at(mutant, path)["payload"] = base64.b64encode(bytes(flipped)).decode()
        return json.dumps(mutant).encode()

    return build


#: A mutant's control: the unmutated member rebuilt the way that mutant is
#: built (re-encoded, and re-signed when the mutant is). Both verifiers must
#: accept it, or a rejection of the mutant says nothing about the edit: a wrong
#: re-sign key, a batch root computed another way, or an encoding a verifier
#: refuses kills every mutant without any rule binding the field.
Control = tuple[str, Build]
DOCUMENT = "document as re-encoded"


def _as_is(document: Any) -> Build:
    def build() -> bytes:
        return json.dumps(document).encode()

    return build


def _resealed_as_is(document: Any, path: Path_, inner: Any, seed: bytes) -> Build:
    def build() -> bytes:
        mutant = copy.deepcopy(document)
        body = json.dumps(inner, separators=(",", ":")).encode()
        get_at(mutant, path)["payload"] = base64.b64encode(body).decode()
        reseal(mutant, seed, path)
        return json.dumps(mutant).encode()

    return build


def bytes_mutants(document: Any, paths: list[Path_]) -> Iterator[tuple[str, Build, Control]]:
    """Every bit of every DSSE payload, flipped; never re-signed."""
    control = (DOCUMENT, _as_is(document))
    for path in paths:
        payload = base64.b64decode(get_at(document, path)["payload"])
        for index in range(len(payload) * 8):
            yield (
                f"{'/'.join(map(str, path))} payload bit {index}",
                _flip(document, path, payload, index),
                control,
            )


def _resigned(
    document: Any, path: Path_, inner: Any, edit: tuple[Path_, Any], seed: bytes
) -> Build:
    def build() -> bytes:
        mutant = copy.deepcopy(document)
        body = json.dumps(apply_edit(inner, *edit), separators=(",", ":")).encode()
        get_at(mutant, path)["payload"] = base64.b64encode(body).decode()
        reseal(mutant, seed, path)
        return json.dumps(mutant).encode()

    return build


def _edited(document: Any, target_path: Path_, edit: tuple[Path_, Any]) -> Build:
    def build() -> bytes:
        if not target_path:
            return json.dumps(apply_edit(document, *edit)).encode()
        mutant = copy.deepcopy(document)
        set_at(mutant, target_path, apply_edit(get_at(document, target_path), *edit))
        return json.dumps(mutant).encode()

    return build


def structural_mutants(
    document: Any, paths: list[Path_], seed: bytes
) -> Iterator[tuple[str, Build, Control]]:
    """Each signed payload's edits, re-signed; then the statement's own edits."""
    for path in paths:
        try:
            inner = json.loads(base64.b64decode(get_at(document, path)["payload"]))
        except ValueError:
            continue
        where = "/".join(map(str, path))
        control = (f"{where} re-signed unchanged", _resealed_as_is(document, path, inner, seed))
        for name, sub, value in structural_edits(inner):
            yield f"{where}: {name}", _resigned(document, path, inner, (sub, value), seed), control
    has_predicate = isinstance(document, dict) and isinstance(document.get("predicate"), dict)
    target_path: Path_ = ["predicate"] if has_predicate else []
    inside = {tuple(p[len(target_path) :]) for p in paths}
    for name, sub, value in structural_edits(get_at(document, target_path)):
        if any(s and tuple(sub[: len(s)]) == s for s in inside):
            continue  # an edit inside an envelope is made, and re-signed, above
        label = f"{'/'.join(map(str, target_path + sub))}: {name}"
        yield label, _edited(document, target_path, (sub, value)), (DOCUMENT, _as_is(document))


Mutant = tuple[str, Build, Control] | tuple[str, str]


def mutants(raw: bytes, mode: str, seed: bytes | None) -> Iterator[Mutant]:
    """(description, builder, control) for one member; (description, str) is a refusal."""
    try:
        document = json.loads(raw)
    except ValueError:
        yield "member", "the member is not JSON, so it has no structure to mutate"
        return
    paths = list(envelopes(document))
    if mode == "bytes" and not paths:
        # Bytes mode flips what a signature covers. A member with no DSSE
        # envelope has no signed bytes, and a flipped bit in an unsigned field
        # says nothing about the verifier; structural mode reads it.
        yield (
            "member",
            SKIP + "it carries no DSSE envelope, so bytes mode has no signed payload to flip",
        )
    elif mode == "bytes":
        yield from bytes_mutants(document, paths)
    elif paths and seed is None:
        yield (
            "member",
            "the corpus publishes no key recipe, so a structural mutant cannot be re-signed",
        )
    else:
        yield from structural_mutants(document, paths, seed or b"")


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
    """The verifier under test on one file: valid, invalid, or why it did not answer."""
    try:
        done = subprocess.run(  # noqa: S603 -- the consumer's verifier, as in the replay
            [*verifier, str(path)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
            env={k: v for k, v in os.environ.items() if k != "AEE_SUBSTRATE_KEYS"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"notrun ({exc})"
    return (
        "valid"
        if done.returncode == 0
        else "invalid"
        if done.returncode == 1
        else f"errored (exit {done.returncode})"
    )


Planned = tuple[dict[str, Any], str, Build, tuple[str, str]]


def plan(
    members: list[dict[str, Any]], corpus_dir: Path, mode: str, seed: bytes | None
) -> tuple[list[Planned], dict[tuple[str, str], Build], list[str], list[str]]:
    """Every mutant of every member, unbuilt, with its control; the members refused or skipped."""
    planned: list[Planned] = []
    controls: dict[tuple[str, str], Build] = {}
    refusals: list[str] = []
    skipped: list[str] = []
    for member in members:
        raw = (corpus_dir / member["path"]).read_bytes()
        for item in mutants(raw, mode, seed):
            if len(item) == 2:
                (skipped if item[1].startswith(SKIP) else refusals).append(
                    f"{member['id']}: {item[1].removeprefix(SKIP)}"
                )
                break
            name, build, (control_name, control_build) = item
            key = (member["id"], control_name)
            controls.setdefault(key, control_build)
            planned.append((member, name, build, key))
    return planned, controls, refusals, skipped


def file_name(member_id: str, suffix: str) -> str:
    """A temporary file name for a member's mutant: the id may hold `/` or `..`."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", member_id).lstrip(".")[:80] or "member"
    return f"{safe}-{suffix}.json"


def compare(mine: str, theirs: str | None, label: str, tally: dict[str, Any]) -> None:
    """File one mutant's two verdicts under checked, survivor, disagreement or unjudged."""
    if theirs is None:
        tally["unjudged"].append(label)
    elif mine != theirs:
        tally["disagreements"].append(f"{label}: verifier under test {mine}, reference {theirs}")
    elif mine == "invalid":
        tally["agreed"] += 1
        tally["checked"] += 1
    else:
        tally["agreed"] += 1
        tally["survivors"].append(f"{label}: both verifiers say {mine}")


def judge_controls(
    keys: set[tuple[str, str]],
    controls: dict[tuple[str, str], Build],
    verifier: list[str],
    route: tuple[Any, str] | None,
    root: Path,
) -> dict[tuple[str, str], str | None]:
    """Each needed control judged by both verifiers: None when both accept it, else why not."""
    failed: dict[tuple[str, str], str | None] = {}
    for number, key in enumerate(sorted(keys)):
        member_id, name = key
        path = root / file_name(member_id, f"c{number:06d}")
        path.write_bytes(controls[key]())
        mine = candidate(verifier, path)
        theirs = None
        if route is not None:
            try:
                theirs = route[0]({"id": member_id, "file": path.name}, root)
            except Exception as exc:  # noqa: BLE001 -- one control must not hide the rest
                theirs = f"errored ({exc!r})"
        path.unlink()
        if mine == "valid" and theirs in (None, "valid"):
            failed[key] = None
        else:
            failed[key] = (
                f"{member_id}: the unmutated member ({name}) is {mine} to the verifier under "
                f"test and {theirs or 'unjudged'} to the reference, so a rejected mutant of it "
                "says nothing about its edit"
            )
    return failed


def run(mode: str, verifier: list[str], corpus_dir: Path, limit: int) -> dict[str, Any]:
    manifest = action_checks.manifest_of(corpus_dir) or {}
    members = [
        m
        for m in action_checks.listed_members(manifest)
        if str(m["entry"].get("kind") or m["entry"].get("disposition"))
        in action_checks.ACCEPT_KINDS
    ]
    route = reference_route(manifest)
    planned, controls, refusals, skipped = plan(members, corpus_dir, mode, key_seed(manifest))
    chosen = sample(len(planned), limit)
    tally: dict[str, Any] = {
        "checked": 0,
        "agreed": 0,
        "survivors": [],
        "disagreements": [],
        "unjudged": [],
        "uncontrolled": 0,
    }
    with tempfile.TemporaryDirectory(prefix="aev-mutants-") as tmp:
        root = Path(tmp)
        control = judge_controls({planned[i][3] for i in chosen}, controls, verifier, route, root)
        control_failures = [why for why in control.values() if why]
        refusals.extend(control_failures)
        for index in sorted(chosen):
            member, name, build, key = planned[index]
            if control[key]:
                tally["uncontrolled"] += 1
                continue
            path = root / file_name(member["id"], f"m{index:06d}")
            path.write_bytes(build())
            theirs = None
            if route is not None:
                try:
                    theirs = route[0]({"id": member["id"], "file": path.name}, root)
                except Exception as exc:  # noqa: BLE001 -- one mutant must not hide the rest
                    theirs = f"errored ({exc!r})"
            compare(candidate(verifier, path), theirs, f"{member['id']} #{index} ({name})", tally)
            path.unlink()
    notes = [] if route else ["no reference route into this corpus, so no mutant was compared"]
    if tally["uncontrolled"]:
        notes.append(
            f"{tally['uncontrolled']} mutants were not compared: their unmutated control was "
            "not accepted by both verifiers"
        )
    if skipped:
        notes.append(
            f"{len(skipped)} of {len(members)} accept members have nothing to mutate in {mode} mode"
        )
        notes.extend(skipped[:MAX_ROWS])
    judged = len(chosen)
    return {
        "mode": mode,
        "checked": tally["checked"],
        "total": judged,
        "generated": len(planned),
        "sampled": judged < len(planned),
        "agreement": tally["agreed"],
        "survivors": tally["survivors"],
        "disagreements": tally["disagreements"],
        "refusals": refusals,
        "controls": {"judged": len(control), "failed": len(control_failures)},
        "notes": notes,
        "referenceVerifierId": route[1] if route else None,
        "pass": bool(judged) and tally["checked"] == judged and not refusals,
    }


def main() -> int:
    mode = required("MUTATE")
    report_path = Path(required("REPORT"))
    corpus_dir = Path(required("CORPUS_DIR"))
    summary_path = required("GITHUB_STEP_SUMMARY")
    output_path = required("GITHUB_OUTPUT")
    try:
        verifier = action_checks.split_command(os.environ.get("VERIFIER", ""))
    except ValueError:
        verifier = []
    limit = int(os.environ.get("MUTATE_LIMIT") or 2000)
    if mode not in ("structural", "bytes"):
        sys.exit(f"action-mutate-stage: mutate must be none, structural or bytes, not {mode!r}")
    if not verifier:
        result: dict[str, Any] = {
            "mode": mode,
            "checked": 0,
            "total": 0,
            "generated": 0,
            "sampled": False,
            "agreement": 0,
            "survivors": [],
            "disagreements": [],
            "refusals": [],
            "controls": {"judged": 0, "failed": 0},
            "notes": ["mutate needs the `verifier` input"],
            "referenceVerifierId": None,
            "pass": False,
        }
    else:
        result = run(mode, verifier, corpus_dir, limit)
    line = f"mutation-checked {result['checked']} of {result['total']}"
    print(line)
    for item in (
        result["refusals"] + result["notes"] + result["survivors"] + result["disagreements"]
    ):
        print(item)
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["mutation"] = {k: v for k, v in result.items() if k != "referenceVerifierId"}
        if result["referenceVerifierId"]:
            report.setdefault("reference", {}).setdefault(
                "verifier", {"id": result["referenceVerifierId"]}
            )
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    rows = [f"## agent-evidence-vectors: {line} ({mode})\n\n"]
    if result["sampled"]:
        rows.append(
            f"A deterministic sample of {result['total']} of {result['generated']} "
            "mutants was judged.\n\n"
        )
    rows.append(
        f"Both rejected {result['checked']}; the verdicts agree on {result['agreement']}; "
        f"{len(result['survivors'])} survived both; {len(result['disagreements'])} disagree.\n\n"
    )
    for title, items in (
        ("refused", result["refusals"]),
        ("note", result["notes"]),
        ("survivor", result["survivors"]),
        ("disagreement", result["disagreements"]),
    ):
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
