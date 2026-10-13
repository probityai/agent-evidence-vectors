"""Write the binding cases and controls under cases/, then rewrite INPUTS.json.

Every case input is derived, deterministically, from a pinned upstream vector and
this repository's observed-effect generator (its fixed test observer key), so a
rerun reproduces every byte. The test suite regenerates into a scratch directory and
requires byte identity with the committed files.

    python gen_cases.py            # rewrite cases/ and INPUTS.json in place
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import bind
import kernel
import pins

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "fixtures" / "aae-v1.4.0"
GENERATOR = bind.REPOSITORY / "vectors-observed-effect" / "gen_vectors.py"

FULL = "CLAIMED_BY_BOUND_RECORD"


def generator() -> ModuleType:
    """This repository's observed-effect generator, loaded under a unique name."""
    spec = importlib.util.spec_from_file_location("aev_observed_effect_gen_vectors", GENERATOR)
    if spec is None or spec.loader is None:
        raise SystemExit("the observed-effect generator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def vector(prefix: str) -> dict[str, Any]:
    path = next(path for path in sorted(VECTORS.glob("*.json")) if path.name.startswith(prefix))
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def verdict_record(prefix: str) -> dict[str, Any]:
    """The record the kernel produces for an enforce vector; it must hit the vector."""
    given = vector(prefix)
    outcome = kernel.enforce_check(given["input"]["mandate"], given["input"]["transaction"])
    if outcome.core_digest != given["expected"]["core_digest"]:
        raise SystemExit(f"vector {prefix} does not reproduce; refusing to write cases")
    return {"core": outcome.core, "core_digest": outcome.core_digest}


def evidence(gen: ModuleType, cited: str) -> dict[str, Any]:
    """A signed observed-effect envelope whose authorityDigest is ``cited``."""
    envelope: dict[str, Any] = gen.envelope(gen.statement(gen.predicate(authorityDigest=cited)))
    return envelope


def one_digit_changed(digest: str) -> str:
    """Change the last hex digit, so exactly one character of the citation differs."""
    return digest[:-1] + format((int(digest[-1], 16) + 1) % 16, "x")


def broken_signature(envelope: dict[str, Any]) -> dict[str, Any]:
    """Flip one bit of the DSSE signature and leave every other byte alone."""
    signature = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
    signature[0] ^= 0x01
    changed = json.loads(json.dumps(envelope))
    changed["signatures"][0]["sig"] = base64.b64encode(bytes(signature)).decode("ascii")
    return dict(changed)


def expect(
    verdict: str,
    binding: str,
    evidence_verdict: str,
    execution: str = "UNKNOWN",
    recomputed: bool = True,
    ratification: str = "NOT_REQUESTED",
) -> dict[str, Any]:
    """A declared per-claim outcome in the dotted form bind.claim_values produces."""
    return {
        "authorization.core_digest_recomputed": recomputed,
        "authorization.verdict": verdict,
        "authorization.ratification.status": ratification,
        "binding.status": binding,
        "evidence.verifier_verdict": evidence_verdict,
        "execution.status": execution,
        "completeness.status": "NOT_ESTABLISHED",
    }


def cases(gen: ModuleType) -> list[dict[str, Any]]:
    """Three cases and four controls, each with the inputs and its declared outcome."""
    permit = verdict_record("01")
    deny = verdict_record("02")
    cited = bind.record_digest(permit)
    bound = evidence(gen, cited)
    mutated = json.loads(json.dumps(permit))
    mutated["core"]["trace"][4]["value"] = 900
    prior = vector("25")["input"]
    return [
        {"name": "B1-valid-binding", "role": "case", "record": permit, "evidence": bound,
         "describe": "The vector 01 PERMIT record and an observed-effect record citing it.",
         "expect": expect("PERMIT", "MATCH", "valid", FULL)},
        {"name": "B2-mismatched-digest", "role": "case", "record": permit,
         "evidence": evidence(gen, one_digit_changed(cited)),
         "describe": "The same PERMIT record; the evidence citation differs in one hex digit.",
         "expect": expect("PERMIT", "MISMATCH", "valid")},
        {"name": "B3-missing-receipt", "role": "case", "record": permit,
         "describe": "The PERMIT record with no evidence record; execution stays unknown.",
         "expect": expect("PERMIT", "ABSENT", "absent")},
        {"name": "C1-mutated-core", "role": "control", "record": mutated, "evidence": bound,
         "describe": "A trace value in the PERMIT core is changed; core_digest is kept.",
         "expect": expect("PERMIT", "MISMATCH", "valid", recomputed=False)},
        {"name": "C2-permit-digest-for-deny", "role": "control", "record": deny,
         "evidence": bound,
         "describe": "The vector 02 DENY record offered with evidence citing the PERMIT record.",
         "expect": expect("DENY", "MISMATCH", "valid")},
        {"name": "C3-ratification-link-elsewhere", "role": "control",
         "record": prior["prior_record"],
         "ratification": {key: prior[key] for key in
                          ("decision", "authority_proof", "prev_core_digest")},
         "describe": "Vector 25: a ratification whose prev_core_digest names another record.",
         "expect": expect("DENY", "ABSENT", "absent", ratification="CALLER_ERROR")},
        {"name": "C4-tampered-evidence", "role": "control", "record": permit,
         "evidence": broken_signature(bound),
         "describe": "B1 with one bit of the evidence signature flipped.",
         "expect": expect("PERMIT", "MATCH", "invalid")},
    ]


def render(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True) + "\n"


def write_cases(root: Path, gen: ModuleType) -> None:
    """Write each case directory: verdict-record, optional evidence and ratification."""
    for case in cases(gen):
        target = root / case["name"]
        target.mkdir(parents=True, exist_ok=True)
        (target / "verdict-record.json").write_text(render(case["record"]), encoding="ascii")
        if "evidence" in case:
            (target / "evidence.dsse.json").write_text(render(case["evidence"]), encoding="ascii")
        if "ratification" in case:
            (target / "ratification.json").write_text(
                render(case["ratification"]), encoding="ascii"
            )
        declared = {key: case[key] for key in ("name", "role", "describe", "expect")}
        (target / "expected.json").write_text(render(declared), encoding="ascii")


if __name__ == "__main__":
    write_cases(HERE / "cases", generator())
    pins.PINS.write_text(pins.render(pins.build()), encoding="ascii")
    sys.exit(0)
