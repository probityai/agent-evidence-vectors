"""Build the HTX case pairs byte-identically.

Every case is plain JSON in one of two shapes. Transaction confirmation: HTX
P18.01 section 6 (a changed detail must not inherit an earlier approval).
Consent and disclosure: a proposal of this repository for what the HTX pattern
pages do not yet say (what is disclosed is within what the person agreed to
share, for the stated purpose). Each control is accepted, and each reject
differs from its control by exactly one field, named in ``changedField``.
Every member is synthetic.
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
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import htxcases as reader  # noqa: E402

SUITE = reader.SUITE
RESULT = {"allow": "accept", "deny": "reject"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


PAYMENT = {
    "beneficiary": "acct:0042",
    "amount": "350.00",
    "currency": "CHF",
    "scope": "single-payment",
}
TRANSACTION_CONTROL: dict[str, Any] = {
    "confirmation": {"outcome": "confirmed", "request": dict(PAYMENT)},
    "action": {"request": dict(PAYMENT)},
}
CONSENT_CONTROL: dict[str, Any] = {
    "consent": {
        "outcome": "agreed",
        "purpose": "age-check",
        "recipient": "verifier:0007",
        "fields": {"required": ["date_of_birth"], "optional_granted": []},
        "refused_optional": ["home_address"],
    },
    "disclosure": {
        "purpose": "age-check",
        "recipient": "verifier:0007",
        "fields": ["date_of_birth"],
    },
}


def edited(control: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    """A copy of ``control`` with the one value at the dotted ``path`` replaced."""
    body = copy.deepcopy(control)
    node = body
    *parents, last = path.split(".")
    for key in parents:
        node = node[key]
    node[last] = value
    return body


Case = tuple[str, dict[str, Any], str, str, str, str | None, str | None]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, what it shows, control id, changed field."""
    tx, co = "allow-request-matches-confirmation", "allow-disclosure-within-consent"
    accepted_tx, accepted_co = (
        reader.ALLOWED_REASONS[reader.TRANSACTION],
        reader.ALLOWED_REASONS[reader.CONSENT],
    )
    changed = "request-changed-after-confirmation"

    def tx_reject(name: str, path: str, value: Any, reason: str, edit: str) -> Case:
        return (name, edited(TRANSACTION_CONTROL, path, value), "deny", reason, edit, tx, path)

    def co_reject(name: str, path: str, value: Any, reason: str, edit: str) -> Case:
        return (name, edited(CONSENT_CONTROL, path, value), "deny", reason, edit, co, path)

    return [
        (
            tx,
            copy.deepcopy(TRANSACTION_CONTROL),
            "allow",
            accepted_tx,
            "control: the action's request is the request the person confirmed",
            None,
            None,
        ),
        tx_reject(
            "reject-beneficiary-changed",
            "action.request.beneficiary",
            "acct:0917",
            changed,
            "the beneficiary changed after the confirmation",
        ),
        tx_reject(
            "reject-amount-changed",
            "action.request.amount",
            "3500.00",
            changed,
            "the amount changed after the confirmation",
        ),
        tx_reject(
            "reject-currency-changed",
            "action.request.currency",
            "EUR",
            changed,
            "the currency changed after the confirmation",
        ),
        tx_reject(
            "reject-scope-changed",
            "action.request.scope",
            "recurring",
            changed,
            "the scope changed after the confirmation, from one payment to a standing one",
        ),
        tx_reject(
            "reject-confirmation-declined",
            "confirmation.outcome",
            "declined",
            "not-confirmed",
            "the person declined, and the request is otherwise unchanged",
        ),
        (
            co,
            copy.deepcopy(CONSENT_CONTROL),
            "allow",
            accepted_co,
            "control: the disclosure is a subset of what the person agreed to, for the stated "
            "purpose and recipient",
            None,
            None,
        ),
        co_reject(
            "reject-field-beyond-consent",
            "disclosure.fields",
            ["date_of_birth", "nationality"],
            "field-not-consented",
            "a field the person never agreed to share is disclosed",
        ),
        co_reject(
            "reject-refused-field-disclosed",
            "disclosure.fields",
            ["date_of_birth", "home_address"],
            "refused-field-disclosed",
            "an optional field the person refused is disclosed anyway",
        ),
        co_reject(
            "reject-purpose-changed",
            "disclosure.purpose",
            "marketing",
            "purpose-changed",
            "the disclosure serves another purpose than the consented one",
        ),
        co_reject(
            "reject-recipient-changed",
            "disclosure.recipient",
            "verifier:0911",
            "recipient-changed",
            "the disclosure goes to another recipient",
        ),
        co_reject(
            "reject-consent-declined-with-disclosure",
            "consent.outcome",
            "declined",
            "not-agreed",
            "the person declined, and fields are disclosed anyway",
        ),
    ]


def diff_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    """The dotted paths at which two parsed JSON values differ."""
    if isinstance(left, dict) and isinstance(right, dict):
        found: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                found.append(f"{prefix}{key}")
            else:
                found += diff_paths(left[key], right[key], f"{prefix}{key}.")
        return found
    return [] if left == right else [prefix.rstrip(".")]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    built = cases()
    bodies = {case[0]: case[1] for case in built}
    entries = []
    for name, body, decision, reason, edit, control, field in built:
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entry: dict[str, Any] = {
            "edit": edit,
            "expected": expected,
            "files": {"record.json": _sha(data)},
            "htxExpected": (
                {"result": RESULT[decision]}
                if decision == "allow"
                else {"reason": reason, "result": RESULT[decision]}
            ),
            "id": name,
            "path": f"cases/{name}",
            "retained": reader.retained(body),
        }
        if control is not None and field is not None:
            if diff_paths(bodies[control], body) != [field]:
                raise SystemExit(f"{name}: differs from {control} in more than {field}")
            entry["changedField"], entry["control"] = field, control
        entries.append(entry)
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


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


if __name__ == "__main__":
    generate()
