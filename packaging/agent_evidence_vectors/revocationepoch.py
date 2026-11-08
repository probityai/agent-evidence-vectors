"""Judge whether a permit and its effect were checked against the revocation state in force.

A revocation that only the permit broker reads is cooperative: work already
admitted keeps running, a worker that ignores the list still reaches the
network, and a broker that read an old or forged list mints a permit nobody can
tell from a good one. This contract asks the record to prove the opposite. A
trusted issuer publishes signed revocation lists (SRLs) under a strictly
increasing ``epoch``. The permit names the list it was checked against
(``permit.srl``: epoch and digest) and so does the effect, where it lands
(``effect.srl``). A witness log orders every grant, list, permit and effect.
A permit or effect that names no list carries no ``srl`` member: absent is not
empty, and an empty list at a stated epoch is a legitimate state.

The record carries the grant the permit rests on, the trusted list issuers,
``freshnessSeconds`` (a list may be used for a decision only while it is younger
than this), every list, the permit, the effect and the witness log. Every
digest is ``sha256:`` over the JCS bytes of its object and is recomputed here;
a digest in the record is a claim to check. A list covers the work when it
revokes the grant's digest, its parent grant's digest, the holder key or the
permit's authority key. A revocation is never undone: a list witnessed before
the effect that covers it stops the effect even when a later list drops the
entry. A restored principal gets a new grant.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the revocation-epoch contract (``contract_id_unknown``);
3. the record has the fields and types the contract names, every number
   anywhere in it is an integer, every time parses, and the witness log's ``seq`` strictly
   increases while its ``at`` never goes back (``malformed_record``);
4. every list was issued by a trusted issuer (``srl_issuer_untrusted``);
5. the permit and the effect name the recomputed grant digest and the effect
   names the permit (``grant_binding_mismatch``);
6. no two lists share an epoch with different content, a later epoch is
   issued later, and the witness log never sees an epoch go back
   (``srl_epoch_not_monotonic``);
7. the permit and the effect each carry an ``srl`` member (``srl_absent``);
8. each names an epoch some list has and that list's recomputed digest
   (``srl_digest_mismatch``);
9. the permit's list was in force when the permit was issued: younger than
   ``freshnessSeconds`` at the later of ``issuedAt`` and the permit's witness
   time, not issued after it, not witnessed after the permit, and no newer list
   witnessed before the permit (``srl_stale_at_permit``);
10. the permit's list does not cover the work (``revoked_at_permit``);
11. no list witnessed before the effect covers the work, unless the effect
    was ``not-applied`` (``effect_after_revocation``);
12. the witness log orders everything: its ``seq`` runs from 1 with no gap, the
    permit, the effect and every list are in it, every witnessed list is in the
    record, the permit comes before the effect, and the effect's list before
    the effect (``revocation_order_ambiguous``);
13. the effect names the newest list witnessed before it
    (``effect_epoch_behind``);
14. the effect's list was younger than ``freshnessSeconds`` at the later of
    ``observedAt`` and the effect's witness time, and not issued after it
    (``srl_stale_at_effect``).

A record that passes all fourteen is ``allow``: ``revocation_enforced_at_effect``
when a covering list was witnessed before an effect that was ``not-applied``
(the enforcement point where the effect lands refused it), and ``not_revoked``
otherwise.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "revocation-epoch/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/revocation-epoch/v1"
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
ALLOW_REASONS = ("not_revoked", "revocation_enforced_at_effect")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "srl_issuer_untrusted",
    "grant_binding_mismatch",
    "srl_epoch_not_monotonic",
    "srl_absent",
    "srl_digest_mismatch",
    "srl_stale_at_permit",
    "revoked_at_permit",
    "effect_after_revocation",
    "revocation_order_ambiguous",
    "effect_epoch_behind",
    "srl_stale_at_effect",
)
WITNESS_KINDS = ("grant", "permit", "effect", "srl", "approval")
OUTCOMES = ("applied", "not-applied", "uncertain")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-revocation-epoch" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-revocation-epoch")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(value: object) -> str:
    """``sha256:`` over the JCS bytes of ``value`` (integers and strings only)."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + _sha(data.encode("utf-8"))


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _texts(value: Any, *, empty: bool) -> bool:
    return (isinstance(value, list) and (empty or bool(value))
            and all(isinstance(v, str) for v in value))


def _has_texts(obj: Any, names: tuple[str, ...]) -> bool:
    return isinstance(obj, dict) and all(isinstance(obj.get(n), str) for n in names)


def _srl_ref_ok(holder: dict[str, Any]) -> bool:
    if "srl" not in holder:
        return True
    ref = holder["srl"]
    return (isinstance(ref, dict) and _is_int(ref.get("epoch")) and ref["epoch"] >= 0
            and isinstance(ref.get("digest"), str))


def _srl_ok(srl: Any) -> bool:
    return (_has_texts(srl, ("issuedAt", "issuerKeyId")) and _is_int(srl.get("epoch"))
            and srl["epoch"] >= 0 and _texts(srl.get("revoked"), empty=True))


def _grant_ok(grant: Any) -> bool:
    return (_has_texts(grant, ("grantId", "issuer", "holder"))
            and (grant.get("parentDigest") is None or isinstance(grant["parentDigest"], str)))


def _witness_ok(entries: Any) -> bool:
    if not isinstance(entries, list):
        return False
    last_seq, last_at = 0, None
    for entry in entries:
        if not (_has_texts(entry, ("kind", "digest", "at")) and _is_int(entry.get("seq"))
                and entry["kind"] in WITNESS_KINDS and entry["seq"] > last_seq):
            return False
        at = _when(entry["at"])
        if last_at is not None and at < last_at:
            return False
        last_seq, last_at = entry["seq"], at
    return True


def _has_fraction(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_fraction(v) for v in value.values())
    return isinstance(value, list) and any(_has_fraction(v) for v in value)


def _malformed(record: dict[str, Any]) -> bool:
    if _has_fraction(record):
        return True
    permit, effect = record.get("permit"), record.get("effect")
    fresh = record.get("freshnessSeconds")
    shape = (
        _texts(record.get("trustedSrlIssuers"), empty=False)
        and _is_int(fresh) and fresh >= 1
        and isinstance(record.get("srls"), list) and all(_srl_ok(s) for s in record["srls"])
        and _grant_ok(record.get("grant"))
        and _has_texts(permit, ("permitId", "grantDigest", "authorityKeyId", "issuedAt"))
        and _has_texts(effect, ("effectId", "permitId", "grantDigest", "observerKeyId",
                                "observedAt", "outcome"))
    )
    if not shape or effect["outcome"] not in OUTCOMES:
        return True
    if not (_srl_ref_ok(permit) and _srl_ref_ok(effect)):
        return True
    try:
        for value in [permit["issuedAt"], effect["observedAt"],
                      *(s["issuedAt"] for s in record["srls"])]:
            _when(value)
        return not _witness_ok(record.get("witness"))
    except ValueError:
        return True


class _View:
    """The record's objects with every digest the checks rely on recomputed."""

    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record
        self.grant: dict[str, Any] = record["grant"]
        self.permit: dict[str, Any] = record["permit"]
        self.effect: dict[str, Any] = record["effect"]
        self.fresh: int = record["freshnessSeconds"]
        self.grant_digest = digest(self.grant)
        self.lists: dict[str, dict[str, Any]] = {digest(s): s for s in record["srls"]}
        self.witness: list[dict[str, Any]] = record["witness"]
        self.permit_seq = self.seq("permit", digest(self.permit))
        self.effect_seq = self.seq("effect", digest(self.effect))
        parent = self.grant.get("parentDigest")
        self.covered = {self.grant_digest, self.grant["holder"], self.permit["authorityKeyId"],
                        *([parent] if isinstance(parent, str) else [])}

    def seq(self, kind: str, value: str) -> int | None:
        for entry in self.witness:
            if (entry["kind"], entry["digest"]) == (kind, value):
                return int(entry["seq"])
        return None

    def at(self, seq: int | None) -> datetime | None:
        for entry in self.witness:
            if entry["seq"] == seq:
                return _when(entry["at"])
        return None

    def witnessed_lists(self) -> list[tuple[int, dict[str, Any]]]:
        """Every witnessed list the record carries, in witness order."""
        return [(int(e["seq"]), self.lists[e["digest"]]) for e in self.witness
                if e["kind"] == "srl" and e["digest"] in self.lists]

    def before(self, seq: int | None) -> list[dict[str, Any]]:
        return [] if seq is None else [s for n, s in self.witnessed_lists() if n < seq]

    def named(self, holder: dict[str, Any]) -> dict[str, Any] | None:
        """The list ``holder.srl`` names, when its epoch and digest match one."""
        ref = holder["srl"]
        found = self.lists.get(ref["digest"])
        return found if found is not None and found["epoch"] == ref["epoch"] else None

    def covers(self, srl: dict[str, Any]) -> bool:
        return bool(self.covered & set(srl["revoked"]))


def _untrusted(v: _View) -> bool:
    trusted = set(v.record["trustedSrlIssuers"])
    return any(s["issuerKeyId"] not in trusted for s in v.lists.values())


def _binding(v: _View) -> bool:
    return (v.permit["grantDigest"] != v.grant_digest or v.effect["grantDigest"] != v.grant_digest
            or v.effect["permitId"] != v.permit["permitId"])


def _not_monotonic(v: _View) -> bool:
    epochs: dict[int, str] = {}
    for key, srl in v.lists.items():
        if epochs.setdefault(srl["epoch"], key) != key:
            return True
    ordered = sorted(v.lists.values(), key=lambda s: s["epoch"])
    if any(_when(b["issuedAt"]) <= _when(a["issuedAt"]) for a, b in zip(ordered, ordered[1:])):
        return True
    seen = [s["epoch"] for _, s in v.witnessed_lists()]
    return any(b < a for a, b in zip(seen, seen[1:]))


def _absent(v: _View) -> bool:
    return "srl" not in v.permit or "srl" not in v.effect


def _digest_mismatch(v: _View) -> bool:
    return v.named(v.permit) is None or v.named(v.effect) is None


def _too_old(v: _View, srl: dict[str, Any], claimed: str, seq: int | None) -> bool:
    moment = _when(claimed)
    witnessed = v.at(seq)
    if witnessed is not None and witnessed > moment:
        moment = witnessed
    age = (moment - _when(srl["issuedAt"])).total_seconds()
    return age < 0 or age >= v.fresh


def _stale_at_permit(v: _View) -> bool:
    srl = v.named(v.permit)
    assert srl is not None
    if _too_old(v, srl, v.permit["issuedAt"], v.permit_seq):
        return True
    if v.permit_seq is None:
        return False
    listed = v.seq("srl", digest(srl))
    if listed is not None and listed > v.permit_seq:
        return True
    return any(s["epoch"] > srl["epoch"] for s in v.before(v.permit_seq))


def _revoked_at_permit(v: _View) -> bool:
    srl = v.named(v.permit)
    return srl is not None and v.covers(srl)


def _revoked_before_effect(v: _View) -> bool:
    return any(v.covers(s) for s in v.before(v.effect_seq))


def _after_revocation(v: _View) -> bool:
    return v.effect["outcome"] != "not-applied" and _revoked_before_effect(v)


def _ambiguous(v: _View) -> bool:
    if [e["seq"] for e in v.witness] != list(range(1, len(v.witness) + 1)):
        return True
    if v.permit_seq is None or v.effect_seq is None or v.effect_seq < v.permit_seq:
        return True
    if any(v.seq("srl", key) is None for key in v.lists):
        return True
    if any(e["kind"] == "srl" and e["digest"] not in v.lists for e in v.witness):
        return True
    own = v.seq("srl", v.effect["srl"]["digest"])
    return own is None or own > v.effect_seq


def _epoch_behind(v: _View) -> bool:
    return any(s["epoch"] > v.effect["srl"]["epoch"] for s in v.before(v.effect_seq))


def _stale_at_effect(v: _View) -> bool:
    srl = v.named(v.effect)
    assert srl is not None
    return _too_old(v, srl, v.effect["observedAt"], v.effect_seq)


_RULES: dict[str, Callable[[_View], bool]] = {
    "srl_issuer_untrusted": _untrusted,
    "grant_binding_mismatch": _binding,
    "srl_epoch_not_monotonic": _not_monotonic,
    "srl_absent": _absent,
    "srl_digest_mismatch": _digest_mismatch,
    "srl_stale_at_permit": _stale_at_permit,
    "revoked_at_permit": _revoked_at_permit,
    "effect_after_revocation": _after_revocation,
    "revocation_order_ambiguous": _ambiguous,
    "effect_epoch_behind": _epoch_behind,
    "srl_stale_at_effect": _stale_at_effect,
}


def _load(record_path: Path) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return record


def _failure(record: dict[str, Any], name: str) -> bool:
    if name == "contract_id_missing":
        return "contractId" not in record
    if name == "contract_id_unknown":
        return record.get("contractId", CONTRACT_ID) != CONTRACT_ID
    if name == "malformed_record":
        return _malformed(record)
    return _RULES[name](_View(record))


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. The checks after
    the contract checks read a record only once ``malformed_record`` has passed,
    so a skipped check can let a record fail in a later one.
    """
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if _failure(record, name):
                return name
        except (KeyError, TypeError, ValueError, IndexError, AttributeError, AssertionError):
            # A record an earlier check would have refused. With that check
            # switched off, the failure is a different one, so the tests see it.
            return "unreadable_record" if skip else "malformed_record"
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    record = _load(record_path)
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    try:
        enforced = record["effect"]["outcome"] == "not-applied" and _revoked_before_effect(
            _View(record))
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return {"decision": DENY, "reason": "unreadable_record"}
    return {"decision": ALLOW, "reason": ALLOW_REASONS[1] if enforced else ALLOW_REASONS[0]}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != value for name, value in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader.

    Returns the number of records answered and every disagreement.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        record_path = directory / "record.json"
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = _external_answer(command, record_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?",
                        help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
