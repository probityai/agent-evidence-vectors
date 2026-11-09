"""Build the execution-billing-finality cases byte-identically.

Every record is an observation, not a drawing: the generator runs the
reference adapter (``tests/billing_adapter.py``) over one scenario against the
P04 spend ledger, unmodified or with one mutant spliced in, and keeps what the
adapter printed. The allowed cases come from the unmodified ledger and pair
with the runtime scenario they ran. Each denied case is either a mutant's
observation, whose first failed check is the defect the mutant introduced, or
an allowed observation with one field changed, built so the check it names is
the first that fails.

The mutation table in the manifest is computed here too: every mutant runs
through every scenario, and the reader's verdict on each observation is kept.
The billing-clause mutant leaves every observation identical to the
unmodified ledger's, so it is recorded as equivalent in the code as written,
a surviving control and not a detected defect.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import executionbilling as reader  # noqa: E402

SUITE = reader.SUITE
ADAPTER = ROOT / "tests" / "billing_adapter.py"
LEDGER = ROOT / "tests" / "p04" / "exposure_ledger.py"
SOURCE = {
    "contributedBy": [
        {"name": "mohammedmessaoudene-cmd",
         "role": "P04 ledger, the F01, F03, F04, F05 and F14 scenarios, the input contract, "
                 "and the decision that dispatch_state is a required output",
         "url": "https://github.com/mohammedmessaoudene-cmd"},
        {"name": "piiiico (Agent Errata)",
         "role": "the X1 scenario, the three dispatch_start mutants and the M4 observation",
         "url": "https://github.com/piiiico"},
    ],
    "contract": "https://github.com/mohammedmessaoudene-cmd/agent-evidence-lab/blob/"
                "8db9989ee5eb071bad4c4c5618bdb8ef6cdb625c/collaborations/open-evidence-lab/"
                "p04-execution-billing/INPUT_CONTRACT.md",
    "issues": ["https://github.com/probityai/agent-evidence-vectors/issues/435",
               "https://github.com/probityai/agent-evidence-vectors/issues/485"],
    "ledger": {"gitBlob": "3b9599c4fa1063156b28aea0588634f9ca04cefe",
               "path": "tests/p04/exposure_ledger.py",
               "sha256": "c321eab3e1adfa2169164f63238597f1a1c2a7868d339540a3da574f09c82d0f"},
    "source": "mohammedmessaoudene-cmd/agent-evidence-lab at 8db9989, "
              "collaborations/open-evidence-lab/p04-execution-billing/",
}

GUARD = 'if row["dispatch_state"] != "RESERVED" or row["billing_finality"] != "UNKNOWN":'
INVOICE_WRITE = ("last_final_invoice=?,cost_evidence_seen=1,unbounded=0,dispatch_state='POSSIBLE',"
                 "updated_ns=? WHERE id=?")
NO_WRITE = "last_final_invoice=?,cost_evidence_seen=1,unbounded=0,updated_ns=? WHERE id=?"
NO_BILLING = 'if row["dispatch_state"] != "RESERVED":'
REMAINDER = ('remainder = 0 if row["billing_finality"] == "FINAL" else '
             'max(0, row["authorized_max"] - row["known"])')
# Each mutant: (summary, credit, splices). A splice must match exactly once.
MUTANTS: dict[str, tuple[str, str, list[tuple[str, str]]]] = {
    "M1-guard-removed": (
        "the dispatch_start guard is removed, so a repeated dispatch is allowed",
        "piiiico", [(GUARD, "if False:")]),
    "M2-final-billing-bypasses-guard": (
        "settled billing lets the same attempt dispatch again", "piiiico",
        [(GUARD, "if (" + GUARD[3:-1] + ') and row["billing_finality"] != "FINAL":')]),
    "M3-billing-clause-removed": (
        "the guard reads the dispatch state only; every write that settles billing also "
        "moves the dispatch state off RESERVED, so nothing can tell", "piiiico",
        [(GUARD, NO_BILLING)]),
    "M4-invoice-possible-write-removed": (
        "an invoice no longer moves the dispatch state to POSSIBLE", "piiiico",
        [(INVOICE_WRITE, NO_WRITE)]),
    "M5-M3-plus-M4": (
        "both: an invoice before any dispatch opens the gate", "piiiico",
        [(GUARD, NO_BILLING), (INVOICE_WRITE, NO_WRITE)]),
    "success-releases-exposure": (
        "a successful execution releases the reservation before any final bill",
        "mohammedmessaoudene-cmd",
        [(REMAINDER, REMAINDER.replace('== "FINAL" else',
                                       '== "FINAL" or row["outcome"] == "SUCCEEDED" else'))]),
    "invoice-implies-execution": (
        "a final invoice also marks the execution SUCCEEDED", "mohammedmessaoudene-cmd",
        [("UPDATE attempts SET known=?,billing_finality='FINAL',finality_basis='final_invoice',",
          "UPDATE attempts SET known=?,outcome='SUCCEEDED',billing_finality='FINAL',"
          "finality_basis='final_invoice',")]),
}
EQUIVALENT = {"M3-billing-clause-removed"}

DISPATCH = {"cmd": "dispatch"}
LOST = {"bounded": True, "cmd": "unknown"}
INVOICE = {"amount": 1, "cmd": "invoice", "event": "invoice-1"}
SECOND = {"cmd": "dispatch", "event": "second-dispatch"}
SUCCEEDED = {"cmd": "outcome", "value": "SUCCEEDED"}
RESERVE_B = {"amount": 2, "attempt": "B", "cmd": "reserve"}
# The scenarios, in P04's input format; the invariants are P04's (X1's is piiiico's).
SCENARIOS: dict[str, tuple[str, dict[str, Any]]] = {
    "F01": ("Success is not final billing",
            {"budget": 3, "probes": [RESERVE_B], "steps": [DISPATCH, SUCCEEDED]}),
    "F03": ("Bounded lost response retains liability",
            {"budget": 3, "probes": [SECOND], "steps": [DISPATCH, LOST]}),
    "F04": ("Final invoice does not establish execution",
            {"budget": 3, "probes": [SECOND, RESERVE_B], "steps": [DISPATCH, LOST, INVOICE]}),
    "F05": ("Real invoice releases only the remainder",
            {"budget": 3, "probes": [], "steps": [DISPATCH, SUCCEEDED, INVOICE]}),
    "F14": ("Positive control permits another affordable operation",
            {"budget": 4, "probes": [RESERVE_B], "steps": [DISPATCH]}),
    "X1": ("Invoice before any recorded dispatch does not open the gate",
           {"budget": 3,
            "probes": [{"cmd": "dispatch", "event": "late-dispatch"}, INVOICE,
                       {"amount": 1, "cmd": "cost", "event": "cost-after-invoice"}],
            "steps": [INVOICE]}),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def scenario(sid: str) -> dict[str, Any]:
    return {"id": sid, **copy.deepcopy(SCENARIOS[sid][1])}


def mutant_source(name: str, work: Path) -> Path:
    """Write the ledger with the mutant's splices applied, each matching exactly once."""
    text = LEDGER.read_text(encoding="utf-8")
    for old, new in MUTANTS[name][2]:
        if text.count(old) != 1:
            raise SystemExit(f"{name}: a splice matches {text.count(old)} times, not once")
        text = text.replace(old, new, 1)
    path = work / f"{name}.py"
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def observe(sid: str, source: Path, work: Path) -> dict[str, Any]:
    """Run the reference adapter over one scenario and return the record it printed."""
    path = work / f"{sid}.json"
    path.write_bytes(_json(scenario(sid)))
    result = subprocess.run([sys.executable, "-B", str(ADAPTER), str(path), "--json",
                             "--source", str(source)],
                            capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise SystemExit(f"the adapter failed on {sid}: {result.stderr[-400:]}")
    record: dict[str, Any] = json.loads(result.stdout.strip().splitlines()[-1])
    return record


def _edit(record: dict[str, Any], change: Any) -> dict[str, Any]:
    changed = copy.deepcopy(record)
    change(changed)
    return changed


# (id, scenario, source, edit or None, decision, reason, what the case shows)
Case = tuple[str, str, str, Any, str, str, str]


def cases() -> list[Case]:
    ok = reader.ALLOWED_REASON
    unmutated = "unmutated"
    boundaries = [b for b in reader.BOUNDARIES if b != "invoice_authenticity"]
    return [
        ("allow-f01-success-reservation-held", "F01", unmutated, None, "allow", ok,
         "control: the call succeeded and no final invoice came; the reservation stays held "
         "and another attempt for two units is refused"),
        ("allow-f01-control-final-invoice", "F05", unmutated, None, "allow", ok,
         "control for F01: the same success followed by a final invoice moves the reservation "
         "to known cost and releases only the remainder"),
        ("allow-f03-lost-reply-redispatch-refused", "F03", unmutated, None, "allow", ok,
         "control: the reply is lost, liability stays held and the second dispatch is refused"),
        ("allow-f04-invoice-after-lost-reply", "F04", unmutated, None, "allow", ok,
         "control: a final invoice after a lost reply settles billing, leaves the execution "
         "UNKNOWN, refuses a second dispatch of the attempt and admits a new attempt"),
        ("allow-f14-first-dispatch", "F14", unmutated, None, "allow", ok,
         "control: the first dispatch of a reserved attempt is allowed, so an always-refuse "
         "ledger fails"),
        ("allow-x1-invoice-before-dispatch", "X1", unmutated, None, "allow", ok,
         "control: an invoice arrives before any recorded dispatch; billing is FINAL, the "
         "execution UNKNOWN and the dispatch state POSSIBLE after the reopen, the refused "
         "dispatch, the replayed invoice and an equal cost observation"),
        ("contract-id-missing", "X1", unmutated, lambda r: r.pop("contractId"), "deny",
         "contract_id_missing", "the record carries no contractId"),
        ("contract-id-unknown", "X1", unmutated,
         lambda r: r.update(contractId=CONTRACT_OTHER), "deny", "contract_id_unknown",
         "the record names the uncertain-effect contract instead"),
        ("money-as-boolean", "F04", unmutated,
         lambda r: r["observed"].update(knownSpendMicroUsd=True), "deny", "record_malformed",
         "the known spend is the boolean true, which is not money"),
        ("dispatch-state-missing", "X1", unmutated,
         lambda r: [r[k].pop("dispatchState") for k in ("observed", "reopened")], "deny",
         "dispatch_state_missing",
         "the states after the invoice omit the dispatch state, the output the v0.1 reader "
         "dropped"),
        ("dispatch-state-null", "X1", unmutated,
         lambda r: r["probes"][0]["state"].update(dispatchState=None), "deny",
         "dispatch_state_missing", "the state after the refused dispatch reports null"),
        ("external-effect-established", "F04", unmutated,
         lambda r: r.update(externalEffect="ESTABLISHED"), "deny", "claim_boundary_dropped",
         "the observation claims an external effect a ledger cannot see"),
        ("claim-boundary-dropped", "F04", unmutated,
         lambda r: r.update(mustNotClaim=boundaries), "deny", "claim_boundary_dropped",
         "the observation no longer declines to claim invoice authenticity"),
        ("reopen-changed-state", "F04", unmutated,
         lambda r: r["reopened"].update(heldMicroUsd=2, availableMicroUsd=0), "deny",
         "reopen_changed_state", "the reopened ledger holds the reservation again"),
        ("f04-invoice-implies-execution", "F04", "invoice-implies-execution", None, "deny",
         "execution_outcome_without_observation",
         "a final invoice after a lost reply is read as a successful execution"),
        ("f01-success-releases-reservation", "F01", "success-releases-exposure", None, "deny",
         "held_released_before_final_billing",
         "the call succeeded and the reservation is released with no final bill"),
        ("f03-guard-removed-redispatch", "F03", "M1-guard-removed", None, "deny",
         "same_attempt_redispatched",
         "with the dispatch guard removed, a second dispatch after a lost reply is allowed"),
        ("f04-final-billing-redispatch", "F04", "M2-final-billing-bypasses-guard", None,
         "deny", "same_attempt_redispatched",
         "settled billing is read as permission to dispatch the same attempt again"),
        ("x1-invoice-opens-dispatch", "X1", "M5-M3-plus-M4", None, "deny",
         "same_attempt_redispatched",
         "an invoice before any recorded dispatch, then the gate opens for the first time"),
        ("x1-dispatch-state-reserved-after-invoice", "X1",
         "M4-invoice-possible-write-removed", None, "deny",
         "dispatch_state_reserved_after_billing",
         "billing is final and the dispatch state still reads RESERVED, as if nothing can "
         "have happened"),
        ("x1-invoice-replay-refinalized", "X1", unmutated,
         lambda r: r["probes"][1]["return"].update(newlyFinalized=True), "deny",
         "invoice_replay_refinalized", "the replayed invoice event is reported as finalizing"),
    ]


CONTRACT_OTHER = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"


def mutation_table(work: Path, base: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Every mutant through every scenario, with the reader's verdict on each observation."""
    rows = []
    for name, (summary, credit, _) in MUTANTS.items():
        source = mutant_source(name, work)
        killed: dict[str, str] = {}
        identical = True
        for sid in SCENARIOS:
            record = observe(sid, source, work)
            verdict = reader.decide(record)
            if verdict["decision"] == "deny":
                killed[sid] = verdict["reason"]
            unsourced = {k: v for k, v in record.items() if k != "sourceSha256"}
            identical &= unsourced == {k: v for k, v in base[sid].items() if k != "sourceSha256"}
        equivalent = name in EQUIVALENT
        if equivalent != (identical and not killed):
            raise SystemExit(f"{name}: equivalence {identical and not killed}, declared "
                             f"{equivalent}")
        rows.append({"credit": credit, "equivalent": equivalent, "id": name,
                     "killedBy": killed, "sha256": _sha(source.read_bytes()),
                     "summary": summary})
    return rows


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


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    with tempfile.TemporaryDirectory(prefix="aev-billing-gen-") as scratch:
        work = Path(scratch)
        base = {sid: observe(sid, LEDGER, work) for sid in SCENARIOS}
        mutants = {name: mutant_source(name, work) for name in MUTANTS}
        for name, sid, variant, change, decision, reason, edit in cases():
            record = (base[sid] if variant == "unmutated"
                      else observe(sid, mutants[variant], work))
            if change is not None:
                record = _edit(record, change)
            directory = root / "cases" / name
            directory.mkdir(parents=True)
            data = _json(record)
            (directory / "record.json").write_bytes(data)
            expected = {"decision": decision, "reason": reason}
            observed = reader.verify(directory / "record.json")
            if observed != expected:
                raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
            entry: dict[str, Any] = {
                "edit": edit, "expected": expected, "files": {"record.json": _sha(data)},
                "id": name, "path": f"cases/{name}", "retained": reader.retained(record),
                "source": {"invariant": SCENARIOS[sid][0], "p04Case": sid,
                           "variant": variant if change is None else f"{variant}, edited"},
            }
            if decision == "allow":
                entry["runtime"] = {"scenario": scenario(sid)}
            entries.append(entry)
        table = mutation_table(work, base)
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "mutants": table,
        "provenance": SOURCE,
        "runtimeContract": "runtime scenario.json --json; prints the record on its last line, "
                           "exit 0; see executionbilling_runtime",
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
