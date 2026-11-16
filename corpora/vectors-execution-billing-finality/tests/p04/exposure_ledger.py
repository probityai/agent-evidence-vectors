"""P04 R2 local accounting of known spend and unsettled exposure.

This is a one-account SQLite fixture, not a payment system or a distributed
exactly-once executor. Integer microdollars only. Cost observations are cumulative
lower bounds, not final invoices. A lost response or an unconfirmed cancellation
cannot release a reservation. Only an explicit final invoice or a fenced,
pre-dispatch non-dispatch proof can release the remainder.

Evidence is checked for semantic kind, source role and attempt scope. Those
assertions are supplied by a trusted adapter; no signature, remote authenticity
or real provider ceiling is established here. A finite authorized maximum is
not itself a physical provider billing guarantee. Set unbounded=True when the
remaining liability has no defensible finite bound; this blocks all admissions.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Iterator


MAX_MONEY = (1 << 63) - 1
SCHEMA_VERSION = 2


class LedgerError(RuntimeError):
    pass


class AdmissionDenied(LedgerError):
    pass


class ConfigurationConflict(LedgerError):
    pass


class UnknownAttempt(LedgerError):
    pass


class EvidenceValidationError(ValueError):
    pass


class EvidenceConflict(LedgerError):
    """Conflict persisted before raising; larger known liability is retained."""

    def __init__(self, message: str):
        super().__init__(message)
        self.evidence_persisted = True
        self.account_frozen = True


def _money(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_MONEY:
        raise ValueError(f"{name} must be a nonnegative integer <= {MAX_MONEY}")
    return value


def _id(value: str, name: str = "id") -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError(f"{name} must be a nonblank string of at most 512 characters")
    return value


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    reference: str
    attempt_id: str


SOURCES = {
    "cost_observation": {"provider_billing", "usage_meter"},
    "final_invoice": {"provider_billing"},
    "response_lost": {"client", "executor"},
    "unconfirmed_cancellation": {"client", "executor"},
    "non_dispatch_proof": {"dispatch_gate"},
    "dispatch_start": {"dispatch_gate"},
    "execution_outcome": {"executor", "provider_receipt"},
    "enforced_cost_ceiling": {"provider_contract", "enforcing_dispatcher"},
}


def _evidence(value: Evidence, kind: str, attempt_id: str) -> Evidence:
    if not isinstance(value, Evidence):
        raise EvidenceValidationError("an Evidence object is required")
    if value.kind != kind or value.source not in SOURCES[kind]:
        raise EvidenceValidationError(f"{kind} requires a matching semantic kind and source role")
    if value.attempt_id != attempt_id:
        raise EvidenceValidationError("evidence belongs to another attempt")
    _id(value.reference, "evidence.reference")
    return value


class ExposureLedger:
    """Transactions serialize cooperative local writers using the same file.

    No expiry, client disappearance or callback finalization flag frees money.
    Frozen accounts have no automatic unfreeze or refund facility. External
    effects must use mark_dispatch_started; reserve alone is not a dispatch.
    """

    def __init__(self, path: str | Path, budget_microusd: int | None = None):
        normalized_path = Path(path)
        if str(normalized_path) == ":memory:":
            raise ValueError("persistent SQLite file required")
        self.path = str(normalized_path.resolve())
        if budget_microusd is not None:
            _money(budget_microusd, "budget_microusd")
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("CREATE TABLE IF NOT EXISTS account (id INTEGER PRIMARY KEY CHECK(id=1), "
                             "version INTEGER NOT NULL, budget INTEGER NOT NULL CHECK(typeof(budget)='integer' AND budget>=0), "
                             "frozen INTEGER NOT NULL DEFAULT 0, freeze_reason TEXT)")
                conn.execute("CREATE TABLE IF NOT EXISTS attempts (id TEXT PRIMARY KEY, "
                             "authorized_max INTEGER NOT NULL CHECK(typeof(authorized_max)='integer' AND authorized_max>=0), "
                             "known INTEGER NOT NULL DEFAULT 0 CHECK(typeof(known)='integer' AND known>=0), "
                             "billing_finality TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(billing_finality IN ('UNKNOWN','FINAL','CONFLICT')), "
                             "finality_basis TEXT, last_final_invoice INTEGER, "
                             "outcome TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK(outcome IN ('UNKNOWN','SUCCEEDED','FAILED','NOT_DISPATCHED')), "
                             "dispatch_state TEXT NOT NULL DEFAULT 'RESERVED' CHECK(dispatch_state IN ('RESERVED','POSSIBLE','NOT_DISPATCHED')), "
                             "cost_evidence_seen INTEGER NOT NULL DEFAULT 0, unbounded INTEGER NOT NULL DEFAULT 0, "
                             "enforced_ceiling_evidence TEXT, "
                             "created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL)")
                conn.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, "
                             "payload TEXT NOT NULL, status TEXT NOT NULL, at_ns INTEGER NOT NULL)")
                conn.execute("CREATE TABLE IF NOT EXISTS conflicts (fingerprint TEXT PRIMARY KEY, event_id TEXT NOT NULL, "
                             "attempt_id TEXT NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL, at_ns INTEGER NOT NULL)")
                account = conn.execute("SELECT * FROM account WHERE id=1").fetchone()
                if account is None:
                    if budget_microusd is None:
                        raise ValueError("budget_microusd is required for a new ledger")
                    conn.execute("INSERT INTO account(id,version,budget) VALUES(1,?,?)", (SCHEMA_VERSION, budget_microusd))
                elif account["version"] != SCHEMA_VERSION:
                    raise ConfigurationConflict("unsupported schema: R2 schema 1 has no persisted ceiling evidence; use a fresh schema 2 file (no automatic migration)")
                elif budget_microusd is not None and account["budget"] != budget_microusd:
                    raise ConfigurationConflict("reopen cannot change the account authorization")
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA synchronous=FULL")
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _transaction(self, write: bool = True) -> Iterator[sqlite3.Connection]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    @staticmethod
    def _attempt_view(row) -> dict:
        remainder = 0 if row["billing_finality"] == "FINAL" else max(0, row["authorized_max"] - row["known"])
        return {
            "attempt_id": row["id"], "authorized_max_microusd": row["authorized_max"],
            "known_spend_microusd": row["known"], "still_exposed_reservation_microusd": remainder,
            "billing_finality": row["billing_finality"], "finality_basis": row["finality_basis"],
            "last_final_invoice_microusd": row["last_final_invoice"], "outcome": row["outcome"],
            "dispatch_state": row["dispatch_state"], "unbounded_exposure": bool(row["unbounded"]),
            "cost_evidence_seen": bool(row["cost_evidence_seen"]),
            "has_enforced_cost_ceiling": row["enforced_ceiling_evidence"] is not None,
            "enforced_ceiling_evidence": json.loads(row["enforced_ceiling_evidence"]) if row["enforced_ceiling_evidence"] else None,
            "authorization_overrun_microusd": max(0, row["known"] - row["authorized_max"]),
        }

    def _snapshot(self, conn) -> dict:
        account = conn.execute("SELECT * FROM account WHERE id=1").fetchone()
        attempts = [self._attempt_view(row) for row in conn.execute("SELECT * FROM attempts ORDER BY id")]
        known = sum(row["known_spend_microusd"] for row in attempts)
        exposed = sum(row["still_exposed_reservation_microusd"] for row in attempts)
        unbounded = sum(row["unbounded_exposure"] for row in attempts)
        nominal = account["budget"] - known - exposed
        return {
            "schema_version": account["version"], "authorized_budget_microusd": account["budget"],
            "known_spend_microusd": known, "still_exposed_reservation_microusd": exposed,
            "nominal_committed_microusd": known + exposed, "nominal_available_microusd": nominal,
            "unbounded_exposure_count": unbounded,
            "available_for_admission_microusd": 0 if account["frozen"] or unbounded else max(0, nominal),
            "frozen": bool(account["frozen"]), "freeze_reason": account["freeze_reason"],
            "attempts": attempts, "event_count": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "conflict_count": conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0],
        }

    def snapshot(self) -> dict:
        with self._transaction(write=False) as conn:
            return self._snapshot(conn)

    @staticmethod
    def _freeze(conn, reason: str):
        conn.execute("UPDATE account SET frozen=1,freeze_reason=COALESCE(freeze_reason,?) WHERE id=1", (reason,))

    def reserve(self, attempt_id: str, authorized_max_microusd: int) -> dict:
        attempt_id = _id(attempt_id, "attempt_id")
        maximum = _money(authorized_max_microusd, "authorized_max_microusd")
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            if row is not None:
                if row["authorized_max"] != maximum:
                    raise ConfigurationConflict("attempt id reused with another authorized maximum")
                return {"newly_reserved": False, "dispatch_allowed": False, "attempt": self._attempt_view(row)}
            snap = self._snapshot(conn)
            if snap["frozen"] or snap["unbounded_exposure_count"] or maximum > snap["available_for_admission_microusd"]:
                raise AdmissionDenied("account frozen, liability unbounded, or insufficient available authorization")
            now = time.time_ns()
            conn.execute("INSERT INTO attempts(id,authorized_max,created_ns,updated_ns) VALUES(?,?,?,?)", (attempt_id, maximum, now, now))
            row = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            return {"newly_reserved": True, "dispatch_allowed": False, "attempt": self._attempt_view(row)}

    def observe_cost(self, attempt_id: str, event_id: str, cumulative_known_microusd: int, evidence: Evidence) -> dict:
        return self._event(attempt_id, event_id, "cost_observation", evidence,
                           amount=_money(cumulative_known_microusd, "cumulative_known_microusd"))

    def mark_unknown(self, attempt_id: str, event_id: str, *, reason: str = "response_lost",
                     unbounded: bool = True, evidence: Evidence, bound_evidence: Evidence | None = None) -> dict:
        if reason not in {"response_lost", "unconfirmed_cancellation"} or type(unbounded) is not bool:
            raise EvidenceValidationError("unknown reason or bound flag is invalid")
        # Authorization/pricing estimates do not prove a provider liability bound.
        # An adapter may assert a finite enforced ceiling only with distinct,
        # attempt-scoped contract evidence. Authenticity remains a trust boundary.
        if not unbounded or bound_evidence is not None:
            _evidence(bound_evidence, "enforced_cost_ceiling", attempt_id)
        return self._event(attempt_id, event_id, reason, evidence, unbounded=unbounded,
                           bound_evidence=asdict(bound_evidence) if bound_evidence is not None else None)

    def finalize_invoice(self, attempt_id: str, event_id: str, final_cost_microusd: int, evidence: Evidence) -> dict:
        return self._event(attempt_id, event_id, "final_invoice", evidence,
                           amount=_money(final_cost_microusd, "final_cost_microusd"))

    def confirm_non_dispatch(self, attempt_id: str, event_id: str, evidence: Evidence) -> dict:
        return self._event(attempt_id, event_id, "non_dispatch_proof", evidence)

    def mark_dispatch_started(self, attempt_id: str, event_id: str, evidence: Evidence, *,
                              bounded_by_authorization: bool = False, bound_evidence: Evidence | None = None) -> dict:
        if type(bounded_by_authorization) is not bool or not bounded_by_authorization:
            raise AdmissionDenied("dispatch needs an explicit external finite-ceiling assumption; this fixture cannot prove it")
        _evidence(bound_evidence, "enforced_cost_ceiling", attempt_id)
        return self._event(attempt_id, event_id, "dispatch_start", evidence, bounded_by_authorization=True,
                           bound_evidence=asdict(bound_evidence))

    def observe_outcome(self, attempt_id: str, event_id: str, outcome: str, evidence: Evidence) -> dict:
        if outcome not in {"SUCCEEDED", "FAILED"}:
            raise EvidenceValidationError("only an actually observed terminal execution outcome is accepted")
        return self._event(attempt_id, event_id, "execution_outcome", evidence, outcome=outcome)

    def _conflict(self, conn, attempt_id: str, event_id: str, payload: str, reason: str, amount=None):
        row = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
        known = max(row["known"], amount if amount is not None else row["known"])
        # A contradictory larger receipt remains visible even though the call raises.
        conn.execute("UPDATE attempts SET known=?,billing_finality='CONFLICT',unbounded=1,"
                     "cost_evidence_seen=MAX(cost_evidence_seen,?),dispatch_state='POSSIBLE',"
                     "outcome=CASE WHEN outcome='NOT_DISPATCHED' THEN 'UNKNOWN' ELSE outcome END,updated_ns=? WHERE id=?",
                     (known, int(amount is not None), time.time_ns(), attempt_id))
        fingerprint = hashlib.sha256((event_id + "\n" + attempt_id + "\n" + payload).encode()).hexdigest()
        conn.execute("INSERT OR IGNORE INTO conflicts(fingerprint,event_id,attempt_id,reason,payload,at_ns) VALUES(?,?,?,?,?,?)",
                     (fingerprint, event_id, attempt_id, reason, payload, time.time_ns()))
        self._freeze(conn, reason)

    def _event(self, attempt_id: str, event_id: str, kind: str, evidence: Evidence, **values) -> dict:
        attempt_id, event_id = _id(attempt_id, "attempt_id"), _id(event_id, "event_id")
        _evidence(evidence, kind, attempt_id)
        payload = json.dumps({"attempt_id": attempt_id, "kind": kind, "evidence": asdict(evidence), **values},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        conflict_reason = None
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            if row is None:
                raise UnknownAttempt(attempt_id)
            old = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            newly_finalized = dispatch_allowed = changed = False
            if old is not None:
                if old["payload"] == payload:
                    if old["status"] == "CONFLICT":
                        conflict_reason = "repeated event was already recorded as conflicting"
                else:
                    conflict_reason = "durable event id reused with a conflicting payload"
                    self._conflict(conn, attempt_id, event_id, payload, conflict_reason, values.get("amount"))
                    if old["attempt_id"] != attempt_id:
                        self._conflict(conn, old["attempt_id"], event_id, old["payload"], conflict_reason)
                new_event = False
            else:
                new_event = True
                before = self._attempt_view(row)
                amount = values.get("amount")
                if kind == "cost_observation":
                    if row["billing_finality"] == "FINAL" and amount > row["known"]:
                        conflict_reason = "observed liability exceeds a previously final bill"
                    elif row["dispatch_state"] == "NOT_DISPATCHED":
                        conflict_reason = "cost evidence contradicts confirmed non-dispatch"
                    else:
                        known = max(row["known"], amount)
                        unbounded = (row["unbounded"] or (row["billing_finality"] != "FINAL" and
                                     row["enforced_ceiling_evidence"] is None))
                        conn.execute("UPDATE attempts SET known=?,cost_evidence_seen=1,dispatch_state='POSSIBLE',unbounded=?,updated_ns=? WHERE id=?",
                                     (known, int(unbounded), time.time_ns(), attempt_id))
                        if known > row["authorized_max"]:
                            if row["billing_finality"] != "FINAL":
                                conn.execute("UPDATE attempts SET unbounded=1 WHERE id=?", (attempt_id,))
                            self._freeze(conn, "observed expense exceeds the authorized per-attempt maximum")
                elif kind == "final_invoice":
                    if amount < row["known"]:
                        conflict_reason = "a final invoice cannot erase already known cumulative expense"
                    elif row["billing_finality"] == "CONFLICT":
                        conflict_reason = "billing conflict needs external/manual resolution; no automatic release"
                    elif row["billing_finality"] == "FINAL" and (row["finality_basis"] != "final_invoice" or amount != row["last_final_invoice"]):
                        conflict_reason = "contradictory finality evidence"
                    else:
                        newly_finalized = row["billing_finality"] != "FINAL"
                        conn.execute("UPDATE attempts SET known=?,billing_finality='FINAL',finality_basis='final_invoice',"
                                     "last_final_invoice=?,cost_evidence_seen=1,unbounded=0,dispatch_state='POSSIBLE',updated_ns=? WHERE id=?",
                                     (amount, amount, time.time_ns(), attempt_id))
                        if amount > row["authorized_max"]:
                            self._freeze(conn, "final invoice exceeds the authorized per-attempt maximum")
                elif kind in {"response_lost", "unconfirmed_cancellation"}:
                    if row["dispatch_state"] == "NOT_DISPATCHED":
                        conflict_reason = "possible dispatch contradicts confirmed non-dispatch"
                    elif not values["unbounded"] and row["known"] > row["authorized_max"]:
                        conflict_reason = "asserted ceiling is below already known expense"
                    else:
                        # Execution uncertainty cannot overturn an authoritative bill.
                        if row["billing_finality"] == "FINAL":
                            unbounded = False
                        elif row["billing_finality"] == "CONFLICT":
                            unbounded = True
                        else:
                            # A new explicit trusted contract can establish a finite
                            # ceiling after a previous missing-bound observation.
                            unbounded = values["unbounded"]
                        ceiling = (json.dumps(values["bound_evidence"], sort_keys=True)
                                   if not values["unbounded"] else row["enforced_ceiling_evidence"])
                        conn.execute("UPDATE attempts SET dispatch_state='POSSIBLE',unbounded=?,enforced_ceiling_evidence=?,updated_ns=? WHERE id=?",
                                     (int(unbounded), ceiling, time.time_ns(), attempt_id))
                elif kind == "non_dispatch_proof":
                    if row["dispatch_state"] == "NOT_DISPATCHED" and row["billing_finality"] == "FINAL":
                        pass
                    elif row["dispatch_state"] != "RESERVED" or row["cost_evidence_seen"] or row["known"]:
                        conflict_reason = "non-dispatch proof is incompatible with recorded possible dispatch or cost evidence"
                    else:
                        newly_finalized = True
                        conn.execute("UPDATE attempts SET billing_finality='FINAL',finality_basis='non_dispatch_proof',"
                                     "outcome='NOT_DISPATCHED',dispatch_state='NOT_DISPATCHED',unbounded=0,updated_ns=? WHERE id=?",
                                     (time.time_ns(), attempt_id))
                elif kind == "dispatch_start":
                    snapshot = self._snapshot(conn)
                    if row["dispatch_state"] != "RESERVED" or row["billing_finality"] != "UNKNOWN":
                        # Repeated gate crossings never permit another side effect.
                        pass
                    elif snapshot["frozen"] or snapshot["unbounded_exposure_count"]:
                        raise AdmissionDenied("dispatch blocked by frozen account or unbounded exposure")
                    else:
                        dispatch_allowed = True
                        conn.execute("UPDATE attempts SET dispatch_state='POSSIBLE',enforced_ceiling_evidence=?,updated_ns=? WHERE id=?",
                                     (json.dumps(values["bound_evidence"], sort_keys=True), time.time_ns(), attempt_id))
                elif kind == "execution_outcome":
                    if row["outcome"] not in {"UNKNOWN", values["outcome"]}:
                        conflict_reason = "contradictory terminal execution outcome"
                    elif row["dispatch_state"] == "NOT_DISPATCHED":
                        conflict_reason = "execution outcome contradicts non-dispatch proof"
                    else:
                        unbounded = (row["unbounded"] or (row["billing_finality"] != "FINAL" and
                                     row["enforced_ceiling_evidence"] is None))
                        conn.execute("UPDATE attempts SET outcome=?,dispatch_state='POSSIBLE',unbounded=?,updated_ns=? WHERE id=?",
                                     (values["outcome"], int(unbounded), time.time_ns(), attempt_id))
                if conflict_reason:
                    self._conflict(conn, attempt_id, event_id, payload, conflict_reason, amount)
                    newly_finalized = dispatch_allowed = False
                after = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
                changed = before != self._attempt_view(after)
                conn.execute("INSERT INTO events(id,attempt_id,payload,status,at_ns) VALUES(?,?,?,?,?)",
                             (event_id, attempt_id, payload, "CONFLICT" if conflict_reason else "APPLIED", time.time_ns()))
            current = conn.execute("SELECT * FROM attempts WHERE id=?", (attempt_id,)).fetchone()
            response = {"event_id": event_id, "new_event": new_event, "state_changed": changed,
                        "newly_finalized": newly_finalized, "dispatch_allowed": dispatch_allowed,
                        "attempt": self._attempt_view(current)}
        # Raising *after* commit preserves conflicting larger liability and freeze.
        if conflict_reason:
            raise EvidenceConflict(conflict_reason)
        return response
