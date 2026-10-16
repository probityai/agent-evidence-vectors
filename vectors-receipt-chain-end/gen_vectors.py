"""Build the receipt-chain-end cases byte-identically.

Every case is one signed receipt chain in the ActionReceipt v1 wire format a
flight-recording egress proxy writes (one compact JSON receipt per line), the
consumer's trust inputs, and, where the consumer kept one, a head it retained
outside the chain. The question each case asks is not whether the receipts are
genuine but whether the chain the consumer holds is the whole chain: whether
its end is proven, and by what.

The edits are the ones a writer with access to the evidence, or a producer
that equivocates, can make while every signature still verifies: cut the tail,
replay a closed prefix, present one branch of a fork, re-root a rotated signing
key on an earlier tail, pin a stale head, hide a gap behind a sequence-number
reset, and swap two receipts whose timestamps tie. The controls keep the
corpus honest.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild
every signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

import run_vectors as rail  # noqa: E402

SUITE = "receipt-chain-end/v1"
SEED_PREFIX = "agent-evidence-vectors/receipt-chain-end/v1/"
GENESIS = "genesis"
OPEN_LABEL = "pipelock.receipt.session_open.v1"
ENDORSEMENT_DOMAIN = b"pipelock-rotation-endorsement-v1\x00"
POLICY = "sha256:" + hashlib.sha256(b"agent-evidence-vectors/policy").hexdigest()
RUN_SESSION = "agent.run." + hashlib.sha256(b"run-1").hexdigest()[:32]
OTHER_RUN_SESSION = "agent.run." + hashlib.sha256(b"run-2").hexdigest()[:32]
SHARED_SESSION = "proxy"


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def public(label: str) -> str:
    return str(rail.ed25519_public_key(_seed(label)).hex())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value: object) -> bytes:
    """Go's encoding/json output for the values this corpus uses: struct field
    order, no spaces, non-ASCII kept as UTF-8. No string here holds <, > or &."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _ts(second: int) -> str:
    minute, sec = divmod(second, 60)
    return f"2026-10-14T16:{minute:02d}:{sec:02d}Z"


def genesis_for(open_payload: dict[str, Any]) -> str:
    """The bound session-open genesis: a length-framed SHA-256 over the open."""
    h = hashlib.sha256()

    def frame(b: bytes) -> None:
        h.update(struct.pack(">Q", len(b)))
        h.update(b)

    for part in (OPEN_LABEL, open_payload["run_nonce"], open_payload["open_nonce"],
                 open_payload["recorder_session"], open_payload["policy_hash"],
                 open_payload["signer_key_epoch"]):
        frame(part.encode())
    frame(struct.pack(">Q", open_payload["heartbeat_seconds"]))
    for _ in range(5):  # anchor head, anchor log, posture capsule, containment nonce, uid
        frame(b"")
    return "g1:" + h.hexdigest()


class Chain:
    """A writer that appends signed receipts exactly as a recorder does."""

    def __init__(self, session: str, run: str, key: str = "producer-a") -> None:
        self.session, self.run, self.key = session, run, key
        self.lines: list[bytes] = []
        self.prev = GENESIS
        self.seq = 0
        self.segment_count = 0
        self.clock = 0

    def copy(self) -> Chain:
        twin = Chain(self.session, self.run, self.key)
        twin.lines, twin.prev, twin.seq = list(self.lines), self.prev, self.seq
        twin.segment_count, twin.clock = self.segment_count, self.clock
        return twin

    def _append(self, extra: dict[str, Any], target: str, verdict: str,
                transport: str, tick: int = 1) -> bytes:
        self.clock += tick
        record: dict[str, Any] = {
            "version": 1,
            "action_id": f"act-{self.run}-{len(self.lines):03d}",
            "action_type": "unclassified",
            "timestamp": _ts(self.clock),
            "principal": "user:operator",
            "actor": "agent:support",
            "delegation_chain": ["user:operator"],
            "target": target,
            "side_effect_class": "external_read",
            "reversibility": "full",
            "policy_hash": POLICY,
            "verdict": verdict,
            "transport": transport,
            "chain_prev_hash": self.prev,
            "chain_seq": self.seq,
            "run_nonce": self.run,
        }
        record.update(extra)
        signature = rail.ed25519_sign(_seed(self.key), hashlib.sha256(compact(record)).digest())
        receipt = {"version": 1, "action_record": record,
                   "signature": "ed25519:" + signature.hex(), "signer_key": public(self.key)}
        line = compact(receipt)
        self.lines.append(line)
        self.prev = _sha(line)
        self.seq += 1
        self.segment_count += 1
        return line

    def open(self) -> Chain:
        payload: dict[str, Any] = {
            "run_nonce": self.run, "open_nonce": "open-" + self.run,
            "recorder_session": self.session, "policy_hash": POLICY,
            "signer_key_epoch": "epoch-1", "heartbeat_seconds": 30, "chain_open_seq": 0,
        }
        payload["genesis_hash"] = genesis_for(payload)
        self.prev = payload["genesis_hash"]
        self._append({"session_control": {"kind": "session_open", "open": payload}},
                     "pipelock://session/open", "allow", "receipt_session")
        return self

    def act(self, n: int, tick: int = 1) -> Chain:
        for i in range(n):
            self._append({}, f"https://api.example.test/v1/tickets/{len(self.lines) + i}",
                         "allow", "https", tick)
        return self

    def tied(self, n: int) -> Chain:
        """Append n receipts that share one timestamp."""
        self.act(1)
        return self.act(n - 1, tick=0)

    def rotate(self, new_key: str) -> Chain:
        marker = {"prior_signer_key": public(self.key), "prior_chain_seq": self.seq - 1,
                  "prior_chain_hash": self.prev}
        self.key, self.seq, self.segment_count = new_key, 0, 0
        self._append({"key_transition": marker}, "https://api.example.test/v1/rotate",
                     "allow", "https")
        return self

    def close(self, count_error: int = 0) -> Chain:
        payload = {"run_nonce": self.run, "open_nonce": "open-" + self.run,
                   "final_seq": self.seq, "root_hash": self.prev,
                   "receipt_count": self.segment_count + 1 + count_error,
                   "close_reason": "graceful_shutdown", "fsync_errors_gated": 0,
                   "durability_blocks": 0}
        self._append({"session_control": {"kind": "session_close", "close": payload}},
                     "pipelock://session/close", "allow", "receipt_session")
        return self


def endorsement(prior: str, new: str, session: str, tail: bytes, final_seq: int) -> dict[str, Any]:
    """An old-key-signed authorisation of one rotation boundary."""
    body = {"version": 1, "session_id": session, "prior_signer_key": public(prior),
            "prior_final_seq": final_seq, "prior_tail_hash": _sha(tail),
            "new_signer_key": public(new), "rotated_at": "2026-10-14T16:30:00Z"}
    digest = hashlib.sha256(ENDORSEMENT_DOMAIN + compact(body)).digest()
    return {**body, "endorsement": "ed25519:" + rail.ed25519_sign(_seed(prior), digest).hex()}


def resign_free_edit(line: bytes, **changes: Any) -> bytes:
    """Change fields of a receipt and keep its old signature, as a writer
    without the key must."""
    receipt = json.loads(line)
    receipt["action_record"].update(changes)
    return compact(receipt)


def head_of(lines: list[bytes], index: int, kind: str) -> dict[str, Any]:
    index %= len(lines)
    receipt = json.loads(lines[index])
    return {"kind": kind, "receipt_hash": _sha(lines[index]), "receipt_index": index,
            "final_seq": receipt["action_record"]["chain_seq"],
            "segment_signer_key": receipt["signer_key"]}


def cases() -> list[dict[str, Any]]:
    """Every case: id, lines, trust, retained head, expected answer, edit, and
    what the bytes do not assert."""
    a, b = public("producer-a"), public("producer-b")
    root_a = {"root_keys": [a], "pinned_keys": [a], "endorsements": []}
    closed = Chain(RUN_SESSION, "r1").open().act(6).close()
    open_run = Chain(RUN_SESSION, "r1").open().act(6)
    other = Chain(OTHER_RUN_SESSION, "r2").open().act(4).close()

    rotated = Chain(RUN_SESSION, "r1").open().act(5)
    boundary_tail, boundary_seq = rotated.lines[-1], rotated.seq - 1
    rotated.rotate("producer-b").act(2).close()
    genuine_endorsement = endorsement("producer-a", "producer-b", RUN_SESSION,
                                      boundary_tail, boundary_seq)
    forged = Chain(RUN_SESSION, "r1")
    forged.lines = list(rotated.lines[:3])
    forged.prev, forged.seq, forged.segment_count = _sha(forged.lines[-1]), 3, 3
    forged.clock = 3
    forged.rotate("producer-b").act(1).close()

    long_rotated = Chain(RUN_SESSION, "r1").open().act(9)
    long_tail, long_seq = long_rotated.lines[-1], long_rotated.seq - 1
    long_rotated.rotate("producer-b").act(3).close()
    long_endorsement = endorsement("producer-a", "producer-b", RUN_SESSION, long_tail, long_seq)
    truncated_at_reset = long_rotated.lines[:5]
    last_b = json.loads(long_rotated.lines[-1])

    fork_base = Chain(RUN_SESSION, "r1").open().act(3)
    branch_x = fork_base.copy().act(3)
    branch_y = fork_base.copy()
    branch_y.run = "r1"
    branch_y._append({}, "https://api.example.test/v1/refunds/7", "allow", "https")
    branch_y.act(2)

    shared = Chain(SHARED_SESSION, "r1").open().act(3).close()

    tie = Chain(RUN_SESSION, "r1").open().act(2).tied(3).act(1).close()
    swapped = [*tie.lines[:3], tie.lines[4], tie.lines[3], *tie.lines[5:]]

    foreign = Chain(RUN_SESSION, "r1", key="producer-b").open().act(3).close()
    miscounted = Chain(RUN_SESSION, "r1").open().act(3).close(count_error=1)
    tampered = [*closed.lines[:3],
                resign_free_edit(closed.lines[3], target="https://api.example.test/v1/refunds/9"),
                *closed.lines[4:]]

    pinned_ab = {"root_keys": [a], "pinned_keys": [a, b], "endorsements": []}
    endorsed = {"root_keys": [a], "pinned_keys": [a],
                "endorsements": ["endorsement.json"], "session": RUN_SESSION}

    return [
        dict(id="control-closed-run", lines=closed.lines, trust=root_a, head=None,
             decision="verified", reason="end_proven_close",
             edit="control: one run-scoped run, opened and closed, nothing removed",
             not_asserted="that the recorder saw every action the agent took, or that the "
             "signing key was held only by the recorder"),
        dict(id="control-closed-run-retained-head", lines=closed.lines, trust=root_a,
             head=head_of(closed.lines, -1, "final"),
             decision="verified", reason="end_proven_close",
             edit="control: the same run, with the consumer's own copy of the final head",
             not_asserted="when the head was retained, or that the retained copy was "
             "itself kept out of the writer's reach"),
        dict(id="control-open-prefix", lines=open_run.lines, trust=root_a, head=None,
             decision="prefix", reason="end_unproven",
             edit="control: a run still recording, so the chain has no end yet",
             not_asserted="that the run will close, or how many receipts follow"),
        dict(id="control-open-run-final-head", lines=open_run.lines, trust=root_a,
             head=head_of(open_run.lines, -1, "final"),
             decision="verified", reason="end_proven_head",
             edit="control: a run with no close, whose final head the consumer retained "
             "when recording stopped",
             not_asserted="why the run stopped without a close"),
        dict(id="control-rotation-endorsed", lines=rotated.lines,
             trust=endorsed, endorsement=genuine_endorsement, head=None,
             decision="verified", reason="end_proven_close",
             edit="control: the signing key rotates mid-run and the retiring key "
             "signs the boundary",
             not_asserted="that the retiring key was not already compromised when it "
             "signed the endorsement"),
        dict(id="control-timestamp-tie", lines=tie.lines, trust=root_a, head=None,
             decision="verified", reason="end_proven_close",
             edit="control: three receipts share one timestamp, in written order",
             not_asserted="the order in which the tied actions happened; the chain "
             "fixes the order they were written, not wall-clock order"),
        dict(id="tail-truncation", lines=closed.lines[:5], trust=root_a, head=None,
             decision="prefix", reason="end_unproven",
             edit="the newest two actions and the close deleted; every remaining link "
             "holds, so chain continuity alone passes it",
             not_asserted="that anything was deleted: without a retained head an honest "
             "open run and a truncated closed run are the same bytes"),
        dict(id="tail-truncation-retained-head", lines=closed.lines[:5], trust=root_a,
             head=head_of(closed.lines, -1, "final"),
             decision="rejected", reason="head_missing",
             edit="the same truncation, checked against the final head the consumer "
             "kept outside the chain",
             not_asserted="which receipts were removed, only that the retained head is "
             "not in the chain"),
        dict(id="prefix-replay-shared-session-close", lines=shared.lines, trust=root_a,
             head=None, decision="prefix", reason="end_unproven",
             edit="a legacy shared session closed by its first run and resumed by later "
             "runs; the later runs deleted so the chain ends on a genuine close",
             not_asserted="whether later runs existed; a close in a resumable session "
             "ends a run, not the chain"),
        dict(id="prefix-replay-other-run", lines=other.lines, trust=root_a,
             head=head_of(closed.lines, -1, "final"),
             decision="rejected", reason="head_missing",
             edit="a complete, closed, genuine run presented in place of the run whose "
             "final head the consumer retained",
             not_asserted="that the presented run is forged; it is genuine, and only the "
             "retained head says it is the wrong one"),
        dict(id="fork-branch-against-retained-head", lines=branch_y.lines, trust=root_a,
             head=head_of(branch_x.lines, -1, "final"),
             decision="rejected", reason="head_missing",
             edit="the producer signed two receipts at sequence 4; the consumer retained "
             "branch X's head and is shown branch Y, which is as long and fully linked",
             not_asserted="which branch the producer acted on"),
        dict(id="fork-branch-against-retained-seq", lines=branch_y.lines, trust=root_a,
             head={"kind": "final",
                   "final_seq": json.loads(branch_x.lines[-1])["action_record"]["chain_seq"]},
             decision="prefix", reason="end_unproven",
             edit="the same fork, checked against a retained final sequence number "
             "without a hash: both branches end at that number",
             not_asserted="the identity of the final receipt; a sequence number binds "
             "the length of a chain, not its content"),
        dict(id="fork-both-branches", lines=[*branch_x.lines, *branch_y.lines[4:]],
             trust=root_a, head=None, decision="rejected", reason="chain_link_broken",
             edit="both branches of the fork written into one file",
             not_asserted="which branch is the genuine one"),
        dict(id="rotation-resigned-tail-keys-pinned", lines=forged.lines, trust=pinned_ab,
             head=None, decision="rejected", reason="rotation_unendorsed",
             edit="the holder of the incoming key cuts the retiring key's segment after "
             "sequence 2, writes its own rotation marker on that earlier tail, and closes "
             "the run; the consumer pins both keys, as it must to read any rotated chain",
             not_asserted="that the incoming key was stolen; it may be the producer's own "
             "successor key acting on the history it inherited"),
        dict(id="rotation-resigned-tail-endorsement", lines=forged.lines, trust=endorsed,
             endorsement=genuine_endorsement, head=None,
             decision="rejected", reason="rotation_unendorsed",
             edit="the same re-rooted chain, checked against the retiring key's signed "
             "endorsement of the genuine boundary at sequence 5",
             not_asserted="the contents of the deleted receipts"),
        dict(id="stale-head-honest-extension", lines=closed.lines, trust=root_a,
             head=head_of(closed.lines, 3, "interim"),
             decision="verified", reason="end_proven_close",
             edit="no edit: the consumer retained an interim head at sequence 3 and the "
             "run kept recording and closed",
             not_asserted="anything about receipts after the interim head beyond what "
             "the chain links and the close bind"),
        dict(id="stale-head-truncated-to-it", lines=closed.lines[:4], trust=root_a,
             head=head_of(closed.lines, 3, "interim"),
             decision="prefix", reason="end_unproven",
             edit="the chain cut exactly at the consumer's interim head; the head matches "
             "the last receipt",
             not_asserted="that the run ended there; an interim head proves a prefix "
             "was written, not that nothing followed it"),
        dict(id="seq-reset-hides-gap", lines=truncated_at_reset, trust=root_a,
             head={"kind": "final", "final_seq": last_b["action_record"]["chain_seq"],
                   "segment_signer_key": last_b["signer_key"],
                   "receipt_index": len(long_rotated.lines) - 1},
             decision="rejected", reason="head_position_mismatch",
             edit="the run rotated keys at sequence 9 and the new segment restarted at "
             "sequence 0; the chain is cut at the old segment's sequence 4, which is "
             "the number the run's real final receipt carries",
             not_asserted="the contents of the deleted receipts"),
        dict(id="reorder-timestamp-tie", lines=swapped, trust=root_a, head=None,
             decision="rejected", reason="chain_link_broken",
             edit="two receipts whose timestamps tie swapped in the file, so a "
             "verifier that orders by timestamp sees no change",
             not_asserted="which order the actions happened in"),
        dict(id="signature-tamper", lines=tampered, trust=root_a, head=None,
             decision="rejected", reason="signature_invalid",
             edit="one receipt's target changed in place, its signature kept",
             not_asserted="what the receipt said before the edit"),
        dict(id="untrusted-genesis-key", lines=foreign.lines, trust=root_a, head=None,
             decision="rejected", reason="signer_untrusted",
             edit="a complete, closed run signed end to end by a key the consumer does "
             "not hold as a root",
             not_asserted="who holds the key that signed it"),
        dict(id="close-count-forged", lines=miscounted.lines, trust=root_a, head=None,
             decision="rejected", reason="close_binding_invalid",
             edit="the producer's own close claims one more receipt than the run holds",
             not_asserted="whether a receipt was lost or the close was miscounted"),
        dict(id="final-head-not-at-end", lines=open_run.lines, trust=root_a,
             head=head_of(open_run.lines, 4, "final"),
             decision="rejected", reason="head_not_final",
             edit="the consumer retained a final head at sequence 4 and the chain it is "
             "shown continues past it",
             not_asserted="whether the receipts after the head were appended by the "
             "producer or by someone else holding its key"),
    ] + [dict(id="seq-reset-control-endorsed", lines=long_rotated.lines, trust=endorsed,
              endorsement=long_endorsement,
              head={"kind": "final", "final_seq": last_b["action_record"]["chain_seq"],
                    "segment_signer_key": last_b["signer_key"],
                    "receipt_index": len(long_rotated.lines) - 1},
              decision="verified", reason="end_proven_close",
              edit="control: the whole rotated run, checked against the same retained "
                   "position",
              not_asserted="that the retiring key was not compromised before it signed")]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _signatures_verify(lines: list[bytes]) -> bool:
    for line in lines:
        receipt = json.loads(line)
        sig = bytes.fromhex(receipt["signature"].removeprefix("ed25519:"))
        digest = hashlib.sha256(compact(receipt["action_record"])).digest()
        if not rail.ed25519_verify(bytes.fromhex(receipt["signer_key"]), digest, sig):
            return False
    return True


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for spec in cases():
        name = spec["id"]
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case: dict[str, Any] = {"chain": "chain.jsonl", "schema_version":
                                "receipt-chain-end-case/v1", "trust": spec["trust"]}
        files = {"chain.jsonl": b"".join(line + b"\n" for line in spec["lines"])}
        if spec["head"] is not None:
            case["head"] = "head.json"
            files["head.json"] = _json(spec["head"])
        if "endorsement" in spec:
            files["endorsement.json"] = compact(spec["endorsement"]) + b"\n"
        files["case.json"] = _json(case)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "doesNotAssert": spec["not_asserted"], "edit": spec["edit"],
            "expected": {"decision": spec["decision"], "reason": spec["reason"]},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
            "signaturesVerify": _signatures_verify(spec["lines"]),
        })
    manifest = {
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": ("verifier case.json --json; exit 0 verified, 3 prefix, "
                             "1 rejected"),
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
