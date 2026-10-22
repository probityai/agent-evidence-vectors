"""Which preimage each corpus digest is computed over, inferred from the corpus bytes alone.

draft-correctover-ccs-10 states a construction for params_hash (6.5), request_hash (6.1),
response_hash (6.2), runtime_context_hash (6.3), config_hash (5.3) and the key
fingerprint (7.2), and names previous_receipt_hash without its preimage (11.2). This
script tries the draft's construction and the candidates the corpus files suggest, and
counts, over every receipt that carries the needed input, which one reproduces the value.
It never reads a CCS checker. Usage: python infer_constructions.py <corpus-dir> <out.json>
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from agent_evidence_vectors.a2ajcs import canonicalize


def h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def draft_json(o: object) -> bytes:
    # The draft's own Python (sections 6.1, 6.3, 6.5): sort_keys, compact separators.
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def raw_key(key: str) -> bytes:
    try:
        return base64.b64decode(key, validate=True)
    except ValueError:
        return b""


def main(root: Path, out: Path) -> int:
    tally: dict[str, dict[str, int]] = {}

    def count(field: str, name: str, ok: bool) -> None:
        tally.setdefault(field, {}).setdefault(name, 0)
        tally[field][name] += int(ok)
        tally[field].setdefault("_receipts", 0)

    for rp in sorted(root.rglob("receipt*.json")):
        if "original" in rp.parts or rp.name.startswith("receipt-tampered"):
            continue
        r = json.loads(rp.read_text())
        if "receipt_type" in r:
            continue
        d, idx = rp.parent, rp.stem.replace("receipt", "")
        args_p = d / f"tool-args{idx}.json"
        if args_p.exists():
            a = json.loads(args_p.read_text())
            tally.setdefault("params_hash", {}).setdefault("_receipts", 0)
            tally["params_hash"]["_receipts"] += 1
            full = h(draft_json(a))
            count(
                "params_hash",
                "draft-6.5 sha256(params) full or first 16",
                r.get("params_hash") in (full, full[:16]),
            )
            count(
                "params_hash",
                "sha256(JCS{tool, param_keys sorted})",
                r.get("params_hash")
                == h(canonicalize({"tool": r["tool"], "param_keys": sorted(a)})),
            )
            count(
                "params_hash",
                "args_digest == sha256(JCS(args))",
                r.get("args_digest") == h(canonicalize(a)),
            )
            tally.setdefault("request_hash", {}).setdefault("_receipts", 0)
            tally["request_hash"]["_receipts"] += 1
            count(
                "request_hash",
                "sha256(JCS{tool, tool_call_id, args})",
                r.get("request_hash")
                == h(
                    canonicalize(
                        {"tool": r["tool"], "tool_call_id": r.get("tool_call_id"), "args": a}
                    )
                ),
            )
            tally.setdefault("action", {}).setdefault("_receipts", 0)
            tally["action"]["_receipts"] += 1
            count(
                "action",
                "draft-6.4 ccs:tool-invoke:{tool}:{sha256(params)}",
                r.get("action") == f"ccs:tool-invoke:{r['tool']}:{full}",
            )
        key = r.get("public_key")
        if isinstance(key, str) and "public_key_fingerprint" in r:
            raw = raw_key(key)
            tally.setdefault("fingerprint", {}).setdefault("_receipts", 0)
            tally["fingerprint"]["_receipts"] += 1
            count(
                "fingerprint",
                "draft-7.2 sha256(raw key) full",
                r["public_key_fingerprint"] == h(raw),
            )
            count(
                "fingerprint",
                "sha256(raw key) first 8 bytes",
                r["public_key_fingerprint"] == h(raw)[:16],
            )
    # params_hash under a changed argument value: the corpus construction does not move.
    allow = json.loads((root / "01-allow" / "receipt.json").read_text())
    args = json.loads((root / "01-allow" / "tool-args.json").read_text())
    changed = dict(args, customer_id="CUST-99999")
    demo = {
        "receipt_params_hash": allow["params_hash"],
        "names_only_hash_after_value_change": h(
            canonicalize({"tool": allow["tool"], "param_keys": sorted(changed)})
        ),
        "draft_6_5_hash_before": h(draft_json(args)),
        "draft_6_5_hash_after_value_change": h(draft_json(changed)),
        "args_digest_after_value_change": h(canonicalize(changed)),
        "receipt_args_digest": allow["args_digest"],
    }
    # previous-receipt digest in the chain cases.
    prev = []
    for chain in sorted(root.rglob("chain.json")):
        c = json.loads(chain.read_text())
        for i, want in enumerate(c.get("expected_prev_digests") or []):
            if not want or i == 0:
                continue
            d = chain.parent
            r_prev = json.loads((d / f"receipt-{i}.json").read_text())
            si = (d / f"signing-input-{i}.jcs").read_bytes()
            prev.append(
                {
                    "case": str(d.relative_to(root)),
                    "hop": i,
                    "equals_sha256_of_signing_input": want == "sha256:" + h(si),
                    "equals_sha256_of_JCS_full_receipt": want
                    == "sha256:" + h(canonicalize(r_prev)),
                }
            )
    out.write_text(
        json.dumps(
            {"tally": tally, "params_hash_value_change": demo, "previous_digest": prev},
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    print(json.dumps(tally, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
