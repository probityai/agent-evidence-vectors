"""Build the fixed test-key witness records and consumer policies."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import run_vectors
from prior_witness import DOMAIN, GENESIS, canonical, digest

ROOT = Path(__file__).resolve().parent
RECORD = ROOT.parent.parent / "corpora/vectors-observed-effect/statements/v162352770f2f6c1c.json"
SEED = hashlib.sha256(b"probity-ws4-prior-witness-public-test-key-v0").digest()
NONCE = hashlib.sha256(b"probity-ws4-prior-witness-public-test-invocation-v0").hexdigest()[:32]
OBSERVER_KEY = "4f2a59edc8367deb40047ce83ee7f5ce711a57d93abbda9d1ce8588c56a3ce88"


def content() -> dict[str, bytes]:
    raw = RECORD.read_bytes()
    predicate = json.loads(base64.b64decode(json.loads(raw)["payload"]))["predicate"]
    commitment = predicate["observation"]["priorCommitment"]["commitmentDigest"]
    claim = predicate["intervalId"]
    key = run_vectors.ed25519_public_key(SEED).hex()
    prior = {
        "sequence": 1,
        "previous": GENESIS,
        "kind": "prior-commitment",
        "claimRef": claim,
        "invocationNonce": NONCE,
        "commitmentDigest": commitment,
    }
    first = {
        "body": prior,
        "signature": run_vectors.ed25519_sign(SEED, DOMAIN + canonical(prior)).hex(),
    }
    first_head = digest(canonical(first))
    opened = {
        "sequence": 2,
        "previous": first_head,
        "kind": "invocation-open",
        "claimRef": claim,
        "invocationNonce": NONCE,
        "priorHead": first_head,
    }
    second = {
        "body": opened,
        "signature": run_vectors.ed25519_sign(SEED, DOMAIN + canonical(opened)).hex(),
    }
    witness = canonical(first) + b"\n" + canonical(second) + b"\n"
    base = {
        "observerKey": OBSERVER_KEY,
        "claimRef": claim,
        "scope": "/srv/app/",
        "producerCapability": {"claimRef": claim, "visibleWritePaths": ["/srv/app/"]},
        "claimedCommitmentDigest": commitment,
    }
    witnessed = {
        **{key_: value for key_, value in base.items() if key_ != "claimedCommitmentDigest"},
        "trustedWitness": {
            "witnessKey": key,
            "openHead": digest(canonical(second)),
            "invocationNonce": NONCE,
        },
    }
    action = {
        "claimRef": claim,
        "reported": "pending",
        "windowEnd": "2026-09-19T00:00:10Z",
        "checkedAt": "2026-09-19T00:00:10Z",
        "authenticatedTerminal": None,
    }
    return {
        "witness.jsonl": witness,
        "claimed-policy.json": (json.dumps(base, indent=2, sort_keys=True) + "\n").encode(),
        "witnessed-policy.json": (json.dumps(witnessed, indent=2, sort_keys=True) + "\n").encode(),
        "action-at-window.json": (json.dumps(action, indent=2, sort_keys=True) + "\n").encode(),
        "action-after-window.json": (
            json.dumps({**action, "checkedAt": "2026-09-19T00:00:11Z"}, indent=2, sort_keys=True)
            + "\n"
        ).encode(),
    }


def main() -> int:
    import sys

    want = content()
    if sys.argv[1:] == ["--write"]:
        for name, data in want.items():
            (ROOT / "fixtures" / name).write_bytes(data)
        return 0
    if sys.argv[1:] != ["--check"]:
        print("usage: python gen_fixture.py --check|--write")
        return 2
    changed = [
        name for name, data in want.items() if (ROOT / "fixtures" / name).read_bytes() != data
    ]
    if changed:
        print("fixture bytes differ: " + ", ".join(changed))
        return 1
    print(f"{len(want)} fixture files reproduce exactly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
