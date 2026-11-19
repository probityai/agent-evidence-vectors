"""Reference reader for the *proposed* BuddyLists registration evidence boundary.

This is a standalone, synthetic test policy, not an MCP standard and not a
verification of any live BuddyLists registration. Needs cryptography >= 41.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def canonical(value: Any) -> bytes:
    # Our local, explicitly constrained JSON subset, NOT RFC 8785 JCS.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value: Any) -> str:
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def signed(message: bytes, signature_b64: str, public_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
        sig = base64.b64decode(signature_b64, validate=True)
        pub.verify(sig, message)
        return True
    except (InvalidSignature, TypeError, ValueError, KeyError):
        return False


def parse_time(value: str) -> datetime:
    d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if d.tzinfo is None:
        raise ValueError('timestamp lacks offset')
    return d.astimezone(timezone.utc)


def classify(record: dict, context: dict) -> tuple[bool, str]:
    """Return registration credit and the first explicit reason.

    Fail closed: an unknown or malformed record must not earn registration.
    This function deliberately grants no activation or independence credit.
    """
    try:
        core = record['core']
        if core.get('event_type') != 'registration':
            return False, 'not_registration_event'
        if core.get('intake_state') != 'durably_committed':
            return False, 'not_durably_committed'
        if core.get('consent') is not True:
            return False, 'consent_not_affirmative'
        if core.get('consent_scope') != 'registration':
            return False, 'consent_scope_mismatch'
        if core.get('parent_agent_id') is not None:
            return False, 'ephemeral_or_child_agent'
        if core.get('swarm_id') in context['prior_registered_swarms']:
            return False, 'swarm_already_registered'
        if core.get('agent_id') in context['prior_registered_agents']:
            return False, 'agent_already_registered'
        challenge = context['issued_challenge']
        if any(challenge.get(k) != core.get(k) for k in ('agent_id', 'swarm_id', 'challenge_nonce')):
            return False, 'challenge_binding_mismatch'
        now = parse_time(context['evaluation_time'])
        if not (parse_time(challenge['issued_at']) <= now < parse_time(challenge['expires_at'])):
            return False, 'challenge_expired_or_not_yet_issued'
        if challenge.get('consumed') is True:
            return False, 'challenge_replayed'
        # Unknown and missing consumption states are NOT evidence of non-use.
        # In particular, `None` or an omitted field must never be credited as
        # an unused nonce (the caller is relying on a trusted registry ledger).
        if challenge.get('consumed') is not False:
            return False, 'challenge_state_unverified'
        agent_public = record['agent_public_key']
        if agent_public != challenge['agent_public_key']:
            return False, 'challenge_key_mismatch'
        if not signed(b'BUDDYLISTS_TEST_REGISTRATION_V1\x00' + canonical(core), record['agent_signature'], agent_public):
            return False, 'agent_proof_invalid'
        receipt = record['registry_receipt']
        receipt_body = receipt['body']
        if (receipt_body.get('record_digest') != digest(core) or receipt_body.get('agent_id') != core['agent_id']
                or receipt_body.get('swarm_id') != core['swarm_id'] or receipt_body.get('status') != 'committed'):
            return False, 'durable_receipt_binding_mismatch'
        if not signed(b'BUDDYLISTS_TEST_RECEIPT_V1\x00' + canonical(receipt_body),
                      receipt['signature'], context['trusted_registry_public_key']):
            return False, 'durable_receipt_signature_invalid'
        return True, 'registration_evidence_sufficient_for_fixture'
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        return False, 'malformed_or_missing_evidence'
