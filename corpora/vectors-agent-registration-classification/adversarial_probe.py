#!/usr/bin/env python3
"""Deterministic extra falsification probes on synthetic records only.

Not an independent audit and not evidence of actual registration.
The goal is to find cases where missing or contradictory evidence is credited.
"""
from __future__ import annotations
import copy, json, random
from pathlib import Path
from contract import classify

root=Path(__file__).resolve().parent
record=json.loads((root/'cases/valid-new-registration/record.json').read_text())
context=json.loads((root/'cases/valid-new-registration/context.json').read_text())
assert classify(record,context)[0] is True


def mutate(r,c,which):
    challenge=c['issued_challenge']; core=r['core']; receipt=r['registry_receipt']
    match which:
        case 'missing-consumed': challenge.pop('consumed',None)
        case 'unknown-consumed': challenge['consumed']=None
        case 'wrong-type-consumed': challenge['consumed']='false'
        case 'numeric-consumed': challenge['consumed']=0
        case 'replayed': challenge['consumed']=True
        case 'missing-challenge': c.pop('issued_challenge',None)
        case 'wrong-issued-nonce': challenge['challenge_nonce']='other'
        case 'expired': challenge['expires_at']='2026-11-17T11:00:01Z'
        case 'wrong-challenge-key': challenge['agent_public_key']='AA=='
        case 'wrong-core-purpose': core['consent_scope']='telemetry'
        case 'no-consent': core['consent']=False
        case 'no-consent-field': core.pop('consent',None)
        case 'child-agent': core['parent_agent_id']='child-of-parent'
        case 'quarantine': core['intake_state']='quarantined'
        case 'fake-discovery': core['event_type']='tools/list'
        case 'wrong-agent-signature': r['agent_signature']='AAAA'
        case 'missing-agent-signature': r.pop('agent_signature',None)
        case 'forged-registry-signature': receipt['signature']='AAAA'
        case 'missing-registry-receipt': r.pop('registry_receipt',None)
        case 'wrong-registry-status': receipt['body']['status']='pending'
        case 'changed-payload': core['agent_id']='different-agent'
        case 'duplicate-swarm': c['prior_registered_swarms']=[core['swarm_id']]
        case 'duplicate-agent': c['prior_registered_agents']=[core['agent_id']]
        case _: raise AssertionError(which)

names=('missing-consumed','unknown-consumed','wrong-type-consumed','numeric-consumed',
       'replayed','missing-challenge','wrong-issued-nonce','expired','wrong-challenge-key',
       'wrong-core-purpose','no-consent','no-consent-field','child-agent','quarantine',
       'fake-discovery','wrong-agent-signature','missing-agent-signature',
       'forged-registry-signature','missing-registry-receipt','wrong-registry-status',
       'changed-payload','duplicate-swarm','duplicate-agent')

rng=random.Random(20261117)
for idx in range(500):
    r,c=copy.deepcopy(record),copy.deepcopy(context)
    name=rng.choice(names)
    mutate(r,c,name)
    verdict=classify(r,c)
    assert verdict[0] is False,(idx,name,verdict)

for name in names:
    r,c=copy.deepcopy(record),copy.deepcopy(context)
    mutate(r,c,name)
    verdict=classify(r,c)
    assert verdict[0] is False,(name,verdict)
print(f'ADVERSARIAL_PROBES_PASS: 500 deterministic mutant trials, {len(names)} distinct mutation classes; no false credit')
