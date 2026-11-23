#!/usr/bin/env python3
"""Build synthetic registration-classification vectors reproducibly; --check verifies byte identity.

Tests implement a proposed community-level policy, NOT MCP normative registration.
All keys derived from public labels; all agent identities are synthetic.
"""
from __future__ import annotations
import argparse, base64, copy, hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from contract import canonical, digest

ROOT = Path(__file__).resolve().parent
PREFIX = 'buddylists-synthetic-registration/v1/'

def key(label):
    seed = hashlib.sha256((PREFIX+label).encode('utf8')).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)

def b64(b): return base64.b64encode(b).decode('ascii')
def pub(k): return b64(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
def sign(k, msg): return b64(k.sign(msg))
def js(value): return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')

AGENT, REGISTRY = key('agent-demo'), key('registry-demo')
CORE = {
  'event_type': 'registration', 'intake_state': 'durably_committed',
  'agent_id': 'synthetic-agent-a', 'swarm_id': 'synthetic-swarm-new',
  'parent_agent_id': None, 'consent': True, 'consent_scope': 'registration',
  'challenge_nonce': 'synthetic-issued-nonce-7'
}

def make(name, core_change=None, context_change=None, record_change=None):
    c=copy.deepcopy(CORE)
    if core_change:
        c.update(core_change)
        for k in [k for k, v in c.items() if v == '__REMOVE__']: c.pop(k)
    ctx={
      'evaluation_time':'2026-11-17T12:00:00Z',
      'prior_registered_swarms':['synthetic-swarm-occupied'],
      'prior_registered_agents':['synthetic-agent-occupied'],
      'trusted_registry_public_key':pub(REGISTRY),
      'issued_challenge':{
        'agent_id':c['agent_id'], 'swarm_id':c['swarm_id'],
        'challenge_nonce':CORE['challenge_nonce'],
        'agent_public_key':pub(AGENT),
        'issued_at':'2026-11-17T11:00:00Z',
        'expires_at':'2026-11-17T13:00:00Z',
        'consumed':False
      }
    }
    if context_change:
        for path,val in context_change.items():
            target=ctx
            parts=path.split('.')
            for p in parts[:-1]:target=target[p]
            if val == '__REMOVE__':
                target.pop(parts[-1], None)
            else:
                target[parts[-1]]=val
    body={'record_digest': digest(c),'agent_id':c['agent_id'],'swarm_id':c['swarm_id'],'status':'committed'}
    r={
      'core':c,
      'agent_public_key':pub(AGENT),
      'agent_signature':sign(AGENT,b'BUDDYLISTS_TEST_REGISTRATION_V1\x00'+canonical(c)),
      'registry_receipt': {'body':body,'signature':sign(REGISTRY,b'BUDDYLISTS_TEST_RECEIPT_V1\x00'+canonical(body))}
    }
    if record_change:
        for path,val in record_change.items():
            target=r
            parts=path.split('.')
            for p in parts[:-1]:target=target[p]
            target[parts[-1]]=val
    return name,r,ctx

CASES=[
 ('valid-new-registration', None,None,None,True,'registration_evidence_sufficient_for_fixture','positive control'),
 ('anonymous-mcp-discovery', {'event_type':'mcp_discovery'},None,None,False,'not_registration_event','MCP tools/list is not a registration'),
 ('signed-report-not-registration', {'event_type':'signed_report'},None,None,False,'not_registration_event','signed report is not registration'),
 ('quarantined-report', {'intake_state':'quarantined'},None,None,False,'not_durably_committed','quarantined record is not admission'),
 ('consent-revoked', {'consent':False},None,None,False,'consent_not_affirmative','single semantic-field change'),
 ('wrong-consent-purpose', {'consent_scope':'telemetry'},None,None,False,'consent_scope_mismatch','consent to a different purpose'),
 ('child-agent', {'parent_agent_id':'synthetic-parent'},None,None,False,'ephemeral_or_child_agent','one agent swarm cannot register each child'),
 ('duplicate-swarm', {'swarm_id':'synthetic-swarm-occupied'},None,None,False,'swarm_already_registered','known existing swarm'),
 ('duplicate-agent', {'agent_id':'synthetic-agent-occupied'},None,None,False,'agent_already_registered','known existing agent'),
 ('nonce-not-issued', {'challenge_nonce':'synthetic-unissued'},None,None,False,'challenge_binding_mismatch','fresh signature cannot replace issuer challenge'),
 ('challenge-expired', None,{'issued_challenge.expires_at':'2026-11-17T11:30:00Z'},None,False,'challenge_expired_or_not_yet_issued','expired issued challenge'),
 ('challenge-replayed', None,{'issued_challenge.consumed':True},None,False,'challenge_replayed','one-time challenge must not replay'),
 ('challenge-state-missing', None,{'issued_challenge.consumed':'__REMOVE__'},None,False,'challenge_state_unverified','an absent consumption flag is not evidence of non-use'),
 ('challenge-state-null', None,{'issued_challenge.consumed':None},None,False,'challenge_state_unverified','unknown consumption state cannot earn credit'),
 ('challenge-state-text', None,{'issued_challenge.consumed':'not-checked'},None,False,'challenge_state_unverified','textual claim cannot replace an explicit unused state'),
 ('wrong-challenge-key',None,{'issued_challenge.agent_public_key':pub(key('other-agent'))},None,False,'challenge_key_mismatch','challenge binds agent key'),
 ('forged-agent-signature',None,None,{'agent_signature':b64(b'\x00'*64)},False,'agent_proof_invalid','no agent signing key possession'),
 ('tampered-committed-digest',None,None,{'registry_receipt.body.record_digest':'sha256:'+'0'*64},False,'durable_receipt_binding_mismatch','receipt must bind exact claimed payload'),
 ('forged-registry-receipt',None,None,{'registry_receipt.signature':b64(b'\x00'*64)},False,'durable_receipt_signature_invalid','registry authority must sign receipt'),
 ('missing-registry-receipt',None,None,{'registry_receipt':None},False,'malformed_or_missing_evidence','asserted durable status alone not sufficient'),
 ('agent-id-null', {'agent_id':None},None,None,False,'malformed_or_missing_evidence','a null agent_id is never in the prior list and matches a null receipt id'),
 ('swarm-id-null', {'swarm_id':None},None,None,False,'malformed_or_missing_evidence','a null swarm_id is never in the prior list and matches a null receipt id'),
 ('parent-marker-absent', {'parent_agent_id':'__REMOVE__'},None,None,False,'malformed_or_missing_evidence','an absent parent marker is not read as top level'),
 ('duplicate-consent-scope', None,None,None,False,'evidence_bytes_not_strict_json','record bytes carry consent_scope twice, the unsigned value first'),
]

# Byte-level edits applied after serialisation, for cases a parsed dict cannot
# express. The signed value stays last, so a decoder that keeps the last of
# two equal member names reads exactly the positive control.
RAW_EDITS={
 'duplicate-consent-scope':('"consent_scope": "registration"','"consent_scope": "telemetry",\n    "consent_scope": "registration"'),
}

def materialize():
    manifest={'suite':'synthetic-agent-registration-classification/v1','status':'candidate-not-accepted-upstream',
      'normativeScope':'BuddyLists policy proposal; MCP has no general agent registration rule',
      'counts':{'registration_credit':sum(e[4] for e in CASES),'no_registration_credit':sum(not e[4] for e in CASES)},
      'vectors':[]}
    outputs={}
    for name,cchange,ctxchange,rchange,expected,reason,note in CASES:
        _,record,context=make(name,cchange,ctxchange,rchange)
        for fn,obj in [('record.json',record),('context.json',context)]:
            path=f'cases/{name}/{fn}'
            contents=js(obj)
            if fn=='record.json' and name in RAW_EDITS:
                old,new=RAW_EDITS[name]
                assert contents.count(old.encode())==1,name
                contents=contents.replace(old.encode(),new.encode())
            outputs[path]=contents
        manifest['vectors'].append({'id':name,'path':'cases/'+name,'expected':{'registration_credit':expected,'reason':reason},
            'difference_from_positive_control':note,
            'files':{fn:hashlib.sha256(outputs[f'cases/{name}/{fn}']).hexdigest() for fn in ('record.json','context.json')}})
    manifest['corpusDigest']=hashlib.sha256(b''.join(outputs[k] for k in sorted(outputs))).hexdigest()
    outputs['MANIFEST.json']=js(manifest)
    lines=['# Test vector index','','| ID | Registration credit | Reason |','|---|---|---|']
    for v in manifest['vectors']:lines.append(f"| {v['id']} | {str(v['expected']['registration_credit']).lower()} | {v['expected']['reason']} |")
    outputs['INDEX.md']=('\n'.join(lines)+'\n').encode()
    return outputs

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true');args=ap.parse_args()
    outputs=materialize(); bad=[]
    for name,b in outputs.items():
        path=ROOT/name
        if args.check:
            if not path.exists() or path.read_bytes()!=b:bad.append(name)
        else:
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b)
    if args.check and bad:
        raise SystemExit('Generator mismatch: '+', '.join(bad))
    print(('GENERATOR_CHECK_PASS' if args.check else 'GENERATED')+' '+str(len(CASES))+' synthetic vector cases')
if __name__=='__main__':main()
