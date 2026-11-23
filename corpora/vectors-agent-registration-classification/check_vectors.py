#!/usr/bin/env python3
"""Validate generated digests, case-by-case verdicts, then negative controls."""
from __future__ import annotations
import copy,hashlib,json,sys
from pathlib import Path
import contract
from contract import classify,classify_bytes,canonical
ROOT=Path(__file__).resolve().parent
def _pairs(items):
    out={}
    for k,v in items:
        if k in out: raise ValueError('repeated member '+repr(k))
        out[k]=v
    return out
def _no_constant(name): raise ValueError('non-finite constant '+name)
def _strict(text): return json.loads(text,object_pairs_hook=_pairs,parse_constant=_no_constant)
manifest=_strict((ROOT/'MANIFEST.json').read_text())

def corpus_json():
    """Print every case's reading as one JSON object, for the intake record."""
    members=[]
    for entry in sorted(manifest['vectors'],key=lambda e:e['id']):
        path=ROOT/entry['path']
        credit,reason=classify_bytes((path/'record.json').read_bytes(),(path/'context.json').read_bytes())
        member={'id':entry['id'],'kind':'accept' if credit else 'reject'}
        expected=entry['expected']
        if (credit,reason)!=(expected['registration_credit'],expected['reason']):
            member['findings']=['reads as '+str(credit)+' '+reason+', manifest says '+str(expected['registration_credit'])+' '+expected['reason']]
        members.append(member)
    print(json.dumps({'suite':manifest['suite'],'dir':ROOT.name,'members':members},sort_keys=True,separators=(',',':')))

if sys.argv[1:]==['--json']:
    corpus_json()
    raise SystemExit(0)

def validate_manifest(document):
    paths = []
    for entry in document['vectors']:
        for fn in ('record.json', 'context.json'):
            paths.append(f"{entry['path']}/{fn}")
    recomputed = hashlib.sha256(b''.join((ROOT / path).read_bytes() for path in sorted(paths))).hexdigest()
    assert document['corpusDigest'] == recomputed, 'aggregate corpus digest does not match generated data'
    expected_counts = {
        'registration_credit': sum(x['expected']['registration_credit'] is True for x in document['vectors']),
        'no_registration_credit': sum(x['expected']['registration_credit'] is False for x in document['vectors']),
    }
    assert document['counts'] == expected_counts, 'manifest summary does not agree with vectors'

validate_manifest(manifest)
mutantdoc=copy.deepcopy(manifest);mutantdoc['corpusDigest']='0'*64
try:
    validate_manifest(mutantdoc)
except AssertionError:
    pass
else:
    raise AssertionError('tampered aggregate digest incorrectly accepted')
mutantdoc=copy.deepcopy(manifest);mutantdoc['counts']['registration_credit'] += 1
try:
    validate_manifest(mutantdoc)
except AssertionError:
    pass
else:
    raise AssertionError('tampered summary count incorrectly accepted')
for entry in manifest['vectors']:
    path=ROOT/entry['path']
    for fn,h in entry['files'].items():
        assert hashlib.sha256((path/fn).read_bytes()).hexdigest()==h,entry['id']+fn
    result=classify_bytes((path/'record.json').read_bytes(),(path/'context.json').read_bytes())
    expected=entry['expected']
    assert result == (expected['registration_credit'],expected['reason']),(entry['id'],result,expected)
# Tests that a checker which accepts everything or believes a boolean consent alone is insufficient.
positive=_strict((ROOT/'cases/valid-new-registration/record.json').read_text())
ctx=_strict((ROOT/'cases/valid-new-registration/context.json').read_text())
# Absent and explicit members must canonicalize to different bytes. The
# signed cases already pin a None-dropping encoder (the positive core carries
# parent_agent_id null), but nothing signed carries consent false or an empty
# agent_id, so an encoder dropping those passed every check above.
differentials=0
for key, explicit in [('consent', False), ('parent_agent_id', None), ('agent_id', '')]:
    absent = copy.deepcopy(positive['core'])
    absent.pop(key)
    present = copy.deepcopy(absent)
    present[key] = explicit
    assert canonical(absent) != canonical(present), key
    differentials+=1
assert classify(positive,ctx)[0] is True
mutant=copy.deepcopy(positive);mutant['core']['consent']=False
assert classify(mutant,ctx)[0] is False
mutant=copy.deepcopy(positive);mutant['registry_receipt']['body']['status']='pending'
assert classify(mutant,ctx)[0] is False
mutant=copy.deepcopy(positive);mutant['agent_signature']=''
assert classify(mutant,ctx)[0] is False
mutantctx=copy.deepcopy(ctx);mutantctx['issued_challenge'].pop('consumed')
assert classify(positive,mutantctx)[0] is False
mutantctx=copy.deepcopy(ctx);mutantctx['issued_challenge']['consumed']=None
assert classify(positive,mutantctx)[0] is False
# Forcing: each case below must be credited by a reader without the rule it
# pins, so the case fails that reader instead of passing either way.
def lenient(case):
    return classify(_strict((ROOT/'cases'/case/'record.json').read_text()),
                    _strict((ROOT/'cases'/case/'context.json').read_text()))
forced=0
assert lenient('duplicate-consent-scope') == (True,'registration_evidence_sufficient_for_fixture'); forced+=1
strict_types=contract.required_types_hold
contract.required_types_hold=lambda record,context: True
try:
    for case in ('agent-id-null','swarm-id-null','parent-marker-absent'):
        assert lenient(case)[0] is True,(case,lenient(case)); forced+=1
finally:
    contract.required_types_hold=strict_types
print('CLASSIFICATION_PASS '+str(len(manifest['vectors']))+' generated cases; 5 adversarial reader controls; 2 manifest-integrity probes; '+str(forced)+' cases forcing a rule; '+str(differentials)+' absent-vs-explicit canonical differentials')
