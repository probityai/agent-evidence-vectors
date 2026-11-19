#!/usr/bin/env python3
"""Validate generated digests, case-by-case verdicts, then negative controls."""
from __future__ import annotations
import copy,hashlib,json
from pathlib import Path
from contract import classify,canonical
ROOT=Path(__file__).resolve().parent
manifest=json.loads((ROOT/'MANIFEST.json').read_text())

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
    record=json.loads((path/'record.json').read_text())
    context=json.loads((path/'context.json').read_text())
    result=classify(record,context)
    expected=entry['expected']
    assert result == (expected['registration_credit'],expected['reason']),(entry['id'],result,expected)
# Tests that a checker which accepts everything or believes a boolean consent alone is insufficient.
positive=json.loads((ROOT/'cases/valid-new-registration/record.json').read_text())
ctx=json.loads((ROOT/'cases/valid-new-registration/context.json').read_text())
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
print('CLASSIFICATION_PASS '+str(len(manifest['vectors']))+' generated cases; 5 adversarial reader controls; 2 manifest-integrity probes')
