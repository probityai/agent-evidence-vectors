"""R3-v01 recount: Anton Sokolov's command from Nov/0023, as posted.

    python3 -I rows/r3_v01_recount.py <R3 records/> <run-report-v01.json>

Recounts the checks the 44 controls fail from the R3 records (run-report.json
and control-results.json) and compares them with the two lists in the
re-encoded report's control roll-up. It prints three lines: the declared
checks, the control results, the checks those controls fail, the checks
without a control, and whether every controlled check is a declared one; then
whether the two sets are the report's two lists; then the uncontrolled checks
by kind. The body below is the program of Nov/0023, unchanged.
"""
import json,sys
p=sys.argv[1]
r=json.load(open(p+'/run-report.json'))
c=json.load(open(p+'/control-results.json'))
v=json.load(open(sys.argv[2]))['roll-up']
v=v['negative-capable']['control']
f=lambda a,x:a['case']+'/'+x['site']+'/'+x['check_id']
d={f(x,x) for x in r['records']}
k={f(x['seed_record'],x) for x in c}
u=sorted(d-k)
t=[x.split('/')[2] for x in u]
print(len(d),len(c),len(k),len(u),k<=d)
print(sorted(k)==sorted(v['checks']),u==sorted(v['not-covered']))
print({i:t.count(i) for i in sorted(set(t))})
