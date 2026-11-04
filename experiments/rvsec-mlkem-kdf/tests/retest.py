#!/usr/bin/env python3
"""Re-execute archived, unmodified D2-10/11/12 Java programs in isolated sandbox.
Requires compiled classes and bcprov-jdk18on-1.86.jar in the surrounding folders.
Does not modify RVSec. No secret values are printed or stored.
"""
from pathlib import Path
import subprocess,csv,hashlib,json,sys
base=Path(__file__).resolve().parent
out=base/'logs_repeated';out.mkdir(exist_ok=True)
cp=f'{base / "classes"}:{base / "lib/bcprov-jdk18on-1.86.jar"}'
def get(x,s):
 for line in s.splitlines():
  if line.startswith(x+'='):return line.split('=',1)[1]
 return ''
cases=[]
for repeat in range(1,4):
 for m in ['HONEST','OMIT','SUBSTITUTE','WRONG_SESSION']:
  for e in ['ENFORCED','AUDIT_ONLY']:
   cases.append(('D2-10',repeat,'KdfBindingExperiment',[m,e]))
 for m in ['HONEST','MUTATE_AFTER_CHECK']:
  for e in ['DIRECT','PINNED']:
   cases.append(('D2-11',repeat,'PolicyKdfRace',[m,e]))
 for m in ['HONEST','FORGED_REGISTRATION']:
  for g in ['APPLICATION_REGISTRY','PROVIDER_REFERENCE']:
   for e in ['ENFORCED','AUDIT_ONLY']:
    cases.append(('D2-12',repeat,'RegistrationTrustExperiment',[m,g,e]))
rows=[]
for stage,repeat,cls,args in cases:
 process=subprocess.run(['java','-cp',cp,cls,*args],capture_output=True,text=True,timeout=30)
 log=(process.stdout or '')+'\n'+(process.stderr or '')
 path=out/f'{stage}_rep{repeat}_{"_".join(args)}.log';path.write_text(log)
 d={k:get(k,log) for k in ('RESULT','BINDING_OK','EFFECTIVE_ACCEPT','RECORD_ROUNDTRIP','KDF_INPUT_BINDING','GUARD_DECISION','UNBOUND_SECRET_USED','APP_REGISTERED_MATCHES_PROVIDER')}
 valid=process.returncode==0 and d['RESULT']=='PASS'
 if stage=='D2-10':
  expected_bind=str(args[0]=='HONEST').lower()
  expected_accept=str(args[0]=='HONEST' or args[1]=='AUDIT_ONLY').lower()
  valid &= d['BINDING_OK']==expected_bind and d['EFFECTIVE_ACCEPT']==expected_accept
  valid &= d['RECORD_ROUNDTRIP']==expected_accept
 if stage=='D2-11':
  expected=str(args[0]=='HONEST' or args[1]=='PINNED').lower()
  valid &= d['KDF_INPUT_BINDING']==expected
 if stage=='D2-12':
  forged=args[0]=='FORGED_REGISTRATION'
  allowed=(not forged or args[1]=='APPLICATION_REGISTRY')
  effective=(allowed or args[2]=='AUDIT_ONLY')
  valid &= d['GUARD_DECISION']==('ALLOW' if allowed else 'DENY')
  valid &= d['UNBOUND_SECRET_USED']==str(forged and effective).lower()
 rows.append({'stage':stage,'rep':repeat,'class':cls,'args':' '.join(args),'exit_code':process.returncode,'check': 'PASS' if valid else 'FAIL', 'log':str(path.relative_to(base)),**d})
 if not valid: print('FAIL',stage,repeat,args, log[-1000:])
fields=list(rows[0]); f=base/'actual_runs_20261104.csv'
with f.open('w',newline='') as fh:
 w=csv.DictWriter(fh,fieldnames=fields);w.writeheader();w.writerows(rows)
result={'JVM':subprocess.run(['java','-version'],capture_output=True,text=True).stderr.splitlines()[0],
 'bouncycastle':'bcprov-jdk18on-1.86.jar',
 'files':{x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in [base/'src/KdfBindingExperiment.java',base/'src/PolicyKdfRace.java',base/'src/RegistrationTrustExperiment.java',base/'src/AlternateKdf.java',base/'lib/bcprov-jdk18on-1.86.jar']},
 'tested':len(rows),'pass':sum(x['check']=='PASS' for x in rows),
 'by_stage':{k:{'tested':sum(x['stage']==k for x in rows),'pass':sum(x['stage']==k and x['check']=='PASS' for x in rows)} for k in ['D2-10','D2-11','D2-12']},
 'not_run':['D2-13 Java Agent','D2-14 Java Agent','D2-15 Java Agent','RVSec original with javaagent']}
(base/'actual_summary_20261104.json').write_text(json.dumps(result,indent=2,ensure_ascii=False))
print(json.dumps(result,indent=2,ensure_ascii=False))
if result['pass']!=len(rows):sys.exit(1)
