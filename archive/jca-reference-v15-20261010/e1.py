"""Fixture-only actual E1 collection. Never exposes weak modes through the normal CLI."""
import io,os,csv,hashlib,json,pathlib,platform,statistics,subprocess,sys,time,uuid
BASE=pathlib.Path(__file__).resolve().parent
MODES=['VULNERABLE','ALLOWLIST','PROPOSED']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inputs():
 paths=[p for pattern in ('*.java','*.py','*.sh') for p in BASE.glob(pattern)]+list((BASE/'research/e1').glob('*.java'))+list((BASE/'research').glob('*.py'))+[BASE/'paper/e1-protocol.json',BASE/'dependencies.sha256']
 return {str(p.relative_to(BASE)):sha(p) for p in sorted(paths)}
def durable_capture(path):
 data=path.read_bytes()
 if not data:raise IOError('Empty raw artifact: '+str(path))
 temporary=path.with_name(path.name+'.publish.tmp')
 try:
  with temporary.open('xb') as stream:
   stream.write(data);stream.flush();os.fsync(stream.fileno())
  os.replace(temporary,path)
  directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:
  if temporary.exists():temporary.unlink()
 return data

def pqc_artifacts(folder):
 # Only raw experiment outputs belong here; never hash summary.json into itself.
 paths=[p for fork in range(1,7) for p in [folder/f'fork-{fork}.log',folder/f'fork-{fork}'/'pqc-downgrade.csv',folder/f'fork-{fork}'/'allowlist-control.json']]
 if any(p.is_symlink() or not p.is_file() or p.stat().st_size==0 for p in paths):raise IOError('Missing/unsafe PQC raw artifact')
 return {str(p.relative_to(folder)):sha(p) for p in paths}

def collect():
 before=inputs();output=BASE/'results/e1/current'
 if output.exists():
  if output.is_symlink() or not output.is_dir():raise ValueError('Unsafe E1 output')
  history=BASE/'results/e1/history';history.mkdir(exist_ok=True);output.rename(history/uuid.uuid4().hex)
 output.mkdir(parents=True,exist_ok=False);build=output/'build';build.mkdir();started=time.time()
 record={'status':'running','source_sha256':before,'environment':{'platform':platform.platform(),'java':subprocess.run(['java','-version'],capture_output=True,text=True,check=True).stderr},'scope':'Classical deterministic fixture matrix (not attack blocking-rate estimation) plus real TrustedStateStore. Not a production PQC-vs-classical performance comparison.'}
 (output/'metadata.json').write_text(json.dumps(record,indent=2)+'\n')
 try:
  command=['java','-m','jdk.compiler/com.sun.tools.javac.Main','--release','17','-Xlint:all','-Werror','-cp','build:lib/bcprov-jdk18on-1.86.jar','-d',str(build),*[str(p.relative_to(BASE)) for p in sorted((BASE/'research/e1').glob('*.java'))]]
  done=subprocess.run(command,cwd=BASE,capture_output=True,text=True,check=True,timeout=120);(output/'compile.log').write_text(done.stdout+done.stderr)
  attacks=[];costs=[];captured_raw={}
  for fork in range(1,7):
   folder=output/f'fork-{fork}';done=subprocess.run(['java','-Xms256m','-Xmx512m','-cp',str(build)+':'+str(BASE/'build'),'E1Experiment',str(folder),str(fork)],cwd=BASE,capture_output=True,text=True,check=True,timeout=180)
   (output/f'fork-{fork}.log').write_text(done.stdout+done.stderr)
   for filename,target in [('attacks.csv',attacks),('normal-cost.csv',costs)]:
    path=folder/filename;data=durable_capture(path);captured_raw[path]=hashlib.sha256(data).hexdigest()
    target.extend(csv.DictReader(io.StringIO(data.decode('utf-8'),newline='')))
   print(done.stdout.strip(),flush=True)
  expected={(str(f),m,f'{s:02}',str(t)) for f in range(1,7) for m in MODES for s in range(1,7) for t in range(5)}
  actual={(r['fork'],r['mode'],r['scenario'],r['trial']) for r in attacks}
  assert len(attacks)==len(actual)==540 and actual==expected
  for r in attacks:
   assert set(r)=={'fork','mode','scenario','trial','attack_effect','blocked','normal_success','reason'}
   assert r['normal_success'] in ['true','false'] and r['reason'] in ['predicate','policy_rejection','authentication_rejection','unexpected_failure']
   assert r['attack_effect'] in ['true','false','unknown'] and r['blocked'] in ['true','false','unknown']
   assert r['blocked']==({'true':'false','false':'true','unknown':'unknown'}[r['attack_effect']])
  expected={(str(f),m,str(s)) for f in range(1,7) for m in MODES for s in range(50)}
  assert len(costs)==900 and {(r['fork'],r['mode'],r['sample']) for r in costs}==expected
  assert all(r['normal_success']=='true' and int(r['ns'])>0 and set(r)=={'fork','mode','sample','ns','normal_success'} for r in costs)
  groups=[]
  for mode in MODES:
   for scenario in range(1,7):
    rows=[r for r in attacks if r['mode']==mode and r['scenario']==f'{scenario:02}'];blocked=sum(r['blocked']=='true' for r in rows)
    groups.append({'mode':mode,'scenario':f'{scenario:02}','trials':len(rows),'blocked':blocked,'independent_fixture_count':1,'observation':('INDETERMINATE' if any(r['normal_success']!='true' or r['blocked']=='unknown' for r in rows) else 'BLOCKED' if blocked==len(rows) else 'ATTACK_EFFECT' if blocked==0 else 'MIXED'),'normal_success':len(rows)})
  timing=[]
  for mode in MODES:
   medians=[statistics.median(int(r['ns']) for r in costs if r['mode']==mode and r['fork']==str(f)) for f in range(1,7)]
   timing.append({'mode':mode,'fork_medians_ns':medians,'median_of_fork_medians_ns':statistics.median(medians),'samples':300})
  baseline=timing[0]['median_of_fork_medians_ns']
  for t in timing:t['relative_to_vulnerable']=t['median_of_fork_medians_ns']/baseline
  pq_folder=BASE/'results/pqc-downgrade/current'
  if pq_folder.exists():
   history=BASE/'results/pqc-downgrade/history';history.mkdir(exist_ok=True);pq_folder.rename(history/uuid.uuid4().hex)
  pq_folder.mkdir(parents=True);pq_rows=[]
  for fork in range(1,7):
   folder=pq_folder/f'fork-{fork}'
   done=subprocess.run(['java','-Xmx512m','-cp',str(build)+':'+str(BASE/'build')+':'+str(BASE/'lib/bcprov-jdk18on-1.86.jar'),'PqcDowngradeExperiment',str(folder),str(fork)],cwd=BASE,capture_output=True,text=True,check=True,timeout=180)
   (pq_folder/f'fork-{fork}.log').write_text(done.stdout+done.stderr)
   path=folder/'pqc-downgrade.csv';data=durable_capture(path);captured_raw[path]=hashlib.sha256(data).hexdigest()
   pq_rows.extend(csv.DictReader(io.StringIO(data.decode('utf-8'),newline='')))
  assert len(pq_rows)==36 and all(r['normal_hybrid_success']=='true' for r in pq_rows)
  pq_summary={'collection_complete':True,'source_sha256':before,'rows':36,'normal_hybrid_controls':36,'independent_failure_variants':2,'groups':[],'scope':'Actual ML-KEM-768 encapsulation/decapsulation and X25519 normal control. Two real JCA failure conditions. Synthetic HMAC combiner is not a standardized hybrid protocol or RFC HPKE implementation.'}
  for mode in MODES:
   for variant in [1,2]:
    selected=[r for r in pq_rows if r['mode']==mode and r['failure_variant']==str(variant)]
    pq_summary['groups'].append({'mode':mode,'failure_variant':variant,'observations':sorted(set(r['outcome']+':'+r['observed_suite'] for r in selected)),'downgrade_effect_observed':any(r['downgrade_effect']=='true' for r in selected),'diagnostic_repeats':len(selected)})
  for path,digest in captured_raw.items():
   if sha(path)!=digest:raise IOError('Raw artifact changed after collection: '+str(path))
  pq_summary['raw_sha256']=pqc_artifacts(pq_folder)
  (pq_folder/'summary.json').write_text(json.dumps(pq_summary,indent=2)+'\n')
  for path,digest in captured_raw.items():
   if sha(path)!=digest:raise IOError('Raw artifact changed before completion: '+str(path))
  assert inputs()==before,'E1 inputs changed during measurement'
  summary={'passed':True,'fresh_jvms':6,'attack_rows':540,'normal_cost_rows':900,'baseline_effect_rows':sum(r['mode']=='VULNERABLE' and r['attack_effect']=='true' for r in attacks),'groups':groups,'timing':timing,'normal_control_rows':540,'independent_attack_fixtures':6,'result_kind':'deterministic_fixture_observation_matrix','limits':'Six deterministic synthetic scenarios, five repeats per fork. Repeats are diagnostics, not independent attack samples. No blocking percentage or success-forcing expectation is used. Timing includes two 4KiB encryptions and two authenticated opens, config transition and durable nonce reservation when needed; excludes fixture creation, restart, JVM startup. No significance or production-PQC superiority claim.'}
  (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
  record.update(captured_raw_sha256={str(p.relative_to(BASE)):digest for p,digest in captured_raw.items()},raw_publication='Captured JVM bytes, file fsync, atomic replace and directory fsync; digest rechecked before final completion.',status='complete',elapsed_seconds=time.time()-started,inputs_changed=False,artifacts_sha256={str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file() and 'build' not in p.parts and p.name!='metadata.json'})
  (output/'metadata.json').write_text(json.dumps(record,indent=2)+'\n')
 except BaseException as e:
  record.update(status='incomplete',error=type(e).__name__+': '+str(e));(output/'metadata.json').write_text(json.dumps(record,indent=2)+'\n');raise
if __name__=='__main__':collect()
