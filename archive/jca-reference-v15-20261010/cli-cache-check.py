"""Missing nested-class recovery and matched isolated shell-cache overhead."""
import hashlib,json,os,pathlib,shutil,statistics,subprocess,tempfile,time
b=pathlib.Path(__file__).resolve().parent;checks=0
def check(value,message):
 global checks
 if not value:raise AssertionError(message)
 checks+=1
with tempfile.TemporaryDirectory(prefix='cli-cache-check-') as temp:
 root=pathlib.Path(temp);tools=root/'tools';tools.mkdir()
 java=tools/'java';java.write_text('''#!/bin/bash
set -euo pipefail
if [[ "$1" == -m ]]; then
 printf 'compile\\n' >> compiles
 for source in ./*.java; do stem="${source##*/}"; stem="${stem%.java}"; printf 'class' > "build/$stem.class"; done
 printf 'inner' > 'build/Example$Inner.class'
else
 project="${3%%/build:*}"
 [[ -f "$project/build/Example\\$Inner.class" ]] || exit 8
 printf 'HELP\\n'
fi
''');java.chmod(0o700)
 env=dict(os.environ);env['PATH']=str(tools)+os.pathsep+env['PATH']
 def fixture(name,script):
  project=root/name;project.mkdir();shutil.copy2(script,project/'cli.sh')
  for stem in sorted(set([p.stem for p in b.glob('*.java')]+['Example'])):(project/(stem+'.java')).write_text('fixture\n')
  p=next(project.glob('*.java'));(project/'dependencies.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
  return project
 def run(project):
  started=time.perf_counter_ns();r=subprocess.run(['bash','cli.sh','help'],cwd=project,env=env,capture_output=True,text=True,timeout=30);return r,time.perf_counter_ns()-started
 def count(project):return len((project/'compiles').read_text().splitlines())
 previous=fixture('previous',b/'history-cache-opt-20261009/cli.sh.previous')
 r,_=run(previous);check(r.returncode==0,'Baseline cold failed')
 (previous/'build/Example$Inner.class').unlink();r,_=run(previous)
 check(r.returncode==8 and count(previous)==1,'Baseline missing-nested bug did not reproduce')
 current=fixture('current',b/'cli.sh');r,_=run(current);check(r.returncode==0,'Current cold failed')
 r,_=run(current);check(r.returncode==0 and count(current)==1,'Warm cache recompiled')
 (current/'build/Example$Inner.class').unlink();r,_=run(current)
 check(r.returncode==0 and count(current)==2,'Missing nested class not recovered')
 (current/'build/.cli-classes').unlink();r,_=run(current)
 check(r.returncode==0 and count(current)==3,'Old cache without manifest not upgraded')
 (current/'build/.cli-classes').write_text('');r,_=run(current)
 check(r.returncode==0 and count(current)==4,'Empty class manifest reused')
 with (current/'build/.cli-classes').open('a') as f:f.write('build/Missing$Nested.class\n')
 r,_=run(current);check(r.returncode==0 and count(current)==5,'Missing manifest entry ignored')
 (current/'build/Stale.class').write_text('old');(current/'build/.cli-source-sha').unlink();r,_=run(current)
 check(r.returncode==0 and count(current)==6 and not (current/'build/Stale.class').exists(),'Stale class left after rebuild')
 check('build/Example$Inner.class' in (current/'build/.cli-classes').read_text(),'Nested class not listed')
 # Independent matching warm fixtures; same fake Java and source count; no crypto/JVM work.
 projects={name:fixture('measure-'+name,script) for name,script in [('previous',b/'history-cache-opt-20261009/cli.sh.previous'),('optimized',b/'cli.sh')]}
 for project in projects.values():
  r,_=run(project);check(r.returncode==0,'Measurement fixture cold failed')
 rows=[]
 for sample in range(24):
  for name in (['previous','optimized'] if sample%2==0 else ['optimized','previous']):
   r,ns=run(projects[name]);assert r.returncode==0
   rows.append(dict(variant=name,sample=sample,ns=ns))
 check(all(count(project)==1 for project in projects.values()),'Warm measurement unexpectedly compiled')
 source_count=len(list(current.glob('*.java')))
 medians={name:statistics.median([x['ns'] for x in rows if x['variant']==name])/1e6 for name in projects}
 (b/'results/security').mkdir(parents=True,exist_ok=True)
 record=dict(passed=True,checks=checks,baseline_missing_nested_reproduced=True,source_count=source_count,samples=rows,median_ms=medians,scope='isolated synthetic Java; actual shell/cache/source hashing and locking, 24 balanced samples per variant; excludes real JVM startup, JAR size/hash cost and all cryptography; uncontrolled CPU/cache; descriptive, no end-to-end throughput claim',cli_sha256={name:hashlib.sha256(script.read_bytes()).hexdigest() for name,script in [('previous',b/'history-cache-opt-20261009/cli.sh.previous'),('optimized',b/'cli.sh')]})
 (b/'results/security/cli-cache-checks.json').write_text(json.dumps(record,indent=2)+'\n')
 print('PASS CLI cache checks='+str(checks)+' '+json.dumps(medians))
