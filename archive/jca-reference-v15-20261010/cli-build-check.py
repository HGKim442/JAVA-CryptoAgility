"""Isolated CLI compiler-cache race/failure tests; fake Java never touches user state."""
import json,os,pathlib,shutil,subprocess,tempfile
b=pathlib.Path(__file__).resolve().parent;checks=0
def check(value,message):
 global checks
 if not value:raise AssertionError(message)
 checks+=1
with tempfile.TemporaryDirectory(prefix='cli-build-check-') as temp:
 root=pathlib.Path(temp);project=root/'project';project.mkdir();tools=root/'tools';tools.mkdir()
 shutil.copy2(b/'cli.sh',project/'cli.sh');(project/'Example.java').write_text('class Example {}\n');(project/'dependencies.sha256').write_text(__import__('hashlib').sha256((project/'Example.java').read_bytes()).hexdigest()+'  Example.java\n')
 java=tools/'java';java.write_text('''#!/usr/bin/env python3
import os,pathlib,sys,time,subprocess
p=pathlib.Path.cwd()
if '-m' in sys.argv:
 with (p/'compiles').open('a') as f:f.write(str(os.getpid())+'\\n')
 time.sleep(0.4)
 (p/'build/Example.class').write_bytes(b'partial')
 if (p/'fail').exists():sys.exit(9)
 (p/'build/Example.class').write_bytes(b'complete')
else:
 p=pathlib.Path(sys.argv[sys.argv.index('-cp')+1].split(':')[0]).parent
 if (p/'build/Example.class').read_bytes()!=b'complete':sys.exit(8)
 # Another CLI may legitimately hold the lock; inspect this child's inherited FD instead.
 try:
  if os.readlink('/proc/self/fd/9')==str(p/'build/.cli-build.lock'):sys.exit(7)
 except FileNotFoundError:pass
 print('HELP')
''');java.chmod(0o700)
 env=dict(os.environ);env['PATH']=str(tools)+os.pathsep+env['PATH']
 def launch():return subprocess.Popen(['bash',str(project/'cli.sh'),'help'],cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
 def wait(p):
  out,err=p.communicate(timeout=20);return p.returncode,out,err
 def count():return len((project/'compiles').read_text().splitlines())
 first,second=launch(),launch();a,c=wait(first),wait(second)
 check(a[0]==c[0]==0,'Concurrent help failed')
 check(count()==1,'Concurrent cold start compiled twice: '+str(count()))
 check((project/'build/.cli-source-sha').exists(),'Success stamp missing')
 check(wait(launch())[0]==0 and count()==1,'Warm cache recompiled')
 # A valid old stamp with a missing class must not survive a failed rebuild.
 (project/'build/Example.class').unlink();(project/'fail').touch()
 check(wait(launch())[0]==9,'Injected compiler failure not preserved')
 check(not (project/'build/.cli-source-sha').exists(),'Failed rebuild retained success stamp')
 (project/'fail').unlink();check(wait(launch())[0]==0 and count()==3,'Failed rebuild was incorrectly reused')
 check((project/'build/Example.class').read_bytes()==b'complete','Retry class incomplete')
 check(wait(launch())[0]==0 and count()==3,'Recovered cache recompiled')
 # A forced termination in compilation also leaves no valid stamp.
 (project/'build/Example.class').unlink();p=launch()
 import time,signal
 deadline=time.monotonic()+10
 while count()<4 and time.monotonic()<deadline:time.sleep(0.01)
 check(count()==4,'Compiler did not start')
 # launch helper is amended below to own a session so only this fixture is killed.
 os.killpg(p.pid,signal.SIGKILL);wait(p)
 check(not (project/'build/.cli-source-sha').exists(),'Killed rebuild retained stamp')
 check(wait(launch())[0]==0 and count()==5,'Killed compiler recovery failed')
 # Lock must be released before Java execution: concurrent help reuses cache.
 a,c=launch(),launch();check(wait(a)[0]==wait(c)[0]==0 and count()==5,'Post-recovery launches failed')
(b/'results/security').mkdir(parents=True,exist_ok=True)
(b/'results/security/cli-build-checks.json').write_text(json.dumps(dict(passed=True,checks=checks,scope='owned synthetic compiler: concurrent cold start, warm reuse, missing class + compiler failure, forced compilation termination, retry; no live source updates supported'),indent=2)+'\n')
print('PASS CLI build checks='+str(checks))
