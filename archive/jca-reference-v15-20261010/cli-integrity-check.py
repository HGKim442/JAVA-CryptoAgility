"""Owned synthetic compiler reproduces and recovers accidental class byte corruption."""
import hashlib,json,os,pathlib,shutil,subprocess,tempfile
b=pathlib.Path(__file__).resolve().parent;checks=0
def check(value,message):
 global checks
 if not value:raise AssertionError(message)
 checks+=1
with tempfile.TemporaryDirectory(prefix='cli-integrity-') as temp:
 root=pathlib.Path(temp);tools=root/'tools';tools.mkdir()
 java=tools/'java';java.write_text('''#!/bin/bash
set -euo pipefail
if [[ "$1" == -m ]]; then
 printf 'compile\\n' >> compiles
 printf 'valid' > build/Example.class
 printf 'inner' > 'build/Example$Inner.class'
else
 project="${3%%/build:*}"
 [[ "$(cat "$project/build/Example.class")" == valid ]] || exit 8
 [[ "$(cat "$project/build/Example\\$Inner.class")" == inner ]] || exit 8
 printf 'HELP\\n'
fi
''');java.chmod(0o700)
 env=dict(os.environ);env['PATH']=str(tools)+os.pathsep+env['PATH']
 def fixture(name,script):
  p=root/name;p.mkdir();shutil.copy2(script,p/'cli.sh');(p/'Example.java').write_text('fixture\n');(p/'dependencies.sha256').write_text(hashlib.sha256((p/'Example.java').read_bytes()).hexdigest()+'  Example.java\n');return p
 def run(p):return subprocess.run(['bash','cli.sh','help'],cwd=p,env=env,capture_output=True,text=True,timeout=20)
 def count(p):return len((p/'compiles').read_text().splitlines())
 old=fixture('previous',b/'history-class-integrity-20261009/cli.sh.previous')
 check(run(old).returncode==0,'Baseline cold failed');(old/'build/Example.class').write_bytes(b'')
 check(run(old).returncode==8 and count(old)==1,'Baseline empty class not reproduced')
 current=fixture('current',b/'cli.sh');check(run(current).returncode==0,'Current cold failed')
 (current/'build/Example.class').write_bytes(b'');check(run(current).returncode==0 and count(current)==2,'Empty class not rebuilt')
 (current/'build/Example$Inner.class').write_bytes(b'Xnner');check(run(current).returncode==0 and count(current)==3,'Same-size nested corruption not rebuilt')
 # Corrupt list even with a matching list hash: format/content validation must refuse it.
 manifest=current/'build/.cli-classes';manifest.write_text('build/Example.class\n');stamp=current/'build/.cli-source-sha';lines=stamp.read_text().splitlines();lines[1]=hashlib.sha256(manifest.read_bytes()).hexdigest()+'  build/.cli-classes';stamp.write_text('\n'.join(lines)+'\n')
 check(run(current).returncode==0 and count(current)==4,'Old/malformed list incorrectly reused')
 check(run(current).returncode==0 and count(current)==4,'Unchanged checksum cache recompiled')
(b/'results/security').mkdir(parents=True,exist_ok=True)
(b/'results/security/cli-integrity-checks.json').write_text(json.dumps(dict(passed=True,checks=checks,baseline_corruption_reproduced=True,scope='synthetic owned compiler: zero-byte top class, same-size nested corruption, legacy/malformed manifest, warm reuse; accidental corruption detection, not signed deployment or same-UID attacker protection'),indent=2)+'\n')
print('PASS CLI integrity checks='+str(checks))
