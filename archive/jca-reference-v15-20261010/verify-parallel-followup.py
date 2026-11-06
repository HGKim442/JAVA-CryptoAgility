"""Focused current-source regression; old measurements remain historical evidence."""
import hashlib,json,pathlib,subprocess,time,tempfile
b=pathlib.Path(__file__).resolve().parent
def inputs():
 paths=[p for pattern in ['*.java','*.py','*.sh'] for p in b.glob(pattern)]+list((b/'research/e1').glob('*.java'))+list((b/'research').glob('*.py'))+[b/'paper/e1-protocol.json',b/'paper/claims.json',b/'dependencies.sha256',b/'lib/bcprov-jdk18on-1.86.jar']
 return {str(p.relative_to(b)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
def main():
 before=inputs();started=time.time();records=[]
 commands=[['java','-m','jdk.compiler/com.sun.tools.javac.Main','--release','17','-Xlint:all','-Werror','-cp','lib/bcprov-jdk18on-1.86.jar','-d','build',*[p.name for p in sorted(b.glob('*.java'))]]]
 for name,folder in [('StabilityTest','integrated'),('RecoveryTest','recovery'),('SecurityAuditTest','security'),('LifecycleCleanupTest','security'),('CodecRegressionTest','security'),('ReuseCleanupTest','security'),('StoreIsolationTest','security'),('ParallelBatchTest','security'),('ParallelRiskTest','security'),('ParallelFollowupTest','security'),('CompletionSecurityTest','security')]:
  commands.append(['java','-Xmx512m','-cp','build' if name=='StoreIsolationTest' else 'build:lib/bcprov-jdk18on-1.86.jar',name,'results/'+folder])
 for name in ['research/e1_recording_check.py','process-check.py','engine-process-check.py','cli-check.py','cli-wrapper-check.py','cli-build-check.py','cli-cache-check.py','cli-integrity-check.py','easy-check.py','easy-optimization-check.py','easy-batch-check.py','easy-parallel-check.py','easy-stream-check.py','packet-stream-check.py','packet-stream-roundtrip.py','decrypt-memory-check.py','decrypt-auth-check.py','easy-cancel-check.py','normal-v13-compatibility.py','normal-v14-compatibility.py']:
  commands.append(['python3',name])
 (b/'build').mkdir(exist_ok=True);code=0
 for command in commands:
  result=subprocess.run(command,cwd=b,capture_output=True,text=True);records.append(dict(command=command,exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr))
  print('PASS' if not result.returncode else 'FAIL',command[0],command[-1],flush=True)
  if result.returncode:code=result.returncode;break
 changed=inputs()!=before
 if changed:code=1
 record=dict(passed=code==0,exit_code=code,elapsed_seconds=time.time()-started,inputs_changed=changed,input_sha256=before,checks=records,scope='Current-source cryptographic/parallel/CLI/process recovery regression plus checkpoint/document API fixes. E1 and full normal paper workload are recorded separately. Includes isolated shell-cache micro-measurements and packet-publication/decrypt-staging helper tracemalloc samples; no new real-JVM crypto throughput/RSS benchmark or full paper workload. Previous full measurements are historical, not current-source certification.')
 (b/'PARALLEL_FOLLOWUP_VALIDATION.json').write_text(json.dumps(record,indent=2)+'\n')
 raise SystemExit(code)
if __name__=='__main__':main()
