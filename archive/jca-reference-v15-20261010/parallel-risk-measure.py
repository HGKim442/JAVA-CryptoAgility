"""Balanced fresh-JVM comparison, actual baseline code, monotonically live store."""
import csv,hashlib,json,pathlib,statistics,subprocess,tempfile,shutil,platform
b=pathlib.Path(__file__).resolve().parent;out=b/'results/parallel-risk';out.mkdir(parents=True,exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sources(root):return {p.name:sha(p) for p in sorted(root.glob('*.java'))}
current=sources(b);rows=[];raw_hashes={}
with tempfile.TemporaryDirectory(prefix='parallel-risk-cost-') as temp:
 root=pathlib.Path(temp);baseline=root/'baseline';baseline.mkdir(mode=0o700);(baseline/'build').mkdir();(baseline/'lib').mkdir()
 shutil.copy2(b/'lib/bcprov-jdk18on-1.86.jar',baseline/'lib/bcprov-jdk18on-1.86.jar')
 baseline_names=['PqcExtension.java','NonceReservations.java','TrustedStateStore.java','SecretBuffer.java','AnchorCodec.java','CheckpointCodec.java','CryptoCli.java','ParallelRiskBenchmark.java','PacketCodecBenchmark.java']
 for name in baseline_names:
  path=b/name
  reference=b/'history-v15-parallel-risk'/(path.name+'.reference')
  shutil.copy2(reference if reference.exists() else path,baseline/path.name)
 baseline_hashes=sources(baseline)
 compiled=subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','--release','17','-Xlint:all','-Werror','-cp','lib/bcprov-jdk18on-1.86.jar','-d','build',*[p.name for p in sorted(baseline.glob('*.java'))]],cwd=baseline,capture_output=True,text=True)
 (out/'baseline-compile.log').write_text(compiled.stdout+compiled.stderr)
 if compiled.returncode:raise RuntimeError('Baseline compile failed; see results/parallel-risk/baseline-compile.log')
 def cli(*args):subprocess.run(['bash',str(b/'cli.sh'),*map(str,args)],cwd=b,capture_output=True,text=True,check=True,timeout=120)
 for profile in [3,5]:
  fixture=root/f'fixture-{profile}';fixture.mkdir(mode=0o700)
  for name in ['data','anchor']:(fixture/name).mkdir(mode=0o700)
  cli('keygen',fixture/'master.key');cli('init',fixture/'master.key',fixture/'data',fixture/'anchor','parallel-risk-cost')
  if profile==5:cli('upgrade5',fixture/'master.key',fixture/'data',fixture/'anchor','parallel-risk-cost')
  for size in [1048576,16777216]:
   for i in range(8):
    p=fixture/f'input-{size}-{i}';p.write_bytes(bytes([i])*size);p.chmod(0o600)
   for fork in range(1,4):
    workers_order=[1,2,4];workers_order=workers_order[fork-1:]+workers_order[:fork-1]
    for workers in workers_order:
     variants=['previous','revised'] if (fork+workers)%2 else ['revised','previous']
     for variant in variants:
      folder=out/f'p{profile}-b{size}-w{workers}-f{fork}-{variant}';folder.mkdir(mode=0o700,exist_ok=True)
      project=baseline if variant=='previous' else b
      process=subprocess.run(['java','-XX:-UsePerfData','-Xms64m','-Xmx512m','-cp','build:lib/bcprov-jdk18on-1.86.jar','ParallelRiskBenchmark',str(folder),str(workers),str(size),str(fixture)],cwd=project,capture_output=True,text=True,timeout=180)
      (folder/'execution.log').write_text(process.stdout+process.stderr)
      if process.returncode:raise RuntimeError('Risk benchmark failed: '+str(folder)+' '+process.stderr)
      assert json.loads((folder/'checks.json').read_text())=={'passed':True,'normal_decryptions':32,'rows':3}
      part=list(csv.DictReader((folder/'cost.csv').open()));assert len(part)==3 and {r['sample'] for r in part}=={'0','1','2'}
      for r in part:
       assert (int(r['profile']),int(r['requested_workers']),int(r['message_bytes']),int(r['files']))==(profile,workers,size,8)
       expected=2 if variant=='revised' and size==16777216 and workers==4 else workers
       assert int(r['effective_workers'])==expected and all(int(r[k])>0 for k in ['wall_ns','heap_pool_peak_sum_bytes','rss_hwm_bytes'])
       rows.append(dict(r,fork=fork,variant=variant))
      raw_hashes[str((folder/'cost.csv').relative_to(b))]=sha(folder/'cost.csv')
    print(f'PASS risk comparison profile={profile} bytes={size} fork={fork} completed_JVMs={len(rows)//3}',flush=True)
 assert sources(b)==current,'Sources changed during comparison'
expected={(p,s,w,f,v,i) for p in [3,5] for s in [1048576,16777216] for w in [1,2,4] for f in [1,2,3] for v in ['previous','revised'] for i in [0,1,2]}
assert len(rows)==len(expected)==216 and {(int(r['profile']),int(r['message_bytes']),int(r['requested_workers']),r['fork'],r['variant'],int(r['sample'])) for r in rows}==expected
stats=[]
for p,s,w,v in sorted({(int(r['profile']),int(r['message_bytes']),int(r['requested_workers']),r['variant']) for r in rows}):
 selected=[r for r in rows if (int(r['profile']),int(r['message_bytes']),int(r['requested_workers']),r['variant'])==(p,s,w,v)]
 medians=[statistics.median(int(r['wall_ns']) for r in selected if r['fork']==f) for f in [1,2,3]]
 heap=[statistics.median(int(r['heap_pool_peak_sum_bytes']) for r in selected if r['fork']==f) for f in [1,2,3]]
 rss=[max(int(r['rss_hwm_bytes']) for r in selected if r['fork']==f) for f in [1,2,3]]
 stats.append(dict(profile=p,message_bytes=s,requested_workers=w,effective_workers=int(selected[0]['effective_workers']),variant=v,median_batch_ns=statistics.median(medians),fork_median_range_ns=[min(medians),max(medians)],median_heap_pool_peak_sum_bytes=statistics.median(heap),median_jvm_rss_hwm_bytes=statistics.median(rss)))
with (out/'cost.csv').open('w',newline='') as stream:
 writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
result=dict(passed=True,rows=216,fresh_jvms=72,normal_decryptions=2304,statistics=stats,current_java_sha256=current,baseline_java_sha256=baseline_hashes,raw_sha256=raw_hashes,environment={'platform':platform.platform(),'java':subprocess.run(['java','-version'],capture_output=True,text=True).stderr},scope='Same harness compiled against saved original vs revised engines. Live same-profile key/store never cloned; nonce advances. 3 fresh JVMs per variant/profile/size/requested workers; rotated workers and alternated variant order. One untimed warmup8-file batch then3 measured batches. GC/heap reset before timing. Includes preflight/read/crypto/reservation query/durable publication/worker startup+drain; excludes startup/reopen/decrypt/unlink. Warmup commits128 nonces; measured24 stay within reservation. Heap pool peak sum not simultaneous peak; VmHWM is cumulative JVM peak including prior checks, not full easy.py process tree. Fixed512MiB heap, uncontrolled host load, descriptive data only. Largest16MiB revised requested4 actually2: compares safer policy, not same-concurrency cipher speed.')
(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS risk comparison rows=216 JVMs=72')
