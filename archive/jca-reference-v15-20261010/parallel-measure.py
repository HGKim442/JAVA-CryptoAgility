"""Workers 1/2/4: three fresh JVMs per profile/size condition, no cloned key stores."""
import csv,json,pathlib,statistics,subprocess,tempfile
b=pathlib.Path(__file__).resolve().parent;out=b/'results/parallel';out.mkdir(parents=True,exist_ok=True)
def cli(*args):subprocess.run(['bash',str(b/'cli.sh'),*map(str,args)],cwd=b,capture_output=True,text=True,check=True,timeout=120)
rows=[]
with tempfile.TemporaryDirectory(prefix='parallel-normal-cost-') as temp:
 root=pathlib.Path(temp)
 for profile in [3,5]:
  fixture=root/str(profile);fixture.mkdir(mode=0o700)
  for name in ['data','anchor']:(fixture/name).mkdir(mode=0o700)
  cli('keygen',fixture/'master.key');cli('init',fixture/'master.key',fixture/'data',fixture/'anchor','parallel-cost')
  if profile==5:cli('upgrade5',fixture/'master.key',fixture/'data',fixture/'anchor','parallel-cost')
  for size in [4096,1048576]:
   for i in range(8):
    p=fixture/f'input-{size}-{i}';p.write_bytes(bytes([i])*size);p.chmod(0o600)
   for fork in range(3):
    order=[1,2,4];order=order[fork:]+order[:fork]
    for workers in order:
     folder=out/f'p{profile}-b{size}-w{workers}-f{fork+1}'
     process=subprocess.run(['java','-XX:-UsePerfData','-Xms64m','-Xmx512m','-cp','build:lib/bcprov-jdk18on-1.86.jar','ParallelBatchBenchmark',str(folder),str(workers),str(size),str(fixture)],cwd=b,capture_output=True,text=True,timeout=120)
     (folder/'execution.log').write_text(process.stdout+process.stderr)
     if process.returncode:raise RuntimeError('Parallel cost JVM failed: '+process.stderr)
     normal=json.loads((folder/'parallel-normal-checks.json').read_text());assert normal=={'passed':True,'normal_decryptions':32,'measured_rows':3}
     part=list(csv.DictReader((folder/'parallel-cost.csv').open()));assert len(part)==3 and {r['sample'] for r in part}=={'0','1','2'}
     for r in part:
      assert (int(r['profile']),int(r['workers']),int(r['message_bytes']),int(r['files']))==(profile,workers,size,8)
      assert all(int(r[k])>0 for k in ['wall_ns','heap_pool_peak_sum_bytes','rss_hwm_bytes'])
      rows.append(dict(r,fork=fork+1))
expected={(p,s,w,f,i) for p in [3,5] for s in [4096,1048576] for w in [1,2,4] for f in [1,2,3] for i in [0,1,2]}
assert len(rows)==len(expected)==108 and {(int(r['profile']),int(r['message_bytes']),int(r['workers']),r['fork'],int(r['sample'])) for r in rows}==expected
stats=[]
for p in [3,5]:
 for size in [4096,1048576]:
  for workers in [1,2,4]:
   selected=[r for r in rows if (int(r['profile']),int(r['message_bytes']),int(r['workers']))==(p,size,workers)]
   medians=[statistics.median(int(r['wall_ns']) for r in selected if r['fork']==f) for f in [1,2,3]]
   heap=[statistics.median(int(r['heap_pool_peak_sum_bytes']) for r in selected if r['fork']==f) for f in [1,2,3]]
   rss=[max(int(r['rss_hwm_bytes']) for r in selected if r['fork']==f) for f in [1,2,3]]
   wall=statistics.median(medians);stats.append(dict(profile=p,message_bytes=size,workers=workers,median_batch_ns=wall,fork_median_range_ns=[min(medians),max(medians)],files_per_second=8e9/wall,median_heap_pool_peak_sum_bytes=statistics.median(heap),median_jvm_rss_hwm_bytes=statistics.median(rss)))
with (out/'parallel-cost.csv').open('w',newline='') as stream:
 writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
result=dict(environment={name:pathlib.Path("/sys/fs/cgroup/"+name).read_text().strip() for name in ["cpu.max","memory.max"]},passed=True,rows=108,fresh_jvms=36,normal_decryptions=1152,files_per_batch=8,statistics=stats,scope='3 fresh JVMs per condition, workers rotated 1/2/4 order; same live profile key/store, reservations monotonically advance, never clone anchor; untimed one batch warmup and three measured batches; System.gc before batch outside timing; core read/nonce reservation/crypto/durable publication/thread startup+drain included, JVM startup/reopen and verification excluded; sum of heap-pool peaks may represent different instants; JVM VmHWM cumulative includes startup/reopen/warmup/post-checks, not per-batch RSS; uncontrolled host load, descriptive small sample, no significance or general speed guarantee')
(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS parallel normal measurements rows=108 JVMs=36')
