"""v15 singles versus v15 batch, including Python/Bash/JVM startup and file I/O."""
import csv,json,pathlib,statistics,subprocess,tempfile,time
BASE=pathlib.Path(__file__).resolve().parent;OUT=BASE/'results/reuse';OUT.mkdir(parents=True,exist_ok=True)
def run(home,*args):
 return subprocess.run(['python3',str(BASE/'easy.py'),'--home',str(home),*map(str,args)],capture_output=True,text=True,timeout=120,check=True)
rows=[]
with tempfile.TemporaryDirectory(prefix='normal-batch-cost-') as temp:
 root=pathlib.Path(temp);home=root/'home';run(home,'setup','--anchor',root/'anchor');sources=[]
 for i in range(8):
  p=root/f'input-{i}.bin';p.write_bytes(bytes([i])*4096);p.chmod(0o644);sources.append(p)
 for sample in range(-1,6):
  for variant in (['single','batch'] if sample%2==0 else ['batch','single']):
   output=root/f'out-{sample}-{variant}';output.mkdir(mode=0o700);start=time.perf_counter_ns()
   if variant=='batch':run(home,'encrypt-batch',*sources,'--output-dir',output)
   else:
    for p in sources:run(home,'encrypt',p,'--output',output/(p.name+'.pqc'))
   ns=time.perf_counter_ns()-start
   if sample>=0:rows.append({'sample':sample,'variant':variant,'files':8,'plaintext_bytes_per_file':4096,'wall_ns':ns,'core_jvm_invocations':1 if variant=='batch' else 8})
   for p in sources:
    packet=output/(p.name+'.pqc');assert packet.read_bytes()[:8]==b'PQCEASY1' and packet.stat().st_mode&0o777==0o600
   # Post-timing normal verification, excluded from encryption cost.
   for p in [sources[0],sources[-1]]:
    restored=output/(p.name+'.restored');run(home,'decrypt',output/(p.name+'.pqc'),'--output',restored);assert restored.read_bytes()==p.read_bytes()
assert len(rows)==12 and {(r['sample'],r['variant']) for r in rows}=={(s,v) for s in range(6) for v in ['single','batch']}
with (OUT/'batch-cost.csv').open('w',newline='') as stream:
 writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
stats={v:{'samples':6,'median_wall_ns':statistics.median(r['wall_ns'] for r in rows if r['variant']==v),'wall_ns_range':[min(r['wall_ns'] for r in rows if r['variant']==v),max(r['wall_ns'] for r in rows if r['variant']==v)],'core_jvm_invocations':1 if v=='batch' else 8} for v in ['single','batch']}
(OUT/'batch-summary.json').write_text(json.dumps({'passed':True,'rows':12,'files':8,'plaintext_bytes_per_file':4096,'statistics':stats,'scope':'same v15 engine/config, 1 untimed warmup per variant then 6 balanced paired runs; startup/wrapper/normal file I/O included; 2 post-timing decryptions per run; descriptive wall times, uncontrolled host load, no significance'},indent=2)+'\n')
print('PASS batch normal wall-cost rows=12 files=8')
