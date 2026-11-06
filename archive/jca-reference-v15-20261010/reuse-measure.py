"""Matched v14/v15 reopen fixtures and repeat 8KiB component measurement."""
import csv,json,pathlib,shutil,statistics,subprocess,tempfile
BASE=pathlib.Path(__file__).resolve().parent;OUT=BASE/'results/reuse';OUT.mkdir(parents=True,exist_ok=True)
def execute(args,**kwargs):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=120,**kwargs)
def aggregate(rows,keys,value):
 groups={}
 for row in rows:groups.setdefault(tuple(row[k] for k in keys),[]).append(row)
 result=[]
 for key,data in sorted(groups.items()):
  medians=[statistics.median(int(r[value]) for r in data if int(r['fork'])==f) for f in range(1,7)]
  allocations=[int(r['allocated_bytes']) for r in data]
  result.append({**dict(zip(keys,key)),'rows':len(data),'median_of_fork_medians_ns':statistics.median(medians),'fork_median_range_ns':[min(medians),max(medians)],'median_allocated_bytes':None if -1 in allocations else statistics.median(allocations)})
 return result
def load(path,fields,fork,expected):
 with path.open(newline='') as stream:
  reader=csv.DictReader(stream);assert reader.fieldnames==fields;rows=list(reader)
 seen=set()
 for row in rows:
  cell=tuple(row[k] for k in fields if k not in ['fork','ns','allocated_bytes']);assert int(row['fork'])==fork and int(row['ns'])>0 and int(row['allocated_bytes'])>=-1 and cell not in seen;seen.add(cell)
 assert seen==expected;return rows
with tempfile.TemporaryDirectory(prefix='reuse-cost-') as temp:
 root=pathlib.Path(temp);old=root/'v14';old.mkdir();(old/'build').mkdir();sources=[]
 for ref in sorted((BASE/'history-v14').glob('*.java.reference')):
  p=old/ref.name.removesuffix('.reference');shutil.copy2(ref,p);sources.append(str(p))
 jar=str(BASE/'lib/bcprov-jdk18on-1.86.jar');sources.append(str(BASE/'ReopenCost.java'))
 execute(['java','-m','jdk.compiler/com.sun.tools.javac.Main','--release','17','-Xlint:all','-Werror','-cp',jar,'-d',str(old/'build'),*sources])
 oldcp=str(old/'build')+':'+jar;newcp=str(BASE/'build')+':'+jar;reopen=[];small=[]
 for fork in range(1,7):
  fixture=root/f'fixture-{fork}';fixture.mkdir(mode=0o700);master=fixture/'master.key'
  execute(['java','-XX:-UsePerfData','-cp',oldcp,'CryptoCli','keygen',str(master)])
  for profile in [3,5]:
   data=fixture/f'data{profile}';anchor=fixture/f'anchor{profile}';data.mkdir(mode=0o700);anchor.mkdir(mode=0o700);common=list(map(str,[master,data,anchor,'normal-reopen-v15']))
   execute(['java','-XX:-UsePerfData','-cp',oldcp,'CryptoCli','init',*common])
   if profile==5:execute(['java','-XX:-UsePerfData','-cp',oldcp,'CryptoCli','upgrade5',*common])
  for variant,cp in ([('v14',oldcp),('v15',newcp)] if fork%2 else [('v15',newcp),('v14',oldcp)]):
   path=OUT/f'reopen-{fork}-{variant}.csv';r=execute(['java','-XX:-UsePerfData','-Xms256m','-Xmx512m','-cp',cp,'ReopenCost',str(fixture),str(path),variant,str(fork)]);(OUT/f'reopen-{fork}-{variant}.log').write_text(r.stdout+r.stderr)
   expected={(variant,str(profile),str(sample)) for profile in [3,5] for sample in range(31)}
   reopen+=load(path,['fork','variant','profile','sample','ns','allocated_bytes'],fork,expected)
  path=OUT/f'small-{fork}.csv';r=execute(['java','-XX:-UsePerfData','-Xms256m','-Xmx512m','-cp',newcp,'SmallCheckpointCost',str(path),str(fork)]);(OUT/f'small-{fork}.log').write_text(r.stdout+r.stderr)
  small+=load(path,['fork','variant','sample','ns','allocated_bytes'],fork,{(v,str(s)) for v in ['v13_reference','direct_output'] for s in range(101)})
 result={'passed':True,'reopen_rows':len(reopen),'small_checkpoint_rows':len(small),'reopen':aggregate(reopen,['variant','profile'],'ns'),'small_checkpoint':aggregate(small,['variant'],'ns'),'scope':'6 fresh JVMs per version; identical v14 checkpoint fixture, 20 warmup/31 reopen samples; 8KiB 200 warmup/101 samples per variant, balanced order, Cipher initialization excluded; descriptive medians not significance or whole CLI performance'}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
 print('PASS matched reopen rows=744 small checkpoint rows=1212')
