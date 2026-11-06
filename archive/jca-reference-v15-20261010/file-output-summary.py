"""Validate every expected cell before pooling descriptive file-output measurements."""
import csv,json,pathlib,statistics
b=pathlib.Path(__file__).resolve().parent
all_rows=[]
for fork in range(1,4):
 folder=b/'results/file-output'/('fork-'+str(fork));rows=list(csv.DictReader((folder/'file-output-cost.csv').open()))
 expected={(str(p),str(size),str(sample),variant) for p in [3,5] for size in [0,4096,1048576,16777216] for sample in range(7 if size>=1048576 else 31) for variant in ['encode_then_publish','gather_publish']}
 actual=[(r['profile'],r['message_bytes'],r['sample'],r['variant']) for r in rows]
 assert len(rows)==len(set(actual))==304 and set(actual)==expected
 for r in rows:assert int(r['ns'])>0 and int(r['allocated_bytes'])>=0
 checks=json.loads((folder/'file-output-checks.json').read_text());assert checks['passed'] and checks['checks']==62
 all_rows.extend(dict(r,fork=fork) for r in rows)
summary=[]
for profile in [3,5]:
 for size in [0,4096,1048576,16777216]:
  for variant in ['encode_then_publish','gather_publish']:
   selected=[r for r in all_rows if int(r['profile'])==profile and int(r['message_bytes'])==size and r['variant']==variant]
   fork_ns=[statistics.median(int(r['ns']) for r in selected if r['fork']==f) for f in range(1,4)]
   fork_alloc=[statistics.median(int(r['allocated_bytes']) for r in selected if r['fork']==f) for f in range(1,4)]
   summary.append(dict(profile=profile,message_bytes=size,variant=variant,rows=len(selected),median_of_fork_medians_ns=statistics.median(fork_ns),fork_median_range_ns=[min(fork_ns),max(fork_ns)],median_allocated_bytes=statistics.median(fork_alloc)))
result=dict(passed=True,rows=len(all_rows),checks=186,statistics=summary,scope='3 fresh JVMs; same authenticated packet per condition; durable file creation/write/force/link/directory force included, encryption/decryption excluded; unlink and output checking outside timing; thread heap allocation excludes native buffers and RSS; descriptive medians, small warmup and 7 large-input samples per fork, no general speed guarantee')
(b/'results/file-output/summary.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS file output rows='+str(len(all_rows))+' checks=186')
