"""Strict component aggregation: 3 fresh JVMs, complete unique cells, no significance claim."""
import collections,csv,json,pathlib,statistics
BASE=pathlib.Path(__file__).resolve().parent
rows=[]
expected={(op,variant,size,keys,sample) for op,size,keys in [('checkpoint_seal',0,0),('checkpoint_seal',8192,0),('checkpoint_seal',1048576,0),('anchor_parse',28,0),('anchor_parse',8192,32),('anchor_parse',1048604,4096)] for variant in ('v13_reference','v15') for sample in range(7)}
for fork in range(1,4):
 folder=BASE/f'results/optimization/fork-{fork}';check=json.loads((folder/'checks.json').read_text());assert check['passed'] and check['checks']==41 and check['rows']==84
 with (folder/'cost.csv').open(newline='') as stream:
  reader=csv.DictReader(stream);assert reader.fieldnames==['fork','operation','variant','bytes','keys','sample','ns','allocated_bytes'];part=list(reader)
 seen=set();assert len(part)==84
 for row in part:
  for key in ['fork','bytes','keys','sample','ns','allocated_bytes']:row[key]=int(row[key])
  cell=(row['operation'],row['variant'],row['bytes'],row['keys'],row['sample']);assert row['fork']==fork and row['ns']>0 and row['allocated_bytes']>=-1 and cell in expected and cell not in seen;seen.add(cell)
 assert seen==expected;rows.extend(part)
groups=collections.defaultdict(list)
for row in rows:groups[(row['operation'],row['variant'],row['bytes'],row['keys'])].append(row)
stats=[]
for (op,variant,size,keys),data in sorted(groups.items()):
 medians=[statistics.median(r['ns'] for r in data if r['fork']==f) for f in range(1,4)]
 allocations=[r['allocated_bytes'] for r in data]
 stats.append({'operation':op,'variant':variant,'bytes':size,'keys':keys,'rows':len(data),'median_of_fork_medians_ns':statistics.median(medians),'fork_median_range_ns':[min(medians),max(medians)],'median_allocated_bytes':None if -1 in allocations else statistics.median(allocations)})
result={'passed':True,'rows':len(rows),'fresh_jvms':3,'checks':123,'groups':stats,'scope':'component costs with synthetic data; checkpoint Cipher initialization excluded; anchor HMAC and state publication excluded; allocations include measurement overhead; not RSS, significance or global speedup'}
(BASE/'results/optimization/summary.json').write_text(json.dumps(result,indent=2)+'\n')
table=['| 작업 | 입력 B / 키 수 | v13 할당 B | v15 할당 B | 할당 감소 | v13 중앙 µs | v15 중앙 µs |','|---|---:|---:|---:|---:|---:|---:|']
for op,size,keys in [('checkpoint_seal',0,0),('checkpoint_seal',8192,0),('checkpoint_seal',1048576,0),('anchor_parse',28,0),('anchor_parse',8192,32),('anchor_parse',1048604,4096)]:
 a=next(g for g in stats if (g['operation'],g['variant'],g['bytes'],g['keys'])==(op,'v13_reference',size,keys));b=next(g for g in stats if (g['operation'],g['variant'],g['bytes'],g['keys'])==(op,'v15',size,keys));aa=a['median_allocated_bytes'];bb=b['median_allocated_bytes'];reduction='미측정' if aa is None or bb is None or aa==0 else f'{(aa-bb)/aa*100:.1f}%'
 table.append(f"| {op} | {size:,} / {keys} | {aa} | {bb} | {reduction} | {a['median_of_fork_medians_ns']/1000:.3f} | {b['median_of_fork_medians_ns']/1000:.3f} |")
(BASE/'results/optimization/table.md').write_text('\n'.join(table)+'\n')
print('PASS optimization aggregate rows=252 fresh_jvms=3 checks=123')
