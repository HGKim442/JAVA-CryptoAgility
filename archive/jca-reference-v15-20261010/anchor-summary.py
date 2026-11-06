import pathlib,json,csv,collections,statistics
b=pathlib.Path(__file__).resolve().parent
paths=sorted((b/'results/anchor').glob('*/anchor-cost.csv'));assert len(paths)==3
rows=[]
for p in paths:
 check=json.loads((p.parent/'anchor-checks.json').read_text());assert check['passed'] and check['checks']==20
 rows.extend(csv.DictReader(p.open()))
assert len(rows)==1512
g=collections.defaultdict(list)
for r in rows:g[int(r['sealed_bytes']),int(r['keys']),r['method']].append(r)
result=[];table=['| 암호화 checkpoint B | 키 수 | 기존 할당 B | 개선 할당 B | 감소 | 기존 중앙 µs | 개선 중앙 µs |','|---:|---:|---:|---:|---:|---:|---:|']
for size,keys in [(28,0),(8192,1),(65536,32),(1048604,4096)]:
 old=g[size,keys,'legacy'];new=g[size,keys,'exact'];expected=36 if size>1000000 else 120 if size>60000 else 300;assert len(old)==len(new)==expected
 ba=statistics.median(int(r['allocated_bytes']) for r in old);aa=statistics.median(int(r['allocated_bytes']) for r in new);bt=statistics.median(int(r['ns']) for r in old)/1000;at=statistics.median(int(r['ns']) for r in new)/1000
 result.append({'sealed_bytes':size,'keys':keys,'samples_per_method':expected,'legacy_allocated_bytes_median':ba,'exact_allocated_bytes_median':aa,'allocation_reduction_percent':100*(1-aa/ba),'legacy_us_median':bt,'exact_us_median':at})
 table.append(f'| {size:,} | {keys:,} | {ba:,.0f} | {aa:,.0f} | {100*(1-aa/ba):.1f}% | {bt:,.3f} | {at:,.3f} |')
summary={'passed':True,'checks':60,'fresh_jvms':3,'samples':1512,'rows':result,'scope':'serialization of synthetic already-sealed bytes only; no filesystem or HMAC timing; v9 reference body vs exact record; paired alternating order; allocation is ThreadMXBean not RSS'}
(b/'results/anchor/pooled-summary.json').write_text(json.dumps(summary,indent=2)+'\n');(b/'results/anchor/table.md').write_text('\n'.join(table)+'\n');print(json.dumps(result))
