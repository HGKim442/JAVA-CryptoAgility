import pathlib,csv,json,collections,statistics
b=pathlib.Path(__file__).resolve().parent
paths=sorted((b/'results/codec').glob('*/codec-cost.csv'));assert len(paths)==3
rows=[]
for p in paths:
 check=json.loads((p.parent/'codec-checks.json').read_text());assert check['passed'] and check['checks']==24
 rows.extend(csv.DictReader(p.open()))
assert len(rows)==2712
g=collections.defaultdict(list)
for r in rows:g[int(r['profile']),int(r['message_bytes']),r['method']].append(r)
summary=[];table=['| 프로필 | 평문 크기 | 기존 할당 B | 개선 할당 B | 할당 감소 | 기존 중앙 µs | 개선 중앙 µs |','|---|---:|---:|---:|---:|---:|---:|']
for profile in [3,5]:
 for size in [0,4096,1048576,16777216]:
  before=g[profile,size,'legacy'];after=g[profile,size,'exact'];assert len(before)==len(after)==(18 if size==16777216 else 60 if size==1048576 else 300)
  ba=statistics.median(int(r['allocated_bytes']) for r in before);aa=statistics.median(int(r['allocated_bytes']) for r in after)
  bt=statistics.median(int(r['ns']) for r in before)/1000;at=statistics.median(int(r['ns']) for r in after)/1000
  item={'profile':profile,'message_bytes':size,'samples_per_method':len(before),'legacy_allocated_bytes_median':ba,'exact_allocated_bytes_median':aa,'allocation_reduction_percent':100*(1-aa/ba),'legacy_us_median':bt,'exact_us_median':at};summary.append(item)
  table.append(f'| P{profile} | {size:,} | {ba:,.0f} | {aa:,.0f} | {100*(1-aa/ba):.1f}% | {bt:,.3f} | {at:,.3f} |')
result={'fresh_jvms':3,'checks':72,'samples':2712,'rows':summary,'scope':'serialization only; v7 reference encoder body and v8 encoder on same normal packet; no whole-engine speedup claim; local ThreadMXBean allocations, not RSS; paired alternating order'}
(b/'results/codec/pooled-summary.json').write_text(json.dumps(result,indent=2)+'\n')
(b/'results/codec/table.md').write_text('\n'.join(table)+'\n')
