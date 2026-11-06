import pathlib,json,csv,statistics,collections,hashlib,zipfile,re,subprocess
subprocess.run(['python3',str(pathlib.Path(__file__).resolve().parent/'codec-summary.py')],check=True)
subprocess.run(['python3',str(pathlib.Path(__file__).resolve().parent/'anchor-summary.py')],check=True)
subprocess.run(['python3',str(pathlib.Path(__file__).resolve().parent/'optimization-summary.py')],check=True)
b=pathlib.Path(__file__).resolve().parent;c=b.parent
run=json.loads((b/'run.json').read_text());assert run['exit_code']==0 and 'PASS integrated stability checks=105' in run['stdout'];process=json.loads((b/'results/integrated/process-check.json').read_text());assert process['cross_process_reservations']['unique']==80 and process['post_reservation_sigkill']['restart_values']==[128,129,130,131]
parts=collections.defaultdict(list)
for p in sorted((b/'results/parts').glob('*/part-cost.csv')):
 rows=list(csv.DictReader(p.open()));assert len(rows)==264
 for r in rows:parts[(r['part'],r['variant'])].append(r)
part_stats=[];table=[]
for (part,variant),rows in sorted(parts.items()):
 times=[int(r['ns'])/int(r['batch_operations']) for r in rows];alloc=[int(r['thread_allocated_bytes'])/int(r['batch_operations']) for r in rows];ops=sum(int(r['batch_operations']) for r in rows);writes=sum(int(r['durable_reservations']) for r in rows)
 item={'part':part,'variant':variant,'samples':len(rows),'median_ns_per_operation':statistics.median(times),'mean_ns_per_operation':sum(int(r['ns']) for r in rows)/ops,'median_thread_allocated_bytes_per_operation':statistics.median(alloc),'measured_operations':ops,'durable_reservation_writes':writes};part_stats.append(item)
 table.append(f"| {part} | {variant} | {item['median_ns_per_operation']:.2f} | {item['mean_ns_per_operation']:.2f} | {item['median_thread_allocated_bytes_per_operation']:.2f} | {writes} |")
old=next(x for x in part_stats if x['variant']=='format_each_call');new=next(x for x in part_stats if x['variant']=='cached_copy');one=next(x for x in part_stats if x['variant']=='block_1');many=next(x for x in part_stats if x['variant']=='block_128')
allocation_reduction=(old['median_thread_allocated_bytes_per_operation']-new['median_thread_allocated_bytes_per_operation'])/old['median_thread_allocated_bytes_per_operation']*100
assert one['measured_operations']==many['measured_operations']==2976 and one['durable_reservation_writes']==2976 and many['durable_reservation_writes']==24
request=collections.defaultdict(list)
for p in sorted((b/'results/request').glob('*/request-cost.csv')):
 rows=list(csv.DictReader(p.open()));assert len(rows)==124
 for r in rows:request[(r['profile'],r['component'])].append(r)
request_stats=[];request_table=[]
for (profile,component),rows in sorted(request.items()):
 assert len(rows)==186
 item={'profile':profile,'component':component,'samples':len(rows),'median_ns':statistics.median(int(r['ns']) for r in rows),'median_thread_allocated_bytes':statistics.median(int(r['thread_allocated_bytes']) for r in rows)};request_stats.append(item)
 request_table.append(f"| P{profile} | {component} | {item['median_ns']/1000:.3f} | {item['median_thread_allocated_bytes']:.0f} |")
for p in sorted((b/'results/pqc').glob('*/pqc-functional.csv')):
 rows=list(csv.DictReader(p.open()));assert len(rows)==40 and all(all(r[k]=='true' for k in ['kem_secret_match','aead_roundtrip','signature_valid','wrong_context_rejected','changed_message_rejected','changed_encapsulation_aead_rejected']) for r in rows)
for p in sorted((b/'results/pqc').glob('*/pqc-policy.csv')):
 rows=list(csv.DictReader(p.open()));assert len(rows)==22 and all(r['rejected']=='true' and r['backend_invocations']=='0' for r in rows)
for p in sorted((b/'results/pqc').glob('*/pqc-cost.csv')):assert len(list(csv.DictReader(p.open())))==1212
for p in sorted((b/'results/classical').glob('*/normal-transitions.csv')):assert len(list(csv.DictReader(p.open())))==450
for name,digest in run['source_sha256'].items():assert hashlib.sha256((b/name).read_bytes()).hexdigest()==digest
for folder,file in [('parts','part-cost.csv'),('pqc','pqc-cost.csv'),('classical','normal-transitions.csv')]:assert len(list((b/'results'/folder).glob('*/'+file)))==3
for folder,file in [('request','request-cost.csv'),('persistent','persistent-cost.csv'),('evidence','evidence-matrix.csv')]:assert len(list((b/'results'/folder).glob('*/'+file)))==6
recovery=json.loads((b/'results/recovery/recovery-results.json').read_text());engine_process=json.loads((b/'results/recovery/engine-process-results.json').read_text());assert recovery['passed'] and recovery['checks']>=133 and engine_process['passed']
stability=int(re.search(r'PASS checks=(\d+)',(b/'results/integrated/stability.log').read_text()).group(1));assert stability==105
persistent=collections.defaultdict(list)
for p in sorted((b/'results/persistent').glob('*/persistent-cost.csv')):
 rows=list(csv.DictReader(p.open()));assert len(rows)==124
 for r in rows:persistent[(r['profile'],r['component'])].append(int(r['ns']))
persistent_stats=[];persistent_table=[]
for (profile,component),times in sorted(persistent.items()):
 assert len(times)==186
 item={'profile':profile,'component':component,'samples':len(times),'median_ns':statistics.median(times),'mean_ns':statistics.mean(times)};persistent_stats.append(item)
 persistent_table.append(f"| P{profile} | {component} | {item['median_ns']/1000:.3f} | {item['mean_ns']/1000:.3f} |")
evidence_rows=[]
for file in sorted((b/'results/evidence').glob('*/evidence-matrix.csv')):
 rows=list(csv.DictReader(file.open()));assert len(rows)==76 and all(r['passed']=='true' for r in rows);evidence_rows.extend(rows)
parser_cases=sum(json.loads(p.read_text())['parser_cases'] for p in (b/'results/evidence').glob('*/evidence-summary.json'))
assert len(evidence_rows)==456 and parser_cases==6144
(b/'results/evidence/pooled-summary.json').write_text(json.dumps({'defensive_matrix_rows':len(evidence_rows),'parser_invalid_length_trials':parser_cases,'fresh_jvms':6,'scope':'defensive protected-engine checks; not attack blocking rate'},indent=2)+'\n')
orders={}
for folder,file in [('request','request-cost.csv'),('persistent','persistent-cost.csv')]:
 orders[folder]=[next(csv.DictReader(p.open()))['profile'] for p in sorted((b/'results'/folder).glob('*/'+file))]
 assert collections.Counter(orders[folder])=={'3':3,'5':3}
(b/'results/experiment-orders.json').write_text(json.dumps(orders,indent=2)+'\n')
audit=json.loads((b/'results/security/security-audit-tests.json').read_text());assert audit['passed'] and audit['checks']==15
lifecycle=json.loads((b/'results/security/lifecycle-cleanup-tests.json').read_text());assert lifecycle['passed'] and lifecycle['checks']==10
codec=json.loads((b/'results/codec/pooled-summary.json').read_text())
codec_regression=json.loads((b/'results/security/codec-regression.json').read_text());assert codec_regression['passed'] and codec_regression['checks']==109 and codec_regression['boundary_cases']==24 and codec_regression['concurrent_encodes']==1024
anchor=json.loads((b/'results/anchor/pooled-summary.json').read_text());assert anchor['passed'] and anchor['checks']==60
cli=json.loads((b/'results/security/cli-checks.json').read_text());assert cli['passed'] and cli['checks']==81
wrapper=json.loads((b/'results/security/cli-wrapper-checks.json').read_text());assert wrapper['passed'] and wrapper['checks']==6
easy=json.loads((b/'results/security/easy-checks.json').read_text());assert easy['passed']
paper_latest=json.loads((b/'results/paper/latest.json').read_text());paper_result=json.loads((b/'results/paper'/paper_latest['run_id']/'summary.json').read_text());assert paper_result['passed'] and paper_result['rows']==2226
optimization=json.loads((b/'results/optimization/summary.json').read_text());easy_opt=json.loads((b/'results/security/easy-optimization.json').read_text());compat=json.loads((b/'results/security/compatibility-v13-v15.json').read_text());assert optimization['passed'] and easy_opt['passed'] and compat['passed']
reuse=json.loads((b/'results/reuse/summary.json').read_text());batch=json.loads((b/'results/reuse/batch-summary.json').read_text());compat14=json.loads((b/'results/security/compatibility-v14-v15.json').read_text());assert reuse['passed'] and batch['passed'] and compat14['passed']
summary={'reuse_measurements':reuse,'batch_measurements':batch,'normal_v14_compatibility':compat14,'optimization':optimization,'easy_optimization':easy_opt,'normal_v13_compatibility':compat,'paper_workload':paper_result,'easy':easy,'cli_wrapper':wrapper,'cli':cli,'anchor':anchor,'codec_regression':codec_regression,'codec':codec,'lifecycle_cleanup':lifecycle,'security_audit':audit,'profile_start_orders':orders,'defensive_matrix_rows' :len(evidence_rows),'parser_invalid_length_trials':parser_cases,'integrated_stability_checks' :stability,'recovery_checks':recovery['checks'],'engine_process':engine_process,'nonce_process':process,'parts':part_stats,'warm_request':request_stats,'persistent_request':persistent_stats,'scope':'trusted anchor and master key excluded from rollback; no physical power durability or attack blocking rate claim'}
(b/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
replacements={
 'OPTIMIZATION_TABLE':(b/'results/optimization/table.md').read_text(),
 'PAPER_WORKLOAD_TABLE':(b/'results/paper'/paper_latest['run_id']/'table.md').read_text(),
 'ANCHOR_TABLE':(b/'results/anchor/table.md').read_text(),
 'CODEC_TABLE':(b/'results/codec/table.md').read_text(),
 'TEST_RESULTS':f"- 신규 보안 강화 **15체크** 통과: 소유 버퍼 정리, 거부 경로 할당 상한 및 큰 데이터 정상 처리.\n- 신규 실제 엔진 방어 matrix **456행** 및 잘못된 길이 parser **6,144회** 검증, 독립 JVM 6개에서 전부 통과.\n- 통합 안정성 **{stability}체크** 통과.\n- 신규 영속 복구 **{recovery['checks']}체크** 통과.\n- 별도 JVM 전체 엔진 재시작·SIGKILL·P3/P5 이력·독점 lease 검사 통과.\n- 기존 고전 정상 roundtrip 1,350건, PQC 정상 roundtrip 120건/서명 검증 120건, 부적합 정책 후보 66건과 인증 거부 검사 재실행.\n- PQC 구성요소 비용 3,636표본, standalone binding/nonce 비용 792묶음 표본, warm 요청 744표본, 신규 persistent 비용 744표본.\n- nonce 구성요소 4프로세스 동시 예약 **80개 모두 고유**, 예약 직후 SIGKILL 후 시작값 128 확인.",
 'PART_TABLE':'| 파트 | 방식 | 중앙 ns/호출 | 총 시간/호출 ns | 중앙 할당 B/호출 | 예약 쓰기 |\n|---|---|---:|---:|---:|---:|\n'+'\n'.join(table),
 'REQUEST_TABLE':'| 프로필 | 작업 | 중앙 µs | 중앙 thread 할당 B |\n|---|---|---:|---:|\n'+'\n'.join(request_table),
 'PERSISTENT_TABLE':'| 프로필 | 작업 | 중앙 µs | 평균 µs |\n|---|---|---:|---:|\n'+'\n'.join(persistent_table)
}
for template,target in [('REPORT_TEMPLATE_KO.md','REPORT_EVIDENCE_KO.md'),('PAPER_TEMPLATE_KO.md','PAPER_DRAFT_KO.md')]:
 text=(b/template).read_text()
 for key,value in replacements.items():text=text.replace('{'+key+'}',value)
 (b/target).write_text(text)
report_name='JCA_JCE_Research_Comparison_Report_v15_Optimized_KO.md';(c/report_name).write_text((b/'REPORT_EVIDENCE_KO.md').read_text())
(b/'README.md').write_text('# JCA/JCE PQC research v15\n\nStart with `python3 easy.py help`; read QUICK_START_KO.md and USAGE_KO.md for file operations. Read SECURITY_AUDIT_KO.md and REPORT_EVIDENCE_KO.md for implemented features, trust model and measured results. PAPER_DRAFT_KO.md is a scoped manuscript draft, not a claim of completing attack PoCs or peer review.\n\nRead paper/RESEARCH_COMPLETION_KO.md and paper/COMPARISON_PROTOCOL_KO.md for the manuscript scope and future comparator. Reproduce offline: `python3 verify.py`, then `python3 summarize.py`. New normal workloads and strict evidence validation are included; comparator results are pending. Requires Java17, Python3, POSIX private directories, atomic move and directory fsync. BC1.86 and baseline archives are included.\n\nProtect the independent anchor and provide an external random 32-byte master key. RecoveryTest uses a deterministic TEST-ONLY key. A separate directory by itself is not an independent trust boundary.\n\nThis research engine is separate from Crypto Agility v6.9 product. History and baseline measurements are excluded from final aggregates.\n')
subprocess.run(['python3',str(b/'paper.py'),'audit'],check=True)
files={}
for p in sorted(b.rglob('*')):
 if p.is_file() and not {'build','__pycache__'}.intersection(p.relative_to(b).parts):files['research-comparison-v15-optimized/'+str(p.relative_to(b))]=p
pdf=c/'upload/Java_JCA_JCE_암호민첩성의_보안성_분석_20260925091255.pdf'
if not pdf.exists():pdf=c/'assignment.pdf'
if pdf.exists():files['assignment.pdf']=pdf
manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+name+'\n' for name,p in files.items())
out=c/'JCA_JCE_Research_Comparison_v15_Optimized.zip'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
 for name,p in files.items():z.write(p,name)
 z.writestr('SHA256SUMS',manifest)
with zipfile.ZipFile(out) as z:assert z.testzip() is None
print(json.dumps({'report':report_name,'zip':out.name,'summary':summary},ensure_ascii=False,indent=2))
