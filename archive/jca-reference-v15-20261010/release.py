from pathlib import Path
import json,statistics,subprocess,shutil,hashlib,zipfile
from parallel_report import note as parallel_report_note
from parallel_risk_report import note as parallel_risk_report_note
b=Path(__file__).resolve().parent;root=b.parent
run=json.loads((b/'run.json').read_text());assert run['exit_code']==0 and not run['inputs_changed_during_run']
r=json.loads((b/'results/reuse/summary.json').read_text());batch=json.loads((b/'results/reuse/batch-summary.json').read_text());assert r['passed'] and batch['passed'] and r['reopen_rows']==744 and r['small_checkpoint_rows']==1212
latest=json.loads((b/'results/paper/latest.json').read_text());meta=json.loads((b/'results/paper'/latest['run_id']/'metadata.json').read_text());assert meta['status']=='complete' and meta['implementation']['id']=='proposed-v15'
file_result=json.loads((b/'results/file-output/summary.json').read_text());assert file_result['passed'] and file_result['rows']==912 and file_result['checks']==186
file_lines=['| 프로필 | 입력 B | 기존 할당 B | 직접 쓰기 할당 B | 기존 중앙 ms | 직접 쓰기 중앙 ms |','|---|---:|---:|---:|---:|---:|']
for profile in [3,5]:
 for size in [0,4096,1048576,16777216]:
  old=next(x for x in file_result['statistics'] if x['profile']==profile and x['message_bytes']==size and x['variant']=='encode_then_publish')
  new=next(x for x in file_result['statistics'] if x['profile']==profile and x['message_bytes']==size and x['variant']=='gather_publish')
  file_lines.append(f"| P{profile} | {size} | {old['median_allocated_bytes']} | {new['median_allocated_bytes']} | {old['median_of_fork_medians_ns']/1e6:.3f} | {new['median_of_fork_medians_ns']/1e6:.3f} |")
file_note='\n\n## 암호문 파일 직접 쓰기 최적화 (2026-10-08 Asia/Seoul)\n\nCLI seal/seal-batch에서 Packet.encode의 전체 wire 배열 복사를 제거했다. 기존 공개 encode/decode API와 파일 형식은 그대로다. 내부 파일 경로에서는 읽기 전용 ByteBuffer view를 gathering write로 전달한다. 부분 쓰기를 처리하고 진행 없는 쓰기는 거부한다. 0600 임시 파일, fsync, 덮어쓰기 없는 hard-link 게시와 디렉터리 fsync를 유지한다.\n\n'+ '\n'.join(file_lines)+'\n\n같은 인증 패킷·같은 durable publisher를 사용하여 기존 encode→publish와 gather→publish를 비교했다. 3개 새 JVM, 각 조건 warmup2회/큰 입력7표본 또는 warmup8회/작은 입력31표본, 912행이다. 파일 생성/쓰기/fsync/link/디렉터리 fsync를 시간 구간에 포함하고 암호화·복호화·unlink는 제외한다. 표는 JVM 중앙값들의 중앙값이며 fork 범위는 results/file-output/summary.json에 있다. CPU/파일시스템 cache와 부하 통제가 없어 유의성이나 전체 암호화 속도 향상을 주장하지 않는다. thread heap 할당량은 native I/O buffer·RSS·동시 메모리 peak를 포함하지 않는다.\n\n정상 바이트 동등성, 실제 P3/P5 복호화, 권한, 기존 파일 거부, 임시 파일 정리, 부분 쓰기, 읽기 전용 view, 합성 쓰기 실패/진행 없음 검사를 각62체크×3JVM=186체크 실행했다. 동일 사례의 반복이며 186개 독립 공격은 아니다. 원시 CSV와 수정 전 소스는 results/file-output 및 history-v15-file-output에 보존한다. 외부 비교 대상/E1 평가 완료를 의미하지 않는다.\n'
lines=['| 재개 조건 | v14 중앙 µs | v15 중앙 µs | v14 할당 B | v15 할당 B |','|---|---:|---:|---:|---:|']
for profile in ['3','5']:
 a=next(x for x in r['reopen'] if x['variant']=='v14' and x['profile']==profile);c=next(x for x in r['reopen'] if x['variant']=='v15' and x['profile']==profile)
 lines.append(f"| P{profile} | {a['median_of_fork_medians_ns']/1000:.3f} | {c['median_of_fork_medians_ns']/1000:.3f} | {a['median_allocated_bytes']} | {c['median_allocated_bytes']} |")
reopen_table='\n'.join(lines)
lines=['| 8KiB 체크포인트 방식 | 중앙 µs | JVM 중앙값 범위 µs | 중앙 할당 B |','|---|---:|---:|---:|']
for x in r['small_checkpoint']:
 lines.append(f"| {x['variant']} | {x['median_of_fork_medians_ns']/1000:.3f} | {x['fork_median_range_ns'][0]/1000:.3f}–{x['fork_median_range_ns'][1]/1000:.3f} | {x['median_allocated_bytes']} |")
small_table='\n'.join(lines)
lines=['| 8개×4KiB 암호화 | 중앙 wall ms | 범위 ms | 핵심 JVM 호출 수 |','|---|---:|---:|---:|']
for variant in ['single','batch']:
 x=batch['statistics'][variant];lines.append(f"| {variant} | {x['median_wall_ns']/1000000:.3f} | {x['wall_ns_range'][0]/1000000:.3f}–{x['wall_ns_range'][1]/1000000:.3f} | {x['core_jvm_invocations']} |")
batch_table='\n'.join(lines)
review='''# JCA/JCE PQC v15: 배치·복구 최적화와 보안 검증\n\n2026-10-07, Asia/Seoul. 저장된 v14를 기준으로 적용한 수정본. 전체 verify.py 종료 코드0, 실행 전후 소스·실험 입력 해시 일치. 별도 비교 대상 없이 현재 구현과 실제 컴파일한 v14의 정상 자료를 비교했다. 이 자료는 교수님 외부 비교 대상/E1 완료를 의미하지 않는다.\n\n## 적용 내용\n\n1. easy encrypt-batch: 최대64개 파일을 기존 seal-batch 한 core JVM/lease에서 처리한다. 각 입력16MiB 상한과0600 staging을 유지하고, 한 파일씩 읽어 메모리에 전체 입력을 쌓지 않는다. 동일 출력명·기존 출력·누락 입력을 검사한다. 단일 encrypt/decrypt는 유지한다.\n2. Engine.reopen 중복 복호화 제거: Store 생성자에서 인증된 평문을 내부 경로에서 load로 한 번 이전한다. load는 Store 참조를 제거하고 Engine restore 뒤 finally에서 평문을 지운다. 생성 실패/미소비 close/save도 정리한다. 공개 Store 생성자는 종전대로 인증 뒤 평문을 즉시 지운다.\n3. Store당 anchor MAC key32B를 한 번 파생하고 종료·생성 실패 시 master와 함께 정리한다. domain/HMAC 형식은 같고, 연산마다 별도 Mac을 사용한다.\n4. makeState의 SHA256 fingerprint를 State 생성자로 전달하여 같은 공개키의 인코딩·해시 재계산을 없앴다. bound/nonce/packet 형식은 유지한다.\n\n## 같은 저장 상태를 이용한 재개 비용\n\n'''+reopen_table+'''\n\n각버전6개 새 JVM, 각P3/P5 조건 warmup20회와31표본, 총744행이다. v14에서 생성한 동일 checkpoint fixture를 두 버전이 읽으며 순서는 균형을 맞췄다. 재개 구간에는 인증·키 import·pair 검사·mirror 검사 등이 포함되고 close와 JVM 시작은 제외한다. CPU 부하 통제가 없는 기술적 중앙값과 범위이며 유의성/인과적 단일 구성요소 개선율은 주장하지 않는다. 한 수치에 중복 복호화 제거·fingerprint·MAC 변화가 같이 반영된다.\n\n## 8KiB 체크포인트 재측정\n\n'''+small_table+'''\n\n6개 새 JVM에서 조건별 warmup200회/101표본, 총1,212행. 각 표본의 방식 순서를 번갈아 배치하고 정상 출력 동등성을 확인한다. Cipher 초기화와 파일 I/O는 제외한다. v13_reference는 종전 출력+concat 방식, direct_output은 v14부터 유지한 출력 배열 직접 쓰기 방식이다. 두 버전 전체 엔진 성능이 아니다. 이전7표본 측정의 시간 차이를 안정된 성능 저하라고 단정하지 않고 이번 원시 결과·JVM 범위와 함께 평가한다. 작은 입력 임계값/자동 방식 전환은 추가하지 않았다.\n\n## 실제 간편 도구의 배치 비용\n\n'''+batch_table+'''\n\n같은 v15 구현·설정·P3 key에서8개×4KiB 정상 파일을 처리한다. 방식별 무측정 warmup1회 후 순서를 균형 맞춘6쌍(12행). Python/Bash/JVM 시작, 의존성 확인, staging, core 암호화/예약, 출력 게시를 포함한다. 각실행 뒤 첫/마지막 파일의 복호화와 평문 일치를 시간 구간 밖에서 확인한다. CPU/디스크 cache와 부하가 통제되지 않아 일반 성능 보증으로 해석하지 않는다. 처리량 결과는 별도 근거이며 프로세스 수8→1은 코드 경로와 실제 배치 검사에서 확인했다.\n\n## 보안·호환성 확인\n\n- 새 소유 MAC/임시 평문 수명주기19체크, 실제 P3/P5 배치77체크와 JDK-only 저장소8체크.\n- 원본 v13↔v15 및 v14↔v15 각각 양방향 P3/P5 패킷·신뢰 상태 정상 roundtrip4건. 단순 구버전 모형 대신 보존한 원본 소스를 직접 컴파일했다.\n- 통합105, 복구133, 보안15, 정리10, 패킷 회귀109, CLI81, CLI wrapper6, easy31, 간편 helper25, 구성요소 동등성41×3, 논문 결과 검증기27체크 통과.\n- matrix76종×6JVM=456행, parser6,144회, nonce4프로세스80개 고유 및 SIGKILL 예약 건너뛰기 확인. 반복행은 독립 공격 수나 차단률이 아니다.\n- 정상 workload6개 JVM·2,226행, source/result SHA256와 완전한 cell·정상 출력·집계를 검사했다.\n\n서명 선검증, approved profile/Provider/context binding, 요청 일회 사용, 정책 하향 거부, key pair 확인, 과거 읽기와 퇴역, mirror 거부/명시 복구, nonce 선예약/앵커 선커밋을 유지했다. 이번 검사 범위에서 인증 우회나 새 기능의 회귀를 확인하지 않았으며 무취약 증명은 아니다.\n\n## 남은 범위와 사용\n\n배치 게시 도중 오류 시 앞의 출력은 남을 수 있다. 전체 트랜잭션이 아니다. 최대64개×16MiB staging은 입력+패킷 합계 약2GiB 디스크를 요구할 수 있다. crash 이후 staging 정리/평문 secure erase, 원자적 입력 snapshot은 보장하지 않는다.\n\nMAC key32B를 Store 수명 동안 보관하는 비용과 임시 인증 평문의 짧은 소유권 이전을 추가했다. public Store는 장기 평문 cache를 만들지 않는다. Provider/JVM 내부 사본의 완전한 삭제, 악의적인 동일 UID/부모 경로 격리, 독립 앵커 현재성, 외부 master key 관리, anti-replay, 다중 호스트와 물리 전원 내구성은 여전히 별도 범위이다. 보안 검사나 내구성 force를 생략해서 속도를 높이지 않았다.\n\n```bash\npython3 easy.py encrypt-batch "문서 1.txt" "문서 2.txt"\npython3 verify.py\npython3 release.py\n```\n\n세부 원시값: results/reuse/*.csv, summary.json, batch-summary.json. 보안 기록: SECURITY_AUDIT_KO.md. 이전 v14 원시값·문서는 history-v14에 보존했다. 기존 실패 기록도 유지하며 현재 집계와 혼합하지 않는다.\n'''
parallel_note=parallel_report_note(b)+parallel_risk_report_note(b)
(b/'OPTIMIZATION_REVIEW_KO.md').write_text(review+'\n\n'+(b/'REINSPECTION_KO.md').read_text()+file_note+parallel_note)
with (root/'summarize-v15-console.log').open('w') as f:subprocess.run(['python3','summarize.py'],cwd=b,stdout=f,stderr=subprocess.STDOUT,check=True)
# Derived descriptive tables for the current manuscript/report.
appendix='\n\n## v15 최종 측정 수치\n\n'+reopen_table+'\n\n'+small_table+'\n\n'+batch_table+'\n\n측정 구간·표본과 범위는 OPTIMIZATION_REVIEW_KO.md 및 results/reuse/summary.json, batch-summary.json을 참고한다. 기술적 중앙값이며 통계적 유의성이나 일반 성능 보증이 아니다.\n'
for name in ['REPORT_EVIDENCE_KO.md','PAPER_DRAFT_KO.md']:
 p=b/name;p.write_text(p.read_text()+appendix+file_note+parallel_note)
shutil.copy2(b/'REPORT_EVIDENCE_KO.md',root/'JCA_JCE_Research_Comparison_Report_v15_Optimized_KO.md')
with (b/'README.md').open('a') as f:f.write('\nRead OPTIMIZATION_REVIEW_KO.md for v15 batch/reopen changes, matched measurements and limits. Use encrypt-batch for up to64 private-staged normal files. Raw repeated results are in results/reuse.\n')
security=b/'SECURITY_AUDIT_KO.md';marker='\n<!-- file-output-current -->';security.write_text(security.read_text().split(marker)[0]+marker+file_note+parallel_note)
for src,dst in [('SECURITY_AUDIT_KO.md','JCA_JCE_Security_Audit_v15_KO.md'),('PAPER_DRAFT_KO.md','JCA_JCE_PQC_Paper_Draft_v15_KO.md'),('OPTIMIZATION_REVIEW_KO.md','JCA_JCE_Optimization_Review_v15_KO.md')]:shutil.copy2(b/src,root/dst)
subprocess.run(['python3','paper.py','check'],cwd=b,check=True);subprocess.run(['python3','paper.py','audit'],cwd=b,check=True)
files={}
for p in sorted(b.rglob('*')):
 if p.is_file() and not {'build','__pycache__'}.intersection(p.relative_to(b).parts) and not any(part.startswith('.parallel-work-') for part in p.relative_to(b).parts):files['research-comparison-v15-optimized/'+p.relative_to(b).as_posix()]=p
files['assignment.pdf']=root/'assignment.pdf';manifest=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+name+'\n' for name,p in files.items());out=root/'JCA_JCE_Research_Comparison_v15_Optimized.zip'
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
 for name,p in files.items():z.write(p,name)
 z.writestr('SHA256SUMS',manifest)
with zipfile.ZipFile(out) as z:
 assert z.testzip() is None
 for line in z.read('SHA256SUMS').decode().splitlines():
  digest,name=line.split('  ',1);assert hashlib.sha256(z.read(name)).hexdigest()==digest
print('PASS final archive files',len(files),'bytes',out.stat().st_size,'sha256',hashlib.sha256(out.read_bytes()).hexdigest())
