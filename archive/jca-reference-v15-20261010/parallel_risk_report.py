"""Render current same-harness comparison without overstating memory or speed."""
import json
def note(base):
 r=json.loads((base/'results/parallel-risk/summary.json').read_text())
 assert r['passed'] and (r['rows'],r['fresh_jvms'],r['normal_decryptions'])==(216,72,2304)
 lines=['| 프로필 | 파일당 MiB | 요청 작업 | 수정 전→후 실제 작업 | 수정 전→후 배치 ms | 수정 전→후 힙 지표 MiB | 수정 전→후 JVM RSS HWM MiB |','|---|---:|---:|---:|---:|---:|---:|']
 for p in [3,5]:
  for size in [1048576,16777216]:
   for w in [1,2,4]:
    old=next(x for x in r['statistics'] if (x['profile'],x['message_bytes'],x['requested_workers'],x['variant'])==(p,size,w,'previous'))
    new=next(x for x in r['statistics'] if (x['profile'],x['message_bytes'],x['requested_workers'],x['variant'])==(p,size,w,'revised'))
    lines.append(f"| P{p} | {size//1048576} | {w} | {old['effective_workers']}→{new['effective_workers']} | {old['median_batch_ns']/1e6:.2f}→{new['median_batch_ns']/1e6:.2f} | {old['median_heap_pool_peak_sum_bytes']/1048576:.2f}→{new['median_heap_pool_peak_sum_bytes']/1048576:.2f} | {old['median_jvm_rss_hwm_bytes']/1048576:.2f}→{new['median_jvm_rss_hwm_bytes']/1048576:.2f} |")
 stream=json.loads((base/'results/security/easy-stream-checks.json').read_text())
 old=next(x for x in stream['samples'] if x['message_bytes']==16777216 and x['variant']=='previous_whole_file')
 new=next(x for x in stream['samples'] if x['message_bytes']==16777216 and x['variant']=='chunked')
 return '''

## 병렬 문제점 감소: 메모리·중단 개선 (2026-10-08 Asia/Seoul)

파일용 내부 암호화에서 privately owned 평문의 중복 clone을 없앴다. 외부 public seal의 방어적 복사는 유지한다. Python 입력 staging은1MiB 청크로 바꾸고 복사 전후 크기/mtime/ctime 변경을 거부한다. 청크는 정리하지만 모든 런타임 사본의 secure erase나 원자적 입력 snapshot을 보증하지 않는다.

병렬 동시 수는 요청 수를 상한으로 하며 파일 최대 크기와 max heap에 따라 자동 낮춘다. 예산=min(128MiB,maxHeap/4), 파일당 추정=3×최대입력+1MiB, 최소1개다. 실제 메모리 상한이나 모든 Provider의 안전한 heap 크기를 증명하는 식이 아니다.512MiB heap/16MiB 입력에서 요청4개는 실제2개가 된다. 계획 뒤 커진 입력은 실제 읽기 상한으로 거부한다. nonce는 선예약하고 실패 예약은 재사용하지 않는다.

실패한 작업은 완료 순서로 관찰하고 최초 예외를 보존한다. 읽기 후/KEM 전후/서명 전/게시 전에서 중단을 확인하여 불필요한 다음 단계를 줄인다. 키/정책/lease는 모든 worker가 끝날 때까지 유지한다. 무응답 I/O/Provider의 즉시 종료, 배치 전체 원자성, 정책 변경의 무대기는 제공하지 않는다. 중단 확인 직후 진행 중인 게시가 완료될 수 있다.

### 수정 전 원본과 같은 harness로 재측정

'''+ '\n'.join(lines)+f'''

각 값은8파일 배치, 조건별3개 새 JVM 중앙값의 중앙값이다. P3/P5×1/16MiB×요청1/2/4×수정전후×3JVM=72JVM,216측정행, warmup 포함 실제 인증 복호화2,304회. 원래 PqcExtension/CryptoCli/ParallelBatchTest 소스를 history-v15-parallel-risk에서 복원해 별도로 컴파일했다. 같은 live key/store로 nonce를 계속 증가시키고 앵커를 복제하지 않았다. worker 순서를 회전하고 전후 순서를 교대했다. 요청4/16MiB 조건은 실제 동시 수가 바뀌므로 동일 동시 수의 암호 연산 속도 비교로 해석하지 않는다.

시간은 preflight/read/nonce 조회/암호화/서명/durable 게시/worker 생성·drain을 포함하고 JVM 시작·재개·검증·삭제는 제외한다. 각 새 JVM warmup8파일에서128개 예약을 커밋하므로 측정24파일은 추가 앵커 커밋을 하지 않는다. 측정 전 System.gc와 heap peak reset을 사용한다. heap pool별 peak 합은 동시 최대치가 아니며 RSS VmHWM은 시작/warmup/이전 복호화까지 포함한 JVM 누적 최고치다. 전체 Python+Java 프로세스 트리의 peak가 아니다. 고정512MiB heap, host/cache/CPU 부하 미통제, 작은 기술적 표본이며 일반 속도/메모리 보증이나 유의성 주장이 아니다. 원시값·fork 범위·소스해시·CSV해시는 results/parallel-risk에 보존했다.

16MiB 입력 복사의 Python helper-only tracemalloc peak는 이전 전체 읽기 {old['traced_peak_bytes']/1048576:.2f}MiB → 청크 방식 {new['traced_peak_bytes']/1048576:.2f}MiB였다. 이 값은 생성해 둔 source와 JVM/RSS를 제외하며 단일 helper 호출 측정이다.

추가 검사: ParallelRiskTest31체크(계획/증가한 입력 거부/이전 출력 복호화/실패 원인 보존/다음 암호 단계 중지/public 입력 소유권), easy-stream-check29체크(실제 바이트/권한/기존 파일·symlink·크기 거부/합성 descriptor·metadata 변경). 기존 parallel1435/easy parallel78/easy batch77와 전체 보안·복구·호환성·논문 정상 검사를 새 소스로 다시 실행한다. 반복체크는 독립 공격 수가 아니며 E1 외부 비교 대상/독립 감사는 여전히 미완료다.
'''
