"""Derived parallel cost table; keep sampling and memory scope with every presentation."""
import json
def note(base):
 result=json.loads((base/'results/parallel/summary.json').read_text())
 assert result['passed'] and result['rows']==108 and result['fresh_jvms']==36 and result['normal_decryptions']==1152
 lines=['| 프로필 | 파일당 입력 B | 작업 수 | 8개 배치 중앙 ms | files/s | 힙 pool peak 합 MiB | JVM RSS HWM MiB |','|---|---:|---:|---:|---:|---:|---:|']
 for x in result['statistics']:
  lines.append(f"| P{x['profile']} | {x['message_bytes']} | {x['workers']} | {x['median_batch_ns']/1e6:.3f} | {x['files_per_second']:.2f} | {x['median_heap_pool_peak_sum_bytes']/1048576:.2f} | {x['median_jvm_rss_hwm_bytes']/1048576:.2f} |")
 return '''

## 제한된 병렬 파일 암호화 (2026-10-08 Asia/Seoul)

`python3 easy.py encrypt-batch --workers 2 FILE1 FILE2 ...` 또는 `--workers 4`로 선택한다. 기본값1은 기존 순차 경로를 유지한다. 요청 작업 수는 상한이며 병렬 경로는 파일 크기와 max heap에 따라 실제 동시 작업 수를 낮출 수 있다. CLI/easy 완료 메시지에 요청·실제 작업 수를 표시한다. raw CLI는 `seal-batch-parallel WORKERS KEY DATA ANCHOR CONTEXT INPUT OUTPUT ...`이다. 파일은 최대64개, 각16MiB, 실행 중 평문 파일 작업은 최대4개다. 복호화·정책 변경을 병렬화한 기능은 아니다.

내부 파일 어댑터는 배치 전체에서 Engine monitor를 유지하여 activate/retire/close와 동시 진입을 막는다. nonce는 현재 키의 cursor에서 입력 순서대로 미리 선예약하며, 각 worker는 고정 State와 전용 KEM/Cipher/Signature 인스턴스로 암호화·서명·내구성 게시를 한다. 공유한 가변 Cipher/Signature는 없다. 큐에 모든 평문/패킷을 미리 만들지 않으며 worker당 한 파일씩 읽고 종료 시 평문·파생키를 정리한다.

실패를 완료 순서로 감지하고 새 작업 배정을 중지한다. 읽기 후/KEM 전후/서명 전/게시 전의 협력적 중단 확인으로 이후 단계의 불필요한 작업을 줄인다. 모든 worker가 끝날 때까지 기다린 뒤 monitor·저장소 lease를 해제한다. coordinator interrupt도 drain 후 interrupt flag를 복원한다. 진행 중 I/O나 Provider가 멈추면 종료 대기도 길어질 수 있다. raw CLI의 이미 게시된 파일은 남을 수 있고 처리 완료 순서는 입력 순서와 다르다. 전체 배치 원자성이 아니다. easy는 core 성공 후에만 외부 envelope 파일을 게시하며, core 실패 시 private staging을 정리한다. 예약된 nonce는 실패해도 되돌리지 않는다.

### 같은 키·현재 앵커의 workers1/2/4 비용

'''+ '\n'.join(lines)+'''

P3/P5 × 4KiB/1MiB × workers1/2/4 × 3개 새 JVM =36 JVM. 조건별8파일의 untimed warmup1배치 뒤3배치를 측정하여108행을 수집한다. worker 순서는 fork마다 순환한다. 각 프로필의 동일한 live key/store를 순차적으로 재개하고 nonce를 계속 증가시킨다. key/anchor snapshot을 복제해 같은 nonce 공간으로 분기하지 않는다. 각 배치의 모든 파일을 시간 구간 밖에서 실제 인증·복호화하여 총1,152회 확인한다.

시간 구간에는 core 입력 읽기, nonce 예약 조회, KEM/HKDF/AES-GCM/서명, 파일 force/link/디렉터리 force, worker 생성·종료 대기를 포함한다. JVM 시작·재개와 후속 복호화는 제외한다. 각8파일 warmup에서128개 구간을 선커밋하므로 이후 측정3배치(24파일)에는 추가 앵커 커밋이 없다. 구간 경계/cold 비용은 이 warm 측정과 별도이며 실제 커밋 경계 안전성은64파일 배치 검사에서 확인한다. 순차 비교도 같은 sealFiles 내부 경로이며 일반 public seal/easy의 전체 wall time과는 다르다. JIT/파일시스템 cache/host 부하를 통제하지 않았고 표본이 작아 기술적 중앙값과 범위만 보고한다. 통계적 유의성이나 일반적인 속도 보장은 주장하지 않는다.

힙 수치는 측정 전 System.gc 및 heap pool peak reset 후 pool별 peak used의 합이다. 서로 다른 순간의 peak가 섞일 수 있어 동시 실제 최대 힙을 뜻하지 않는다. RSS는 JVM별 누적 VmHWM이며 시작·재개·warmup·이전 복호화 검사도 포함한다. 배치별 RSS peak나 모든 파일 크기의 메모리 상한이 아니다. CLI는 -Xmx512m, 비교 JVM은 -Xms64m -Xmx512m이며 native I/O buffer·thread stack은 heap 상한에 포함되지 않는다. 실행 수를 높이면 메모리와 I/O 경쟁도 증가하므로 기본값을 자동 변경하지 않는다.

### 동시성·보안·재현 검사

- ParallelBatchTest1435체크: P3/P5 workers1/2/4 정상 roundtrip, 입력 순서의 nonce 증가·중복 없음, 최대64개 파일 배치와128개 예약 경계 통과, 실패한 배치의 예약 건너뛰기와 재개, 요청workers4의4×16MiB (512MiB heap에서 실제2개 동시 작업), 잘못된 worker/파일 수/중복 출력, 누락 입력·합성 서명 실패, activate/retire/close pinning 및 interrupt drain.
- easy-parallel-check78체크: 실제 P3/P5 workers2/4 파일 복호화, 비공개 권한과 원본 보존, 기존 출력·부적합 작업 수 거부, staging 정리.
- 포함한 BC1.86 MLDSASigner/MLDSAEngine bytecode에서 signer별 새 engine 생성을 확인했다. 실제 동일 키의 동시 정상 서명/검증도 검사했지만 Provider 전반의 무오류·무취약 보증은 아니다.
- 첫 측정 도구의 출력 폴더가 owner-only가 아니어서 기존 보안 검사가 거부했다. 폴더0700으로 수정한 실패 기록과 원래 측정 소스를 history-v15-parallel/benchmark-attempt-1에 보존하고 최종 집계에 혼합하지 않는다.

검사 개수 갱신 중 expected upgrade payload 상수가 잘못 치환된 것을 발견하여 바로 수정했다. 해당 실행은 중단하고 verification-attempt-1에 보존했으며, 최종 근거는 수정된 소스로 전체 재실행한 결과만 사용한다.

이전 측정의 남은 임시 출력이 재실행 시 이름 충돌을 일으킨 기록은 verification-attempt-2에 보존했다. 측정마다 별도의 private 임시 출력 디렉터리를 사용하고 정리·디렉터리 force를 수행하도록 도구를 보완했다. 이전 임시 암호문은 경로·크기·해시를 남겨 최종 데이터와 구분했다.

이번 유지보수 수정 전 병렬 결과와 재개 이력은 history-v15-parallel-risk에 보존했다. 최신 run.json은 수정된 모든 암호·테스트 소스를 대상으로 일반 전체 verify.py를 실행한 근거다.

원시 CSV/범위/메모리 지표: results/parallel. 재현은 verify.py 후 release.py. 외부 비교 대상/E1 평가·독립 감사·물리 전원 내구성 검증은 여전히 별도 범위이다.
'''
