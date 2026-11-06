# Java JCA/JCE 암호민첩성 원 과제·v2.4 연구 체크포인트

기준일: 2026-11-06. 연구/실험 파일에 존재하는 증거 범위에서만 완료 표시.

## 1. 원 과제 고정 요구사항

과제 1~3쪽: PoC01 ECB 다운그레이드, 02 비신뢰 Provider의 입력 관측, 03 실패 후 약한 Fallback, 04 같은 AES 키의 nonce 재사용, 05 업무 메타데이터 AAD/인증 누락, 06 정책 검사 후 실제 사용의 불일치. P1 알고리즘·Provider 통제 / P2 요청별 정책·키 버전·nonce 상태 / P3 AAD 및 인증 실패 후 Fallback 차단. E1 취약·허용목록·제안 구현의 효과·정상 성공·처리비용 비교. E2 ML-KEM/ML-DSA의 PQC 필수 계약에서 고전 단독 성공 금지 검증.

v2.4 우선순위: 03·06 우선, E2는 공통 정책 조건, 단일 요인 → 유의미한 최소 쌍별 결합, Snapshot/Strict cutover 구별, 실제 OSS 및 동등 조건 평가, 신규성 근거 없으면 주장 금지.

## 2. 검증 실적과 공백

| 범위 | 검증/관측 상태 | 미완료 또는 제한 |
|---|---|---|
| PoC01 + P1 | 원본 E1에서 ECB 패턴 재현, V1/V2 제어 성공 | 일반 실제 앱의 Provider 설정 전수 보장 아님 |
| PoC02 + P1 | 비신뢰 시험용 해시 Provider 입력 관측 재현, V1/V2 거부 | 별도 예외 위협 모델. 일반 Provider 장애와 혼합 금지 |
| PoC03 + P3/P1 | E1 AES-256→AES-128 약화 재현; E2 ML-KEM 실패 고전-only; 추가 PoC03+06 쌍 실험 | 실제 공개 앱 내부 KEM 실패→Fallback 경로 재현 미완료 |
| PoC04 + P2 | 고정 AES 키 서비스 재시작 nonce 재사용 관측/방어 | packet별 새 KEM 파생 키 위협과 합산 금지 |
| PoC05 + P3 | AAD 메타데이터 변조 가능 여부 E1 원본 재현 | 실제 멀티테넌트 OSS 적용 미검증 |
| PoC06 + P2 | 원본 E1 구성 TOCTOU, 11월 6일 Snapshot/Strict + Provider 실패 144행, 이번 키 버전 단일 인자 54행 | 키 회전·정책·Provider의 실제 단일 요청 전 과정 및 선형화 전체 증명 미완료 |
| E1 | 원본 6 JVM: 공격 540행, 정상 비용 900행 재수집 | JVM 편차 심함. p50/p95는 예비 값이며 통계적 성능 개선 주장 불가 |
| E2 | 원본 6 JVM: 장애 36행/정상 hybrid 36대조; 결합 144행 | 서명 요구 요청의 ML-DSA 및 범용 하이브리드 프로토콜 검증 미완료 |
| 공개 OSS 검증 | Vert.x TLS/JSSE PoC06 한정 사례 별도 최종 확인(2026-11-06) | **JSSE 사례이며 원본 JCA/JCE Cipher/KEM 요청 단위 경로를 대체하지 않음** |
| 외부 비교/신규성 | CrySL, CryptoGuard, RVSec 등 분석 범위와 선행 논문 목록 보유 | 기능 미지원 도구를 자동 FN 계산하지 말 것, 독립 신규성 판단 미완료 |

## 3. 이번 재실행 데이터의 정확한 판정

### 원본 E1/E2 — 바이트 그대로의 코드

- 10월 10일 보존된 원본 E1/E2 5개 소스를 실제 `javac --release 17`으로 컴파일; JDK 21 runtime.
- E1: `540` 진단 결과(각 모드·시나리오 `30`행), `900` 정상 전환 처리 비용(각 모드 `300`회), 모든 정상 대조 성공.
- E1 V0: 6개 시나리오에서 공격 효과 관측. V1: 01,02 공격 효과 없음 / 03~06 존재. V2: 01~06 공격 효과 없음.
- E2: `36` 정책 장애 관측, 36건의 정상 하이브리드 선행 제어 모두 성공. V0/V1: Provider 실패 2종 모두 X25519 단독 완주. V2: 해당 실패 두 종류에서 `POLICY_REJECTION`.
- **E1 지연시간**은 source 변경 없이도 fork별 중앙값 순위가 엇갈림. 재현 성공과 성능 효과 판단을 분리.

### 기존 PoC03+06/E2 재실행

- `48`조건/JVM × `3` JVM = `144`행. 실제 SunEC X25519, BC ML-KEM-768, SunJCE AES-GCM을 사용했으며 KDF는 실험용 합성 계산.
- `COMPLIANT=81`, `VIOLATION=30`, `REJECTED_POLICY=15`, `REJECTED_EXECUTION=18`.
- C1은 KEM 실패 시 명시적인 고전 단독 예외를 허용하는 실험 가정. C2/PQC_REQUIRED는 하이브리드 필수.
- 명시된 승인 시점/완료 시점 계약에 따라 동일한 C1→C2 작업도 Snapshot/Strict의 준수 여부가 다름.

### 신규 PoC06 키 버전 단일 요인

- `STABLE_K1`, `STABLE_K2`, `ROTATE_K1_TO_K2` × `SNAPSHOT`, `STRICT_CUTOVER` × `V0`, `V1`, `V2` × `3` fresh JVM = `54`행.
- `COMPLIANT=45`, `VIOLATION=6`, `REJECTED_POLICY=3`.
- 키 K1→K2 교체가 요청 승인 뒤, 실제 암호 연산 전 발생할 때 **Strict cutover의 V0/V1이 K1 암호화에 성공해 최종 요구 K2를 위반**, V2는 3회 거부. Snapshot에서 요청 시작 당시 K1 사용은 정책상 정상.
- `Cipher` 사용 자체는 SunJCE AES-GCM/정상 AAD roundtrip이며 악성 Provider나 취약 알고리즘이 아니어도 정책 준수 실패가 발생한다는 통제 예시.
- **별도의 PQC 실험이 아님**. 이번 단계에서 키 회전 문제를 독립시키기 위해 암호 알고리즘·Provider·AAD는 고정.

## 4. 다음 실제 연구 단계: 추가 synthetic을 무작정 확대하지 말 것

**가장 중요한 미완료 과제:** 실제 공개 Java 프로그램의 JCA/JCE KEM·정책 요청 처리 경로에서 PoC03 Fallback 또는 PoC06 유효정책/키·Provider 변경을 관측하는 것.

우선 검토할 공개 후보: Apache Camel `camel-pqc` 공식 테스트(예: `components/camel-pqc/src/test/java/org/apache/camel/component/pqc/dataformat/PQCDataFormatTest.java`)와 버전 4.22 문서. 실제 원본 테스트를 먼저 **수정 없이** 빌드·실행하고, 실패 시 BLOCKED 및 의존성/환경 기록. 그 다음 최소 1요인(정상, 승인된 Provider 장애 또는 정책 epoch 변화)을 정해 GO/PIVOT 판정. Camel 내부에서 성공한 단일 KEM 호출을 임의로 공격 성공으로 단정하지 말 것.

참고: https://github.com/apache/camel/blob/main/components/camel-pqc/src/test/java/org/apache/camel/component/pqc/dataformat/PQCDataFormatTest.java
https://camel.apache.org/components/4.22.x/dataformats/pqc-dataformat.html

독립 테스트가 지원되지 않으면, Vert.x JSSE 사례는 별도 완료로 보존하고 원 과제의 성과/한계를 정직하게 정리한다. `RVSec` 및 범용 `PqcAgent` 기능 확대는 이번 원 과제에서 제외.

## 5. 기술적 한계 및 주장 통제

- `VIOLATION=6`, `VIOLATION=30`은 의도적 취약 fixture에서 나타난 성공 위반. `54/54`, `144/144`는 예상 결과가 재현된 조건 수다.
- P2 요청 시점 정책의 **신뢰된 효력 모델**은 현실 서비스에 맞게 지정해야 한다. Snapshot에서 정상인 과거 요청을 Strict cutover 위반으로 섞지 않는다.
- 신규 PoC06 키 버전은 동일 프로세스·키 메모리·정상 AAD의 합성 통제 실험, 디스크 영속 키 저장/분산 조정/실서비스 외부 커밋을 실험하지 않았다.
- 비용 p50/p95는 참고값일 뿐 캐시, JVM JIT, 파일 I/O, GC, 분산/실서비스 처리량과 동일하지 않다.
- Vert.x 미공개 상세 결함 보고서와 패치 코드는 비공개 유지. 공식 패치/보안 권고가 검증되기 전 공개 수치나 취약 세부를 확대 공개하지 않는다.
