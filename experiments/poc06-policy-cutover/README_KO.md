# PoC 06 / E2 — 정책 효력 시점의 차이를 확인하는 독립 통제 실험

**연구:** Java JCA/JCE 암호민첩성의 보안성 분석
**계획 기준:** 교수님 원 과제 3쪽 + `PQC_JCA_Research_Direction_Review_v2_4.pdf`
**실행 기준:** 합성 Java fixture, PoC 06 우선·E2 공통 정책 조건. RVSec 개선안과 별개.
**상태:** 로컬 JDK 21/BC 1.86에서 36조건 × 3회 = **108/108 기대 결과 일치**. 실제 공개 소프트웨어 취약점 발견 아님.

## 이번 질문

승인된 운영자가 요청의 **정책 검사 이후, 암호 연산 실행 이전에 정책을 갱신**할 때, `Snapshot`과 `Strict cutover` 정책에 따라 같은 `X25519_ONLY` 결과를 달리 판단해야 하는가?

- `C1_HYBRID_ALLOWED`: 이 fixture에서 X25519 단독 또는 X25519+ML-KEM-768 허용.
- `C2_PQC_REQUIRED`: 이 fixture에서 X25519와 ML-KEM-768 **두 기여**가 모두 필요.
- `Snapshot`: 요청 시작 때의 정책·epoch가 완료 판단에 유효.
- `Strict cutover`: 완료 시점의 정책·epoch가 유효.
- `V0`: 정책 검증 없는 의도적인 취약 대조군.
- `V1`: 구성요소 명칭별 허용목록만 검사하는 대조군.
- `V2`: 유효 정책에 맞는 최종 suite를 검사한 뒤 업무상 성공 여부를 결정하는 **연구용 오라클 경로**. 원 과제 P1/P2/P3의 전체 구현을 대체하지 않음.

최종 정책 계약(실험 가설):

```
FINAL_SUCCESS(request) => Approved(actual_components, effective_policy(request))
```

## 실험 방법

1. 작업 스레드가 초기 정책 epoch 1을 읽고 정책 검사 완료 신호를 보냄.
2. 운영자 시뮬레이터가 정책을 유지하거나 epoch 2로 변경.
3. 작업 스레드를 재개. **실제 X25519**, 조건부 **실제 BC ML-KEM-768**, 장난감(labelled) HMAC combiner, **실제 AES-GCM 암·복호**를 수행.
4. Cipher 객체를 스레드 사이에 공유하지 않음. `V0/V1/V2`에 따라 최종 업무 성공/거부를 결정.
5. 요청별 정책, epoch, 실제 suite, KEM 완료 여부, AEAD roundtrip, 판정과 동기화 순서를 CSV에 보존. 비밀값은 로그에 남기지 않음.

**주의:** 이는 표준 hybrid handshake나 독립적인 Provider 출처 추적 구현이 아님. `actual_suite`는 통제 fixture에서 선택한 경로를 기록하며, 미계측 임의 앱의 실제 suite를 독립 탐지하는 기술은 아님. `ML-DSA` 서명·인증은 이 **키 설정** 실험의 필수 요소로 지정하지 않았으므로 시험하지 않음. 외부 파일 커밋/분산 서버/실제 정책 서버에도 적용한 결과가 아님.

## 주요 비교 결과

| 설정 변화 / 실제 실행 | 효력 모델 | V0, V1 | V2 | 연구 해석 |
|---|---|---|---|---|
| C1 → C2 / X25519만 성공 | Snapshot | 허용·준수 | 허용·준수 | 시작 정책을 유효하게 보면 위반 아님 |
| C1 → C2 / X25519만 성공 | Strict cutover | **위반 성공** | **거부** | 새 `PQC_REQUIRED`에 미달 |
| C2 → C1 / X25519만 성공 | Snapshot | **위반 성공** | **거부** | 이전 `PQC_REQUIRED`가 유효 |
| C2 → C1 / X25519만 성공 | Strict cutover | 허용·준수 | 허용·준수 | 완화된 새 정책을 적용 |

`C1/C2`의 의미와 효력 모델은 **연구자가 사전에 정한 fixture 정책**이다. 실제 조직에서는 보안 요구를 만족하는 별도 정책 사양이 필요하다.

## 실행 (WSL/Linux)

사전 조건: JDK 17 이상, Python 3.8 이상, `bcprov-jdk18on-1.86.jar` 로컬 설치. BC 바이너리는 배포하지 않음.

```bash
python3 run.py --repeat 3 --bc-jar "$HOME/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar"
```

경로가 다르면 `--bc-jar` 뒤를 바꾸거나 `BC_JAR` 환경변수를 지정한다. `--output /path/to/evidence`로 저장 위치 지정 가능. 스크립트는 **원본 E1/E2 ZIP이나 기존 상태 파일을 변경하지 않으며**, 별도 임시 클래스 디렉터리에 컴파일한다.

기대 출력:

```
JAVA_COMPILE=PASS
REPEAT=1 EXPECTED_MATCH=36/36
REPEAT=2 EXPECTED_MATCH=36/36
REPEAT=3 EXPECTED_MATCH=36/36
EXPECTED_MATCH=108/108
OBSERVED_ORACLE_VERDICTS={"COMPLIANT": 90, "VIOLATION": 12, "REJECTED": 6}
V2_POLICY_VIOLATIONS_ACCEPTED=0
RESULT=CONTROLLED_FIXTURE_PASS
```

여기서 `108/108`은 **기대 결과와 실제 결과의 일치**, 공격 108개를 차단했다는 의미가 아니다. `VIOLATION 12`는 의도적으로 열어 둔 V0/V1 취약 경로의 관측이다.

## 관련 연구와 다른 증거 수준

- **원 과제**: PoC01~06, P1/P2/P3, E1/E2. 이 패키지는 **PoC06 단일 요인(정책 핫리로드)**을 새로 통제 검증한 것.
- **기존 보관 실험**: E1의 6개 합성 fixture 및 E2의 Provider 실패 2종 실험 결과는 2026-10-15 인수인계에 기록돼 있음. 이 패키지는 해당 코드나 결과를 수정/재실행하지 않음.
- **RVSec**: 기존 동적 API 오용 탐지는 별도 베이스라인이다. 이 패키지에서 RVSec를 계측·패치하거나 실제 오탐률을 측정하지 않음.
- **공개 Java 프로젝트**: 실제 정책 핫리로드에서 동일 경로가 발생하는지 아직 검증하지 않음.

## 다음 연구 검증 순서

1. PoC03/E2 기존 Provider 장애 결과와 이 PoC06의 정책 모델을 **별도** 표로 대조.
2. 단일 조건에서 의미 있는 차이가 나온 `C1→C2 + 고전 단독 성공` 하나를 선택해 **03 실패 + 06 전환** 순서 결합 실험. 전체 조합 전수검사 금지.
3. 같은 조건에서 `V0/V1/V2`, 요청 성공률 및 필요한 p50/p95 비용 측정. `V2`는 P1/P2/P3를 모두 통합한 방어로 과대 표시하지 않음.
4. 가능하면 실제 공개 Java 라이브러리의 **정상 전환 경로부터** 독립 검증한 뒤 취약성·신규성 판정.

더 자세한 계획서 기준 및 증거 구분은 `RESEARCH_CHECKPOINT_KO.md`, 표준화된 관측 데이터는 `reports/local_run/` 참조.
