# PoC 03 + PoC 06 + E2: ML-KEM 실패와 정책 전환 시점의 교차 검증

> **연구 상태:** 합성 통제 실험 완료. 실제 공개 Java 제품의 취약점, 범용 암호민첩성 보장, 학술적 신규성을 주장하지 않음.

## 1. 문서 기반 범위

- 원 과제: `Java_JCA_JCE_암호민첩성의_보안성_분석_20260925091255.pdf` (3쪽). PoC 03 취약한 오류 처리, PoC 06 정책 불일치, P1/P2/P3, E1/E2.
- v2.4 검토안: `PQC_JCA_Research_Direction_Review_v2_4.pdf`. **PoC 03/06 우선**, E2의 `PQC_REQUIRED` 공통 조건, Snapshot/Strict cutover 구분, 단일 요인 실험 후 **최소 쌍별 결합**.
- 기존 결과: `PoC06_Policy_Cutover_E2_v1.zip`의 108/108 합성 조건과 2026-10-15 인수인계의 E1/E2 관측. **원본 자료·코드는 수정하지 않음**.

## 2. 정책 정의 (실험 전에 고정)

- `C1_HYBRID_ALLOWED`: 명시적인 **KEM 실패 시 고전 단독 예외**를 허용하는 합성 전환 정책. 모든 현실의 C1 운영 정책이 이렇게 행동한다고 의미하지 않는다.
- `C2_PQC_REQUIRED`: 최종 요청 성공 시 ML-KEM-768을 포함한 X25519+ML-KEM-768 구성의 KEM 성공을 필수로 한다. 실험에서는 서명·인증이 요구되지 않는 요청으로 한정해 ML-DSA를 실행하지 않는다.
- `SNAPSHOT`: 요청의 최초 정책 검사 시점(epoch 1)을 끝까지 적용.
- `STRICT_CUTOVER`: 최종 요청 승인 시점의 정책을 적용. 요청의 정책 확인과 암호 수행 사이에 승인된 정책 변경이 발생.
- `V0_VULNERABLE`: 최종 구성·정책 연결 없음. `V1_ALLOWLIST`: 구성요소가 알려진 목록에 있는지 검사하지만 실제 조합의 C2 충족 여부는 검사하지 않음. `V2_FINAL_POLICY`: 유효 정책에 대한 최종 구성 검사.
- 판정 불변식: `SUCCESS(r) ⇒ Approved(ActualSuite(r), EffectivePolicy(r))`.

## 3. 구현 및 조건

`src/FallbackCutoverFixture.java`는 Java 17 소스이며 JDK 21에서도 실행된다.

- 실제 SunEC X25519 양측 공유 비밀 일치 검사.
- BC 1.86 ML-KEM-768 양측 공유 비밀 일치 검사.
- 실제 JCA 실패 경로: `NoSuchProviderException` (`ML-KEM` by unregistered `BC` name), `NoSuchAlgorithmException` (`ML-KEM` pinned to `SunEC`). BC JAR는 클래스패스에 있지만 `Security` 전역 Provider 레지스트리에는 등록하지 않음.
- 합성 HMAC-SHA256 키 결합과 실제 SunJCE AES-GCM 암·복호화 roundtrip. **표준화된 하이브리드 KDF/프로토콜이 아님**.
- `CountDownLatch`로 `policy_check ≤ policy_update ≤ crypto_start ≤ final_verdict` 순서를 보장. 임의 스레드 공유 Cipher 객체 사용 없음.
- 비밀값, 개인키, 평문 본문은 원시 CSV에 저장하지 않는다. 키 버전은 **K1으로 고정**하여 키 회전 교차요인은 이번에 시험하지 않는다.
- `V2`는 실험 내에서 암호 처리 후 **외부 성공으로 인정할지** 결정하는 참조 검증기이다. 생성한 암호문을 실제 서비스로 송신하거나 디스크에 커밋하는 부분은 없음.

8 cases × 2 effective-policy models × 3 variants = 48 conditions per JVM. 각 JVM 3회 반복 = 144 observations.

8 cases: `C1_STABLE_HYBRID`, `C2_STABLE_HYBRID`, `C1_STABLE_BC_FAIL`, `C2_STABLE_BC_FAIL`, `UPGRADE_BC_FAIL`, `UPGRADE_SUNEC_FAIL`, `RELAX_BC_FAIL`, `UPGRADE_NO_FALLBACK`.

## 4. 직접 실행 및 결과

현재 제공된 실행 결과는 OpenJDK 21과 Bouncy Castle 1.86에서 **실제 컴파일·실행**하여 수집한 것이다.

```text
JAVA_COMPILE=PASS
REPEAT=1 EXPECTED_MATCH=48/48
REPEAT=2 EXPECTED_MATCH=48/48
REPEAT=3 EXPECTED_MATCH=48/48
EXPECTED_MATCH=144/144
VERDICTS={"COMPLIANT": 81, "VIOLATION": 30, "REJECTED_POLICY": 15, "REJECTED_EXECUTION": 18}
RESULT=CONTROLLED_PAIRWISE_PASS
```

**중요:** `144/144`는 기대 판정 일치율이다. `VIOLATION=30`은 취약 비교군에서 **고전 단독 요청이 C2 아래서 최종 성공한 의도적 보안 위반**이며 차단 성공이 아니다. `REJECTED_POLICY=15`는 V2의 정책 거부이고 `REJECTED_EXECUTION=18`은 Fallback이 없는 요청의 정상 실행 실패이다.

핵심 대비(각 셀의 결과가 3회 반복):

| 조건 | Snapshot V0/V1 | Snapshot V2 | Strict V0/V1 | Strict V2 |
|---|---|---|---|---|
| `UPGRADE_BC_FAIL`, C1→C2 | 정책상 준수 | 준수 | **위반 성공** | 정책 거부 |
| `UPGRADE_SUNEC_FAIL`, C1→C2 | 정책상 준수 | 준수 | **위반 성공** | 정책 거부 |
| `RELAX_BC_FAIL`, C2→C1 | **위반 성공** | 정책 거부 | 준수 | 준수 |
| `C2_STABLE_BC_FAIL`, C2→C2 | **위반 성공** | 정책 거부 | **위반 성공** | 정책 거부 |

실험 원시 증거: `reports/local_run/all_cases.csv`, 조건 집계 `reports/local_run/contrast_matrix.csv`, 버전·SHA `reports/local_run/summary.json`, 실행 원문 `reports/local_run/logs/`.

## 5. 재현 방법

JDK 17+와 BC `bcprov-jdk18on-1.86.jar` 준비. JAR 자체는 배포하지 않음.

```bash
python3 run.py --repeat 3 --bc-jar /absolute/path/to/bcprov-jdk18on-1.86.jar
```

Maven 캐시가 있으면 `--bc-jar`를 생략할 수 있음. `--output`을 생략하면 임시 디렉터리로 로그와 CSV를 기록.

## 6. 한계 및 다음 단계

- 동일한 합성 제어 경로에서 정책 효력의 차이를 보였지만, 공개 Java 프로젝트의 실제 취약점을 확인한 것은 아니다.
- KDF는 실험용이고 ML-DSA 인증·키 버전 교체·nonce 동시성·Provider 출처 위조는 이번 테스트 범위에 포함되지 않는다.
- V1은 실제 암호 API 호출 출처를 검증하는 완전한 Provider 허용목록 구현이 아닌 **구성요소 목록 대조군**이다.
- 측정 지연시간은 정상 제어와 실패 조건 간 작업량 자체가 다르므로 p50/p95 비교나 비용 개선 주장에 직접 사용하지 않는다.
- 기존 RVSec KEM–KDF 탐지 개선안/범용 Java Agent v0.5는 **별도 번외 프로젝트**로 유지.

다음은 v2.4 단계 ④에 따라 Apache Camel 등의 **공식 PQC 정상 동작 테스트**를 먼저 원본 그대로 재현하고, 같은 경로에 정책 변경·장애 주입이 가능한지 소규모로 검토한 뒤 GO/PIVOT을 결정한다.
