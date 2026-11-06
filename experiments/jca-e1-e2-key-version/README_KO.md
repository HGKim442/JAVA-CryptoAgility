# Java JCA/JCE 암호민첩성 연구 — E1/E2 재검증 및 PoC06 키 버전 단일 요인

**기준일:** 2026-11-06
**연구 범위:** 교수님 원 과제 `Java JCA/JCE 암호민첩성의 보안성 분석`과 연구 방향 검토안 v2.4.
**상태:** 합성 통제 실험 재현 완료. 원본 E1/E2 수정 없음. 실제 공개 Java 프로그램의 일반적인 취약점 발견이나 모든 전환 안전성 증명 아님.

## 무엇을 수행했는가

1. **원본 E1 (6종 PoC / 3비교군)**: 2026-10-10 원본 ZIP에 들어 있던 `E1Experiment.java`를 관련 원본 클래스와 함께 추출해 Java 17 타깃으로 컴파일. 6개 fresh JVM에서 `attacks.csv` 540행, `normal-cost.csv` 900행 재수집.
2. **원본 E2 (PQC 실패 변형 2종)**: 원본 `PqcDowngradeExperiment.java`를 Bouncy Castle 1.86과 실행. 6개 fresh JVM에서 36행 재수집; 정상 ML-KEM+X25519 대조 성공 후 두 가지 실패 주입.
3. **PoC03+06/E2**: 기존 11월 6일 `FallbackCutoverFixture.java` 원본을 다시 실행해 144/144 기대 결과 일치 확인. 새 코드로 대체하지 않음.
4. **PoC06 단일 인자 — 키 버전 변경**: 이번 패키지의 `KeyVersionCutoverFixture.java` 신규 구현. AES-GCM 실제 암·복호화, 정책 확인 후 승인된 K1→K2 전환, SNAPSHOT/STRICT_CUTOVER 분리, 3비교군. 3개 JVM × 18조건 = 54/54 기대 결과 일치.

## 결과 요약

| 실험 | 관측 | 실제 결과 | 해석 |
|---|---:|---|---|
| 원본 E1 | 공격 540, 정상 비용 900 | V0: 6종 공격 효과; V1: 01·02 차단, 03~06 허용; V2: 6종 공격 효과 없음 | 6종 동일 결정적 fixture의 반복 |
| 원본 E2 | 실패 시나리오 36 | V0/V1: `X25519_ONLY`; V2: `POLICY_REJECTION` | 고전 Fallback과 `PQC_REQUIRED` 계약 차이 |
| PoC03+06/E2 결합 | 144 | 준수 81, 위반 성공 30, 정책 거부 15, 실행 실패 18 | Snapshot/Strict 전환효력 구분, 실제 X25519/ML-KEM-768/AES-GCM |
| 신규 PoC06 키 버전 | 54 | 준수 45, 위반 성공 6, 정책 거부 3 | 키 K1→K2 회전 단일 요인 검증, **PQC 미사용** |

**수치 주의:** `54/54`, `144/144`는 사전 기대 결과와 일치했다는 뜻입니다. `VIOLATION`은 의도적인 취약 비교군이 정책 위반 요청을 성공시킨 결과입니다. 서로 다른 실험의 행 수를 합산해 보안 차단율·표본 독립성을 주장하지 않습니다.

## 신규 키 버전 실험의 계약

- `SNAPSHOT`: 요청 승인 시점 키 버전이 그 요청의 승인 기준.
- `STRICT_CUTOVER`: 최종 처리 시점의 키 버전이 해당 요청의 승인 기준.
- `V0_VULNERABLE`: 요청 발급 당시 키를 그대로 사용, 최종 정책 재검사 없음.
- `V1_ALLOWLIST`: 승인된 Provider와 키 버전 존재를 시작 시 확인하나, 최종 정책 재검사 없음.
- `V2_POLICY_BOUND`: 효력 있는 키 버전과 요청 키를 최종 암호화 직전에 비교, 불일치 시 거부.
- 고정: AES-GCM/SunJCE와 AAD(테넌트·문서·키 버전)는 모든 성공 경로에서 동일하게 사용. **따라서 P1/P3 비교가 아닌 P2의 단일 인자 시험**.

동기화(`CountDownLatch`)로 `요청 승인 → 정책 관리자의 키 버전 전환 → 작업 재개 → 실제 AES-GCM 또는 정책 거부` 순서를 고정했습니다. 제3자가 키 관리자를 공격하거나 임의 Java 코드를 주입하는 위협 모델이 아닙니다.

## 재현

Java 17+와 Python 3 준비. 신규 PoC06 키 버전 단일 인자에는 외부 JAR가 필요 없습니다.

```bash
python3 run.py --repeat 3
```

원본 E1/E2는 Java 17+와 `bcprov-jdk18on-1.86.jar`가 필요합니다. JAR 자체는 이 ZIP에 포함하지 않았습니다.

```bash
python3 reproduce_original.py --forks 6 --bc-jar /absolute/path/to/bcprov-jdk18on-1.86.jar
```

제공한 **이미 생성된** CSV와 보고서를 독립 스키마·관측 규칙으로 검증하는 명령:

```bash
python3 audit_reports.py
```

`audit_reports.py`는 재실행 명령이 아니라 포함된 결과 파일의 일관성을 확인합니다. 새 컴퓨터에서 실제 실험을 재수행하려면 앞의 두 스크립트를 실행하세요.

## 파일 안내

- `original_e1_e2_sources/*.java`: 10월 10일 보관 ZIP에서 바이트 그대로 추출한 원본 소스 5개
- `src/KeyVersionCutoverFixture.java`: 이번에 신규 작성한 PoC06 단일 요인 코드
- `run.py`, `reproduce_original.py`: 각 실험의 실제 컴파일·실행·독립 기대 결과 대조
- `reports/baseline_recheck`: 원본 E1/E2 fresh JVM 6개 재검증 데이터
- `reports/pairwise_recheck`: 11월 6일 PoC03+06/E2 재실행 데이터
- `reports/local_run`: 신규 PoC06 키 버전 54개 데이터
- `RESEARCH_CHECKPOINT_KO.md`: 계획서 매핑, 완료/미완료 및 다음 실험
- `SHA256SUMS.txt`: 포함 자료 무결성 해시

## 분리·한계

- 이 자료는 원본 과제 E1/E2와 RQ2 검증을 진행하기 위한 **합성 실험 자료**입니다.
- Vert.x는 PoC06/P2의 별도 **실제 TLS/JSSE 확장 사례**로 이미 제한적 검증 완료했으나, 상세 비공개 패치·실험 로그는 이 ZIP에 넣지 않았습니다.
- RVSec KDF 개선안/범용 Agent는 이번 연구와 분리합니다.
- `PQC_REQUIRED` 최종 계약의 ML-DSA 서명·인증 요건, 공개 애플리케이션의 실제 JCA/JCE 요청 단위 검증, 실제 성능 오차 범위는 추가 연구가 필요합니다.
