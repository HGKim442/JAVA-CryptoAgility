# 2026-11-06 연구계획서 재개 체크포인트

## 1. 기준 문서에 직접 명시된 과제

**교수님 원문 3쪽**
- P1: 승인 알고리즘·모드·파라미터 및 신뢰 Provider 선택 통제
- P2: 요청별 정책 스냅샷과 키 버전·키별 nonce 상태 보호
- P3: 업무 메타데이터 AAD 및 인증 실패·취약 fallback 차단
- PoC01 다운그레이드 / 02 시험 Provider 입력 관측 / 03 오류 후 약한 재시도 / 04 키·nonce 재사용 / 05 비인증 메타데이터 변조 / 06 정책 검사·실행 불일치
- E1 취약·허용목록·제안 경로 비교, E2 ML-KEM/ML-DSA 전환 중 PQC 필수 정책 강등 여부 검증

**v2.4 연구 방향**
- 우선: **PoC03(Fallback)와 PoC06(정책 불일치)**, 공통 조건 E2 `PQC_REQUIRED`.
- 두 정책 효력 모델 **Snapshot**과 **Strict cutover**를 구별.
- 먼저 단일요인, 판단 차이 발생 시 필요한 쌍별 결합만.
- `GO/PIVOT/STOP` 조건은 독립 재현 및 선행연구·공개 Java 코드 대조가 있어야 함.

## 2. 기존 파일·보관 관측 (이번 실험에서 재실행하지 않음)

`JCA_JCE_PQC_MASTER_HANDOVER_2026-10-15.md`의 정리에 따르면 원본 `JCA_JCE_PQC_Research_Repeat2_20261010 (1).zip`에는:
- E1 6개 합성 PoC, 6 fresh JVM, 진단 540행. VULNERABLE 6종 효과, 단순 ALLOWLIST는 PoC01·02 차단하고 03~06에 남는 효과, PROPOSED는 6종 거부로 보관.
- E2 두 가지 Provider 실패 경로. VULNERABLE/ALLOWLIST는 `X25519_ONLY`, PROPOSED는 `PQC_REQUIRED` 거부로 보관.
- 정상 비용 900행. 측정 간 큰 JVM 변동으로 성능 향상 확정 금지.

이 자료는 **기존 보관 기록**이지 2026-11-06 신규 실험의 직접 측정 결과가 아님.

## 3. 2026-11-06 이 턴에서 실제 실행한 내용

- Java 17 대상 컴파일 (`javac --release 17`), OpenJDK 21 런타임, BC 1.86.
- 소스: `src/PolicyCutoverFixture.java`; 도구: `run.py`.
- 정상 C1/X25519, 정상 C2/X25519+ML-KEM-768; 강화(C1→C2)·완화(C2→C1) 각각 고전 또는 hybrid 실행.
- `6 cases × 2 models × 3 variants × 3 independent JVM repetitions = 108 controlled observations`.
- `108/108 EXPECTATION_MATCH`, `COMPLIANT=90`, `VIOLATION=12`, `REJECTED=6`.
- `V2_POLICY_VIOLATIONS_ACCEPTED=0`; 의도적으로 취약한 경로의 위반 허용 12건을 분리함.
- 사건 순서는 두 latch를 통해 `check ≤ update ≤ crypto_start ≤ completion` 강제·검증.

**판정:** 연구 질문 '정책 효력 모델이 같은 실행의 판정을 바꾸는가?'를 합성 통제 실험에서 확인. **실제 취약점 발견, 학술적 신규성, 운영 환경 방어 효과는 미입증**.

## 4. 현재 완료 / 미완료

| 작업 | 상태 | 근거/제약 |
|---|---|---|
| 원 과제 요구사항 고정 | 완료 | 교수님 원문 3쪽 |
| E1 6종 fixture 결과 | 보관 관측 | 원본 ZIP 기반 인수인계, 이번 턴 재실행 안 함 |
| E2 기존 2개 장애 조건 | 보관 관측 | 원본 ZIP 기반 인수인계, 이번 턴 재실행 안 함 |
| PoC06 정책 핫리로드 단일요인 | **이 턴 108/108 실행** | 합성 fixture, 실제 Java cryptography, toy KDF |
| PoC03 + PoC06 결정적 쌍별 결합 | 미완료 | 모델이 갈리는 최소 한 경우만 수행 권장 |
| 요청 단위 P1/P2/P3 전체 통합 | 미완료 | 새 fixture V2는 final policy 일부만 실험 |
| 동일 조건 E1 비용 p50/p95 | 미완료 | fixture의 crypto 비용 측정은 본 패키지에서 하지 않음 |
| 독립 공개 OSS Java 적용 | 미완료 | 공개 코드 정상 경로부터 검증 필요 |
| 기여 신규성 및 기존 도구와 직접 비교 | 미확정 | 지원 범위 밖은 기존 도구 FN으로 계산 불가 |

## 5. 다음 GO/PIVOT 기준

- **GO**: 공개 소프트웨어의 동일한 통제 조건/정책 계약에서 실제로 차이가 재현되고, 지원 범위를 고려한 선행 비교상 실험적 차별성이 확인.
- **PIVOT**: 합성 fixture에서만 재현되거나 기존 선행 구현이 동일 해결을 제공.
- **STOP/REDEFINE**: 정책 효력·공격자 권한을 고정할 수 없거나 재현 불가.

RVSec KEM–KDF 탐지 제안은 **번외 연구로 별도 보관**하고 이 주 연구의 검증 수치에 섞지 않음.
