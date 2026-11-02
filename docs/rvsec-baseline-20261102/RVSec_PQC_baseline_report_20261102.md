# RVSec 0.2.0의 PQC 기여 누락 탐지 한계 — 재현성 기준선

**기록일:** 2026-11-02
**범위:** Java JCA/JCE 암호민첩성 연구의 비교 기준선(D1), 합성 실험.
**상태:** 사용자 제공 터미널 출력에 근거한 결과 정리. 전체 원자료의 직접 접근·독립 재실행은 수행하지 않았음.

## 1. 검증 질문

정책 `PQC_REQUIRED` 하에서 X25519와 ML-KEM-768의 공유 비밀을 모두 생성한 뒤 최종 HMAC 기반 키 도출의 입력에서 ML-KEM 비밀을 고의로 제외했을 때, **RVSec 0.2.0의 기존 경고 출력이 정상 구성과 위반 구성을 구분하는가?** Java 8, 17, 21에서 결과가 달라지는가?

실험의 `APP_POLICY_VIOLATION` 및 `APP_MLKEM_USED_IN_KDF`는 **실험용 애플리케이션의 기준 정답(ground truth)**이며, RVSec가 자체 판정한 값이 아니다. `APP_RESULT=PASS`는 실행·암호 연산의 성공이지 보안 정책 승인 여부를 뜻하지 않는다.

## 2. 환경 및 주요 식별자

- RVSec 원본: `0.2.0`, 확인된 소스 commit `177e2e4714f559d1448ea456b5618d207cc8cb3b` (사용자 연구 로그 기준).
- AspectJ 기반 실제 에이전트: `JavaMOPAgent.jar`, SHA-256 `a8f888eee1af20c342ff395fea992568f9546d8fec57222815c81f2460e1608d`.
- Bouncy Castle: `bcprov-jdk18on-1.86.jar`, SHA-256 `2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f`.
- Java 8 Temurin `8.0.504+1`, Java 17 Temurin `17.0.21.0+9`, Java 21 Temurin `21.0.13.0+9`.
- Java 8·17 비교 클래스: `BCPqcSurfaceProbe.class`, SHA-256 `b579eb3218e342d50c67b616f9c89b4b76c7ea5ab98f42f6f71e88b0e3d88b14`.
- Java 21 표준 KEM 실험: `javax.crypto.KEM` + BC Provider의 `ML-KEM`, `KemPolicyProbe.java`; Java 21 `javac -source 8 -target 8`로 생성한 **major version 52** 클래스 파일을 Java 21 JVM에서 실행. 이는 호환성 우회 조건으로, Java 8 런타임 지원을 의미하지 않음.

## 3. 확정된 실험 관찰

| 실행 JVM | API 경로 | 정상 RVSec 경고 | KEM 기여 누락 RVSec 경고 | 경고 멀티셋 일치 | 실행/기준정답 |
|---|---|---:|---:|---|---|
| Java 8 | BC JCA `KeyGenerator` 기반 | 26 | 26 | **True** | 모두 PASS; 누락 정책위반 true |
| Java 8 | BC Lightweight | 16 | 16 | **True** | 모두 PASS; 누락 정책위반 true |
| Java 17 | BC JCA `KeyGenerator` 기반 | 26 | 26 | **True** | 모두 PASS; 누락 정책위반 true |
| Java 17 | BC Lightweight | 16 | 16 | **True** | 모두 PASS; 누락 정책위반 true |
| Java 21 | 표준 `javax.crypto.KEM` + BC | 16 | 16 | **True** | 모두 PASS; 누락 정책위반 true |

멀티셋 비교는 CSV 헤더를 제외한 각 경고의 모든 열을 함께 비교하므로 단순 건수 일치보다 강하다. 서로 다른 두 프로그램/API 경로 간 **경고 건수 자체를 직접적인 우열 지표로 비교해서는 안 된다.** 각 정상·누락 쌍 내부의 차이가 판단 대상이다.

### 양성 대조군과 계측 호환성

- 동일 RSA 1024-bit 약한 키 사례: Java 8, 17, 21 JVM에서 기존 Java 8 기반 실험 클래스 실행 시 RVSec `InvalidKeySize` 1건 + `InvalidSequenceOfMethodCalls` 2건(총 3건) 감지.
- Java 21에서 새로 컴파일한 RSA·KEM 클래스(major 65)는 AspectJ의 `unable to add stackmap attributes` 및 JVM `VerifyError`로 실행 불가.
- 동일 RSA 소스를 Java 8/17/21로 각각 컴파일해 Java 21에서 실행한 결과: class major 52만 계측 성공, major 61·65는 동일한 `VerifyError`. 별도의 Java 21 컴파일러 `-source 17 -target 17` major 61 KEM/RSA 테스트도 실패.
- Java 21 컴파일러로 `-source 8 -target 8`을 사용한 KEM 클래스(major 52)는 Java 21에서 RVSec ON/OFF 정상 실행. 이 방식은 Java 21 API를 참조하므로 **진짜 Java 8 호환 프로그램이 아니다.**
- 이는 확인한 에이전트·컴파일 조건의 문제를 드러내지만, 모든 최신 Java 클래스에 대한 범용 호환성 결론은 아니다.

## 4. 소스 규칙과 탐지 한계의 연결

확인한 `rvsec-agent/src/main/mop` 기준:

- `MacSpec.mop`: `Mac.getInstance(...)`의 허용 알고리즘과 메서드 호출 순서, `Mac.doFinal` 결과의 `GENERATED_MAC` 속성 등을 처리. `doFinal` 입력의 X25519/ML-KEM **출처나 결합 기여 여부**에 대한 검사는 확인되지 않음.
- `SecretKeySpecSpec.mop`: 알고리즘 허용목록, `RANDOMIZED` 관련 속성 및 길이 등을 검사. `RANDOMIZED`는 PQC 공유 비밀의 **최종 키 기여**와 동치가 아님.
- 검사한 `.mop` 코퍼스에서 `javax.crypto.KEM`용 직접 규칙과 `PQC_REQUIRED`, `hybrid`, `downgrade`, `fallback`, `HKDF` 정책 표현을 찾지 못함.
- BC 내부 메서드에 대한 기존 RVSec 경고가 있으므로 **BC 실행 전체가 불가시적**이라고 주장해서는 안 됨.
- 정상 경로에도 수많은 경고가 존재한다는 사실은 거짓 양성 가능성 또는 실험 조건에 부적합한 규칙을 시사하나, 경고별 수동 분류 없이 각각을 확정적 거짓 양성으로 선언해서는 안 됨.

### 재현된 직접 결론

> 확인한 RVSec 0.2.0 에이전트·규칙과 합성 실험 환경에서는 Java 8·17의 BC JCA/Lightweight 및 Java 21의 표준 KEM+BC 경로에서, 최종 HMAC 입력에서 ML-KEM 공유 비밀을 제거해도 기존 RVSec 경고 멀티셋이 변하지 않았다.

**한계:** 이 시험은 의도적으로 단순화한 HMAC 입력 조립(`omit ? x25519Secret : concat(x25519Secret, kemSecret)`)을 사용하며, 표준화된 실제 하이브리드 TLS 핸드셰이크나 완성된 HKDF 구성의 보안성을 평가하지 않는다. `PQC_REQUIRED`는 시험 로직이 부여한 정책이며 RVSec 내장 정책이 아니다. 암호학적 취약성의 공격 성공률이나 모든 Provider/런타임에서의 일반성을 증명한 것도 아니다.

## 5. 본 연구의 P1·P2·P3와 비교

| 연구 속성 | RVSec 기존 규칙에서 관찰된 범위 | 본 연구에서 검증해야 할 전환 불변식 |
|---|---|---|
| **P1 알고리즘/Provider 선택** | 알려진 API의 알고리즘 이름, 허용목록, 호출 순서와 일부 Provider 경로 경고 | 정책에 승인된 알고리즘/Provider 선택, `PQC_REQUIRED` 만족, classical-only 회귀 금지 |
| **P2 키·상태·nonce 및 키 재료 기여** | 키 생성/난수 등 API 관련 속성·일부 상태 추적; KDF 기여 증명은 확인되지 않음 | 최종 키에 X25519와 ML-KEM이 모두 기여했음을 검증, 전환 중 키·nonce 재사용과 상태 혼선 방지 |
| **P3 인증 실패 및 폴백** | 일반 암호 API 사용 규칙 중심; 다운그레이드 승인·핸드셰이크 인증 정책 규칙 미확인 | 실패 시 fail-closed, 승인 없는 classical-only fallback 금지, 협상/정책 바인딩 |

이 표에서 **RVSec의 미검출 사실은 P2의 'KEM 기여'에 대한 직접 시험 결과**다. P1의 전면적 적합성이나 P2의 nonce 재사용, P3의 실전 폴백 안전성까지 본 시험이 검증한 것은 아니다. 해당 사항은 별도 E1/E2 구현·시험에서 증명해야 한다.

## 6. 다음 연구 업무

1. 동봉된 수집 스크립트를 사용자 WSL에서 실행해 로그·소스·SHA-256 매니페스트·경고 멀티셋 판정 자료를 복사하여 증거 묶음으로 보존한다.
2. 기존 E1/E2의 취약 기준선/허용목록/제안 경로에서 P1·P2·P3 각 조건이 실제로 강제되는지 별도 실험과 연결한다.
3. RVSec는 비교 기준선으로 유지한다. 원본 에이전트·MOP 규칙을 수정한 결과와 섞지 않는다.
4. 회의/논문에서는 '탐지 불가'를 해당 실험 조건에서의 **경고 출력상 비구별성**으로 정확히 표현한다.

## 7. 사용자 WSL의 증거 디렉터리

- Java 8·17 반복 비교: `~/pqc-research/D0-rvsec/runs/RVSec-JDK8-17-PQC-comparison-20261102/`
- Java 21 KEM 표준 API 비교: `~/pqc-research/D0-rvsec/runs/RVSec-JDK21-classfile8-KEM-control-20261102/`
- Java 21 컴파일 계측 실험: `~/pqc-research/D0-rvsec/runs/RVSec-JDK21-cross-compile-control-20261102/`, `RVSec-JDK21-bytecode-control-20261102/`, `RVSec-JDK21-classfile17-control-20261102/`
- 원본 24회 관측 실험: `~/pqc-research/D0-rvsec/runs/RVSec-BC-PQC-observability-20261102-152403-2195/`

**증거 상태:** 본 보고서의 수치는 사용자 제공 실행 출력에 기반한다. 별도 증거 묶음의 manifest는 사용자의 WSL에서 수집을 실행해야 생성된다.
