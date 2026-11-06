# Apache Camel 4.22.0 – P1/PoC06 E1 단일 요인 비교 v1

- 원본 `camel-pqc:4.22.0` **공식 배포 JAR 수정 없음**.
- 실행 환경: WSL JDK 21 이상, Maven 3.9 이상, 최초 Maven Central 의존성 다운로드 가능.
- 목적: 요청된 KEM 헤더와 실제 JCA `KeyGenerator`의 알고리즘·Provider 일치 여부를 평가.
- 검증 범위: **동일 프로세스의 순차 요청**만 다룸. 동시성/TOCTOU 원자성, 실제 원격 입력 신뢰경계, 악용 가능성, 보안 인증은 입증하지 않음.
- 논문/과제 연결: PoC06 및 P1 단일 인자 E1 비교. P2는 후속 전환 시점 정의와 함께 별도 실험.

## 실행

GitHub 저장소 최상위에서 `cd experiments/camel-pqc`로 이동한 다음 실행합니다.

```bash
bash run_wsl.sh
```

모든 테스트 결과는 `reports/camel_pqc_p1_e1_result.txt`에 기록. 비밀키·평문·암호문·공유비밀 출력 없음.
정상 종료 기대값: `EXPECTED_MATCH=12/12` 및 `RESULT=CONTROLLED_E1_P1_COMPARISON_PASS`.
`EXPECTED_MATCH`는 **미리 설계한 판정 12개와 일치했다는 의미일 뿐 안전성을 보장하지 않음**.

## 비교 방식

- **V0 (기준선)**: 헤더 KEM 일치 여부를 확인하지 않고 Camel `PQCDataFormat` 호출.
- **V1 (허용목록)**: 문자 그대로의 헤더가 `MLKEM` / `KYBER` / `HQC`에 속하는지만 검사. `HQC`가 허용목록에 들어간 것은 검증을 위한 의도적 시험 조건이며, 제품 사용 권장이 아님.
- **V2 (P1 일치 검사)**: V1을 통과한 요청에 대해 `PQCKeyEncapsulationAlgorithms`로 별칭(`KYBER` → `ML-KEM`) 정규화, Camel이 실제 보관 중인 JCA `KeyGenerator`의 알고리즘과 Provider가 요청에 부합하는지 확인하고 그렇지 않으면 거부.

최소 정량 기대 판정:

| 헤더 | V0 | V1 | V2 |
|---|---|---|---|
| MLKEM | EXECUTED | EXECUTED | EXECUTED |
| KYBER | EXECUTED | EXECUTED | EXECUTED (Camel 내부 별칭) |
| HQC | EXECUTED (ML-KEM 사용) | EXECUTED (ML-KEM 사용) | BLOCKED_POLICY |
| NOT_A_REAL_KEM_ALGORITHM | EXECUTED (ML-KEM 사용) | BLOCKED_POLICY | BLOCKED_POLICY |

V0/V1의 HQC 행에서 `MLKEM_ROUNDTRIP=true`는 실제 요청과 실행이 불일치한 간접 관측이고,
`ACTUAL_KEM=ML-KEM`는 캐시된 KeyGenerator의 알고리즘을 보여줌.

## 원인 대조(사용자 WSL 실행, 2026-11-06)

- 초기 `STARTED_KEY_GENERATOR_ALGORITHM=ML-KEM`.
- `HQC` 헤더 및 존재하지 않는 헤더 모두 ML-KEM으로 복호화 성공.
- `NO_STARTUP_CACHE=true` 대조군에서는 존재하지 않는 헤더를 `IOException`으로 거부.
- `CACHE_CAUSALITY_CONTROL_PASS=true`.
- 캐시가 없는 HQC의 `IOException`은 알고리즘 라우팅, 키 호환성 또는 제공자 설정이 원인일 수 있어 하나로 단정하지 않음.

## 제한 및 공개

- Apache Camel 최신 개발 브랜치에는 캐시 없이 새 KeyGenerator를 만드는 변경이 존재. 4.22.0 결과를 현행 모든 버전의 문제로 일반화할 수 없음.
- 특정 보안 정책을 정의·신뢰하지 않은 헤더는 공격자가 바꾼 정책 자체와 동등하지 않음.
- V2는 **검사 시점의 일치성**만 보임. 동시 변경/캐시 상태 원자성/기밀성 측면 보호가 검증된 것은 아님.
- 공식 프로젝트에 공개 이슈를 내기 전 해당 변경의 이력과 영향 범위를 확인하고 필요시 비공개로 보고.

## 근거

- https://github.com/apache/camel/blob/camel-4.22.0/components/camel-pqc/src/main/java/org/apache/camel/component/pqc/dataformat/PQCDataFormat.java
- https://github.com/apache/camel/blob/camel-4.22.0/components/camel-pqc/src/main/java/org/apache/camel/component/pqc/PQCKeyEncapsulationAlgorithms.java

기능 비교와 정상 성능 측정은 동일한 `pom.xml`과 비교 Java 클래스를 사용하며, 별도 소스 복사본은 두지 않습니다. [정상 성능 측정 안내](README_KO.md).

10개 독립 JVM 반복 검증 요약: [`USER_WSL_REPEAT_CHECK.txt`](reports/p1-reproduction/USER_WSL_REPEAT_CHECK.txt). 동일 조건의 반복 판정 10건이며 별개 결함 10건을 뜻하지 않습니다.
