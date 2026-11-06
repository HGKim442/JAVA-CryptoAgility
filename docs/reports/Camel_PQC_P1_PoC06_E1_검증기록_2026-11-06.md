# Apache Camel `camel-pqc` P1/PoC06 E1 단일 요인 검증 기록

**일자:** 2026-11-06 (KST)
**성격:** 사용자 WSL 출력에 근거한 연구 체크포인트. 연구용 외부 정책 게이트이며 Camel 소스 수정은 없음.
**범위:** Apache Camel 4.22.0 공개 배포 JAR, 동일 JVM의 순차 실행, 메시지 헤더의 KEM 요청과 캐시된 JCA KeyGenerator의 실제 선택 일치성.

## 1. 환경 및 증거

- JDK: Eclipse Temurin `25.0.5+8-LTS` (Java compile release 21)
- Maven: 3.9.12
- 대상: `org.apache.camel:camel-pqc:4.22.0` 배포 JAR (개발 브랜치가 아님)
- 실험 프로그램: `CamelPqcP1E1Comparison.java`; 보관된 배포본의 SHA-256 `0813498ce6b1d047e01538414bb94efb82f05cd3921553dd5232ae8e1ee2fdfa`
- 제공된 WSL 출력: `BUILD SUCCESS`, `EXPECTED_MATCH=12/12`, `EFFECTIVE_KEM_MISMATCH_SUCCESSES=3`, `RESULT=CONTROLLED_E1_P1_COMPARISON_PASS`
- 이 문서의 판정은 제공된 로그 기준임. 이 문서 작성 환경에서 동일 Maven/JAR을 재실행했다고 주장하지 않음.

## 2. E1 결과

| 요청 헤더 | V0(기존 호출) | V1(문자열 허용목록) | V2(허용목록 + 활성 JCA 생성기 비교) |
|---|---|---|---|
| MLKEM | ML-KEM으로 실행 성공 | 실행 성공 | 실행 성공 |
| KYBER | ML-KEM으로 실행 성공 | 실행 성공 | 실행 성공 |
| HQC | **ML-KEM으로 실행 성공** | **ML-KEM으로 실행 성공** | `ACTUAL_KEM_MISMATCH` 거부 |
| NOT_A_REAL_KEM_ALGORITHM | **ML-KEM으로 실행 성공** | `HEADER_NOT_ALLOWLISTED` 거부 | `HEADER_NOT_ALLOWLISTED` 거부 |

- `KYBER`는 4.22.0의 `PQCKeyEncapsulationAlgorithms`에서 `ML-KEM` 별칭이므로 불일치로 집계하지 않음.
- V0의 `HQC` 및 잘못된 이름, V1의 `HQC`가 실행 성공한 **3건**은 요청 KEM 선택과 캐시된 실제 ML-KEM 생성기가 일치하지 않는 사례임.
- V2는 제시된 순차 통제 조건에서 이 3건 모두 차단했음. V2는 Camel 공식 패치가 아니라 연구자가 부착한 사전 검사임.
- `EXPECTED_MATCH=12/12`는 자체 정의한 예상 판정과의 일치율. 12건 독립 취약점이나 보안 증명으로 해석 금지.

## 3. 원인 대조군 (직전 WSL 실행 결과)

- 시작 시 `STARTED_KEY_GENERATOR_ALGORITHM=ML-KEM`.
- 캐시된 생성기가 있을 때 `HQC`, 존재하지 않는 KEM 헤더로 암호화가 되고 기본 ML-KEM으로 복호화됨.
- `NO_STARTUP_CACHE=true`에서 존재하지 않는 KEM 요청이 `IOException`으로 거부됨.
- `CACHE_CAUSALITY_CONTROL_PASS=true`.
- 캐시 없는 HQC 실패는 KEM 라우팅/키 호환성/Provider 문제를 분해하지 않았으므로 구체적 원인 확정 금지.

## 4. 소스 연계

4.22.0 `PQCDataFormat.doStart()`는 초기 KEM 이름으로 `keyGenerator`를 생성·보관하고, `getOrCreateKeyGenerator(kemAlgorithm)`는 해당 객체가 있으면 메시지의 KEM 이름을 사용해 새 생성기를 만들지 않고 재사용한다. 실제 암호화 호출은 `marshal()`에서 이 메서드를 사용한다.

- https://github.com/apache/camel/blob/camel-4.22.0/components/camel-pqc/src/main/java/org/apache/camel/component/pqc/dataformat/PQCDataFormat.java
- https://github.com/apache/camel/blob/camel-4.22.0/components/camel-pqc/src/main/java/org/apache/camel/component/pqc/PQCKeyEncapsulationAlgorithms.java

Camel `main`에서는 시작 시 해당 생성기 생성 대신 유효성 확인만 수행하고, 요청마다 생성기를 생성하는 코드가 이미 확인됐음. 따라서 **모든 현행/향후 버전에 같은 동작이 남아 있다고 주장하지 않음**. 수정 시점/이유와 기존 보안 이슈 연계 여부는 별도 이력 확인 필요.

## 5. 연구계획서와의 정확한 연관성

- **PoC06:** 요청 당시 설정된 KEM 식별자와 실제 JCA 실행의 알고리즘 선택 불일치.
- **P1:** 단순 허용목록만이 아니라, 승인 요청 KEM/Provider를 **실제 사용될 암호 구현**과 결합해 확인해야 한다는 통제 실험.
- **E1:** V0/V1/V2 동일 시험 조건의 기능적 보안 위반/차단 비교는 수행.
- **P2:** 정책 변경 경쟁, 키 버전, 요청 스냅샷의 원자성은 이 실험에서 다루지 않음.
- **E1 정상 전환 비용:** 세 방식의 지연/처리량 통계는 아직 측정하지 않음.
- **E2:** 하이브리드의 두 비밀 기여 또는 `PQC_REQUIRED` 최종 키 결합은 이 실험에서 다루지 않음.

## 6. 후속 검증 우선순위

1. **반복 안정성:** 원본 배포 JAR과 동일 소스를 여러 독립 JVM에서 재실행하여 12/12과 3건의 재현성을 확인. 실패 실행과 로그도 그대로 보존.
2. **독립 판정 강화:** 요청 정책과 실제 사용된 생성기의 알고리즘/Provider/키 파라미터를 동일 요청 ID로 연계. 현재 결과는 보관된 생성기 정보와 ML-KEM 복호화 성공의 조합에 근거하며, 완전한 호출 추적은 아님.
3. **E1 비용:** 정상 ML-KEM 요청만 대상으로 warmup, 반복, 별도 JVM, 동일 하드웨어, 분리된 게이트 지연/암호 연산 시간을 측정. 오류/거부 응답과 정상 작업 시간을 합쳐 비교 금지.
4. **P2 분리:** 동시 구성 변경과 승인된 정책 효력 시점을 명시한 별도 실험. 이번 P1 단일 조건과 결과 혼합 금지.
5. **선행 수정 확인:** upstream `main` 변경 이력과 관련 테스트를 검토해 신규성/공개 범위 판단.

## 7. 공개 관련 주의

재현 코드를 공격 도구나 인증 우회 가능성으로 과장하지 않는다. 공개 전 최신 릴리스 영향, 이미 수정된 코드, 프로젝트 보안 신고 정책 및 지도교수 협의를 점검한다. 비밀키, 캡슐화 공유 비밀, 인증서/토큰 및 개인정보를 로그·GitHub에 올리지 않는다.
