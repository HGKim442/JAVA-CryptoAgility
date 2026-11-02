# RVSec D0 선행연구 재현 및 검증

## 1. 연구 목적

본 브랜치는 Java 암호 API 오용 탐지 도구인 RVSec의
선행연구 재현 실험(D0)을 정리한 자료입니다.

목표는 원본 연구의 실험을 재현하고, 탐지 결과의 일치 여부,
실행 간 변동성, 재현 과정의 제약 사항을 검증하는 것입니다.

이 실험은 이후 JCA/JCE 암호민첩성 및 PQC 전환 안전성 연구를
위한 기존 탐지 도구의 적용 범위를 확인하는 기초 단계입니다.

## 2. 원본 구현 및 재현 패키지

### RVSec 원본
- 저장소: https://github.com/PAMunb/rvsec
- 커밋: 177e2e4714f559d1448ea456b5618d207cc8cb3b

### RVSec 재현 패키지
- 저장소: https://github.com/PAMunb/RVSec-replication-package
- 커밋: d0349919e991a3519cee8eacd290ca4ac31a29b5

원본 구현과 본 연구의 재현 증거는 구분하여 관리합니다.

## 3. 실험 환경

- Java: Eclipse Temurin OpenJDK 8u504
- Maven: Apache Maven 3.9.12
- 운영체제: Linux / WSL2 (x86_64)
- 대상: Java 암호 API 오용 탐지

## 4. 벤치마크 구성

| 구분 | 벤치마크 | 확인 대상 |
|---|---|---|
| D0-01 | MASCBench | 암호 API 오용 탐지 결과 |
| D0-02 | SmallCryptoAPIBench | 취약한 암호 사용 탐지 결과 |
| D0-03 | JulietBench | 반복 실행 정확도 및 변동성 |
| D0-04 | OWASPBench | 크롤러 실행 전후 탐지 결과 |
| D0-05 | ApacheCryptoAPIBench | 실제 프로젝트의 경고 이벤트 재현 |

각 실험의 증거 자료는 results/evidence/에 보관합니다.

## 5. 주요 검증 결과

### 5.1 MASCBench 및 SmallCryptoAPIBench

RVSec가 생성한 summary.csv를 확보했습니다.

해당 파일은 암호 API 오용 경고 이벤트의 목록이며,
그 자체가 TP, FP, FN 또는 F1 평가 결과를 의미하지 않습니다.

정확한 성능 평가는 원본 정답 데이터와의 비교가 필요합니다.

### 5.2 JulietBench

정답 데이터의 class-method 쌍은 총 102개입니다.

| 실행 | TP | FP | FN | F1 |
|---|---:|---:|---:|---:|
| ORIGINAL | 100 | 0 | 2 | 0.9901 |
| RUN-01 | 98 | 0 | 4 | 0.9800 |
| RUN-02 | 100 | 0 | 2 | 0.9901 |
| RUN-03 | 100 | 0 | 2 | 0.9901 |

반복 실행에서 탐지 결과의 차이가 관측됐습니다.
동일한 F1 점수라도 탐지 항목이 완전히 일치하지 않을 수 있습니다.

근거: results/evidence/D0-03-JulietBench/metrics.txt

### 5.3 OWASPBench

크롤러 실행 전후의 summary.csv가 확보됐습니다.

다만 본 문서에서는 최종 TP, FP, FN 수치를 확정하지 않습니다.
평가 결과와 정답 데이터의 대응 관계를 추가로 검증해야 합니다.

### 5.4 ApacheCryptoAPIBench — Spark

독립 검증 기록에서 다음 결과를 확인했습니다.

- 참조 암호 이벤트: 22개
- 일치한 암호 이벤트: 22개
- 실제 관측 암호 이벤트: 24개
- 추가 암호 이벤트: 2개
- Spark 전체 참조 이벤트: 55개
- Spark 참조 이벤트 누락: 0개
- Spark 추가 이벤트: 19개

따라서 참조 이벤트는 모두 대응됐지만,
단일 실행 결과가 완전히 동일하게 재현된 것은 아닙니다.

근거:
results/evidence/D0-05-ApacheCryptoAPIBench/spark-run01/
isolated-reproduction-final-verification.txt

서로 다른 Apache 집계 결과를 비교할 때는
프로젝트 범위, 이벤트 식별 기준, 중복 제거 조건을
확인해야 합니다.

## 6. 증거 자료 관리

results/evidence/에는 벤치마크별 재현 증거를 보관합니다.

공개용 자료는 일부 개인정보와 로컬 환경 식별자를
비식별화한 사본입니다.

따라서 원본 실험 출력과 공개용 파일의 SHA-256 해시는
서로 다를 수 있습니다.

대용량 WAR 파일, 과거 빌드 디렉터리 및 일부 실행 로그는
Git 저장소에 포함하지 않습니다.

## 7. 재현 범위와 한계

현재 확보된 자료는 기존 실험의 증거를 보존한 것입니다.

모든 벤치마크에 대해 제3자가 동일한 결과를 얻는
완전 자동 재현 절차가 검증된 상태는 아닙니다.

향후 벤치마크별 실행 명령어, 정답 데이터,
결과 비교 방식 및 실행 환경을 추가 검증합니다.

참조 이벤트의 누락이 없다는 사실만으로
탐지 정확도 100%를 주장하지 않습니다.

## 8. 후속 연구와의 연결

D0에서 확인한 기존 암호 API 탐지 도구의 적용 범위와
제약 사항은 이후 JCA/JCE 기반 PQC 전환 연구의
비교 기준으로 활용합니다.

PQC 관련 실험은 별도 브랜치로 구분하여 관리합니다.
