# Repeat2 재현 절차

## 1. 준비

Ubuntu 또는 WSL의 Linux 파일시스템에서 실행합니다.

필수 환경:
- Temurin/OpenJDK 17 (컴파일·실행)
- Python 3
- Bash
- SHA-256 검증 도구

## 2. Bouncy Castle 설치

Bouncy Castle 공식 배포처 또는 Maven Central에서
bcprov-jdk18on 버전 1.86 JAR을 확보하여
다음 경로에 배치합니다.

lib/bcprov-jdk18on-1.86.jar

예상 SHA-256:

2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f

검증:

sha256sum -c dependencies.sha256

해시가 일치하지 않으면 실행하지 않습니다.

## 3. 빌드

java -version
bash scripts/build.sh

컴파일 기준:
javac --release 17 -Xlint:all -Werror

## 4. E1/PQC 재현

bash scripts/reproduce-e1-pqc.sh

새 실행 결과는 Git에서 제외된 다음 경로에 생성됩니다.

- results/e1/current/
- results/pqc-downgrade/current/

## 5. 결과 확인

예상 결과:
- E1 공격 진단: 540행
- E1 정상 비용: 900행
- PQC 실패 실험: 36행

각 실행은 6개 fork로 구성됩니다.
반복 관측을 서로 독립적인 취약점 표본으로
간주하지 않습니다.

공개 증거의 해시 검증:

sha256sum -c SHA256SUMS_EVIDENCE.txt

이 명령은 공개 시점의 증거 파일을 검증합니다.
새로 실행한 결과와 과거 결과가 바이트 단위로
동일해야 한다는 의미는 아닙니다.

## 6. 검증의 범위

2026-11-02에 실제 재현한 항목:
- Java 17 엄격 컴파일
- E1 여섯 합성 시나리오
- PQC 실패 조건 두 가지
- 새 CSV/JSON 수집 및 해시 확인

이번 작업에서 재실행하지 않은 항목:
- 정상 PQC workload 전체 2,226행
- 과거 성능 비교 전체
- 전체 보안 회귀 시험
- JDK 24 비교
- 실제 서비스 배포 실험

실험 코드의 설계와 독립적인 보안 증명,
기존 패키지의 작성·실행 주체 확인 역시
이번 검증 범위에 포함되지 않습니다.

## 7. 원본과 신규 증거 구분

기존 Repeat2 패키지:
JCA_JCE_PQC_Research_Repeat2_20261010.zip

이 브랜치의 evidence/:
2026-11-02 GitHub 작업 브랜치에서
직접 실행하여 생성한 원자료의 복사본입니다.

이 브랜치는 원본 패키지의 전체 연구 성과를
독립적으로 검증했다는 주장을 하지 않습니다.
