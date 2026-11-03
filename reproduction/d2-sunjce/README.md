# D2 — SunJCE 기반 ML-KEM 기여 누락 재현

## 목적

RVSec 0.2.0이 X25519 + ML-KEM-768 합성 하이브리드 구성에서
ML-KEM 공유 비밀의 최종 키 도출 기여 누락을
기존 경고 출력으로 구별하는지 평가한다.

## 실험 환경

- Java: Temurin 25.0.5 LTS
- X25519: SunEC
- ML-KEM-768: SunJCE
- KDF: 실험용 HKDF-HMAC-SHA256, SunJCE
- RVSec: 0.2.0 기반 기존 JavaMOPAgent.jar
- RVSec 에이전트 SHA-256:
  a8f888eee1af20c342ff395fea992568f9546d8fec57222815c81f2460e1608d

Bouncy Castle은 이 실험의 X25519 및 ML-KEM 구현에 사용하지 않는다.

## 호환성 조건

Java 25에서 직접 생성한 클래스 파일(major 69)을
기존 RVSec 에이전트로 계측하면 AspectJ/VerifyError가 발생했다.

따라서 Java 25의 javac에 -source 8 -target 8을 적용하여
major 52 클래스 파일을 생성한 후 Java 25 JVM에서 실행했다.

이 컴파일 조건은 Java 8 런타임 호환성을 의미하지 않는다.
--release 8로 대체하면 Java 25 KEM API를 참조할 수 없다.

## 실험 조건

HYBRID:
X25519와 ML-KEM 공유 비밀을 모두 KDF 입력에 포함한다.

OMIT_KEM:
ML-KEM 캡슐화·복원은 정상 수행하지만
ML-KEM 공유 비밀을 KDF 입력에서 제외한다.

APP_POLICY_VIOLATION은 실험 프로그램의 기준 정답이며,
RVSec 자체의 경고 또는 정책 판정이 아니다.

## 관측 결과

초기 비교:
- HYBRID: 14 warnings
- OMIT_KEM: 14 warnings
- 두 경고 멀티셋 동일

3회 반복:
- 매회 HYBRID 14건, OMIT_KEM 14건
- 매회 정상/누락 경고 멀티셋 동일
- 반복 간 경고 멀티셋 동일

## 증거 구조

- src/: Java 실험 소스
- reference_class/: 실제 실행한 클래스 파일 사본
- evidence/initial/: 초기 비교 로그와 RVSec CSV
- evidence/repeat3/: 3회 반복 실행 로그와 RVSec CSV
- SHA256SUMS.txt: 보관 파일 무결성 확인

## 재현을 위한 준비

- Temurin 25.0.5 LTS JDK
- 동일한 RVSec JavaMOPAgent.jar
- Python 3 및 Linux/WSL Bash 환경

RVSec 에이전트는 본 브랜치에 동봉하지 않았다.
반드시 위 SHA-256에 일치하는 에이전트를 준비해야 한다.

기록된 결과는 이 폴더의 증거 파일로 검토할 수 있다.
동일 WSL 환경에서 소스 기반 자동 재실행을 완료했다. 다른 연구원 환경에서의 독립 재현은 아직 검증되지 않았다.

## 해석의 범위

이 결과는 합성 실험에서 RVSec 경고 출력의 비구별성을 보인다.
실제 TLS 프로토콜 보안성, 모든 Provider에 대한 일반성,
RVSec의 전체 암호 API 오용 탐지 성능을 증명하지 않는다.


## 자동 재현 절차

필요 환경:
- Eclipse Temurin 25.0.5 LTS
- Python 3
- 동일한 RVSec JavaMOPAgent.jar
- Linux 또는 WSL2

에이전트 SHA-256:
a8f888eee1af20c342ff395fea992568f9546d8fec57222815c81f2460e1608d

저장소 루트에서 기존 증거 검증:
python3 reproduction/d2-sunjce/reproduce.py verify

저장소 루트에서 새로운 실험 실행:
python3 reproduction/d2-sunjce/reproduce.py run

환경변수:
- JAVA25_HOME: JDK 25 설치 위치
- RVSEC_AGENT: JavaMOPAgent.jar 위치
- D2_OUTPUT_DIR: 새로운 실험 결과 저장 위치

스크립트는 새로운 출력 폴더를 생성하며 기존 증거를 덮어쓰지 않는다.

Java 25의 -source 8 -target 8 컴파일은
RVSec 계측 호환성을 위한 클래스 형식 52 생성 조건이다.
Java 8 런타임에서 실행할 수 있다는 뜻은 아니다.

검증된 결과:
- 정상 구성 경고 14건
- ML-KEM 기여 누락 구성 경고 14건
- 경고 전체 멀티셋 동일
- 초기 비교 및 3회 반복 안정성 확인
- 소스 기반 신규 재실행 PASS

이 결과는 해당 합성 실험에서의 RVSec 경고 비구별성을 의미한다.
