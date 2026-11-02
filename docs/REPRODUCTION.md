# D0 재현 및 검증 안내

## 1. 목적

이 문서는 RVSec D0 실험 증거의 검증 절차와
실험 환경 재구성에 필요한 정보를 정리합니다.

주의: 현재 모든 벤치마크의 완전 자동 재실행이
검증된 상태는 아닙니다.

## 2. 확인된 실험 환경

- Java: Eclipse Temurin OpenJDK 8u504
- Maven: Apache Maven 3.9.12
- 운영체제: Linux / WSL2 (x86_64)

환경 확인:

```bash
java -version
mvn -version
```

## 3. 원본 연구 코드 확보

RVSec:

```bash
git clone https://github.com/PAMunb/rvsec.git
cd rvsec
git checkout 177e2e4714f559d1448ea456b5618d207cc8cb3b
```

재현 패키지:

```bash
git clone https://github.com/PAMunb/RVSec-replication-package.git
cd RVSec-replication-package
git checkout d0349919e991a3519cee8eacd290ca4ac31a29b5
```

위 명령은 원본 소스를 특정 커밋으로 고정합니다.
벤치마크별 빌드 및 실행 명령은 원본 패키지의
설정과 의존성을 확인한 후 사용해야 합니다.

## 4. 공개용 증거 무결성 검사

본 저장소의 reproduction/rvsec-d0 브랜치에서:

```bash
sha256sum -c SHA256SUMS_PUBLIC.txt
```

모든 파일에 OK가 표시되고 종료 코드가 0이면
공개용 증거가 기록된 해시와 일치한 것입니다.

이 검사는 암호학적 무결성 확인이며,
실험 결과의 정확성을 보장하지 않습니다.

## 5. 벤치마크별 증거

- D0-01-MASCBench: 경고 CSV 및 빌드 로그
- D0-02-SmallCryptoAPIBench: 경고 CSV 및 빌드 로그
- D0-03-JulietBench: 원본 및 반복 실행 CSV, 평가 결과
- D0-04-OWASPBench: 크롤러 실행 전후 자료
- D0-05-ApacheCryptoAPIBench: 프로젝트별 비교 및 감사 기록

위 파일들은 results/evidence/에 있습니다.

## 6. JulietBench 확인

```bash
cat results/evidence/D0-03-JulietBench/metrics.txt
```

이 문서에서 ORIGINAL, RUN-01, RUN-02, RUN-03의
TP, FP, FN 및 F1을 확인할 수 있습니다.

F1이 같더라도 탐지 항목이 동일한 것은 아닙니다.

## 7. Apache Spark 확인

```bash
cat results/evidence/D0-05-ApacheCryptoAPIBench/spark-run01/isolated-reproduction-final-verification.txt
```

참조 이벤트 대응 여부와 추가 이벤트를
각각 확인해야 합니다.

참조 이벤트가 모두 대응됐다는 사실을
완전히 동일한 단일 실행 재현으로 해석하지 않습니다.

## 8. 원본과 공개용 증거 구분

공개용 증거 일부에는 로컬 경로 및
식별정보 비식별화가 적용됐습니다.

SHA256SUMS_ORIGINAL.txt:
원본 실험 당시의 체크섬 기록입니다.

SHA256SUMS_PUBLIC.txt:
본 Git 브랜치에 포함할 공개용 증거의 체크섬입니다.

원본 기록의 경로는 과거 실험 환경을 가리킬 수 있으므로
공개용 무결성 검사에는 SHA256SUMS_PUBLIC.txt를 사용합니다.

## 9. 재현의 한계

현재 문서로는 기존 결과와 공개 증거를 확인할 수 있습니다.

모든 벤치마크를 처음부터 실행해
동일한 결과를 얻는 절차는 추가 검증이 필요합니다.

벤치마크별 실행 명령과 예상 결과는
실제 재실행 검증 후 확정해야 합니다.
