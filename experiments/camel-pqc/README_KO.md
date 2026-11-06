# Apache Camel P1·PoC06 E1 정상 경로 탐색적 비용 측정

**대상:** 공식 `org.apache.camel:camel-pqc:4.22.0` 릴리스 JAR, 비수정 원본
**실험 목적:** 기존에 순차 E1 기능 판정(12/12), 서로 다른 JVM 10회 재현을 확보한 뒤, 정상 요청에서 사전 정책 검사가 실제 처리 비용에 어떤 차이를 갖는지 확인한다.

## 파일 구성

- `src/main/java/CamelPqcP1E1Comparison.java`: 기존 기능 비교 소스 변경 없이 보존.
- `src/main/java/CamelPqcP1E1Timing.java`: V0/V1/V2의 정상 `MLKEM` 선택과 ML-KEM-768→AES-GCM-256 왕복 처리 시간을 분리 수집하는 탐색 실험.
- `scripts/run_timing.sh`: 5개 독립 JVM, JVM별 warmup, 측정 CSV 저장, 자동 집계.
- `scripts/summarize_timing.py`: CSV 스키마/건수 확인, 각 JVM의 중앙값과 V2 대 V0 비용 비 계산.

## 실행 (Ubuntu/WSL)

GitHub 저장소를 복제한 뒤 저장소 최상위 경로에서:

```bash
cd experiments/camel-pqc
bash run_wsl.sh             # P1·PoC06 V0/V1/V2 기능 비교
bash scripts/run_timing.sh # 정상 경로 비용 측정: 5개 독립 JVM
```

기능 비교 실험의 설계와 판정은 [`P1_COMPARISON_KO.md`](P1_COMPARISON_KO.md)를 참고하세요.

요구사항: Java 21 이상, Maven 3.9.x, Python 3, SHA256SUMS.txt 검사 가능 환경. 첫 실행 시 Maven 종속성 다운로드가 필요할 수 있다.

출력 끝의 `RESULT=FIVE_FORK_TIMING_COLLECTED`, `RESULT_DIR=reports/normal_timing_...`가 있는지 확인한다. 실제 숫자는 현장에서 실행 전까지 미정이다. 외부 GitHub나 Camel 본체 파일을 수정하지 않는다. 로컬 새 측정 결과(`reports/normal_timing_*`)는 기본적으로 Git 추적 대상이 아닙니다. 이미 검증된 요약·원시 CSV는 `reports/verified-wsl-run/`에 보존되어 있습니다. 비밀키는 업로드하지 마세요.

## 설계와 해석

1. **정상 처리 비용**: 매 호출에 동일한 `MLKEM` 헤더, 동일한 키 쌍, 원본 Camel DataFormat. 각 모드는 별도의 DataFormat 인스턴스, 같은 크기의 메시지, ML-KEM KEM→AES-GCM 암호화→역캡슐화→AES-GCM 복호화→결과 비교.
2. **V0**: 사전 정책 게이트 없음. **V1**: 문자열 허용목록 검사. **V2**: 허용목록 + 요청 알고리즘의 Camel 정규화 + 활성 KeyGenerator 알고리즘/Provider 비교.
3. **정상 요청에 한정**: 정책 거부의 조기 반환과 정상 암복호화 시간을 섞지 않음. 이상 요청(예: HQC) 차단 성능과 오탐률은 앞선 *기능* 실험에서만 다룸.
4. **각 JVM에서** 모드별 왕복 120회 warmup 후 300회 측정; 3개 모드를 seeded interleave 하여 한 모드만 먼저/나중에 처리되는 편향 완화. 동일 JVM에서 각 모드의 정렬된 중앙값과 p95 계산. 이 전체 과정을 5개 *새 JVM*으로 반복.
5. **정책 게이트 자체**: 유효한 `MLKEM`, `KYBER`(명시적 ML-KEM 별칭)를 번갈아 사용하고, 모드별 `10,000`회 게이트 호출을 1배치로 하여 warmup 35배치+측정 120배치. 배치별 시간/호출수로 산출. 정책 측정값의 절대 ns 단위는 JVM 최적화·분기·시계정밀도 영향을 크게 받아 참고용.
6. **결과**: 각 JVM 별 지연 분포와 중앙값을 보존하고, JVM별 `(V2 median / V0 median - 1)×100`을 구한 뒤 그 5개 변화율의 중앙값을 표시한다. 전체 데이터를 합쳐 독립 표본 4500개로 주장하지 않음.

### 반드시 지킬 한계

- JMH가 아닌 탐색적 계측. OS 스케줄링, CPU 주파수, JIT, SecureRandom, GC, VM/WSL 간 변동을 분리하지 못한다. 특정 차이가 작으면 `측정해 구별할 수 없음`으로 보고한다.
- `P1` **사전 알고리즘 선택 확인**에 한정. 요청 도중 `KeyGenerator`가 바뀔 수 있는 경쟁 조건(`P2`), 키 버전/정책 cutover, 하이브리드 기여(`E2`)는 이 실험으로 다루지 않음.
- 키/Provider는 고정, `ML-KEM-768 + AES-GCM-256`의 작은 메시지 왕복 처리만 다룬다. 일반적인 Apache Camel 처리량/지연 및 다른 공급자 성능으로 외삽하지 않음.
- `실제 JCA에서 실행된 KEM`은 캐시된 KeyGenerator 특성과 성공한 ML-KEM 왕복 결과를 통해 관찰함. 별도 instrumentation으로 모든 암호 호출을 완전 추적한 것은 아님.
- 파일을 실행하는 것은 특정 보안 문제나 신규성의 증명이 아니며 공식 프로젝트 수정본도 아님.
