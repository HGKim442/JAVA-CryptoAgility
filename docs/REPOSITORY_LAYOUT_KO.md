# GitHub 저장소 구조 및 실행 기준 (2026-11-06)

> 기존 `research/jca-jce-full-evidence-20261106` 브랜치는 구조 정리 **전** 상태로 보존합니다. 이 `main`의 실험 소스는 기존 코드의 동작을 바꾸지 않고 폴더·설명·검증용 SHA 목록만 정리했습니다.

## 어디서 시작할까?

| 폴더 | 역할 | 주요 실행 명령 |
|---|---|---|
| `experiments/camel-pqc/` | **현재 Camel P1/PoC06 비교 및 5-JVM 성능 측정** | `bash run_wsl.sh`, `bash scripts/run_timing.sh` |
| `experiments/camel-pqc-probe/` | **WSL 최종 원인 대조 코드**(해당 파일이 존재할 때) | `bash run_wsl.sh` |
| `experiments/jca-e1-e2-key-version/` | 원 과제 E1/E2 및 키 버전 | `python3 audit_reports.py`, `python3 run.py --repeat 3` |
| `experiments/poc06-policy-cutover/` | PoC06 정책 epoch | `python3 run.py` |
| `experiments/poc03-poc06-fallback-cutover/` | PoC03+06 / PQC 장애 | `python3 run.py` |
| `docs/` | 결과·검증 범위·한계 | `PROJECT_STATUS_KO.md` |
| `archive/jca-reference-v15-20261010/` | 10월 소스 역사 보존 | **최신 재현 대상 아님** |
| `archive/camel-pqc-initial-probe-20261106/` | 초기 Camel 탐색 원본 | **최종본 아님** |

모든 명령은 해당 실험 폴더에서 수행하고, 첫 실행 전에 해당 폴더의 `README_KO.md`를 읽으세요.

## 중복 제거와 보존의 구분

1. 과거 `camel-pqc-p1-comparison`와 `camel-pqc-timing`에 중복된 `pom.xml`, `run_wsl.sh`, `CamelPqcP1E1Comparison.java`는 **하나의 `experiments/camel-pqc/`로 통합**했습니다. 기능·성능 두 실행 방법을 유지합니다.
2. Camel 5-JVM 재검증 결과의 동일한 텍스트 요약 사본은 하나(`summary.txt`)만 유지합니다. 10개 독립 JVM 반복 검증 기록 `USER_WSL_REPEAT_CHECK.txt`는 유일한 검증 요약이므로 `experiments/camel-pqc/reports/p1-reproduction/`에 별도로 보존합니다.
3. `archive/jca-reference-v15-20261010/`의 세 Java 소스와 원본 E1/E2 재현 소스는 바이트가 같지만 **역사적 스냅샷과 독립 실행을 위해 의도적으로 보존**합니다.
4. PoC03+06 결과 `summary.json`의 사본 두 개는 E1/E2 독립 감사 스크립트(`audit_reports.py`)가 각각 경로를 직접 참조하므로 **두 곳 유지**합니다. 숫자를 서로 다른 실험 결과로 중복 계산하지 않습니다.
5. 과거 `reproduction/*`, `experiment/*` 브랜치는 재현 기록이고 `main`의 최신 실행 경로가 아닙니다. **현재 유지하는 브랜치와 백업 태그는 [전체 브랜치 안내](BRANCH_INVENTORY_KO.md)를 참고하세요.**

## 보안 및 검증 한계

- `main`에는 공개 가능한 연구 코드·보고서만 유지하며 Vert.x 미공개 상세 수정·결함 재현·원시 로그는 넣지 않습니다. 별도 **Private 저장소에서만** 관리해야 합니다.
- 이 저장소의 `P1` 실행 일치 검사는 통제된 조건의 실험이지 모든 버전·Provider·동시성 환경의 보안성 보증이 아닙니다.
- 벤치마크 수치는 특정 WSL/JVM 환경의 탐색적 계측입니다.
