# GitHub 전체 브랜치·연구 자료 안내 (2026-11-06)

> 대상: `HGKim442/JAVA-CryptoAgility` / 작업 계정: `hs-pqc`. 공개용 연구 기록입니다. 미공개 Vert.x 재현·패치·원시 로그는 포함되지 않습니다.
>
> 이번 정리는 Java/Python 실험 코드의 동작을 수정하지 않습니다. 브랜치별 **커밋 및 파일**을 확인한 후 수행한 저장소 구성 정리입니다.

## 시작점: `main`

- [현재 실행용 Camel P1/PoC06 기능·성능 실험](../experiments/camel-pqc/README_KO.md): `bash run_wsl.sh` / `bash scripts/run_timing.sh`; JDK 21+, Maven 3.9+
- [최종 Camel 원인 대조 Probe](../experiments/camel-pqc-probe/): `bash run_wsl.sh`
- [E1/E2 및 키 버전](../experiments/jca-e1-e2-key-version/README_KO.md): `python3 audit_reports.py` 또는 README의 재현 명령
- [PoC06 정책 전환](../experiments/poc06-policy-cutover/): `python3 run.py`
- [PoC03·06 결합 실험](../experiments/poc03-poc06-fallback-cutover/): `python3 run.py`
- [Vert.x 공개용 요약](vertx-jsse-poc06/README_KO.md): 보안 결함 재현 및 내부 패치는 공개하지 않음
- [기존 구조 안내](REPOSITORY_LAYOUT_KO.md): 독립 실행·역사 보존을 위한 사본 설명

## 유지하는 브랜치 (총 7개, `main` 포함)

| 브랜치 | 용도 | 파일 수(정리 전 조사) | 유지 이유 |
|---|---|---:|---|
| [`main`](../README.md) | JCA/JCE·Camel의 최신 공개 실행 경로 | 154 | 기본 재현 진입점 |
| [`research/jca-jce-full-evidence-20261106`](https://github.com/HGKim442/JAVA-CryptoAgility/tree/research/jca-jce-full-evidence-20261106) | 11월 6일 폴더 정리 전 원형 | 158 | 당시 형태 재검증/백업; `main`의 조상 |
| [`reproduction/jca-pqc-repeat2`](https://github.com/HGKim442/JAVA-CryptoAgility/tree/reproduction/jca-pqc-repeat2) | 11월 2일 E1/PQC 별도 JVM 재현 | 72 | `main`과 38개 파일 내용이 같지만 개별 실행 증거는 고유 |
| [`experiment/jsse-pqc-e2-20261103`](https://github.com/HGKim442/JAVA-CryptoAgility/tree/experiment/jsse-pqc-e2-20261103) | JSSE TLS 1.3 PQC 협상 기준선 | 4 | 별도 JDK/환경 및 실행 스크립트. 기기 종속 경로 있음 |
| [`reproduction/rvsec-d0`](https://github.com/HGKim442/JAVA-CryptoAgility/tree/reproduction/rvsec-d0) | RVSec 선행연구 D0 재현 | 247 | 별도 벤치마크 및 원시 재현 증거. `main`에 통합하지 않음 |
| [`reproduction/rvsec-d2-sunjce`](https://github.com/HGKim442/JAVA-CryptoAgility/tree/reproduction/rvsec-d2-sunjce) | RVSec D1 기준선 + D2 SunJCE 재현 | 28 | D1 커밋을 계승하고 추가 실험 보유 |
| [`experiment/rvsec-mlkem-kdf-contribution-20261104`](https://github.com/HGKim442/JAVA-CryptoAgility/tree/experiment/rvsec-mlkem-kdf-contribution-20261104) | RVSec ML-KEM/KDF D2 실험 | 20 | 별도 구현·테스트·검증 문서 |

링크된 다른 브랜치에 들어간 소스와 결과는 `main`에서 **자동 실행되지 않습니다**. 각 브랜치로 `git switch <branch>` 후 해당 README를 확인하세요. 서로 다른 브랜치의 결과 수치를 단순 합산해 독립 실험처럼 취급하지 않습니다.

## 백업 태그로 전환할 과거 브랜치 (4개)

| 기존 브랜치 | 확인된 관계 | 커밋 백업 태그 |
|---|---|---|
| `research/jca-jce-clean-layout-20261106` | `main`과 동일 커밋/전체 파일 | `archive/pre-cleanup-20261106/research/jca-jce-clean-layout-20261106` |
| `docs/camel-pqc-p1-e1-checkpoint-20261106` | 3개 연구 문서가 `main`에 바이트 단위 동일, 루트 README만 상이 | `archive/pre-cleanup-20261106/docs/camel-pqc-p1-e1-checkpoint-20261106` |
| `docs/vertx-poc06-research-checkpoint-20261106` | 2개 연구 문서가 `main`에 바이트 단위 동일, 루트 README만 상이 | `archive/pre-cleanup-20261106/docs/vertx-poc06-research-checkpoint-20261106` |
| `experiment/pqc-d1` | D1 커밋이 `reproduction/rvsec-d2-sunjce`의 직접 조상이고 D1 파일 전부 D2에서 보존 | `archive/pre-cleanup-20261106/experiment/pqc-d1` |

위 브랜치는 삭제 전에 **Git 태그로 동일 커밋을 보존**합니다. 태그는 GitHub에서 공개적으로 열람할 수 있으며 원형 확인을 위한 기록입니다. 브랜치 삭제는 Git 데이터 자체를 즉시 영구 파기하는 방식으로 사용하지 않습니다. 단, 브랜치명에 의존하던 외부 링크는 삭제 후 작동하지 않으므로 필요한 경우 백업 태그 링크를 사용하세요.

## 내용이 정확히 같은 파일과 보존 이유

`main`의 동일 내용 4쌍은 다음과 같습니다.

1. `archive/jca-reference-v15-20261010/{AnchorCodec,CheckpointCodec,TrustedStateStore}.java`와 `experiments/jca-e1-e2-key-version/original_e1_e2_sources/`의 동명 3개: 역사적 원본 보존과 현재 실험 독립 컴파일을 위해 유지.
2. `experiments/jca-e1-e2-key-version/reports/pairwise_recheck/summary.json`과 `experiments/poc03-poc06-fallback-cutover/reports/local_run/summary.json`: 단일 공통 실행 결과의 두 위치. 독립 감사 스크립트가 기존 상대경로를 사용하므로 유지하되 **서로 다른 실험으로 중복 집계 금지**.

중복 브랜치의 관리와 `main` 내부의 실행에 필요한 사본 제거는 별개 작업입니다. 이 정리 과정에서는 실험 코드 또는 감사 스크립트의 경로 동작을 손대지 않습니다.

## 검증 범위와 주의

- 커밋/트리/파일 동일성은 GitHub의 브랜치 및 Git blob SHA를 비교한 것입니다. 원격 브랜치는 작업 시점에 한 번 더 검증합니다.
- `main`의 154개 파일 중 `archive/`는 역사적 실험 스냅샷입니다. 최신 재현 명령과 확인된 결과는 `experiments/`에서 찾으세요.
- 기존 다른 브랜치의 README 내용은 서로 다른 작성 시점의 기록이므로 일부 안내가 `main`과 다를 수 있습니다.
- 제3자 연구의 신규성·운영환경 보안성·제품 취약점 여부는 GitHub 저장소 파일 정리만으로 입증되지 않습니다.
- Private 자료를 공개 저장소에 병합하지 않습니다.
