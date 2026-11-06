# JAVA-CryptoAgility

Java JCA/JCE 암호민첩성(Cryptographic Agility) 전환 시 보안 불변식과 적용 비용을 검증하는 연구 코드·보고서 모음입니다.

> **연구용 실험 자료:** 통제된 PoC가 실제 서비스의 취약성·보안 보증·공식 업스트림 패치를 뜻하지 않습니다. 새로운 취약점 및 신규성을 주장하지 않습니다.

## 연구 항목

| 대상 | 자료 | 범위 |
|---|---|---|
| 원 과제 E1/E2와 키 버전 | [Java E1/E2 + 키 버전 교체](experiments/jca-e1-e2-key-version/) | 6종 합성 PoC, PQC Provider 장애, 키 전환 |
| PoC06 정책 전환 | [정책 효력 시점 검증](experiments/poc06-policy-cutover/) | Snapshot / Strict cutover |
| PoC03+06/E2 | [Fallback 결합 실험](experiments/poc03-poc06-fallback-cutover/) | X25519·ML-KEM-768·AES-GCM, 연구용 combiner |
| Apache Camel 4.22.0 | [P1/PoC06 기능·성능 통합 실험](experiments/camel-pqc/) | V0/V1/V2, KEM 실행 일치 및 5-JVM 정상 비용 |
| Camel 원인 대조 | [최종 WSL Probe](experiments/camel-pqc-probe/) | 캐시 유무에 따른 알고리즘 요청 대조 |
| Camel 초기 Probe | [과거 초기 검증 소스](archive/camel-pqc-initial-probe-20261106/) | 중간 기록 보존용, 최신 재현 기본 대상 아님 |
| 과거 확장 코드 | [2026-10-10 보존용 소스](archive/jca-reference-v15-20261010/) | 당시 상태의 코드만, 최신 검증 아님 |
| Vert.x 5.2.2 | [PoC06 TLS/JSSE 공개용 보고](docs/vertx-jsse-poc06/README_KO.md) | 미공개 결함 세부자료·패치 제외 |

## 요약 결과

- E1 기준선: 6개 독립 JVM에서 합성 공격 기록 540건 및 정상 비용 기록 900건.
- E2 기준선: 실패 조건 비교 36건. 실험용 `PQC_REQUIRED`에서 V2는 고전 단독 fallback 거부.
- PoC06 정책 전환: 108/108 사전 기대 판정 일치.
- PoC03+06 / E2 결합: 144/144 기대 판정 일치. 위반 실행 30건을 포함하며 **144건 차단을 뜻하지 않음**.
- 키 버전 회전: 54/54 기대 판정 일치. PQC 알고리즘 미사용 단일 요인 실험.
- Camel P1/E1: 12/12 기대 판정 일치, 10개 독립 JVM에서 120/120 반복. 캐시된 KeyGenerator와 KEM 요청 불일치 대조.
- Camel 정상 왕복: 5개 JVM에서 V0 108.400μs, V1 108.913μs, V2 108.474μs(각 JVM 중앙값들의 중앙값). **운영 성능 보장 아님.**

세부 근거 및 정확한 범위: [연구 현황](docs/PROJECT_STATUS_KO.md) · [공개/재현 규칙](docs/PUBLICATION_AND_REPRODUCIBILITY_KO.md).

## GitHub 복제 후 빠른 시작

```bash
git clone https://github.com/HGKim442/JAVA-CryptoAgility.git
cd JAVA-CryptoAgility

# Camel 4.22.0의 P1/PoC06 기능 비교 (JDK 21+, Maven 3.9+)
cd experiments/camel-pqc
bash run_wsl.sh

# 동일 폴더에서 탐색적 성능 측정
bash scripts/run_timing.sh
```

원 과제 E1/E2 재현은 [`experiments/jca-e1-e2-key-version/README_KO.md`](experiments/jca-e1-e2-key-version/README_KO.md)를 따르세요. 해당 E2 재현에는 Bouncy Castle 1.86 JAR 경로를 지정해야 합니다. 전체 구조와 의도적으로 유지한 사본은 [저장소 구조 안내](docs/REPOSITORY_LAYOUT_KO.md)를 참고하세요.

## 재현 안내

실험별 `README_KO.md`를 먼저 읽고 실행하세요. Java 17+/21+ 및 필요한 모듈의 Maven·Bouncy Castle 1.86 등 조건이 서로 다릅니다. 연구 코드는 실제 사용자/운영시스템을 대상으로 하지 않고 통제 fixture로 실행됩니다.

**공개 제한:** 상세 Vert.x 결함 재현/패치/원시 로그, 비밀키/자격증명, 제3자 논문 PDF, 미출판 연구 초안, RVSec 별도 트랙은 포함하지 않습니다. 공개 저장소에 업로드하기 전에 지도교수·연구실의 공유 권한을 확인하세요.
