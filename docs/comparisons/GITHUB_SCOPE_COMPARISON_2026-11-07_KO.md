# 공개 GitHub 기준선과 연구 범위 대조 (2026-11-07)

> **공개용 범위 안내** — 본 문서는 공개 저장소의 기존 실험과 공개 선행 도구의 **분석 대상 차이**를 정리한 것입니다. 연구실 미출판 상세 실험, 원시 CSV, Java 에이전트 소스, 보안 결함 재현 방법은 포함하지 않습니다. 기존 프로젝트나 타 제품의 취약성 및 학술적 신규성을 주장하지 않습니다.

## 현재 공개 저장소에 이미 있는 실험

- [`experiments/jca-e1-e2-key-version/`](../../experiments/jca-e1-e2-key-version/): 원 과제 PoC 01~06의 합성 기준선, E2 및 키 버전 관련 통제 실험.
- [`experiments/poc03-poc06-fallback-cutover/`](../../experiments/poc03-poc06-fallback-cutover/): 실패 후 Fallback과 정책 효력 시점의 합성 대조군.
- [`experiments/poc06-policy-cutover/`](../../experiments/poc06-policy-cutover/): Snapshot과 Strict cutover의 정책 전환 대조군.
- [`experiments/camel-pqc/`](../../experiments/camel-pqc/): Camel 4.22.0 공개 JAR를 이용한 P1 선택 검사 및 정상 경로 비용 탐색.

자세한 실행 범위·수치는 기존 [`docs/PROJECT_STATUS_KO.md`](../PROJECT_STATUS_KO.md)에 명시된 2026-11-06 기준 결과를 사용하세요. 브랜치에 별도로 보존된 RVSec 실험은 `main`의 직접 재현 대상이 아닙니다.

## 관련 공개 GitHub 기준선과 관측 단위

| 공개 도구 | 공개 구현에서 확인되는 주요 대상 | 이 연구의 별도 검증 질문 | 비교 시 주의 |
|---|---|---|---|
| [RVSec](https://github.com/PAMunb/rvsec) | JCA API 호출 순서·파라미터·알고리즘 관련 JavaMOP 런타임 규칙 | 요청 승인 시점의 실효 정책, 실패 후 대체 스위트, 계약의 최종 준수 여부 | 동일 입력의 원본 도구 재현 없이 탐지 실패(FN)라 주장 불가 |
| [RVSec replication package](https://github.com/PAMunb/RVSec-replication-package) | CryptoAPI-Bench·MASCBench·OWASPBench 등 기존 암호 API 오용 벤치마크 | 요청 단위 cutover/fallback 시나리오의 별도 정답 라벨 | 벤치마크 목적과 분모가 달라 F1·속도 직접 비교 불가 |
| [이 공개 저장소의 Camel P1 실험](../../experiments/camel-pqc/) | 알고리즘 요청·실제 KeyGenerator 정규화 및 정상 ML-KEM 왕복 | 동시 정책 변경 및 최종 승인 경계 | 동일한 Camel 공식 JAR 사용과 요청 단위 정책 통합은 별개 |

RVSec 공개 `master` 소스에서 JCA용 `.mop` 23개 파일의 **저장 위치**는 `rvsec/rvsec-mop/src/main/resources/jca/`입니다. 논문의 22개 API 규칙/클래스라는 **연구상 수치**와 저장소 파일 23개라는 **파일 개수**는 다른 집계입니다. `rvsec/rvsec-agent/src/main/mop`는 확인한 공개 트리에 없습니다. 공개 규칙 예: [CipherSpec](https://github.com/PAMunb/rvsec/blob/master/rvsec/rvsec-mop/src/main/resources/jca/CipherSpec.mop), [KeyGeneratorSpec](https://github.com/PAMunb/rvsec/blob/master/rvsec/rvsec-mop/src/main/resources/jca/KeyGeneratorSpec.mop), [GCMParameterSpecSpec](https://github.com/PAMunb/rvsec/blob/master/rvsec/rvsec-mop/src/main/resources/jca/GCMParameterSpecSpec.mop).

RVSec의 `KeyGeneratorSpec`, `KeyPairGeneratorSpec`, `SignatureSpec` 소스에 있는 허용 알고리즘 리스트에는 검토된 스냅샷 기준으로 ML-KEM·ML-DSA가 명시되지 않습니다. 이것만으로 **전체 RVSec 도구가 해당 속성을 반드시 탐지하지 못한다는 뜻은 아닙니다**. 실제 판정과 성능 비교에는 원본 빌드, 규칙 활성화 여부 확인, 같은 실행 trace의 정답 라벨이 필요합니다.

## 연구 프레임의 구별 대상 — 검증 목표이며, 신규성 확정 아님

- **C_use**: 암호 사용 시점에 적용 가능한 정책과 실제 연산 스위트의 일치.
- **C_accept**: 최종 업무 성공 승인 시점의 정책 효력 확인.
- **C_suite**: 명시된 스위트 계약 및 요구한 비밀 입력의 최종 키 설정 기여.
- `Snapshot`/`Strict cutover`는 서로 다른 정책 의미이며 혼합해 오류로 집계하지 않습니다.

동시성·하이브리드 계약·실행 계측의 상세 실험은 별도 검증 단계이며, 공개 저장소에서 실행 가능한 기준선과 동등하게 취급하지 않습니다. **API 오용 검사**, **애플리케이션 보안 계약 검증**, **독립적인 Provider 계측**, **암호학적 안전성 증명**은 서로 다릅니다.

## 재현·배포 원칙

1. 업스트림의 위치와 대상 커밋을 고정하고, 읽기 전용으로 비교합니다.
2. API 규칙의 미지원/범위 밖 속성을 false negative로 계산하지 않습니다.
3. 특정 Java 실험에서 실제로 관측한 로그와 독립 계측/외부 네트워크 협상 증거를 분리합니다.
4. 추가 연구 결과를 공개하기 전 지도교수·연구실의 공개 범위를 확인합니다.
5. 비밀키, 개인 정보, 타 논문 PDF, 미공개 Vert.x 세부 사항, 실험 원시 증거는 이 문서에 포함하지 않습니다.

### 공개 저장소·논문 링크

- RVSec: https://github.com/PAMunb/rvsec
- RVSec replication: https://github.com/PAMunb/RVSec-replication-package
- Torres et al., *Runtime Verification of Crypto APIs: An Empirical Study*, IEEE TSE 2023, DOI: https://doi.org/10.1109/TSE.2023.3301660
- 본 저장소 현황: [`docs/PROJECT_STATUS_KO.md`](../PROJECT_STATUS_KO.md)
