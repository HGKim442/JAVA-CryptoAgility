# 연구계획 v2.4 기준 진행 현황 (2026-11-06)

원 과제 「Java JCA/JCE 암호민첩성의 보안성 분석」을 기준으로 한 자체 연구 기록입니다. 공식 제품 보안 평가 또는 학술 신규성 판정이 아닙니다.

| 연구 항목 | 해당 재현 자료 | 상태 / 한계 |
|---|---|---|
| PoC01~06, E1 | `experiments/jca-e1-e2-key-version` | 합성 6종 PoC V0/V1/V2 기준선 재검증, 6 JVM |
| PoC03, E2 | 원본 PQC 장애 실험 | Provider 장애/전환 정책의 통제 비교, 표준 TLS 아님 |
| PoC06 (정책 epoch) | `experiments/poc06-policy-cutover` | Snapshot / Strict cutover 단일요인 108/108, 통제 fixture |
| PoC03+06 결합 | `experiments/poc03-poc06-fallback-cutover` | 정책 효력시점 + KEM 실패 144/144, 임의 경쟁상황 일반화 금지 |
| PoC06 (키 버전) | `experiments/jca-e1-e2-key-version` | 54/54, AES-GCM 단일요인 |
| P1 + PoC06 실제 OSS | `experiments/camel-pqc-p1-comparison` | Camel 4.22.0 실제 JAR, KEM 헤더·유효 실행 선택 비교 |
| E1 Camel 재현성 | 동일 비교 | 12/12 x 10 JVM = 120/120; 사용자가 제공한 WSL 실행 출력 |
| E1 Camel 정상 비용 | `experiments/camel-pqc-timing` + 요약 CSV | 5 JVM 탐색적 측정, 4,500회 정상 왕복, 운영성능 추론 금지 |
| P2 | 합성 정책·키 전환 항목만 완료 | 공개 Camel의 concurrent policy-key state 전환 증명 아님 |
| P3 | 원 E1 합성 AAD 결합 포함 | 실제 임의 앱의 컨텍스트 결합 보증 아님 |
| Vert.x JSSE 확장 | `docs/vertx-jsse-poc06` | 제한된 범위에서 수정 전후 비교, 상세 자료는 비공개 및 공식 조율 전 공개 금지 |

*보조 주의:* Camel 4.22.0의 `KYBER`는 `ML-KEM` 별칭입니다. 서로 다른 KEM 사례는 `HQC`와 비교했습니다. Camel 개발 브랜치에서는 생성기 생성 경로가 변경된 사실을 확인했으나, 이번 코드가 현재 제품에 그대로 적용된다고 주장하지 않습니다.

원 계획서의 **P1·P2·P3**는 전체 정책 상태, 실제 암호 동작, AEAD 문맥 결합을 함께 검토하는 연구 프레임입니다. 이 저장소의 특정 소규모 테스트 성공으로 세 불변식을 전체 입증했다고 주장하지 않습니다.
