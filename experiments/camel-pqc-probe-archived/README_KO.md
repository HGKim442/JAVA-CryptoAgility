# Apache Camel camel-pqc — PoC06의 실제 공개 구현 검증 준비

- 대상: Apache Camel `camel-pqc:4.22.0` **공식 배포 JAR** (라이브러리 미수정)
- 과제 연결: PoC06(암호 설정 승인/실행 불일치), P1/P2의 키 교환 알고리즘 선택 일치성
- 전제: Java 21+, Maven, Maven Central 접근. 실행 중 비밀값·암호키·암호문 미출력.
- 작성 일자: 2026-11-06

## 목적

1. **양성 대조**: `MLKEM` 메시지 헤더로 암복호화 성공 여부.
2. **주요 음성 대조**: 실행 중 잘못된 `KEM_ALGORITHM` 헤더를 주어도 `MLKEM` 키를 이용한 암복호화가 성공하는지.
3. **변경 비교**: `KYBER` 헤더 요청 시 기존 ML-KEM KeyGenerator가 그대로 적용되는지.
4. **Provider 실패 대조**: 존재하지 않는 JCA Provider 지정 시 fail-closed 되는지.

`CANDIDATE_HEADER_POLICY_MISMATCH=true`가 나온다면 **PoC06 연관 구현 불일치 후보**일 뿐입니다. 사용자가 악의적인 헤더를 주입할 수 있는지, 해당 헤더가 실제 보안 정책을 표현하는지, 정확한 API 계약은 별도 확인해야 합니다. 취약점 또는 다운그레이드가 입증된 것은 아닙니다.

## 실행

```bash
bash run_wsl.sh
```

`RESULT=CONTROLLED_PROBE_COMPLETED`는 양성 대조 및 Provider 음성 대조가 예상대로 완료됐다는 뜻입니다. 헤더 불일치 후보의 참/거짓은 `CANDIDATE_HEADER_POLICY_MISMATCH`를 별도로 확인해야 합니다. 실행 결과를 공유할 때 비밀번호·키 파일은 보내지 마세요.

## 기존 공식 테스트와 관계

- 공식 `PQCDataFormatTest`: 정상·대용량 왕복 테스트.
- 공식 `PQCDataFormatAeadTest`: AES-GCM, ChaCha20-Poly1305, 인증 태그 변조, 비-AEAD 암호 거부.
- 본 코드는 Apache Camel의 **기존 테스트를 통과했다고 주장하지 않으며**, 공식 릴리스 JAR의 별도 검증 프로그램입니다.

참고 소스: https://github.com/apache/camel/blob/camel-4.22.0/components/camel-pqc/src/main/java/org/apache/camel/component/pqc/dataformat/PQCDataFormat.java

공개에 앞서 정책 불일치 후보가 실제로 성립하고 보안상 영향이 있는지 확인하며, 문제가 된다면 해당 프로젝트에 비공개 절차를 우선 검토합니다.


## v1.1: Camel 구동 의존성 보완 (2026-11-06)

이전 v1의 `Maven BUILD SUCCESS` 이후 `NoSuchLanguageException: No language could be found for: simple` 는
암호 연산 문제가 아니라 실험 앱의 **Camel 런타임 의존성 누락**이었습니다.
Apache Camel 4.22.0 소스에서 `org.apache.camel.language.simple.SimpleLanguage`는
`org.apache.camel:camel-core-languages` 모듈에 있으므로 v1.1 POM에 동일 버전을 추가했습니다.
원본 Apache Camel JAR와 `CamelPqcPolicyProbe.java`의 연구 로직은 수정하지 않았습니다.

이 패키지는 소스/구성/스크립트 무결성 및 구조 검사를 거쳤습니다. 실제 Camel 런타임은 WSL Maven 의존성으로 실행해야 합니다.
새 로그에 `BASELINE_ROUNDTRIP=true` 등이 나오기 전에는 PoC06 불일치를 실험 결과로 간주하지 않습니다.
`CANDIDATE_HEADER_POLICY_MISMATCH=true`가 관찰되더라도 실제 운영 취약점 또는 보안 정책 위반의 확정은 아닙니다.
