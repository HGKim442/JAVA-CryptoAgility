# 범위 개편 전 탐색 기록

아래 범용 Java 사례는 논문 결과에서 제외했다. 후속 조사는 PQC_JAVA_FAILURE_SURVEY_PROTOCOL_KO.md의 Java ML-KEM/Kyber 범위로 수행하며, 아직 corpus 수집 전이다.

# 공개 Java 코드 예비 사례 조사 — 2026-10-09

이 자료는 세 개의 목적 표집 자료를 수동 검토한 기록이다. 전체 GitHub 검색 결과의 빈도, 프로젝트 취약점 수, exploitable downgrade 발견 결과가 아니다. 실제 소스 두 파일과 공식 API 문서 하나를 구분한다. 원격 코드 실행·취약점 공격·네트워크 서비스 검사는 수행하지 않았다.

| 자료 | 고정 근거 및 확인 위치 | 실제 관측 패턴 | 현재 판정 |
|---|---|---|---|
| Android/libcore P11KeyAgreement | commit 51b1b6997fd3f980076b8081f7f1165ccc2a4008, blob f9b30ee4a4caadf9f1e47c5a2abbb06fba77dbba; engineDoPhase | 다자 DH가 필요할 때 SunJCE로 provider 전환. 초기화 실패 예외는 전파 | 호환성 provider 전환 후보. 더 약한 알고리즘 fallback 또는 실제 정책 위반으로 확정하지 않음 |
| Apache Commons Codec DigestUtils | commit 4898d123b1d3c11a025e7cc707b85809e3627ef3; getDigest | NoSuchAlgorithmException을 IllegalArgumentException으로 전파. 다른 알고리즘 재조회 없음 | 예외 문자열만 찾으면 오탐할 수 있는 음성 대조 |
| Apache HttpComponents SSLContexts 공식 API | createSystemDefault/createDefault, 5.4.x current API, 확인일 2026-10-09; source revision 미고정 | Default를 사용할 수 없으면 createDefault. 후자는 시스템 속성을 고려하지 않는다고 명시 | 초기화 경로·설정 의미의 전환 후보. 문서 수준 확인이며 특정 앱의 TLS 하한 위반을 증명하지 않음 |

검토한 세 자료 중 provider 전환/fallback 설명 두 건과 단순 예외 전파 한 건을 구분했다. 이는 표집 자료의 분류 수이며 prevalence가 아니다. 세 번째 자료는 실제 고정 소스 검토 수에 포함하지 않는다. **확정 취약점 0건**은 이 제한된 검토의 판정이며 세 프로젝트가 안전하다는 보증이 아니다. TOCTOU 실사례 및 PQC 실제 배포 취약점은 아직 확보하지 않았다.

첫 사례는 알고리즘을 DH에서 더 약한 다른 원시로 바꾸는 예제가 아니다. 암호 제공자 전환에 대한 호출자 보안 정책이 없다면 공격이라고 부를 수 없다. 세 번째 사례의 설정 전환 역시 문서화된 호환 경로다. 사용자 요청의 하한과 배포 설정에 따라 검토해야 하며 특정 애플리케이션의 공격 가능성을 이번 자료만으로 추론하지 않는다.

후속 조사에서는 corpus 목록·commit·제외 규칙을 먼저 고정하고, catch 뒤 getInstance 재호출 후보를 추출한 뒤 함수 간 호출과 실제 알고리즘/Provider/키 길이를 수동 확인해야 한다. 정책 하한을 명시하고 failure가 도달 가능한지 및 다른 suite가 실제 실행되는지 확인한 사례만 fixture에 연결한다. 탐지 정확도 평가에는 정상 호환 전환과 예외 전파의 음성 대조가 필요하다. CryptoGuard의 정적 slice 정제 및 오탐 평가를 참고할 수 있으나 이번에는 CryptoGuard를 실행하지 않았다.

## 원자료

- Android source: https://android.googlesource.com/platform/libcore/+/51b1b6997fd3f980076b8081f7f1165ccc2a4008/ojluni/src/main/java/sun/security/pkcs11/P11KeyAgreement.java
- Commons Codec source: https://apache.googlesource.com/commons-codec/+/4898d123b1d3c11a025e7cc707b85809e3627ef3/src/main/java/org/apache/commons/codec/digest/DigestUtils.java
- HttpComponents API: https://hc.apache.org/httpcomponents-core-5.4.x/current/httpcore5/apidocs/org/apache/hc/core5/ssl/SSLContexts.html
- CryptoGuard author paper: https://yaogroup.cs.vt.edu/papers/CryptoGuardCameraReady.pdf

원문 전체를 재배포하지 않고 revision·함수·판정·URL을 남겼다. 이동하는 API URL은 향후 고정 소스로 대체해야 한다. 이번 자료는 연구 동기와 예비 분류 기록이며 “실제 전환 취약점 증거를 확보했다”는 주장 근거가 아니다.
