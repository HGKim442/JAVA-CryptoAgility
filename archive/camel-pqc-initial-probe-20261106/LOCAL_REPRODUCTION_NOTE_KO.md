# WSL 후속 실험의 소스 보존 안내

이 폴더에는 2026-11-06 최초 배포용 v1.1 추적 코드가 있습니다. 이후 사용자 WSL 환경에서 `HQC` 대조군과 `KeyGenerator` 무캐시 대조군을 **추가 편집하여 실행**했습니다.

최종 WSL 편집 소스 자체는 대화 출력만으로 동일한 파일 바이트를 확인할 수 없어 이 아카이브의 소스와 같다고 주장하지 않습니다. 게시 도구의 `scripts/collect_wsl_evidence.sh`는 이 최종 편집 Java 소스를 WSL에서 복사할 수 있을 때 별도 `camel-pqc-probe-wsl-final` 디렉터리에 추가합니다.

사용자 WSL 로그 관측: `NO_STARTUP_CACHE=true`, `CACHE_CAUSALITY_CONTROL_PASS=true` (해당 제어 조건의 결과); 4.22.0 시작 캐시 재사용과 불일치의 인과적 연관성 확인. 독립적인 제3자 검증 주장은 아닙니다.
