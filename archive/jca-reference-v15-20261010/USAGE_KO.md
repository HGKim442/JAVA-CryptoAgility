# v12 간편 적용

처음에는 QUICK_START_KO.md를 읽고 `python3 easy.py doctor`와 `python3 easy.py setup --anchor ~/pqc-anchor`로 시작하세요. 이후 `encrypt FILE`/`decrypt FILE`만 입력하면 됩니다. 아래는 기존 상세 CLI 사용법입니다.

# v11 파일 도구 사용법

Java17, Python3, POSIX 권한, hard link, atomic move와 파일/디렉터리 fsync를 지원하는 로컬 파일시스템이 필요하다. 네트워크 서비스·Windows 도구·HSM 제품이 아니라 실제 파일을 처리하는 연구용 오프라인 CLI다. 공개키 교환 프로토콜 없이 현재 엔진의 보관 키로 암호화/복호화한다.

`bash cli.sh help`는 처음 실행할 때 컴파일한다. 이후 소스·의존성 checksum이 같고 클래스가 있으면 컴파일을 재사용한다. 작업 파일 경로는 명령을 실행한 디렉터리 기준이며 다른 디렉터리에서 절대 경로의 cli.sh를 실행해도 동일하다. 프로그램/Provider 파일과 부모 경로는 신뢰해야 한다.

## 시작 및 정상 파일 처리

아래 디렉터리 구성은 기능 시연용이다. 운영에서는 master.key와 신뢰 앵커를 각각 보호하고 앵커를 상태 디렉터리와 함께 롤백·복제하지 않는다. 폴더 분리는 독립 신뢰 경계의 대체가 아니다.

```sh
umask 077
mkdir -m 700 demo demo/state demo/anchor demo/files
bash cli.sh keygen demo/files/master.key
bash cli.sh init demo/files/master.key demo/state demo/anchor 'tenant/document'
printf 'sample\n' > demo/files/input.txt
bash cli.sh seal demo/files/master.key demo/state demo/anchor 'tenant/document' demo/files/input.txt demo/files/input.packet
bash cli.sh open demo/files/master.key demo/state demo/anchor 'tenant/document' 1 demo/files/input.packet demo/files/restored.txt
bash cli.sh status demo/files/master.key demo/state demo/anchor 'tenant/document'
```

실제 난수32B master key를 생성하며 키 바이트를 터미널에 출력하거나 명령행/환경변수로 전달하지 않는다. keygen은 key 보호/회전·백업 서비스를 제공하지 않는다. 키 파일과 평문 입력은 owner-only 권한이 필요하고, 출력 디렉터리도 owner-only여야 한다. 출력 파일은0600으로 작성하며 기존 파일·symlink를 덮어쓰지 않는다. 입력16MiB 상한과 완전한 packet 검사/인증 후에만 복호화 출력을 작성한다.

## 여러 파일 및 프로필 전환

```sh
bash cli.sh seal-batch demo/files/master.key demo/state demo/anchor 'tenant/document' demo/files/input.txt demo/files/batch1.packet demo/files/input.txt demo/files/batch2.packet
bash cli.sh upgrade5 demo/files/master.key demo/state demo/anchor 'tenant/document'
bash cli.sh seal demo/files/master.key demo/state demo/anchor 'tenant/document' demo/files/input.txt demo/files/p5.packet
bash cli.sh open demo/files/master.key demo/state demo/anchor 'tenant/document' 2 demo/files/p5.packet demo/files/p5.restored.txt
bash cli.sh open demo/files/master.key demo/state demo/anchor 'tenant/document' 1 demo/files/input.packet demo/files/old.restored.txt
```

seal 성공 메시지에 policy_version과 reservation_writes가 나온다. open에는 해당 파일을 만들 때의 policy_version을 지정한다. upgrade5는 초기 P3에서 P5로 정책·키 버전을 올리며 과거 파일을 읽을 수 있다. 이미 P5이면 다시 전환하지 않는다. 고전 알고리즘 fallback은 없다.

seal-batch는 최대64개 파일을 순차 처리하며 한 번만 키 상태를 복구하고 엔진을 재개한다. 같은128개 nonce 예약 블록을 쓰므로 프로세스를 파일마다 재시작하는 것보다 예약 저장과 미사용 번호 폐기를 줄인다. 입력은 한 파일씩 읽고 정리해 파일 수에 비례해 평문을 메모리에 쌓지 않는다. 기존·중복 출력 경로는 시작 전에 거부한다. 배치는 전체 트랜잭션이 아니다. 뒤 파일에서 오류가 나면 앞 파일의 완료 출력은 남으며, 실패한 항목부터 새 출력 이름으로 다시 실행한다. 서명·KEM·파일별 난수와 인증은 각 파일에서 실행한다.

## 복구 및 오류

미러 파일 손상/누락은 자동 복구하지 않는다. 독립 앵커가 현재 상태임을 운영자가 확인한 경우에만 다음 명령을 사용한다.

```sh
bash cli.sh repair demo/files/master.key demo/state demo/anchor 'tenant/document'
```

키/앵커를 잃거나 함께 롤백한 경우 이 명령으로 보장을 복구할 수 없다. 여러 호스트가 같은 키 상태를 복제해 동시에 사용하면 안 된다. valid packet 반복 읽기는 허용되며 anti-replay는 제공하지 않는다.

종료코드0=성공,2=인자 오류,3=정책/인증 거부,4=파일·권한·크기·출력 오류,5=기타 실패다. stack trace와 비밀 값은 기본 출력에 넣지 않는다. 파일은 임시 파일 쓰기·force 후 hard link로 새 이름에 게시한다. 게시 후 디렉터리 force가 실패하면 오류 종료여도 완성된 파일이 남을 수 있다. 오류 후 자동 삭제·덮어쓰기·nonce 되감기는 하지 않는다. 전원 차단 내구성은 환경 의존이며 SIGKILL 통과만으로 인증하지 않는다.

검증: `python3 verify.py`, `python3 release.py`. cli-check.py는 난수 키·별도 임시 디렉터리로 실행하며 시험 값은 운영에 쓰지 않는다. 남은 연구 요구사항과 신뢰 가정은 SECURITY_AUDIT_KO.md 및 REQUIREMENTS_TRACE_KO.md를 확인한다.


### 큰 파일의 병렬 처리

`python3 easy.py encrypt-batch --workers 2 FILE1 FILE2`로 작업 수 상한을 지정한다. `--workers 4`도 가능하지만 큰 파일은 메모리 추정 예산에 따라 동시 수를 자동 축소한다. 완료 메시지에 실제 수가 표시된다. 512MiB Java heap에서16MiB 파일은 요청4개여도 실제2개씩 처리한다. 이는 프로세스 메모리의 하드 상한을 보증하지 않는다. 실패 시 전체 롤백/즉시 강제 종료를 보장하지 않으며, 이미 게시된 파일은 오류 안내대로 확인한다.
