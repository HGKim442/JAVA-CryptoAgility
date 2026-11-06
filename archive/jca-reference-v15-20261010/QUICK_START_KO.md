# 처음 한 번 설정하고, 파일 이름만 입력하기

Linux POSIX 환경에서 검증한 파일 도구다. Python3·Java17·Bash가 필요하다. Windows에서는 WSL 안의 Linux 폴더(예: `/home/사용자/...`)에 압축을 풀어 실행한다. Windows 네이티브와 `/mnt/c`의 권한 동작은 검증하지 않았다. 자동 설치·관리자 권한·네트워크 연결은 요구하지 않는다.

압축을 푼 프로젝트 폴더에서 다음을 실행한다.

```sh
python3 easy.py doctor
python3 easy.py setup --anchor ~/pqc-anchor
```

설정은 기본 `~/.pqc-files`에 저장된다. 이제 키 경로·상태 폴더·앵커·context·버전을 매번 입력하지 않는다.

```sh
python3 easy.py encrypt "보고서.pdf"
python3 easy.py decrypt ~/.pqc-files/output/보고서.pdf.pqc
```

암호화 결과는 `~/.pqc-files/output/보고서.pdf.pqc`, 복호화 결과는 같은 폴더의 `보고서.pdf.pqc.restored`에 저장된다. 완료 메시지가 정확한 경로를 보여 준다. 원본은 변경하지 않고 기존 결과를 덮어쓰지 않는다. 파일 이름에 공백이 있으면 따옴표로 감싼다. `.restored` 파일 이름은 원하는 이름으로 직접 바꿀 수 있다.

다른 설정 폴더나 결과 이름을 원하면 다음처럼 지정한다.

```sh
python3 easy.py --home ~/pqc-work setup --anchor ~/protected-anchor --context 'my-project'
python3 easy.py --home ~/pqc-work encrypt "보고서.pdf" --output ~/pqc-work/output/custom.pqc
python3 easy.py --home ~/pqc-work decrypt ~/pqc-work/output/custom.pqc --output ~/pqc-work/output/custom.pdf
```

context는 같은 설정의 파일 분류 이름이다. 비밀번호나 키 값은 넣지 않는다. `--output`의 부모 폴더는 비공개여야 한다. 처음 setup에는 비어 있는 새 폴더를 사용한다. 기존 키·앵커·설정은 자동 재초기화하지 않는다.

프로필 전환도 짧게 실행한다.

```sh
python3 easy.py status
python3 easy.py upgrade5
```

전환 전후의 파일 모두 decrypt가 자동으로 맞는 정책 버전을 선택한다. 간편 파일에는 버전 안내와 기존 인증 packet을 함께 저장한다. 버전 안내 자체는 독립 인증값이 아니며, 선택한 키/정책과 실제 packet 인증이 맞아야만 평문이 나온다. 안내를 바꾸면 테스트에서 복호화가 거부됐다. 기존 CLI의 raw packet은 간편 파일과 다르므로 기존 `cli.sh open`을 사용한다.

원본을 읽어 비공개 임시 작업 폴더에 복사한 뒤 처리한다. 정상 종료/오류 시 임시 폴더는 정리하지만 SIGKILL·전원 차단 이후 임시 파일 삭제나 디스크의 안전한 소거를 보장하지 않는다. 원본 파일의 접근 권한·백업을 자동으로 보호하지 않는다. 평문 입력 상한은16MiB다. 반복 파일 처리에는 기존 `cli.sh seal-batch`가 있다.

master.key와 현재 신뢰 앵커는 보존해야 한다. 같은 컴퓨터의 다른 폴더라는 이유만으로 앵커가 독립 신뢰 저장소가 되는 것은 아니다. 이 예제 경로는 로컬 기능 적용용이며 운영에서는 앵커의 현재성을 별도로 보호하고 키/앵커를 함께 롤백·복제하지 않는다. 별도 키 관리 서비스·회전·anti-replay는 제공하지 않는다. `repair`는 현재 신뢰 앵커를 운영자가 확인한 뒤에만 명시적으로 실행한다. 초기 설정 중 실패한 폴더도 자동 삭제·초기화하지 않는다.

문제가 있으면 `doctor`, 일반 사용은 `easy.py help`, 세부 명령은 `easy.py encrypt --help`로 확인한다. 자세한 기존 CLI 및 실패/복구 동작은 USAGE_KO.md에 있다. 프로그램 파일·설정 폴더·부모 경로는 신뢰하는 동일 사용자 환경이어야 한다.


## 여러 파일을 한 번에 암호화 (v15)

```bash
python3 easy.py encrypt-batch "문서 1.txt" "문서 2.txt"
python3 easy.py encrypt-batch a.txt b.txt --output-dir /절대경로/비공개출력폴더
```

파일별16MiB 이하, 최대64개, 같은 출력 파일 이름은 거부한다. 기존 encrypt/decrypt 명령도 유지한다. 출력 폴더는 미리 만들고0700 권한을 설정한다. 전체 배치는 원자적 트랜잭션이 아니며 게시 도중 오류가 나면 먼저 완료된 출력은 남는다. 디스크 여유를 확인한다.


배치 저장 중 오류가 발생하면 메시지의 완료 경로와 확인 필요 경로를 확인하세요. 완료된 파일은 남습니다. 확인 필요 파일은 존재하더라도 저장 내구성이 확정되지 않았으며 자동으로 덮어쓰거나 삭제하지 않습니다. 남은 입력만 새 출력 위치에 다시 처리하세요. 전체 배치 원자성을 보장하지 않습니다.


## 병렬 배치 암호화

```bash
python3 easy.py encrypt-batch --workers 2 "문서 1.txt" "문서 2.txt"
python3 easy.py encrypt-batch --workers 4 --output-dir /비공개/출력폴더 FILE1 FILE2 FILE3 FILE4
```

기본값은 순차 작업1개입니다. 선택지는1/2/4이며 파일 수는 최대64개, 파일당16MiB입니다. 작은 파일에서는 작업 수를 늘려도 더 빨라지지 않을 수 있습니다. 큰 파일은 먼저2개로 실행해 보고, 메모리 여유가 있을 때4개를 비교하세요. 복호화에는 이 옵션을 적용하지 않습니다. 중단이나 실패 시 진행 중 작업의 종료를 기다리므로 즉시 끝나지 않을 수 있습니다. 배치 전체의 원자성을 보장하지 않습니다.


### 큰 파일의 병렬 처리

`python3 easy.py encrypt-batch --workers 2 FILE1 FILE2`로 작업 수 상한을 지정한다. `--workers 4`도 가능하지만 큰 파일은 메모리 추정 예산에 따라 동시 수를 자동 축소한다. 완료 메시지에 실제 수가 표시된다. 512MiB Java heap에서16MiB 파일은 요청4개여도 실제2개씩 처리한다. 이는 프로세스 메모리의 하드 상한을 보증하지 않는다. 실패 시 전체 롤백/즉시 강제 종료를 보장하지 않으며, 이미 게시된 파일은 오류 안내대로 확인한다.
