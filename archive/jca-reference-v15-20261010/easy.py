#!/usr/bin/env python3
"""Convenience adapter for the existing authenticated offline CLI; never shell-evaluates settings."""
import argparse,json,os,pathlib,stat,struct,subprocess,sys,tempfile,shutil,re,signal,time
PROJECT=pathlib.Path(__file__).resolve().parent
MAX=16*1024*1024
MAGIC=b'PQCEASY1'

def private_dir(path):
 if path.is_symlink() or not path.is_dir() or path.stat().st_mode&0o077:raise ValueError('비공개 디렉터리가 필요합니다.')
 return path.resolve()

def target(path):
 path=path.absolute();private_dir(path.parent)
 if os.path.lexists(path):raise ValueError('기존 파일을 덮어쓰지 않습니다. 다른 출력 이름을 선택하세요.')
 return path

def publish(path,*parts):
 path=target(path);fd,name=tempfile.mkstemp(prefix='.easy-output-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as stream:
   for part in parts:stream.write(part)
   stream.flush();os.fsync(stream.fileno())
  os.link(name,path)
  directory=os.open(path.parent,os.O_RDONLY)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:os.unlink(name)

def publish_packet(path,source,header):
 # Keep the legacy envelope bytes; stream the owned Java packet into a private
 # temporary output, validate the descriptor before publication, then fsync/link.
 if len(header)!=8:raise ValueError('정책 버전 헤더가 올바르지 않습니다.')
 path=target(path)
 if source.is_symlink() or not source.is_file():raise ValueError('일반 패킷 파일이 필요합니다.')
 source_fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(source_fd,'rb',buffering=0) as incoming:
  before=os.fstat(incoming.fileno());limit=MAX+10000
  if not stat.S_ISREG(before.st_mode) or before.st_size>limit:raise ValueError('패킷 파일 및 크기 상한을 확인하세요.')
  buffer=bytearray(min(1024*1024,max(1,before.st_size)))
  fd,name=tempfile.mkstemp(prefix='.easy-output-',dir=path.parent)
  try:
   with os.fdopen(fd,'wb') as outgoing:
    outgoing.write(MAGIC);outgoing.write(header);total=0
    while True:
     count=incoming.readinto(buffer)
     if not count:break
     total+=count
     if total>limit:raise ValueError('패킷 크기 상한을 초과했습니다.')
     outgoing.write(memoryview(buffer)[:count])
    after=os.fstat(incoming.fileno())
    if total!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('복사 중 패킷이 변경되었습니다.')
    outgoing.flush();os.fsync(outgoing.fileno())
   os.link(name,path)
   directory=os.open(path.parent,os.O_RDONLY)
   try:os.fsync(directory)
   finally:os.close(directory)
  finally:os.unlink(name)

def read_file(path,limit,secret=False):
 if path.is_symlink() or not path.is_file():raise ValueError('일반 파일만 읽을 수 있습니다.')
 if secret and path.stat().st_mode&0o077:raise ValueError('설정 파일의 비공개 권한을 확인하세요.')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
  opened=os.fstat(stream.fileno())
  if not stat.S_ISREG(opened.st_mode):raise ValueError('일반 파일만 읽을 수 있습니다.')
  if secret and opened.st_mode&0o077:raise ValueError('설정 파일의 비공개 권한을 확인하세요.')
  if opened.st_size>limit:raise ValueError('파일 크기 상한을 초과했습니다.')
  data=stream.read(opened.st_size+1)
  if len(data)>limit:raise ValueError('파일 크기 상한을 초과했습니다.')
  after=os.fstat(stream.fileno())
  if secret and after.st_mode&0o077:raise ValueError('읽는 중 비공개 권한이 변경되었습니다.')
  before_identity=(opened.st_dev,opened.st_ino,opened.st_mode,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
  after_identity=(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
  if len(data)!=opened.st_size or before_identity!=after_identity:raise ValueError('읽는 중 파일이 변경되었습니다.')
  return data

def stage(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(data)

def stage_input(source,destination):
 # Bounded private copy. The source descriptor is validated before reading;
 # reusable chunks avoid retaining a whole large plaintext in Python.
 if source.is_symlink() or not source.is_file():raise ValueError('일반 파일만 읽을 수 있습니다.')
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 created=False;buffer=bytearray()
 try:
  with os.fdopen(fd,'rb',buffering=0) as incoming:
   before=os.fstat(incoming.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_size>MAX:raise ValueError('일반 파일 및 크기 상한을 확인하세요.')
   buffer=bytearray(min(1024*1024,max(1,before.st_size)))
   output_fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);created=True
   with os.fdopen(output_fd,'wb') as outgoing:
    total=0
    while True:
     count=incoming.readinto(buffer)
     if not count:break
     total+=count
     if total>MAX:raise ValueError('파일 크기 상한을 초과했습니다.')
     outgoing.write(memoryview(buffer)[:count])
    after=os.fstat(incoming.fileno())
    if total!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('복사 중 입력 파일이 변경되었습니다. 다시 시도하세요.')
 except BaseException:
  if created:destination.unlink(missing_ok=True)
  raise
 finally:
  zero=bytes(min(65536,len(buffer)));view=memoryview(buffer)
  for offset in range(0,len(buffer),65536):
   count=min(65536,len(buffer)-offset);view[offset:offset+count]=zero[:count]

def stage_packet(source,destination):
 # Strip only the legacy envelope. Java authenticates the packet before plaintext
 # publication; Python never decrypts or retains the whole ciphertext here.
 if source.is_symlink() or not source.is_file():raise ValueError('일반 파일만 읽을 수 있습니다.')
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);created=False
 try:
  with os.fdopen(fd,'rb',buffering=0) as incoming:
   before=os.fstat(incoming.fileno());limit=MAX+10016
   if not stat.S_ISREG(before.st_mode) or before.st_size>limit:raise ValueError('일반 파일 및 크기 상한을 확인하세요.')
   header=incoming.read(16)
   if len(header)!=16 or header[:8]!=MAGIC:raise ValueError('간편 도구의 .pqc 파일 형식이 아닙니다. 기존 raw packet은 cli.sh open으로 읽으세요.')
   version=struct.unpack_from('>Q',header,8)[0]
   if not 1<=version<=2**63-1:raise ValueError('정책 버전이 올바르지 않습니다.')
   buffer=bytearray(min(1024*1024,max(1,before.st_size-16)))
   output_fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);created=True
   with os.fdopen(output_fd,'wb') as outgoing:
    total=16
    while True:
     count=incoming.readinto(buffer)
     if not count:break
     total+=count
     if total>limit:raise ValueError('패킷 크기 상한을 초과했습니다.')
     outgoing.write(memoryview(buffer)[:count])
    after=os.fstat(incoming.fileno())
    if total!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('복사 중 패킷이 변경되었습니다.')
   return version
 except BaseException:
  if created:destination.unlink(missing_ok=True)
  raise

def stop_core(process):
 # Own a separate process group; wait/reap before staging can be removed.
 # Process termination is not a batch rollback or guaranteed cleanup in the JVM.
 deadline=time.monotonic()+3;forced=False
 def send(kind):
  try:os.killpg(process.pid,kind)
  except ProcessLookupError:pass
 send(signal.SIGTERM)
 while True:
  try:
   if not forced and time.monotonic()>=deadline:send(signal.SIGKILL);forced=True
   process.wait(timeout=0.1)
   # Covers a compiler/descendant left in the group after the leader exited.
   send(signal.SIGKILL)
   return
  except subprocess.TimeoutExpired:continue
  except KeyboardInterrupt:send(signal.SIGKILL);forced=True

def cli(args):
 with subprocess.Popen(['bash',str(PROJECT/'cli.sh')]+list(map(str,args)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True) as process:
  try:stdout,stderr=process.communicate()
  except BaseException:
   stop_core(process)
   raise
  if process.returncode:raise ValueError('처리 실패: '+stderr.strip()+' (키·권한·저장소·출력 경로를 확인하세요.)')
  return stdout.strip()

def load(home):
 home=private_dir(home);config=json.loads(read_file(home/'settings.json',4096,True))
 if not isinstance(config,dict) or set(config)!={'format','key','data','anchor','context'} or type(config['format']) is not int or config['format']!=1:raise ValueError('설정 형식이 올바르지 않습니다.')
 if not all(isinstance(config[k],str) for k in ['key','data','anchor','context']):raise ValueError('설정 값이 올바르지 않습니다.')
 for k in ['key','data','anchor']:
  if not pathlib.Path(config[k]).is_absolute():raise ValueError('설정 경로는 절대 경로여야 합니다.')
 return home,config,[config['key'],config['data'],config['anchor'],config['context']]

def setup(args):
 home=args.home.absolute();anchor=args.anchor.absolute();context=args.context
 if not context or '\0' in context or len(context.encode('utf-8'))>64:raise ValueError('context는 비어 있지 않은 UTF-8 64바이트 이하여야 합니다.')
 home=home.parent.resolve(strict=True)/home.name;anchor=anchor.parent.resolve(strict=True)/anchor.name
 if home==anchor or home in anchor.parents or anchor in home.parents:raise ValueError('앵커는 작업 폴더와 분리된 경로를 지정하세요.')
 for path in [home,anchor]:
  if path.exists():
   private_dir(path)
   if any(path.iterdir()):raise ValueError('새 설정에는 비어 있는 폴더가 필요합니다. 기존 키/앵커를 자동 초기화하지 않습니다.')
  else:path.mkdir(mode=0o700)
 for name in ['state','output']: (home/name).mkdir(mode=0o700)
 key=home/'master.key';config={'format':1,'key':str(key),'data':str(home/'state'),'anchor':str(anchor),'context':context}
 cli(['keygen',key]);cli(['init',key,home/'state',anchor,context]);publish(home/'settings.json',json.dumps(config,ensure_ascii=False).encode())
 print('설정 완료. 이제 encrypt FILE 또는 decrypt FILE을 사용하세요.\n출력 폴더: '+str(home/'output'))

def encrypt_batch(args,home,common):
 workers=getattr(args,'workers',1)
 if workers not in [1,2,4]:raise ValueError('병렬 작업 수는 1, 2, 4 중에서 선택하세요.')
 files=args.files
 if not 1<=len(files)<=64:raise ValueError('배치는 1~64개 파일을 지정하세요.')
 directory=private_dir(args.output_dir if args.output_dir else home/'output')
 outputs=[target(directory/(source.name+'.pqc')) for source in files]
 if len(set(outputs))!=len(outputs):raise ValueError('출력 이름이 겹칩니다. 파일 이름을 다르게 지정하세요.')
 with tempfile.TemporaryDirectory(prefix='.easy-work-',dir=home) as temporary:
  work=pathlib.Path(temporary);pairs=[]
  for i,source in enumerate(files):
   private_input=work/f'input-{i}';stage_input(source,private_input)
   pairs.extend([private_input,work/f'packet-{i}'])
  command=['seal-batch'] if workers==1 else ['seal-batch-parallel',workers]
  message=cli(command+common+pairs);match=re.search(r'policy_version=(\d+)',message)
  if not match:raise ValueError('정책 버전 확인에 실패했습니다.')
  header=struct.pack('>Q',int(match.group(1)))
  for i,output in enumerate(outputs):
   try:
    publish_packet(output,work/f'packet-{i}',header)
   except (ValueError,OSError) as error:
    completed='\n'.join(str(path) for path in outputs[:i]) or '(없음)'
    raise ValueError('배치 저장 중단: '+str(i)+'/'+str(len(outputs))+'개 저장 완료.\n완료 경로:\n'+completed+'\n확인 필요: '+str(output)+' (파일이 남아 있어도 내구성 확인이 필요합니다.)\n원인: '+str(error)) from error
 actual=re.search(r'effective_workers=(\d+)',message)
 print('완료: '+str(len(outputs))+'개 파일 → '+str(directory)+((' · 동시 작업 '+actual.group(1)+'개 (요청 '+str(workers)+'개)') if actual else ''))

def execute(args):
 if args.command=='doctor':
  if os.name!='posix':raise ValueError('POSIX 환경이 필요합니다. Windows에서는 WSL에서 실행하세요.')
  cli(['help']);print('준비 완료: Python, Bash, Java 컴파일 및 의존성 검사 통과');return
 if args.command=='setup':return setup(args)
 home,config,common=load(args.home)
 if args.command=='encrypt-batch':return encrypt_batch(args,home,common)
 if args.command in ['status','upgrade5','repair']:
  print(cli([args.command]+common));return
 output=target(args.output if args.output else home/'output'/(args.file.name+('.pqc' if args.command=='encrypt' else '.restored')))
 with tempfile.TemporaryDirectory(prefix='.easy-work-',dir=home) as work:
  work=pathlib.Path(work)
  if args.command=='encrypt':
   # Copy into a private bounded staging file; do not chmod or rewrite the original.
   private_input=work/'input';stage_input(args.file,private_input)
   packet=work/'packet';message=cli(['seal']+common+[private_input,packet]);match=re.search(r'policy_version=(\d+)',message)
   if not match:raise ValueError('정책 버전 확인에 실패했습니다.')
   version=int(match.group(1));publish_packet(output,packet,struct.pack('>Q',version))
  else:
   packet=work/'packet';version=stage_packet(args.file,packet)
   cli(['open']+common+[version,packet,output])
 print('완료: '+str(output))

def parser():
 p=argparse.ArgumentParser(description='처음 한 번 설정한 뒤 짧은 명령으로 파일 암호화/복호화',epilog='Linux POSIX 환경에서 검증했습니다. Windows에서는 WSL의 Linux 파일시스템을 사용하세요. QUICK_START_KO.md 참고.')
 p.add_argument('--home',type=pathlib.Path,default=pathlib.Path.home()/'.pqc-files',help='설정 폴더 (기본 ~/.pqc-files)')
 sub=p.add_subparsers(dest='command',required=True)
 s=sub.add_parser('setup',help='최초 설정');s.add_argument('--anchor',type=pathlib.Path,required=True);s.add_argument('--context',default='local-files-v1')
 for name in ['encrypt','decrypt']:
  s=sub.add_parser(name);s.add_argument('file',type=pathlib.Path);s.add_argument('--output',type=pathlib.Path)
 s=sub.add_parser('encrypt-batch',help='최대 64개 파일을 한 번에 암호화');s.add_argument('files',type=pathlib.Path,nargs='+');s.add_argument('--output-dir',type=pathlib.Path);s.add_argument('--workers',type=int,choices=[1,2,4],default=1,help='동시 파일 작업 수 상한 (기본 1; 큰 파일은 자동 축소)')
 for name in ['status','upgrade5','repair','doctor']:sub.add_parser(name)
 return p

if __name__=='__main__':
 if len(sys.argv)==1 or sys.argv[1]=='help':parser().print_help();sys.exit(0)
 try:execute(parser().parse_args())
 except KeyboardInterrupt:print('중단: Java 프로세스 종료를 확인한 뒤 임시 입력을 정리했습니다. 이미 게시된 출력은 남을 수 있습니다.',file=sys.stderr);sys.exit(130)
 except (ValueError,OSError,subprocess.SubprocessError,UnicodeError) as error:print('오류: '+str(error),file=sys.stderr);sys.exit(2)
