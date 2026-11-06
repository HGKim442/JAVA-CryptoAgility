"""Real P3/P5 decrypts, fail-closed tamper checks, isolated Python RSS samples."""
import hashlib,importlib.machinery,importlib.util,json,pathlib,resource,subprocess,sys,tempfile,time
b=pathlib.Path(__file__).resolve().parent
if len(sys.argv)>1 and sys.argv[1]=='--worker':
 variant,home,source,dest=sys.argv[2:]
 path=b/'easy.py' if variant=='streamed_envelope' else b/'history-decrypt-memory-20261009/easy.py.previous'
 loader=importlib.machinery.SourceFileLoader('measured_adapter',str(path));spec=importlib.util.spec_from_loader('measured_adapter',loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m);m.PROJECT=b
 started=time.perf_counter();m.execute(m.parser().parse_args(['--home',home,'decrypt',source,'--output',dest]))
 print(json.dumps(dict(python_peak_rss_kib=int(next(line.split()[1] for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('VmHWM:'))),child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,wall_seconds=time.perf_counter()-started)));raise SystemExit(0)
checks=0;rows=[]
def check(value,message):
 global checks
 if not value:raise AssertionError(message)
 checks+=1
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  while chunk:=f.read(65536):h.update(chunk)
 return h.hexdigest()
def run(home,*args):
 r=subprocess.run(['python3','easy.py','--home',str(home),*map(str,args)],cwd=b,capture_output=True,text=True,timeout=120);check(r.returncode==0,r.stderr);return r
with tempfile.TemporaryDirectory(prefix='decrypt-auth-') as temp:
 root=pathlib.Path(temp);root.chmod(0o700);home=root/'home';run(home,'setup','--anchor',root/'anchor')
 source=root/'maximum.bin'
 with source.open('wb') as f:
  for _ in range(256):f.write(bytes(range(256))*256)
 source.chmod(0o644);expected=digest(source)
 for profile in [3,5]:
  packet=root/f'p{profile}.pqc';run(home,'encrypt',source,'--output',packet)
  for variant in ['whole_envelope','streamed_envelope']:
   for sample in range(3):
    dest=root/f'{variant}-{profile}-{sample}'
    r=subprocess.run(['python3',str(b/'decrypt-auth-check.py'),'--worker',variant,str(home),str(packet),str(dest)],cwd=b,capture_output=True,text=True,timeout=120)
    check(r.returncode==0,r.stderr);metrics=json.loads(r.stdout.splitlines()[-1]);check(digest(dest)==expected,'Actual decrypt bytes');check(dest.stat().st_mode&0o777==0o600,'Plaintext output privacy');dest.unlink()
    rows.append(dict(profile=profile,variant=variant,sample=sample,plaintext_bytes=16*1024*1024,**metrics))
  wire=packet.read_bytes()
  cases={'magic':b'X'+wire[1:],'version':wire[:8]+bytes(8)+wire[16:],'ciphertext':wire[:-1]+bytes([wire[-1]^1]),'truncated':wire[:-1],'trailing':wire+b'X'}
  for name,altered in cases.items():
   damaged=root/f'damaged-{profile}-{name}';damaged.write_bytes(altered);dest=root/f'forbidden-{profile}-{name}'
   r=subprocess.run(['python3','easy.py','--home',str(home),'decrypt',str(damaged),'--output',str(dest)],cwd=b,capture_output=True,text=True,timeout=120)
   check(r.returncode!=0,'Tampered envelope accepted');check(not dest.exists(),'Unauthenticated plaintext output');check(not list(home.glob('.easy-work-*')),'Tamper staging cleanup');damaged.unlink()
  if profile==3:run(home,'upgrade5')
 check(source.stat().st_mode&0o777==0o644,'Original permissions');check(not list(home.glob('.easy-work-*')),'Staging cleanup')
(b/'results/security').mkdir(parents=True,exist_ok=True)
(b/'results/security/decrypt-auth-checks.json').write_text(json.dumps(dict(passed=True,checks=checks,profiles=[3,5],samples=rows,rss_method='Linux /proc/self/status VmHWM after exec',current_sha256=hashlib.sha256((b/'easy.py').read_bytes()).hexdigest(),previous_sha256=hashlib.sha256((b/'history-decrypt-memory-20261009/easy.py.previous').read_bytes()).hexdigest(),scope='Real16MiB authenticated CLI decrypt, 3 independent Python workers per profile/variant. Linux /proc/self/status VmHWM reports own Python post-exec address-space maximum inKiB; excludes inherited pre-exec parent high water; child maximum separately includes shell/JVM and is not simultaneous process-tree RSS. Setup/encryption/result verification outside worker. Wall interval includes core invocation; fixed baseline-then-current order is descriptive, not a randomized paper throughput benchmark. Altered magic/version/signature,truncation,trailing data publish no plaintext. No enterprise/absolute memory cap claim.'),indent=2)+'\n');print('PASS decrypt auth checks='+str(checks))
