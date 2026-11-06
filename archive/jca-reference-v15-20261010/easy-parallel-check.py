"""Real authenticated parallel CLI batches, with expected preflight refusals."""
import json,pathlib,subprocess,tempfile
b=pathlib.Path(__file__).resolve().parent;checks=0
def check(value):
 global checks
 assert value;checks+=1
def run(home,*args,ok=True):
 r=subprocess.run(['python3',str(b/'easy.py'),'--home',str(home),*map(str,args)],capture_output=True,text=True,timeout=120);check((r.returncode==0)==ok);return r
with tempfile.TemporaryDirectory(prefix='easy-parallel-') as temp:
 root=pathlib.Path(temp);home=root/'home';run(home,'setup','--anchor',root/'anchor');sources=[]
 for i in range(4):
  p=root/f'문서 {i}.txt';p.write_bytes(bytes([i])*4096);p.chmod(0o644);sources.append(p)
 for profile in [3,5]:
  for workers in [2,4]:
   directory=root/f'p{profile}-w{workers}';directory.mkdir(mode=0o700)
   run(home,'encrypt-batch',*sources,'--workers',workers,'--output-dir',directory)
   for i,p in enumerate(sources):
    packet=directory/(p.name+'.pqc');check(packet.stat().st_mode&0o777==0o600);check(p.stat().st_mode&0o777==0o644)
    restored=directory/f'restored-{i}';run(home,'decrypt',packet,'--output',restored);check(restored.read_bytes()==p.read_bytes())
   run(home,'encrypt-batch',*sources,'--workers',workers,'--output-dir',directory,ok=False)
  if profile==3:run(home,'upgrade5')
 for workers in [0,3,5]:run(home,'encrypt-batch',*sources,'--workers',workers,ok=False)
 check(not list(home.glob('.easy-work-*')))
(b/'results/security/easy-parallel-checks.json').write_text(json.dumps(dict(passed=True,checks=checks,profiles=[3,5],workers=[2,4],scope='actual private-staged parallel batches, authenticated decryptions, permissions, existing output and invalid worker refusal, staging cleanup'),indent=2)+'\n')
print('PASS easy parallel checks='+str(checks))
