"""Actual maximum-size plaintext encrypt/decrypt for both approved profiles."""
import hashlib,json,pathlib,subprocess,tempfile
b=pathlib.Path(__file__).resolve().parent;checks=0
def check(value):
 global checks
 assert value;checks+=1
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  while chunk:=f.read(65536):h.update(chunk)
 return h.hexdigest()
def run(home,*args):
 r=subprocess.run(['python3','easy.py','--home',str(home),*map(str,args)],cwd=b,capture_output=True,text=True,timeout=120);check(r.returncode==0);return r
with tempfile.TemporaryDirectory(prefix='stream-roundtrip-') as temp:
 root=pathlib.Path(temp);home=root/'home';run(home,'setup','--anchor',root/'anchor')
 source=root/'maximum.bin'
 with source.open('wb') as f:
  for _ in range(256):f.write(bytes(range(256))*256)
 source.chmod(0o644);original=digest(source)
 for profile in [3,5]:
  packet=root/f'p{profile}.pqc';restored=root/f'p{profile}.restored'
  run(home,'encrypt',source,'--output',packet);run(home,'decrypt',packet,'--output',restored)
  check(digest(restored)==original);check(packet.stat().st_mode&0o777==0o600);check(restored.stat().st_size==16*1024*1024)
  if profile==3:run(home,'upgrade5')
 check(source.stat().st_mode&0o777==0o644);check(not list(home.glob('.easy-work-*')))
(b/'results/security/packet-stream-roundtrips.json').write_text(json.dumps(dict(passed=True,checks=checks,profiles=[3,5],plaintext_bytes=16*1024*1024,scope='actual CLI maximum-size encrypted envelopes and authenticated decrypts match original hash; original permissions, output privacy and staging cleanup; not throughput/RSS measurement'),indent=2)+'\n');print('PASS max packet roundtrip checks='+str(checks))
