import pathlib,subprocess,tempfile,json,struct,os
base=pathlib.Path(__file__).resolve().parent
checks=0
logs=[]
def check(value):
 global checks
 assert value;checks+=1
def cli(args,success=True):
 r=subprocess.run(['java','-Xmx512m','-cp','build:lib/bcprov-jdk18on-1.86.jar','CryptoCli']+list(map(str,args)),cwd=base,capture_output=True,text=True,timeout=30)
 check((r.returncode==0)==success);check('Exception in thread' not in r.stderr);logs.append({'command':str(args[0]),'exit':r.returncode,'stdout':r.stdout.strip(),'stderr':r.stderr.strip()});return r

def nonce(path):
 data=path.read_bytes();offset=4
 for _ in range(3):length=struct.unpack_from('>I',data,offset)[0];offset+=4+length
 check(struct.unpack_from('>I',data,offset)[0]==12);return struct.unpack_from('>Q',data,offset+8)[0]
with tempfile.TemporaryDirectory(prefix='cli-check-') as tmp:
 root=pathlib.Path(tmp)
 for n in ['data','anchor','files']: (root/n).mkdir(mode=0o700)
 key=root/'files/master.key';common=[key,root/'data',root/'anchor','cli/context'];files=root/'files'
 cli(['help']);cli(['bad-command'],False);cli(['keygen',key]);check(len(key.read_bytes())==32);check(key.stat().st_mode&0o777==0o600)
 saved=key.read_bytes();cli(['keygen',key],False);check(key.read_bytes()==saved)
 cli(['init']+common);cli(['init']+common,False);check('category=3' in cli(['status']+common).stdout)
 for name in ['a','b','empty']:
  (files/name).write_bytes(b'' if name=='empty' else ('message '+name).encode());(files/name).chmod(0o600)
 cli(['seal']+common+[files/'a',files/'a.packet']);cli(['seal']+common+[files/'b',files/'b.packet']);check((nonce(files/'a.packet'),nonce(files/'b.packet'))==(0,128))
 r=cli(['seal-batch']+common+[files/'a',files/'batch-a',files/'b',files/'batch-b']);check('reservation_writes=1' in r.stdout);check((nonce(files/'batch-a'),nonce(files/'batch-b'))==(256,257))
 cli(['open']+common+[1,files/'a.packet',files/'restored']);check((files/'restored').read_bytes()==(files/'a').read_bytes());check((files/'restored').stat().st_mode&0o777==0o600)
 cli(['open']+common+[1,files/'a.packet',files/'restored'],False)
 cli(['seal']+common+[files/'empty',files/'empty.packet']);cli(['open']+common+[1,files/'empty.packet',files/'empty.restored']);check((files/'empty.restored').read_bytes()==b'')
 bad=bytearray((files/'a.packet').read_bytes());bad[-1]^=1;(files/'invalid.packet').write_bytes(bad)
 cli(['open']+common+[1,files/'invalid.packet',files/'should-not-exist'],False);check(not (files/'should-not-exist').exists())
 wrong=common[:-1]+['wrong-context'];cli(['open']+wrong+[1,files/'a.packet',files/'wrong-context-output'],False);check(not (files/'wrong-context-output').exists())
 key.chmod(0o644);cli(['status']+common,False);key.chmod(0o600)
 (files/'key-link').symlink_to(key);cli(['status',files/'key-link']+common[1:],False)
 (files/'output-link').symlink_to(files/'a');before=(files/'a').read_bytes();cli(['seal']+common+[files/'a',files/'output-link'],False);check((files/'a').read_bytes()==before)
 (files/'oversize').touch();(files/'oversize').chmod(0o600)
 with (files/'oversize').open('r+b') as f:f.truncate(16*1024*1024+1)
 cli(['seal']+common+[files/'oversize',files/'large-output'],False);check(not (files/'large-output').exists())
 cli(['seal-batch']+common+[files/'a',files/'duplicate',files/'b',files/'duplicate'],False);check(not (files/'duplicate').exists())
 cli(['upgrade5']+common);check('category=5' in cli(['status']+common).stdout)
 cli(['seal']+common+[files/'b',files/'p5.packet']);cli(['open']+common+[2,files/'p5.packet',files/'p5.restored']);check((files/'p5.restored').read_bytes()==(files/'b').read_bytes())
 cli(['open']+common+[1,files/'a.packet',files/'old.restored']);check((files/'old.restored').read_bytes()==(files/'a').read_bytes())
 mirror=root/'data/engine.bin';mirror.unlink();cli(['status']+common,False);cli(['repair']+common);cli(['status']+common)
 check(not list(files.glob('.pqc-output-*')))
result={'passed':True,'checks':checks,'operations':len(logs),'batch_reservation_writes':1,'batch_sequences':[256,257],'separate_process_sequences':[0,128],'scope':'offline CLI with private POSIX directories and trusted parent paths; no distributed anchor or master-key rotation claim','logs':logs}
(base/'results/security/cli-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS practical CLI security and batch checks='+str(checks))
