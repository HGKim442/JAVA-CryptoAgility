import pathlib,subprocess,tempfile,json,struct,os
base=pathlib.Path(__file__).resolve().parent;checks=0

def check(value):
 global checks
 assert value;checks+=1

def run(home,args,success=True):
 r=subprocess.run(['python3',str(base/'easy.py'),'--home',str(home)]+list(map(str,args)),capture_output=True,text=True,timeout=60);check((r.returncode==0)==success);return r
with tempfile.TemporaryDirectory(prefix='easy-check-') as tmp:
 root=pathlib.Path(tmp);home=root/'work';anchor=root/'anchor';source=root/'원본 문서.txt';source.write_bytes(b'normal input content');source.chmod(0o644)
 run(home,['doctor']);run(home,['setup','--anchor',anchor]);check((home/'settings.json').stat().st_mode&0o777==0o600);check((home/'master.key').stat().st_mode&0o777==0o600)
 saved=(home/'master.key').read_bytes();run(home,['setup','--anchor',anchor],False);check((home/'master.key').read_bytes()==saved)
 before=source.read_bytes();run(home,['encrypt',source]);packet=home/'output'/(source.name+'.pqc');check(packet.exists());check(source.read_bytes()==before);check(source.stat().st_mode&0o777==0o644);check(packet.stat().st_mode&0o777==0o600)
 run(home,['decrypt',packet]);restored=home/'output'/(packet.name+'.restored');check(restored.read_bytes()==before);check(restored.stat().st_mode&0o777==0o600)
 run(home,['decrypt',packet],False);check(restored.read_bytes()==before)
 run(home,['upgrade5']);p5=root/'p5.txt';p5.write_bytes(b'new profile');run(home,['encrypt',p5]);p5packet=home/'output'/'p5.txt.pqc';run(home,['decrypt',p5packet]);check((home/'output'/'p5.txt.pqc.restored').read_bytes()==b'new profile')
 run(home,['decrypt',packet,'--output',home/'output'/'old-again']);check((home/'output'/'old-again').read_bytes()==before)
 altered=bytearray(packet.read_bytes());struct.pack_into('>Q',altered,8,2);wrong=home/'output'/'wrong-version.pqc';wrong.write_bytes(altered);wrong.chmod(0o600);run(home,['decrypt',wrong],False);check(not (home/'output'/'wrong-version.pqc.restored').exists())
 changed=bytearray(packet.read_bytes());changed[-1]^=1;bad=home/'output'/'bad.pqc';bad.write_bytes(changed);bad.chmod(0o600);run(home,['decrypt',bad],False);check(not (home/'output'/'bad.pqc.restored').exists())
 link=root/'link.txt';link.symlink_to(source);run(home,['encrypt',link],False)
 config=home/'settings.json';config.chmod(0o644);run(home,['status'],False);config.chmod(0o600)
 nested=root/'nested';run(nested,['setup','--anchor',nested/'inside'],False)
 check(not list(home.glob('.easy-work-*')));check(not list((home/'output').glob('.easy-output-*')))
result={'passed':True,'checks':checks,'auto_policy_version':True,'original_unchanged':True,'unicode_space_names':True,'private_settings_and_output':True,'wrong_version_and_auth_failure_no_output':True,'scope':'convenience envelope routing tested against actual core authentication; no cryptographic authentication claimed for routing header alone'}
(base/'results/security/easy-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS easy usability and security checks='+str(checks))
