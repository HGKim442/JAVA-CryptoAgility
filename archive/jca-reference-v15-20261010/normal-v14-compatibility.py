"""Bidirectional normal file/anchor compatibility, using bundled original v14 sources."""
import hashlib,json,pathlib,shutil,subprocess,tempfile
BASE=pathlib.Path(__file__).resolve().parent
def run(cp,*args):
 result=subprocess.run(['java','-XX:-UsePerfData','-Xmx512m','-cp',cp,'CryptoCli',*map(str,args)],capture_output=True,text=True,timeout=60)
 if result.returncode:raise RuntimeError('Normal compatibility operation failed: '+result.stderr)
 return result.stdout.strip()
with tempfile.TemporaryDirectory(prefix='normal-v14-v15-') as tmp:
 root=pathlib.Path(tmp);old=root/'v14';old.mkdir();(old/'build').mkdir()
 sources=[]
 for ref in sorted((BASE/'history-v14').glob('*.java.reference')):
  p=old/ref.name.removesuffix('.reference');shutil.copyfile(ref,p);sources.append(str(p))
 jar=str(BASE/'lib/bcprov-jdk18on-1.86.jar')
 subprocess.run(['java','-m','jdk.compiler/com.sun.tools.javac.Main','--release','17','-Xlint:all','-Werror','-cp',jar,'-d',str(old/'build'),*sources],check=True,timeout=120)
 oldcp=str(old/'build')+':'+jar;newcp=str(BASE/'build')+':'+jar
 data=root/'data';anchor=root/'anchor';data.mkdir(mode=0o700);anchor.mkdir(mode=0o700)
 key=root/'master.key';source=root/'plain';source.write_bytes(bytes(range(256))*32);source.chmod(0o600);common=[key,data,anchor,'compat-v14-v15']
 run(oldcp,'keygen',key);run(oldcp,'init',*common)
 logs=[];old_packets=[]
 for version in [1,2]:
  if version==2:run(oldcp,'upgrade5',*common)
  packet=root/f'legacy-{version}.raw';logs.append(run(oldcp,'seal',*common,source,packet));old_packets.append((packet,version))
 # New reader accepts genuine old checkpoints and both prior PQC profiles.
 for packet,version in old_packets:
  output=root/f'legacy-{version}.out';run(newcp,'open',*common,version,packet,output);assert output.read_bytes()==source.read_bytes()
 # Rewrite the same synthetic checkpoint in the new writer: encrypted checkpoint format is now v5 (one-way migration).
 subprocess.run(['java','-Xmx512m','-cp',newcp,'CheckpointMigrationTest',*map(str,common[:3])],check=True,timeout=60)
 for packet,version in old_packets:
  output=root/f'migrated-{version}.out';run(newcp,'open',*common,version,packet,output);assert output.read_bytes()==source.read_bytes()
 packet=root/'current.raw';output=root/'current.out';logs.append(run(newcp,'seal',*common,source,packet));run(newcp,'open',*common,2,packet,output);assert output.read_bytes()==source.read_bytes()
 old_reopen=subprocess.run(['java','-Xmx512m','-cp',oldcp,'CryptoCli','status',*map(str,common)],capture_output=True,text=True,timeout=60)
 assert old_reopen.returncode!=0,'Old reader unexpectedly accepted the new checkpoint'
 result={'passed':True,'normal_roundtrips':5,'profiles':[3,5],'legacy_read_and_one_way_checkpoint_migration':True,'old_reader_rejects_new_checkpoint':True,'baseline_sources_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((BASE/'history-v14').glob('*.java.reference'))},'logs':logs,'scope':'synthetic normal data from actual compiled v14 and v15; no rollback attack or deployment certification'}
 (BASE/'results/security/compatibility-v14-v15.json').write_text(json.dumps(result,indent=2)+'\n')
 print('PASS original v14/v15 legacy read and one-way checkpoint migration roundtrips=5')
