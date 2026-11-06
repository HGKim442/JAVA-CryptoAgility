"""Optional development check requiring the original local v7 build; no downloads."""
import pathlib,subprocess,tempfile,selectors,json,shutil
base=pathlib.Path(__file__).resolve().parent
old=base.parent/'research-comparison-v7-lifecycle'
if not (old/'build/PqcExtension.class').exists():raise SystemExit('Original v7 local build unavailable')
root=pathlib.Path(tempfile.mkdtemp(prefix='codec-cross-v7-v12-'))
for name in ('data','trusted'):(root/name).mkdir(mode=0o700)
old_cp=str(old/'build')+':'+str(old/'lib/bcprov-jdk18on-1.86.jar')
p=subprocess.Popen(['java','-Xmx512m','-cp',old_cp,'RecoveryTest','create',str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
 with selectors.DefaultSelector() as sel:
  sel.register(p.stdout,selectors.EVENT_READ)
  if not sel.select(30):raise RuntimeError('v7 create timeout')
  assert p.stdout.readline().strip()=='RESERVED=0'
 p.kill();p.wait(timeout=10)
 current=subprocess.run(['java','-Xmx512m','-cp','build:lib/bcprov-jdk18on-1.86.jar','RecoveryTest','upgrade',str(root)],cwd=base,capture_output=True,text=True,timeout=30,check=True)
 previous=subprocess.run(['java','-Xmx512m','-cp',old_cp,'RecoveryTest','verify',str(root)],capture_output=True,text=True,timeout=30,check=True)
 record={'passed':True,'v7_packet_read_by_v12':True,'v12_packet_read_by_v7':True,'v12_checkpoint_read_by_v7':True,'normal_p3_p5_data':True,'logs':[current.stdout.strip(),previous.stdout.strip()],'scope':'original compiled v7 and current v12 normal packet/checkpoint interoperability; no claim of unsafe rollback deployment'}
 (base/'results/security/codec-cross-v7-v12.json').write_text(json.dumps(record,indent=2)+'\n');print('PASS original v7/current v12 bidirectional packet and checkpoint compatibility')
finally:
 if p.poll() is None:p.kill();p.wait(timeout=10)
 for stream in (p.stdin,p.stdout,p.stderr):
  if stream is not None:stream.close()
 shutil.rmtree(root)
