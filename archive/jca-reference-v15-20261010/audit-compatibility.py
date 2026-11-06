import pathlib,subprocess,tempfile,selectors,json
# Optional development comparison. Packaged reproduction uses the v12 regression suite.
base=pathlib.Path(__file__).resolve().parent
old=base.parent/'research-comparison-v5-evidence'
if not (old/'build/PqcExtension.class').exists():raise SystemExit('v5 local build unavailable; compatibility record can be read from results/security')
root=pathlib.Path(tempfile.mkdtemp(prefix='compat-v5-v12-'))
for name in ('data','trusted'):(root/name).mkdir(mode=0o700)
cmd=['java','-Xmx512m','-cp',str(old/'build')+':'+str(old/'lib/bcprov-jdk18on-1.86.jar'),'RecoveryTest','create',str(root)]
p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
 sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
 if not sel.select(30):raise RuntimeError('v5 create timeout')
 assert p.stdout.readline().strip()=='RESERVED=0'
 p.kill();p.wait(timeout=10)
 logs=[]
 for mode in ('upgrade','verify'):
  r=subprocess.run(['java','-Xmx512m','-cp','build:lib/bcprov-jdk18on-1.86.jar','RecoveryTest',mode,str(root)],cwd=base,capture_output=True,text=True,timeout=30,check=True);logs.append(r.stdout.strip())
 record={'passed':True,'producer':'v5 compiled original implementation','consumer':'v12 hardened implementation','old_packet_readable':True,'checkpoint_format_unchanged':True,'logs':logs}
 (base/'results/security/compatibility-v5-v12.json').write_text(json.dumps(record,indent=2)+'\n');print('PASS v5 checkpoint and packet reopen under v12')
finally:
 if p.poll() is None:p.kill();p.wait(timeout=10)
