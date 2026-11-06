"""Normal batch roundtrip and preflight refusal fixtures; no third-party targets."""
import argparse,importlib.util,json,pathlib,subprocess,tempfile
BASE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('easy_v15',BASE/'easy.py');tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
checks=0
def check(value):
 global checks
 if not value:raise AssertionError('Batch regression')
 checks+=1
def run(home,*args):
 r=subprocess.run(['python3',str(BASE/'easy.py'),'--home',str(home),*map(str,args)],capture_output=True,text=True,timeout=90);check(r.returncode==0);return r
def refused(action):
 try:action()
 except (ValueError,OSError):check(True)
 else:raise AssertionError('Expected refusal')
with tempfile.TemporaryDirectory(prefix='easy-batch-') as temporary:
 root=pathlib.Path(temporary);home=root/'home';anchor=root/'anchor';run(home,'setup','--anchor',anchor)
 sources=[]
 for i in range(4):
  p=root/f'문서 {i}.txt';p.write_bytes(bytes([i])*4096);p.chmod(0o644);sources.append(p)
 _,_,common=tool.load(home);count=[];real=tool.cli
 def counted(args):count.append(args[0]);return real(args)
 tool.cli=counted
 for profile in [3,5]:
  directory=root/f'out{profile}';directory.mkdir(mode=0o700);count.clear()
  tool.encrypt_batch(argparse.Namespace(files=sources,output_dir=directory),home,common);check(count==['seal-batch'])
  for p in sources:
   packet=directory/(p.name+'.pqc');check(packet.stat().st_mode&0o777==0o600);check(packet.read_bytes()[:8]==tool.MAGIC);check(p.stat().st_mode&0o777==0o644)
   output=home/'output'/f'{profile}-{p.name}.restored';run(home,'decrypt',packet,'--output',output);check(output.read_bytes()==p.read_bytes())
  refused(lambda:tool.encrypt_batch(argparse.Namespace(files=sources,output_dir=directory),home,common))
  if profile==3:run(home,'upgrade5')
 # Refusals occur before launching the core; no complete-output claim on late publication errors.
 directory=root/'preflight';directory.mkdir(mode=0o700)
 for files in [[],sources*17,[sources[0],sources[0]],[sources[0],root/'missing']]:
  count.clear();refused(lambda files=files:tool.encrypt_batch(argparse.Namespace(files=files,output_dir=directory),home,common));check(not count);check(not list(directory.iterdir()))
 # Benign fault injection: fail before publication, then after a completed link/write.
 # Earlier completed files remain usable; the uncertain file is identified without
 # claiming rollback or durability after a publication error.
 real_publish=tool.publish_packet
 for after_publish in [False,True]:
  directory=root/('late-after' if after_publish else 'late-before');directory.mkdir(mode=0o700);calls=[]
  def failing_publish(path,*parts):
   calls.append(path)
   if len(calls)==2:
    if after_publish:real_publish(path,*parts)
    raise OSError('synthetic publication failure')
   real_publish(path,*parts)
  tool.publish_packet=failing_publish
  try:
   try:tool.encrypt_batch(argparse.Namespace(files=sources,output_dir=directory),home,common)
   except ValueError as error:
    message=str(error);check('1/4' in message);check(str(directory/(sources[0].name+'.pqc')) in message);check(str(directory/(sources[1].name+'.pqc')) in message)
   else:raise AssertionError('Expected late publication failure')
  finally:tool.publish_packet=real_publish
  check(len(calls)==2);check((directory/(sources[1].name+'.pqc')).exists()==after_publish);check(not (directory/(sources[2].name+'.pqc')).exists());check(not list(home.glob('.easy-work-*')))
  output=home/'output'/('late-'+str(after_publish)+'.restored');run(home,'decrypt',directory/(sources[0].name+'.pqc'),'--output',output);check(output.read_bytes()==sources[0].read_bytes())
 check(not list(home.glob('.easy-work-*')))
result={'passed':True,'checks':checks,'profiles':[3,5],'files_per_batch':4,'core_calls_per_batch':1,'scope':'normal real core roundtrip, preflight failures and synthetic late publication failures before/after publication; earlier outputs remain usable, uncertain path reported; bounded one-file-at-a-time staging'}
(BASE/'results/security/easy-batch-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS easy batch checks='+str(checks))
