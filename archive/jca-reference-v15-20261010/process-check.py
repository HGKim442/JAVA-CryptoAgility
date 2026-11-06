import pathlib,tempfile,subprocess,json,signal,select,os,concurrent.futures
b=pathlib.Path(__file__).resolve().parent;cp=str(b/'build')+':'+str(b/'lib/bcprov-jdk18on-1.86.jar');argv=['java','-XX:-UsePerfData','-cp',cp,'PartBenchmark'];record={}
with tempfile.TemporaryDirectory(prefix='nonce-process-') as t:
 root=pathlib.Path(t);crash=root/'crash';crash.mkdir(mode=0o700)
 p=subprocess.Popen(argv+['crash',str(crash)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  ready,_,_=select.select([p.stdout],[],[],15);assert ready
  marker=p.stdout.readline().strip();assert marker=='RESERVED=0'
  p.kill();p.wait(timeout=10);assert p.returncode==-signal.SIGKILL
 finally:
  if p.poll() is None:p.kill();p.wait()
 r=subprocess.run(argv+['worker',str(crash),'4'],capture_output=True,text=True,check=True);values=list(map(int,r.stdout.strip().split(',')));assert values==[128,129,130,131]
 record['post_reservation_sigkill']={'marker':marker,'killed_exit_code':p.returncode,'restart_values':values,'scope':'process death after successful reservation, not physical power failure'}
 shared=root/'shared';shared.mkdir(mode=0o700)
 def worker(_):
  r=subprocess.run(argv+['worker',str(shared),'20'],capture_output=True,text=True,check=True);return list(map(int,r.stdout.strip().split(',')))
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:groups=list(workers.map(worker,range(4)))
 flat=sum(groups,[]);assert len(flat)==80 and len(set(flat))==80
 record['cross_process_reservations']={'processes':4,'values':groups,'unique':80}
out=b/'results/integrated/process-check.json'
with out.open('w') as f:json.dump(record,f,indent=2);f.flush();os.fsync(f.fileno())
print('PASS SIGKILL restart skips unused reserved values; 4 processes produced 80 unique values')
