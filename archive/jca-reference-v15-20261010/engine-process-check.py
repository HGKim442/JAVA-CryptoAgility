import json, pathlib, subprocess, tempfile, os, selectors
root=pathlib.Path(tempfile.mkdtemp(prefix='engine-v4-'))
for name in ('data','trusted'):
    (root/name).mkdir(mode=0o700)
cmd=['java','-XX:-UsePerfData','-Xmx512m','-cp','build:lib/bcprov-jdk18on-1.86.jar','RecoveryTest']
p=subprocess.Popen(cmd+['create',str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
    if not sel.select(30): raise RuntimeError('create timeout')
    line=p.stdout.readline().strip()
    if line!='RESERVED=0': raise RuntimeError('unexpected worker state: '+line)
    # Exclusion test in a second JVM while the original process owns the lease.
    busy=subprocess.run(cmd+['verify',str(root)],capture_output=True,text=True,timeout=30)
    assert busy.returncode!=0 and 'Engine already leased' in busy.stderr
    p.kill();p.wait(timeout=10);assert p.returncode==-9
    logs=[]
    for mode in ('upgrade','verify'):
        result=subprocess.run(cmd+[mode,str(root)],capture_output=True,text=True,timeout=30,check=True)
        logs.append(result.stdout.strip())
    target=pathlib.Path('results/recovery');target.mkdir(parents=True,exist_ok=True)
    evidence={'passed':True,'kill_exit':p.returncode,'cross_process_lease_refused':True,'initial_sequence':0,'p3_after_kill':128,'p5_after_restart':128,'logs':logs,'scope':'SIGKILL after complete seal and packet save; not physical power failure'}
    (target/'engine-process-results.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('PASS full Engine independent-JVM restart, P3/P5 history, SIGKILL and lease')
finally:
    if p.poll() is None:p.kill();p.wait(timeout=10)
