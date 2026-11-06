import argparse,subprocess,pathlib,json,time,hashlib,platform,importlib.util
b=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('paper_tool',b/'paper.py')
paper=importlib.util.module_from_spec(spec);spec.loader.exec_module(paper)
def require_resume(prior,before):
    if prior.get('exit_code')!=1 or prior.get('inputs_changed_during_run') is not False:raise ValueError('No stable failed measurement checkpoint')
    if not prior.get('stdout','').rstrip().endswith('PASS easy parallel checks=78'):raise ValueError('Functional prefix incomplete; use full verification')
    if "assert not list(folder.glob('.parallel-work-*'))" not in prior.get('stderr',''):raise ValueError('Unsupported failure checkpoint; use full verification')
    previous=prior['input_sha256'];changed={name for name in set(previous)|set(before) if previous.get(name)!=before.get(name)}
    if not changed<= {'verify.py','parallel-measure.py'}:raise ValueError('Prefix inputs changed; use full verification: '+str(sorted(changed)))
    if prior['source_sha256']!={p.name:before[p.name] for p in sorted(b.glob('*.java'))}:raise ValueError('Java sources changed; full verification required')
    return sorted(changed)
def prefix_hashes():
    folders=['integrated','request','parts','classical','pqc','recovery','persistent','evidence','security','codec','anchor','optimization','reuse','file-output']
    return {str(p.relative_to(b)):hashlib.sha256(p.read_bytes()).hexdigest() for folder in folders for p in sorted((b/'results'/folder).rglob('*')) if p.is_file() and p.name!='paper-validation-checks.json'}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resume',action='store_true',help='Only resume a known collection-tool failure with unchanged production/test inputs');args=parser.parse_args()
    before=paper.source_hashes();start=time.time();stdout=[];stderr=[];resume=None;prefix=None;exit_code=0
    if args.resume:
        prior=json.loads((b/'run.json').read_text());allowed_changes=require_resume(prior,before);prefix=prefix_hashes()
        checkpoint=b/'history-v15-parallel/verification-attempt-3/run.json'
        if json.loads(checkpoint.read_text())!=prior:raise ValueError('Retained checkpoint differs from failed run')
        resume={'checkpoint':str(checkpoint.relative_to(b)),'checkpoint_sha256':hashlib.sha256(checkpoint.read_bytes()).hexdigest(),'completed_prefix_input_sha256':prior['input_sha256'],'changed_orchestration_inputs':allowed_changes,'completed_prefix_evidence_sha256':prefix,'prefix_elapsed_seconds':prior['elapsed_seconds'],'scope':'Reuse completed prefix only after exact Java/dependency/protocol/test input equality; collection helper and verifier are the only allowed changes. Freeze/check prefix evidence during resumed suffix; no continuous unchanged-input run is claimed.'}
        stdout.append(prior['stdout']);commands=[['python3','parallel-measure.py'],['python3','paper.py','run'],['python3','paper-check.py']]
    else:commands=[['bash','run.sh']]
    for command in commands:
        result=subprocess.run(command,cwd=b,capture_output=True,text=True);stdout.append(result.stdout);stderr.append(result.stderr)
        if result.returncode:exit_code=result.returncode;break
    changed=paper.source_hashes()!=before;prefix_changed=prefix is not None and prefix_hashes()!=prefix
    exit_code=exit_code or (1 if changed or prefix_changed else 0)
    record={'exit_code':exit_code,'stdout':''.join(stdout),'stderr':''.join(stderr),'elapsed_seconds':time.time()-start,'inputs_changed_during_run':changed,'prefix_evidence_changed_during_resume':prefix_changed,'verification_mode':'verified_prefix_resume' if args.resume else 'full','source_sha256':{p.name:before[p.name] for p in sorted(b.glob('*.java'))},'input_sha256':before}
    if resume:record['resume']=resume
    (b/'run.json').write_text(json.dumps(record,indent=2)+'\n');(b/'run.log').write_text(record['stdout']+record['stderr'])
    env={'java':subprocess.run(['java','-version'],capture_output=True,text=True).stderr,'platform':platform.platform(),'filesystem':subprocess.run(['findmnt','-T',str(b),'-no','FSTYPE,OPTIONS'],capture_output=True,text=True).stdout,'cpu':subprocess.run(['lscpu'],capture_output=True,text=True).stdout,'scope':'local POSIX trusted-anchor reference; SIGKILL not physical power failure'}
    (b/'environment.json').write_text(json.dumps(env,indent=2)+'\n');print(record['stdout']);print(record['stderr'])
    if changed or prefix_changed:print('ERROR sources or completed prefix evidence changed during verification')
    raise SystemExit(exit_code)
if __name__=='__main__':main()
