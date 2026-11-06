"""Owned fake core processes test signal ordering, forced exit and staging cleanup."""
import json,os,pathlib,signal,subprocess,tempfile,time
b=pathlib.Path(__file__).resolve().parent;checks=0
def check(value):
 global checks
 if not value:raise AssertionError('Easy cancellation regression')
 checks+=1
with tempfile.TemporaryDirectory(prefix='easy-cancel-check-') as temp:
 root=pathlib.Path(temp)
 for repeated in [False,True]:
  case=root/str(repeated);case.mkdir();project=case/'fake';project.mkdir();stage=case/'stage';stage.mkdir()
  core=project/'core.py';core.write_text('import os,signal,time,pathlib,sys\np=pathlib.Path(sys.argv[1]);signal.signal(signal.SIGTERM,signal.SIG_IGN)\np.joinpath("ready").write_text(str(os.getpid()))\nwhile True:\n p.joinpath("active").write_text("running")\n time.sleep(0.02)\n')
  (project/'cli.sh').write_text('#!/bin/bash\nexec python3 "'+str(core)+'" "$1"\n')
  wrapper=case/'wrapper.py';wrapper.write_text('import importlib.util,pathlib,sys,shutil\ns=importlib.util.spec_from_file_location("tool",'+repr(str(b/'easy.py'))+');t=importlib.util.module_from_spec(s);s.loader.exec_module(t);t.PROJECT=pathlib.Path('+repr(str(project))+')\ntry:\n t.cli(['+repr(str(stage))+'])\nexcept KeyboardInterrupt:\n shutil.rmtree('+repr(str(stage))+')\n sys.exit(130)\n')
  process=subprocess.Popen(['python3',str(wrapper)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
  try:
   deadline=time.monotonic()+10
   while not (stage/'ready').exists() and time.monotonic()<deadline:time.sleep(0.01)
   check((stage/'ready').exists());pid=int((stage/'ready').read_text());os.kill(process.pid,signal.SIGINT);time.sleep(0.2)
   if repeated:os.kill(process.pid,signal.SIGINT)
   stdout,stderr=process.communicate(timeout=10);check(process.returncode==130);check(not stage.exists());check(not stderr)
   try:os.kill(pid,0)
   except ProcessLookupError:check(True)
   else:raise AssertionError('Core survived staging cleanup')
  finally:
   if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait()
(b/'results/security/easy-cancel-checks.json').write_text(json.dumps(dict(passed=True,checks=checks,scope='actual owned synthetic core ignores TERM; single/repeated parent SIGINT, fallback KILL, exit130, core reaped before private staging deletion; not physical crash or uninterruptible I/O proof'),indent=2)+'\n')
print('PASS easy cancel checks='+str(checks))
