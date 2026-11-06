"""Private chunked staging: actual files, descriptor faults and traced allocations."""
import importlib.machinery,importlib.util,json,os,pathlib,stat,tempfile,tracemalloc
from unittest.mock import patch
b=pathlib.Path(__file__).resolve().parent
loader=importlib.machinery.SourceFileLoader('easy_risk',str(b/'easy.py'));spec=importlib.util.spec_from_loader('easy_risk',loader);tool=importlib.util.module_from_spec(spec);loader.exec_module(tool)
old_loader=importlib.machinery.SourceFileLoader('easy_previous_risk',str(b/'history-v15-parallel-risk/easy.py.reference'));old_spec=importlib.util.spec_from_loader('easy_previous_risk',old_loader);old_tool=importlib.util.module_from_spec(old_spec);old_loader.exec_module(old_tool)
checks=0
def check(value):
 global checks
 if not value:raise AssertionError('Chunk staging regression')
 checks+=1
def refused(action):
 try:action()
 except (ValueError,OSError):check(True)
 else:raise AssertionError('Expected refusal')
rows=[]
with tempfile.TemporaryDirectory(prefix='easy-stream-') as temp:
 root=pathlib.Path(temp)
 for size in [0,4096,16*1024*1024]:
  source=root/f'in-{size}';source.write_bytes(bytes([73])*size);source.chmod(0o644)
  for variant in ['previous_whole_file','chunked']:
   output=root/f'{variant}-{size}'
   tracemalloc.start()
   try:
    if variant=='chunked':tool.stage_input(source,output)
    else:old_tool.stage(output,old_tool.read_file(source,old_tool.MAX))
    peak=tracemalloc.get_traced_memory()[1]
   finally:tracemalloc.stop()
   check(output.read_bytes()==source.read_bytes());check(output.stat().st_mode&0o777==0o600);check(source.stat().st_mode&0o777==0o644)
   rows.append(dict(variant=variant,message_bytes=size,traced_peak_bytes=peak))
 source=root/'in-4096';existing=root/'existing';existing.write_bytes(b'preserved');refused(lambda:tool.stage_input(source,existing));check(existing.read_bytes()==b'preserved')
 link=root/'link';link.symlink_to(source);refused(lambda:tool.stage_input(link,root/'link-out'));check(not (root/'link-out').exists())
 oversized=root/'oversized'
 with oversized.open('wb') as stream:stream.truncate(tool.MAX+1)
 refused(lambda:tool.stage_input(oversized,root/'oversized-out'));check(not (root/'oversized-out').exists())
 actual=source.stat();fake=os.stat_result((stat.S_IFIFO|0o600,*actual[1:]))
 with patch.object(tool.os,'fstat',return_value=fake):refused(lambda:tool.stage_input(source,root/'not-regular'))
 check(not (root/'not-regular').exists())
 real=os.fstat;calls=[]
 def changed(fd):
  current=real(fd);calls.append(fd)
  if len(calls)==2:
   class Altered:
    st_size=current.st_size+1;st_mtime_ns=current.st_mtime_ns;st_ctime_ns=current.st_ctime_ns
   return Altered()
  return current
 with patch.object(tool.os,'fstat',side_effect=changed):refused(lambda:tool.stage_input(source,root/'changed'))
 check(not (root/'changed').exists());check(source.stat().st_size==4096)
result=dict(passed=True,checks=checks,samples=rows,scope='actual staging bytes/modes, symlink and oversized/existing refusal, synthetic descriptor and post-copy metadata change, tracemalloc helper-only peak excludes preallocated sources/JVM/RSS; no atomic snapshot or secure erase guarantee')
(b/'results/security/easy-stream-checks.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS easy stream checks='+str(checks))
