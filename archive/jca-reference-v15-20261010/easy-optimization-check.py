"""Synthetic descriptor fixtures and normal helper costs; never secret data."""
import importlib.machinery, importlib.util, json, os, pathlib, stat, tempfile, tracemalloc
from unittest.mock import patch
BASE=pathlib.Path(__file__).resolve().parent
def load(name,path):
 loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module
old=load('easy_v13_reference',BASE/'history-v13/easy.py.reference');new=load('easy_v15',BASE/'easy.py');checks=0
def check(value):
 global checks
 if not value:raise AssertionError('Easy optimization regression')
 checks+=1
def refused(action):
 try:action()
 except ValueError:check(True)
 else:raise AssertionError('Expected refusal')
def peak(action):
 tracemalloc.start()
 try:action();return tracemalloc.get_traced_memory()[1]
 finally:tracemalloc.stop()
rows=[]
with tempfile.TemporaryDirectory(prefix='easy-optimization-') as tmp:
 root=pathlib.Path(tmp);root.chmod(0o700);source=root/'source';source.write_bytes(b'synthetic');source.chmod(0o600)
 check(new.read_file(source,32,True)==b'synthetic')
 real=os.fstat;actual=source.stat()
 for mode in [stat.S_IFREG|0o644,stat.S_IFIFO|0o600]:
  fake=os.stat_result((mode,*actual[1:]))
  with patch.object(new.os,'fstat',return_value=fake):refused(lambda:new.read_file(source,32,True))
 check(real is os.fstat)
 settings=root/'settings.json';settings.write_text('[]');settings.chmod(0o600);refused(lambda:new.load(root))
 content=bytes(16*1024*1024);header=b'PQCEASY1'+bytes(8);envelope=header+content
 for sample in range(3):
  for variant,tool in [('v13_reference',old),('v15',new)]:
   output=root/f'{variant}-{sample}.pqc'
   alloc=peak(lambda:tool.publish(output,header+content) if variant=='v13_reference' else tool.publish(output,header,content))
   check(output.read_bytes()==envelope);check(output.stat().st_mode&0o777==0o600)
   rows.append({'operation':'publish','variant':variant,'sample':sample,'bytes':len(content),'traced_peak_bytes':alloc})
   staged=root/f'{variant}-{sample}.raw'
   alloc=peak(lambda:tool.stage(staged,envelope[16:]) if variant=='v13_reference' else tool.stage(staged,memoryview(envelope)[16:]))
   check(staged.read_bytes()==content)
   rows.append({'operation':'stage','variant':variant,'sample':sample,'bytes':len(content),'traced_peak_bytes':alloc})
 (root/'exists').write_bytes(b'original')
 refused(lambda:new.publish(root/'exists',b'changed'));check((root/'exists').read_bytes()==b'original')
result={'passed':True,'checks':checks,'samples':rows,'scope':'helper-only tracemalloc; source/envelope allocated before tracing; not complete encryption peak or RSS; descriptor fixtures are mocked regular test files'}
(BASE/'results/security/easy-optimization.json').write_text(json.dumps(result,indent=2)+'\n')
print('PASS easy optimization and descriptor checks='+str(checks))
