"""Envelope-equivalent bounded packet output: real files, faults and traced allocation."""
import hashlib,importlib.machinery,importlib.util,json,os,pathlib,struct,tempfile,tracemalloc
from unittest.mock import patch
b=pathlib.Path(__file__).resolve().parent

def load(name,path):
 loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module
new=load('stream_packet',b/'easy.py');old=load('previous_packet',b/'history-packet-stream-20261009/easy.py.previous');checks=0

def check(value,message):
 global checks
 if not value:raise AssertionError(message)
 checks+=1

def refused(action):
 try:action()
 except (ValueError,OSError):check(True,'Expected refusal')
 else:raise AssertionError('Expected refusal')
rows=[];header=struct.pack('>Q',2)
with tempfile.TemporaryDirectory(prefix='packet-stream-') as temp:
 root=pathlib.Path(temp);root.chmod(0o700)
 for size in [0,4096,new.MAX+10000]:
  source=root/('packet-'+str(size))
  with source.open('wb') as f:
   remaining=size
   while remaining:count=min(65536,remaining);f.write(b'Q'*count);remaining-=count
  source.chmod(0o600)
  for variant in ['whole_packet','streamed_packet']:
   for sample in range(3):
    output=root/f'{variant}-{size}-{sample}';tracemalloc.start()
    try:
     if variant=='whole_packet':old.publish(output,old.MAGIC,header,old.read_file(source,old.MAX+10000))
     else:new.publish_packet(output,source,header)
     peak=tracemalloc.get_traced_memory()[1]
    finally:tracemalloc.stop()
    check(output.read_bytes()==new.MAGIC+header+source.read_bytes(),'Envelope bytes differ')
    check(output.stat().st_mode&0o777==0o600,'Output permissions')
    rows.append(dict(variant=variant,packet_bytes=size,sample=sample,traced_peak_bytes=peak));output.unlink()
 source=root/'packet-4096';existing=root/'existing';existing.write_bytes(b'preserved')
 refused(lambda:new.publish_packet(existing,source,header));check(existing.read_bytes()==b'preserved','Existing output changed')
 link=root/'source-link';link.symlink_to(source);refused(lambda:new.publish_packet(root/'link-output',link,header));check(not (root/'link-output').exists(),'Symlink published')
 over=root/'oversized'
 with over.open('wb') as f:f.truncate(new.MAX+10001)
 refused(lambda:new.publish_packet(root/'oversize-output',over,header));check(not (root/'oversize-output').exists(),'Oversized published')
 refused(lambda:new.publish_packet(root/'bad-header',source,b'bad'));check(not (root/'bad-header').exists(),'Invalid header published')
 real_fstat=os.fstat;calls=[]
 def changed(fd):
  value=real_fstat(fd);calls.append(fd)
  if len(calls)==2:
   class Altered:
    st_size=value.st_size;st_mtime_ns=value.st_mtime_ns+1;st_ctime_ns=value.st_ctime_ns
   return Altered()
  return value
 with patch.object(new.os,'fstat',side_effect=changed):refused(lambda:new.publish_packet(root/'changed',source,header))
 check(not (root/'changed').exists(),'Changed input published')
 with patch.object(new.os,'fsync',side_effect=OSError('owned synthetic sync failure')):refused(lambda:new.publish_packet(root/'sync-failed',source,header))
 check(not (root/'sync-failed').exists(),'Output before failed file fsync')
 real_link=os.link
 def raced(src,dst):
  pathlib.Path(dst).write_bytes(b'other-owner-output');return real_link(src,dst)
 with patch.object(new.os,'link',side_effect=raced):refused(lambda:new.publish_packet(root/'raced',source,header))
 check((root/'raced').read_bytes()==b'other-owner-output','Racing output overwritten')
 check(not list(root.glob('.easy-output-*')),'Temporary outputs left')
(b/'results/security').mkdir(parents=True,exist_ok=True)
record=dict(passed=True,checks=checks,samples=rows,source_sha256={'previous':hashlib.sha256((b/'history-packet-stream-20261009/easy.py.previous').read_bytes()).hexdigest(),'current':hashlib.sha256((b/'easy.py').read_bytes()).hexdigest()},scope='real helper files; exact legacy envelope bytes and0600, existing/symlink/size/header refusals, synthetic metadata/fsync/link-race failures; 3 allocation samples per size/variant; helper-only tracemalloc excludes inputs, verification, JVM and total process RSS; no throughput/secure erase claim')
(b/'results/security/packet-stream-checks.json').write_text(json.dumps(record,indent=2)+'\n');print('PASS packet stream checks='+str(checks))
