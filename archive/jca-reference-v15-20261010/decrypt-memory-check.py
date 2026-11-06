"""Bounded decrypt staging versus exact previous implementation; owned fixtures only."""
import hashlib,importlib.machinery,importlib.util,json,os,pathlib,struct,tempfile,tracemalloc
from unittest.mock import patch
b=pathlib.Path(__file__).resolve().parent

def load(name,path):
 loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m);return m
new=load('new_decrypt_memory',b/'easy.py');baseline=b/'history-decrypt-memory-20261009/easy.py.previous';old=load('old_decrypt_memory',baseline);checks=0;rows=[]
def check(value,message):
 global checks
 if not value:raise AssertionError(message)
 checks+=1
def refused(action):
 try:action()
 except (ValueError,OSError):check(True,'Refusal')
 else:raise AssertionError('Expected refusal')
def previous(source,dest):
 data=old.read_file(source,old.MAX+10016)
 if len(data)<16 or data[:8]!=old.MAGIC:raise ValueError('envelope')
 version=struct.unpack_from('>Q',data,8)[0]
 if not 1<=version<=2**63-1:raise ValueError('version')
 old.stage(dest,memoryview(data)[16:]);return version
with tempfile.TemporaryDirectory(prefix='decrypt-memory-') as temp:
 root=pathlib.Path(temp);root.chmod(0o700)
 for size in [0,4096,new.MAX+10000]:
  source=root/f'envelope-{size}'
  with source.open('wb') as f:
   f.write(new.MAGIC+struct.pack('>Q',2));remaining=size
   while remaining:count=min(65536,remaining);f.write(b'Q'*count);remaining-=count
  source.chmod(0o644)
  for variant,operation in [('whole_envelope',previous),('streamed_envelope',new.stage_packet)]:
   for sample in range(3):
    dest=root/'staged';tracemalloc.start()
    try:version=operation(source,dest);peak=tracemalloc.get_traced_memory()[1]
    finally:tracemalloc.stop()
    check(version==2,'Version');check(dest.read_bytes()==source.read_bytes()[16:],'Packet bytes')
    check(dest.stat().st_mode&0o777==0o600,'Staging privacy');check(source.stat().st_mode&0o777==0o644,'Source permissions')
    rows.append(dict(variant=variant,raw_packet_bytes=size,envelope_bytes=size+16,sample=sample,traced_peak_bytes=peak));dest.unlink()
 source=root/'envelope-4096';dest=root/'staged'
 existing=root/'existing';existing.write_bytes(b'preserved');refused(lambda:new.stage_packet(source,existing));check(existing.read_bytes()==b'preserved','Existing destination')
 link=root/'source-link';link.symlink_to(source);refused(lambda:new.stage_packet(link,dest));check(not dest.exists(),'Symlink staging')
 destination_link=root/'destination-link';destination_link.symlink_to(existing);refused(lambda:new.stage_packet(source,destination_link));check(existing.read_bytes()==b'preserved','Destination symlink target')
 fifo=root/'fifo';os.mkfifo(fifo);refused(lambda:new.stage_packet(fifo,dest));check(not dest.exists(),'FIFO staging')
 for contents in [b'',b'PQCEASY1',b'WRONGMAG'+struct.pack('>Q',1),new.MAGIC+struct.pack('>Q',0),new.MAGIC+struct.pack('>Q',2**63)]:
  invalid=root/'invalid';invalid.write_bytes(contents);refused(lambda:new.stage_packet(invalid,dest));check(not dest.exists(),'Invalid envelope left output')
 over=root/'oversized'
 with over.open('wb') as f:f.truncate(new.MAX+10017)
 refused(lambda:new.stage_packet(over,dest));check(not dest.exists(),'Oversize left output')
 real_fstat=os.fstat;calls=[]
 def changed(fd):
  value=real_fstat(fd);calls.append(fd)
  if len(calls)==2:
   class Altered:
    st_size=value.st_size;st_mtime_ns=value.st_mtime_ns;st_ctime_ns=value.st_ctime_ns+1
   return Altered()
  return value
 with patch.object(new.os,'fstat',side_effect=changed):refused(lambda:new.stage_packet(source,dest))
 check(not dest.exists(),'Changed input staging not removed')
 real_fdopen=os.fdopen
 class FailedWrite:
  def __init__(self,fd):self.stream=real_fdopen(fd,'wb')
  def __enter__(self):return self
  def __exit__(self,*args):self.stream.close()
  def write(self,data):raise OSError('owned synthetic staging write failure')
 def faulty(fd,mode,*args,**kwargs):return FailedWrite(fd) if mode=='wb' else real_fdopen(fd,mode,*args,**kwargs)
 with patch.object(new.os,'fdopen',side_effect=faulty):refused(lambda:new.stage_packet(source,dest))
 check(not dest.exists(),'Failed write staging not removed')
 # Header-only input continues to be handed to the Java codec, which rejects it.
 minimum=root/'minimum';minimum.write_bytes(new.MAGIC+struct.pack('>Q',1));check(new.stage_packet(minimum,dest)==1,'Header-only version');check(dest.stat().st_size==0,'Header-only raw packet');dest.unlink()
(b/'results/security').mkdir(parents=True,exist_ok=True)
record=dict(passed=True,checks=checks,samples=rows,source_sha256={'previous':hashlib.sha256(baseline.read_bytes()).hexdigest(),'current':hashlib.sha256((b/'easy.py').read_bytes()).hexdigest()},scope='Exact previous decrypt staging versus bounded helper, 3 repeats per size/variant; helper tracemalloc only, excludes source preparation/verification/Java/total RSS. Owned synthetic faults cover descriptor metadata and failed writes; privacy, version/magic/size, regular-source and no-overwrite checks. No secure erase/throughput/RSS certification.')
(b/'results/security/decrypt-memory-checks.json').write_text(json.dumps(record,indent=2)+'\n');print('PASS decrypt memory checks='+str(checks))
