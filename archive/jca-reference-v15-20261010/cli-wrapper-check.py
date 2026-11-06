import pathlib,subprocess,tempfile,json
base=pathlib.Path(__file__).resolve().parent
checks=0
def check(value):
 global checks
 assert value;checks+=1
with tempfile.TemporaryDirectory(prefix='cli-wrapper-') as tmp:
 root=pathlib.Path(tmp)
 r=subprocess.run(['bash',str(base/'cli.sh'),'keygen','local.key'],cwd=root,capture_output=True,text=True,timeout=60);check(r.returncode==0);check((root/'local.key').exists());check(len((root/'local.key').read_bytes())==32)
 cls=base/'build/CryptoCli.class';before=cls.stat().st_mtime_ns
 r=subprocess.run(['bash',str(base/'cli.sh'),'help'],cwd=root,capture_output=True,text=True,timeout=30);check(r.returncode==0);check(cls.stat().st_mtime_ns==before)
 check((root/'local.key').stat().st_mode&0o777==0o600)
result={'passed':True,'checks':checks,'caller_relative_paths':True,'unchanged_source_reuses_compile':True}
(base/'results/security/cli-wrapper-checks.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS CLI wrapper checks='+str(checks))
