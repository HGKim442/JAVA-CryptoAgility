#!/usr/bin/env python3
"""Re-run unmodified original E1/E2 sources in isolated output dirs. No keys/logs committed."""
import argparse,hashlib,pathlib,os,subprocess,tempfile,json,csv,collections,sys
ROOT=pathlib.Path(__file__).resolve().parent
SRC=ROOT/'original_e1_e2_sources'
NAMES=['AnchorCodec.java','CheckpointCodec.java','TrustedStateStore.java','E1Experiment.java','PqcDowngradeExperiment.java']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def find_jar(value):
    h=pathlib.Path.home();opts=[value,os.environ.get('BC_JAR'),h/'.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar']
    for p in opts:
        if p and pathlib.Path(p).is_file():return pathlib.Path(p).resolve()
    raise FileNotFoundError('Pass --bc-jar /path/to/bcprov-jdk18on-1.86.jar')
def read_csv(file):
    with file.open(newline='') as f:return list(csv.DictReader(f))
def baseline_check(f,attack,cost,e2):
    emodes=('VULNERABLE','ALLOWLIST','PROPOSED')
    assert len(attack)==90 and len(cost)==150 and len(e2)==6
    assert {(x['mode'],x['scenario'],x['trial']) for x in attack}=={(m,f'{s:02d}',str(t)) for m in emodes for s in range(1,7) for t in range(5)}
    assert {(x['mode'],x['sample']) for x in cost}=={(m,str(s)) for m in emodes for s in range(50)}
    assert {(x['mode'],x['failure_variant']) for x in e2}=={(m,str(s)) for m in emodes for s in (1,2)}
    for row in attack:
        expected=row['mode']=='VULNERABLE' or (row['mode']=='ALLOWLIST' and int(row['scenario'])>2)
        assert row['attack_effect']==str(expected).lower() and row['normal_success']=='true',row
    assert all(row['normal_success']=='true' and int(row['ns'])>0 for row in cost)
    for row in e2:
        assert row['normal_hybrid_success']=='true',row
        if row['mode']=='PROPOSED':assert row['outcome']=='POLICY_REJECTION' and row['observed_suite']=='NONE' and row['downgrade_effect']=='false',row
        else:assert row['outcome']=='OBSERVED' and row['observed_suite']=='X25519_ONLY' and row['downgrade_effect']=='true',row

def main():
    p=argparse.ArgumentParser();p.add_argument('--bc-jar');p.add_argument('--forks',type=int,default=1);p.add_argument('--output')
    a=p.parse_args();assert a.forks in range(1,7)
    bc=find_jar(a.bc_jar)
    out=pathlib.Path(a.output).resolve() if a.output else pathlib.Path(tempfile.mkdtemp(prefix='jca-original-e1e2-'))
    out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='jca-original-e1e2-classes-') as classes:
        names=[str(SRC/n) for n in NAMES]
        # Compile the original source files without altering their bytes.
        cmd=['javac','--release','17','-cp',str(bc),'-d',classes,*names]
        cp=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
        if cp.returncode:raise RuntimeError('COMPILE_FAILED:\n'+cp.stderr[-4000:])
        print('SOURCE_COMPILE=PASS');print('BC_SHA256='+sha(bc))
        for fork in range(1,a.forks+1):
            e1=out/f'e1/fork{fork}';e2=out/f'e2/fork{fork}';e1.mkdir(parents=True,exist_ok=True);e2.mkdir(parents=True,exist_ok=True)
            for cls,dirname,dest in [('E1Experiment','e1',e1),('PqcDowngradeExperiment','e2',e2)]:
                proc=subprocess.run(['java','-cp',os.pathsep.join([classes,str(bc)]),cls,str(dest),str(fork)],capture_output=True,text=True,timeout=150)
                (dest/'stdout.log').write_text(proc.stdout,encoding='utf-8')
                (dest/'stderr.log').write_text(proc.stderr,encoding='utf-8')
                if proc.returncode:raise RuntimeError(f'{cls} fork={fork} EXIT={proc.returncode}: {proc.stderr[-2000:]}')
            attack=read_csv(e1/'attacks.csv');cost=read_csv(e1/'normal-cost.csv');downgrade=read_csv(e2/'pqc-downgrade.csv')
            baseline_check(fork,attack,cost,downgrade)
            print(f'FORK={fork} EXPECTED_E1=90/90 NORMAL=150/150 EXPECTED_E2=6/6')
    data={'status':'REPRODUCED_ORIGINAL_E1E2','forks':a.forks,'attack_rows':90*a.forks,'normal_cost_rows':150*a.forks,'e2_rows':6*a.forks,
          'bc_sha256':sha(bc),'java_sources_sha256':{p.name:sha(p) for p in map(lambda x:SRC/x,NAMES)},
          'notes':'Controlled synthetic tests, original sources unchanged; expected-match includes vulnerable paths. No security claim outside fixtures.'}
    (out/'summary.json').write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
    print('RESULT=ORIGINAL_E1E2_RECHECK_PASS');print('EVIDENCE_DIR='+str(out))
if __name__=='__main__':
    try:main()
    except Exception as e:print('ERROR='+repr(e));sys.exit(1)
