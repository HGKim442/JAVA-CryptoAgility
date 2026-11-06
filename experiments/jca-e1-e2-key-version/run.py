#!/usr/bin/env python3
"""PoC06 key-version single-factor: independent oracle & fresh JVM repetition."""
import argparse,csv,hashlib,io,json,pathlib,subprocess,sys,tempfile,collections
ROOT=pathlib.Path(__file__).resolve().parent
SRC=ROOT/'src/KeyVersionCutoverFixture.java'
COLS='repeat scenario model mode policy_at_check policy_at_finish effective_version check_epoch finish_epoch actual_key_version final_status reason aead_roundtrip ordering_ok oracle_verdict'.split()
SCENARIOS={'STABLE_K1':(1,1),'STABLE_K2':(2,2),'ROTATE_K1_TO_K2':(1,2)}
MODELS=('SNAPSHOT','STRICT_CUTOVER')
MODES=('V0_VULNERABLE','V1_ALLOWLIST','V2_POLICY_BOUND')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check(row,rep):
    assert row['repeat']==str(rep), ('repeat',row)
    begin,end=SCENARIOS[row['scenario']]
    effective=begin if row['model']=='SNAPSHOT' else end
    must_reject=row['mode']=='V2_POLICY_BOUND' and begin!=effective
    observed='REJECTED_POLICY' if must_reject else 'SUCCESS'
    expected={
        'policy_at_check':f'K{begin}','policy_at_finish':f'K{end}',
        'effective_version':f'K{effective}',
        'check_epoch':'1', 'finish_epoch':'2' if begin!=end else '1',
        'actual_key_version':'NONE' if must_reject else f'K{begin}',
        'final_status':observed,
        'reason':'KEY_VERSION_MISMATCH' if must_reject else 'NONE',
        'aead_roundtrip':'false' if must_reject else 'true',
        'ordering_ok':'true',
        'oracle_verdict': 'REJECTED_POLICY' if must_reject else ('COMPLIANT' if begin==effective else 'VIOLATION')
    }
    for field,value in expected.items():
        if row[field]!=value:raise AssertionError((field,row[field],value,row['scenario'],row['model'],row['mode']))

def main():
    p=argparse.ArgumentParser();p.add_argument('--repeat',type=int,default=3);p.add_argument('--output')
    a=p.parse_args();assert a.repeat>0
    out=pathlib.Path(a.output).resolve() if a.output else pathlib.Path(tempfile.mkdtemp(prefix='poc06-keyversion-'))
    out.mkdir(exist_ok=True,parents=True);(out/'logs').mkdir(exist_ok=True)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='poc06-keyversion-classes-') as cl:
        cmd=['javac','--release','17','-d',cl,str(SRC)]
        subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=60)
        print('JAVA_COMPILE=PASS')
        for rep in range(1,a.repeat+1):
            cp=subprocess.run(['java','-cp',cl,'KeyVersionCutoverFixture',str(rep)],capture_output=True,text=True,timeout=100)
            (out/'logs'/f'repeat_{rep}.stdout.csv').write_text(cp.stdout,encoding='utf-8')
            (out/'logs'/f'repeat_{rep}.stderr.log').write_text(cp.stderr,encoding='utf-8')
            assert cp.returncode==0,(rep,cp.stderr[-2000:])
            rdr=csv.DictReader(io.StringIO(cp.stdout));assert rdr.fieldnames==COLS,rdr.fieldnames
            curr=list(rdr);assert len(curr)==len(SCENARIOS)*len(MODELS)*len(MODES)
            expected={(s,p,m) for s in SCENARIOS for p in MODELS for m in MODES}
            assert {(r['scenario'],r['model'],r['mode']) for r in curr}==expected
            for row in curr:check(row,rep)
            rows.extend(curr)
            print(f'REPEAT={rep} EXPECTED_MATCH={len(curr)}/{len(curr)}')
    with (out/'all_cases.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=COLS);w.writeheader();w.writerows(rows)
    stats=collections.Counter(r['oracle_verdict'] for r in rows)
    summary={'scope':'synthetic single-factor key-version transition, real JCA SunJCE AES-GCM, no PQC or external commit',
         'source_sha256':sha(SRC), 'repetitions':a.repeat,'conditions_per_repetition':len(SCENARIOS)*len(MODELS)*len(MODES),
         'rows':len(rows),'verdicts':dict(sorted(stats.items())),
         'assumptions':['administrator-authorized K1->K2 rotation','Snapshot and Strict-cutover are distinct policies','only V2 checks effective required key version before the AEAD operation','all successful paths use identical AAD binding; P3 tamper not compared'],
         'performance_claim':'none; no time or memory comparison',
         'status':'CONTROLLED_EXPECTATION_MATCH'}
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('EXPECTED_MATCH='+f'{len(rows)}/{len(rows)}')
    print('VERDICTS='+json.dumps(summary['verdicts']))
    print('RESULT=CONTROLLED_KEY_VERSION_PASS')
    print('EVIDENCE_DIR='+str(out))
    return 0
if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:print('ERROR='+repr(e));raise
