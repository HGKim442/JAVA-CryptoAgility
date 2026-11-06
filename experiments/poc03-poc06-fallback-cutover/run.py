#!/usr/bin/env python3
"""Run/independently validate PoC03+PoC06/E2 controlled Java 17 fixture. No original E1/E2 file edits."""
import argparse,csv,hashlib,io,json,os,pathlib,statistics,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parent
SRC=ROOT/'src/FallbackCutoverFixture.java'
CASES={
 'C1_STABLE_HYBRID':('C1_HYBRID_ALLOWED','C1_HYBRID_ALLOWED','NONE','CLASSICAL'),
 'C2_STABLE_HYBRID':('C2_PQC_REQUIRED','C2_PQC_REQUIRED','NONE','CLASSICAL'),
 'C1_STABLE_BC_FAIL':('C1_HYBRID_ALLOWED','C1_HYBRID_ALLOWED','BC_UNREGISTERED','CLASSICAL'),
 'C2_STABLE_BC_FAIL':('C2_PQC_REQUIRED','C2_PQC_REQUIRED','BC_UNREGISTERED','CLASSICAL'),
 'UPGRADE_BC_FAIL':('C1_HYBRID_ALLOWED','C2_PQC_REQUIRED','BC_UNREGISTERED','CLASSICAL'),
 'UPGRADE_SUNEC_FAIL':('C1_HYBRID_ALLOWED','C2_PQC_REQUIRED','SUNEC_PINNED','CLASSICAL'),
 'RELAX_BC_FAIL':('C2_PQC_REQUIRED','C1_HYBRID_ALLOWED','BC_UNREGISTERED','CLASSICAL'),
 'UPGRADE_NO_FALLBACK':('C1_HYBRID_ALLOWED','C2_PQC_REQUIRED','BC_UNREGISTERED','NONE'),
}
MODELS=('SNAPSHOT','STRICT_CUTOVER')
VARIANTS=('V0_VULNERABLE','V1_ALLOWLIST','V2_FINAL_POLICY')
COLS='repeat case model variant policy_at_check policy_at_finish effective_policy snapshot_epoch finish_epoch effective_epoch key_version kem_failure_injection provider_attempted kem_failure_type actual_suite kem_complete fallback_taken aead_roundtrip final_status oracle_verdict ordering_ok elapsed_ns'.split()

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def get_bc(explicit):
    home=pathlib.Path.home()
    candidates=[explicit,os.environ.get('BC_JAR'),
        home/'.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar',
        home/'pqc-research/lib/bcprov-jdk18on-1.86.jar']
    for val in candidates:
        if val and pathlib.Path(val).expanduser().is_file(): return pathlib.Path(val).expanduser().resolve()
    raise FileNotFoundError('BC 1.86 JAR not found; pass --bc-jar /path/to/bcprov-jdk18on-1.86.jar')

def oracle(row,rep):
    errors=[]
    if row['case'] not in CASES: return ['Unknown case']
    if row['model'] not in MODELS or row['variant'] not in VARIANTS: return ['Unknown model/variant']
    begin,end,failed,fallback=CASES[row['case']]
    effective=begin if row['model']=='SNAPSHOT' else end
    hybrid=failed=='NONE'
    roundtrip=hybrid or fallback=='CLASSICAL'
    suite=('X25519_MLKEM768' if hybrid else 'X25519_ONLY') if roundtrip else 'NONE'
    error='NONE' if hybrid else ('NoSuchProviderException' if failed=='BC_UNREGISTERED' else 'NoSuchAlgorithmException')
    status=('REJECTED_EXECUTION' if not roundtrip else
           'REJECTED_POLICY' if row['variant']=='V2_FINAL_POLICY' and effective=='C2_PQC_REQUIRED' and not hybrid else 'SUCCESS')
    verdict=(status if status!='SUCCESS' else 'VIOLATION' if effective=='C2_PQC_REQUIRED' and not hybrid else 'COMPLIANT')
    fields={
        'repeat':str(rep),'policy_at_check':begin,'policy_at_finish':end,
        'effective_policy':effective,'snapshot_epoch':'1','finish_epoch':'1' if begin==end else '2',
        'effective_epoch':'1' if row['model']=='SNAPSHOT' or begin==end else '2',
        'key_version':'K1','kem_failure_injection':failed,
        'provider_attempted':'SunEC' if failed=='SUNEC_PINNED' else 'BC',
        'kem_failure_type':error,'actual_suite':suite,'kem_complete':str(hybrid).lower(),
        'fallback_taken':str(not hybrid and fallback=='CLASSICAL').lower(),
        'aead_roundtrip':str(roundtrip).lower(),'final_status':status,
        'oracle_verdict':verdict,'ordering_ok':'true'
    }
    for key,value in fields.items():
        if row[key]!=value: errors.append(f'{key}={row[key]!r} expected {value!r}')
    if int(row['elapsed_ns'])<0: errors.append('negative elapsed_ns')
    return errors

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--bc-jar');p.add_argument('--repeat',type=int,default=3);p.add_argument('--output')
    a=p.parse_args()
    if a.repeat<1: p.error('--repeat must be positive')
    bc=get_bc(a.bc_jar)
    out=pathlib.Path(a.output).expanduser().resolve() if a.output else pathlib.Path(tempfile.mkdtemp(prefix='poc03-06-e2-'))
    out.mkdir(parents=True,exist_ok=True)
    logs=out/'logs';logs.mkdir(exist_ok=True)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='poc03-06-classes-') as cls:
        subprocess.run(['javac','--release','17','-cp',str(bc),'-d',cls,str(SRC)],check=True,capture_output=True,text=True,timeout=90)
        print('JAVA_COMPILE=PASS');print('BC_SHA256='+digest(bc));print('JAVA_SOURCE_SHA256='+digest(SRC))
        for rep in range(1,a.repeat+1):
            proc=subprocess.run(['java','-cp',os.pathsep.join([cls,str(bc)]),'FallbackCutoverFixture',str(rep)],capture_output=True,text=True,timeout=150)
            (logs/f'repeat_{rep}.stdout.csv').write_text(proc.stdout,encoding='utf-8')
            (logs/f'repeat_{rep}.stderr.txt').write_text(proc.stderr,encoding='utf-8')
            if proc.returncode:
                print('JVM_EXIT='+str(proc.returncode));print(proc.stderr[-2000:]);return 1
            reader=csv.DictReader(io.StringIO(proc.stdout))
            if reader.fieldnames!=COLS:
                print('CSV_SCHEMA_MISMATCH='+repr(reader.fieldnames));return 1
            current=list(reader)
            if len(current)!=len(CASES)*len(MODELS)*len(VARIANTS):
                print('ROW_COUNT_MISMATCH='+str(len(current)));return 1
            actual={(r['case'],r['model'],r['variant']) for r in current}
            expected={(c,m,v) for c in CASES for m in MODELS for v in VARIANTS}
            if actual!=expected:
                print('CASE_COVERAGE_MISMATCH='+repr((expected-actual,actual-expected)));return 1
            errors=[(r['case'],r['model'],r['variant'],e) for r in current if (e:=oracle(r,rep))]
            if errors:
                print('ORACLE_ERRORS='+json.dumps(errors[:5],ensure_ascii=False));return 1
            rows.extend(current)
            print(f'REPEAT={rep} EXPECTED_MATCH={len(current)}/{len(current)}')
    with (out/'all_cases.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=COLS);writer.writeheader();writer.writerows(rows)
    verdicts={v:sum(r['oracle_verdict']==v for r in rows) for v in ('COMPLIANT','VIOLATION','REJECTED_POLICY','REJECTED_EXECUTION')}
    focus={}
    for name in ('C2_STABLE_BC_FAIL','UPGRADE_BC_FAIL','UPGRADE_SUNEC_FAIL','RELAX_BC_FAIL'):
        for model in MODELS:
            subset=[r for r in rows if r['case']==name and r['model']==model and r['repeat']=='1']
            focus[f'{name}/{model}']={r['variant']:r['oracle_verdict'] for r in subset}
    summary={
        'status':'CONTROLLED_FIXTURE_EXPECTATION_MATCH',
        'conditions_per_repetition':len(CASES)*len(MODELS)*len(VARIANTS),
        'repetitions':a.repeat,'rows':len(rows),'verdicts':verdicts,'focus':focus,
        'runtime':subprocess.run(['java','-version'],capture_output=True,text=True).stderr.splitlines()[0],
        'java_source_sha256':digest(SRC),'bc_jar_sha256':digest(bc),
        'scope':'synthetic deterministic policy-check/update/crypto ordering, real X25519/ML-KEM-768/AES-GCM, toy combiner, no external commit and no OSS validation',
        'precision_note':'expected matches include intentionally unsafe V0/V1 successes; not vulnerabilities fixed',
        'policy_note':'C1 explicitly permits classical-only fallback on KEM failure; C2 prohibits it',
        'pqc_auth_note':'ML-DSA not tested here; separate signature-authentication policy required for signed requests'
    }
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('EXPECTED_MATCH='+f'{len(rows)}/{len(rows)}')
    print('VERDICTS='+json.dumps(verdicts,ensure_ascii=False))
    print('FOCUS='+json.dumps(focus,ensure_ascii=False))
    print('EVIDENCE_DIR='+str(out))
    print('RESULT=CONTROLLED_PAIRWISE_PASS')
    return 0
if __name__=='__main__':
    try: sys.exit(main())
    except Exception as e: print('ERROR='+repr(e));sys.exit(1)
