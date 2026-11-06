#!/usr/bin/env python3
"""PoC06 / E2 controlled Java fixture runner. No edits to original E1/E2 artifacts."""
import argparse
import csv
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
MAIN = HERE / 'src' / 'PolicyCutoverFixture.java'
CASES = {
    'BASE_C1_CLASSICAL': ('C1_HYBRID_ALLOWED', 'C1_HYBRID_ALLOWED', 'X25519_ONLY'),
    'BASE_C2_HYBRID': ('C2_PQC_REQUIRED', 'C2_PQC_REQUIRED', 'X25519_MLKEM768'),
    'UPGRADE_CLASSICAL': ('C1_HYBRID_ALLOWED', 'C2_PQC_REQUIRED', 'X25519_ONLY'),
    'UPGRADE_HYBRID': ('C1_HYBRID_ALLOWED', 'C2_PQC_REQUIRED', 'X25519_MLKEM768'),
    'RELAX_CLASSICAL': ('C2_PQC_REQUIRED', 'C1_HYBRID_ALLOWED', 'X25519_ONLY'),
    'RELAX_HYBRID': ('C2_PQC_REQUIRED', 'C1_HYBRID_ALLOWED', 'X25519_MLKEM768'),
}
MODELS = ('SNAPSHOT', 'STRICT_CUTOVER')
VARIANTS = ('V0_VULNERABLE', 'V1_ALLOWLIST', 'V2_FINAL_POLICY')
FIELDS = 'repeat case model variant policy_at_check policy_at_finish effective_policy snapshot_epoch finish_epoch effective_epoch actual_suite kem_complete aead_roundtrip final_status oracle_verdict expected_status expectation_match ordering_ok'.split()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def find_bc(explicit):
    choices = []
    if explicit: choices.append(pathlib.Path(explicit).expanduser())
    if os.environ.get('BC_JAR'): choices.append(pathlib.Path(os.environ['BC_JAR']).expanduser())
    home = pathlib.Path.home()
    choices += [
        home / '.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar',
        home / 'pqc-research/lib/bcprov-jdk18on-1.86.jar',
        home / 'pqc-research/RVSec_PQC_Integrated_Prototype_v0_5/lib/bcprov-jdk18on-1.86.jar',
    ]
    for path in choices:
        if path.is_file(): return path.resolve()
    raise FileNotFoundError('BC_JAR_NOT_FOUND: use --bc-jar /path/to/bcprov-jdk18on-1.86.jar')

def test_row(row, repetition):
    fail = []
    c = CASES.get(row['case'])
    if not c: return ['unexpected case']
    if row['model'] not in MODELS or row['variant'] not in VARIANTS: return ['unexpected model or variant']
    start, end, suite = c
    eff = start if row['model']=='SNAPSHOT' else end
    expected = 'REJECTED' if row['variant']=='V2_FINAL_POLICY' and eff=='C2_PQC_REQUIRED' and suite=='X25519_ONLY' else 'SUCCESS'
    verdict = ('REJECTED' if expected == 'REJECTED' else
               ('VIOLATION' if eff=='C2_PQC_REQUIRED' and suite=='X25519_ONLY' else 'COMPLIANT'))
    expected_columns = {
        'repeat': str(repetition), 'policy_at_check':start, 'policy_at_finish':end,
        'effective_policy':eff, 'actual_suite':suite, 'final_status':expected,
        'oracle_verdict':verdict, 'expected_status':expected, 'expectation_match':'true',
        'ordering_ok':'true', 'aead_roundtrip':'true',
        'kem_complete': 'true' if suite=='X25519_MLKEM768' else 'false',
        'snapshot_epoch':'1', 'finish_epoch':'1' if start==end else '2',
        'effective_epoch':'1' if row['model']=='SNAPSHOT' or start==end else '2',
    }
    for col,value in expected_columns.items():
        if row[col]!=value: fail.append(f'{col} actual={row[col]} expected={value}')
    return fail

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bc-jar', help='BC 1.86 JAR location (not redistributed)')
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--output', help='evidence output directory; default a private temporary directory')
    args=p.parse_args()
    if args.repeat < 1: p.error('--repeat must be >=1')
    bc=find_bc(args.bc_jar)
    out=pathlib.Path(args.output).expanduser().resolve() if args.output else pathlib.Path(tempfile.mkdtemp(prefix='poc06-e2-',dir=str(pathlib.Path.home())))
    out.mkdir(parents=True, exist_ok=True)
    logs=out/'logs';logs.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='poc06-classes-') as cls:
        command=['javac','--release','17','-cp',str(bc),'-d',cls,str(MAIN)]
        subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
        print('JAVA_COMPILE=PASS')
        print('BC_SHA256='+sha(bc))
        print('JAVA_SOURCE_SHA256='+sha(MAIN))
        rows=[]
        for n in range(1,args.repeat+1):
            proc=subprocess.run(['java','-cp',os.pathsep.join([cls,str(bc)]),'PolicyCutoverFixture',str(n)],capture_output=True,text=True,timeout=120)
            (logs/f'repeat_{n}.stdout.csv').write_text(proc.stdout,encoding='utf8')
            (logs/f'repeat_{n}.stderr.txt').write_text(proc.stderr,encoding='utf8')
            if proc.returncode:
                print('JAVA_EXIT='+str(proc.returncode));print(proc.stderr[-1200:]);sys.exit(1)
            reader=csv.DictReader(io.StringIO(proc.stdout))
            if reader.fieldnames!=FIELDS: raise ValueError('Unexpected CSV schema: '+str(reader.fieldnames))
            rr=list(reader)
            if len(rr)!=len(CASES)*len(MODELS)*len(VARIANTS): raise ValueError('Unexpected row count: '+str(len(rr)))
            signatures=[(r['case'],r['model'],r['variant']) for r in rr]
            if len(set(signatures))!=len(rr): raise ValueError('Duplicate condition')
            failures=[(r,errs) for r in rr if (errs:=test_row(r,n))]
            if failures:
                print('ERRORS='+json.dumps(failures[:3],ensure_ascii=False));sys.exit(1)
            rows.extend(rr)
            print(f'REPEAT={n} EXPECTED_MATCH={len(rr)}/{len(rr)}')
    with (out/'all_cases.csv').open('w',newline='',encoding='utf8') as fh:
        writer=csv.DictWriter(fh,fieldnames=FIELDS);writer.writeheader();writer.writerows(rows)
    by_verdict={key:sum(r['oracle_verdict']==key for r in rows) for key in ('COMPLIANT','VIOLATION','REJECTED')}
    contrasts=[]
    for model in MODELS:
        for name in ('UPGRADE_CLASSICAL','RELAX_CLASSICAL'):
            contrasts.append({'model':model,'case':name,
                **{var:next(r['oracle_verdict'] for r in rows if r['repeat']=='1' and r['model']==model and r['case']==name and r['variant']==var) for var in VARIANTS}})
    summary={
        'status':'CONTROLLED_FIXTURE_EXPECTATION_MATCH', 'rows':len(rows), 'repeats':args.repeat,
        'conditions_per_repeat':36, 'judgments':by_verdict, 'contrasts':contrasts,
        'java_source_sha256':sha(MAIN),'bc_jar_sha256':sha(bc),
        'java_version':subprocess.run(['java','-version'],capture_output=True,text=True).stderr.splitlines()[0],
        'evidence_scope':'synthetic fixture, deterministic order, real X25519/ML-KEM-768/AES-GCM, toy combiner; no external OSS or RVSec integration',
    }
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print('EXPECTED_MATCH='+f'{len(rows)}/{len(rows)}')
    print('OBSERVED_ORACLE_VERDICTS='+json.dumps(by_verdict,ensure_ascii=False))
    print('V2_POLICY_VIOLATIONS_ACCEPTED='+str(sum(r['variant']=='V2_FINAL_POLICY' and r['oracle_verdict']=='VIOLATION' for r in rows)))
    print('EVIDENCE_DIR='+str(out))
    print('RESULT=CONTROLLED_FIXTURE_PASS')

if __name__=='__main__':
    main()
