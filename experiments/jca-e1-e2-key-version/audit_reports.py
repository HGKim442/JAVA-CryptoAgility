#!/usr/bin/env python3
"""Independent consistency checks of recorded controlled E1/E2 and PoC06 experiments."""
import csv,json,collections,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parent

def read(path):
    with path.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def require(x,msg):
    if not x:raise AssertionError(msg)

def audit_e1():
    base=ROOT/'reports/baseline_recheck'
    attacks=read(base/'e1_attacks_540.csv'); cost=read(base/'e1_normal_cost_900.csv')
    modes=('VULNERABLE','ALLOWLIST','PROPOSED')
    expect={(str(f),m,str(s),str(t)) for f in range(1,7) for m in modes for s in range(1,7) for t in range(5)}
    actual={(r['fork'],r['mode'],r['scenario'],r['trial']) for r in attacks}
    require(len(attacks)==len(expect) and actual==expect,'E1 attack case coverage/duplicates')
    for r in attacks:
        s=int(r['scenario']); mode=r['mode']
        effect=mode=='VULNERABLE' or (mode=='ALLOWLIST' and s>=3)
        require(r['attack_effect'].lower()==str(effect).lower(),'E1 attack observation differs: '+str(r))
        require(r['normal_success'].lower()=='true','E1 normal control failed')
    expect_cost={(str(f),m,str(t)) for f in range(1,7) for m in modes for t in range(50)}
    actual_cost={(r['fork'],r['mode'],r['sample']) for r in cost}
    require(len(cost)==len(expect_cost) and actual_cost==expect_cost,'E1 cost coverage/duplicates')
    require(all(r['normal_success'].lower()=='true' and int(r['ns'])>0 for r in cost),'E1 normal cost record failed')
    print('E1_RECHECK=PASS ATTACKS=540 NORMAL_COST=900')

def audit_e2():
    rows=read(ROOT/'reports/baseline_recheck/e2_downgrade_36.csv')
    modes=('VULNERABLE','ALLOWLIST','PROPOSED')
    expect={(str(f),m,str(k)) for f in range(1,7) for m in modes for k in (1,2)}
    require(len(rows)==len(expect) and {(r['fork'],r['mode'],r['failure_variant']) for r in rows}==expect,'E2 coverage/duplicates')
    for r in rows:
        require(r['normal_hybrid_success'].lower()=='true','E2 normal hybrid failed')
        if r['mode']=='PROPOSED':
            require(r['observed_suite']=='NONE' and r['outcome']=='POLICY_REJECTION' and r['roundtrip'].lower()=='false','E2 policy rejection failed')
        else:
            require(r['observed_suite']=='X25519_ONLY' and r['outcome']=='OBSERVED' and r['downgrade_effect'].lower()=='true' and r['roundtrip'].lower()=='true','E2 fallback observation failed')
    print('E2_RECHECK=PASS ROWS=36')

def audit_key():
    rows=read(ROOT/'reports/local_run/all_cases.csv')
    scenarios={'STABLE_K1':(1,1),'STABLE_K2':(2,2),'ROTATE_K1_TO_K2':(1,2)}
    modes=('V0_VULNERABLE','V1_ALLOWLIST','V2_POLICY_BOUND'); models=('SNAPSHOT','STRICT_CUTOVER')
    expected={(str(rep),case,model,mode) for rep in range(1,4) for case in scenarios for model in models for mode in modes}
    require(len(rows)==len(expected) and {(r['repeat'],r['scenario'],r['model'],r['mode']) for r in rows}==expected,'Key-version case coverage')
    verdicts=collections.Counter()
    for r in rows:
        first,latest=scenarios[r['scenario']]; target=first if r['model']=='SNAPSHOT' else latest
        reject=r['mode']=='V2_POLICY_BOUND' and first!=target
        verdict='REJECTED_POLICY' if reject else 'COMPLIANT' if first==target else 'VIOLATION'
        require(r['policy_at_check']=='K'+str(first) and r['policy_at_finish']=='K'+str(latest) and r['effective_version']=='K'+str(target),'Version observable mismatch')
        require((r['check_epoch'],r['finish_epoch'])==('1',str(1 if latest==first else 2)),'Epoch mismatch')
        require(r['oracle_verdict']==verdict and r['final_status']==('REJECTED_POLICY' if reject else 'SUCCESS'),'Key verdict mismatch')
        require(r['actual_key_version']==('NONE' if reject else 'K'+str(first)),'Actual key mismatch')
        require(r['ordering_ok'].lower()=='true' and r['aead_roundtrip'].lower()==str(not reject).lower(),'AES/ordering mismatch')
        verdicts[verdict]+=1
    require(verdicts=={'COMPLIANT':45,'VIOLATION':6,'REJECTED_POLICY':3},'Key-version counts')
    print('POC06_KEY_VERSION=PASS ROWS=54 VERDICTS='+json.dumps(dict(verdicts),sort_keys=True))

def audit_pairwise():
    rows=read(ROOT/'reports/pairwise_recheck/all_cases.csv')
    summary=json.loads((ROOT/'reports/pairwise_recheck/summary.json').read_text())
    expected_cases=('C1_STABLE_HYBRID','C2_STABLE_HYBRID','C1_STABLE_BC_FAIL','C2_STABLE_BC_FAIL','UPGRADE_BC_FAIL','UPGRADE_SUNEC_FAIL','RELAX_BC_FAIL','UPGRADE_NO_FALLBACK')
    models=('SNAPSHOT','STRICT_CUTOVER');variants=('V0_VULNERABLE','V1_ALLOWLIST','V2_FINAL_POLICY')
    expected={(str(r),s,m,v) for r in range(1,4) for s in expected_cases for m in models for v in variants}
    require(len(rows)==len(expected) and {(r['repeat'],r['case'],r['model'],r['variant']) for r in rows}==expected,'Pairwise case coverage')
    vc=collections.Counter(r['oracle_verdict'] for r in rows)
    require(vc=={'COMPLIANT':81,'VIOLATION':30,'REJECTED_POLICY':15,'REJECTED_EXECUTION':18},'Pairwise distribution')
    require(summary['java_source_sha256']=='8fc9af941d97455017a8e1423eaadfb09620036bcacbb0ab469851fc0832c9c2','Pairwise source changed')
    require(all(r['ordering_ok']=='true' for r in rows),'Pairwise ordering')
    print('POC03_06_E2=PASS ROWS=144 VERDICTS='+json.dumps(dict(vc),sort_keys=True))

def main():
    audit_e1();audit_e2();audit_key();audit_pairwise()
    print('RESULT=PLAN_CHECKPOINT_EVIDENCE_AUDIT_PASS')
if __name__=='__main__':
    try:main()
    except Exception as err:print('AUDIT_FAILED='+repr(err));sys.exit(1)
