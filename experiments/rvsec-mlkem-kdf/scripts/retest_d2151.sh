#!/usr/bin/env bash
# D2-15.1 controlled two-entrypoint KDF coverage fix. Original archives untouched.
set -euo pipefail
umask 077
ROOT="$HOME/pqc-research/D0-rvsec/runs"
D212="$ROOT/RVSec-D2-registration-provenance-20261026-180412"
D214="$ROOT/RVSec-D2-agent-altkdf-20261104-171835"
D215="$ROOT/RVSec-D2-coverage-failclosed-20261026-184838"
BC="$HOME/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar"
JV="$HOME/.m2/repository/org/javassist/javassist/3.30.2-GA/javassist-3.30.2-GA.jar"
for f in \
 "$D215/agent-src/AgentProbe.java" "$D215/agent-src/BindingAgent.java" \
 "$D215/MANIFEST.MF" "$D215/SHA256SUMS.txt" "$D214/SHA256SUMS.txt" \
 "$D212/classes/RegistrationTrustExperiment.class" \
 "$D214/alt-classes/RegistrationTrustExperiment.class" \
 "$D214/alt-classes/AlternateKdf.class" "$BC" "$JV"; do
 [[ -f "$f" ]] || { echo "MISSING=$f"; exit 1; }
done
(cd "$D215" && sha256sum -c SHA256SUMS.txt >/dev/null)
(cd "$D214" && sha256sum -c SHA256SUMS.txt >/dev/null)
echo 'ORIGINAL_INPUT_CHECKSUMS=PASS'
BASE="$HOME/pqc-research-private/rvsec-kdf-runs"
mkdir -p "$BASE"
OUT="$(mktemp -d "$BASE/d2151-dualpath-XXXXXX")"
mkdir -p "$OUT/agent-src" "$OUT/agent-classes"
python3 - "$D215/agent-src" "$OUT/agent-src" <<'PY'
from pathlib import Path
import sys
orig, dest = map(Path, sys.argv[1:])
s=(orig/'BindingAgent.java').read_text()
old='''if (!"RegistrationTrustExperiment".equals(name)
                        && !"KdfBindingExperiment".equals(name)) return null;'''
new='''if (!"RegistrationTrustExperiment".equals(name)
                        && !"KdfBindingExperiment".equals(name)
                        && !"AlternateKdf".equals(name)) return null;'''
assert s.count(old)==1, 'class filter differs: manual review required'
s=s.replace(old,new)
old='''} else {
                        cc.getDeclaredMethod("derive")
                            .insertBefore("{ AgentProbe.beforeKdf($2); }");
                        cc.getDeclaredMethod("record")
                            .insertBefore("{ AgentProbe.beforeRecord(); }");
                    }'''
new='''} else if ("KdfBindingExperiment".equals(name)) {
                        cc.getDeclaredMethod("derive")
                            .insertBefore("{ AgentProbe.beforeKdf($2); }");
                        cc.getDeclaredMethod("record")
                            .insertBefore("{ AgentProbe.beforeRecord(); }");
                    } else if ("AlternateKdf".equals(name)) {
                        cc.getDeclaredMethod("derive")
                            .insertBefore("{ AgentProbe.beforeKdf($2); }");
                    }'''
assert s.count(old)==1, 'hook block differs: manual review required'
s=s.replace(old,new)
(dest/'BindingAgent.java').write_text(s)
t=(orig/'AgentProbe.java').read_text()
old='''final boolean coverageReady = captured == 2 && derived == 2
            && transforms == 2;'''
new='''final boolean coverageReady = captured == 2 && derived == 2
            && transforms >= 2;'''
assert t.count(old)==1, 'gate differs: manual review required'
t=t.replace(old,new)
(dest/'AgentProbe.java').write_text(t)
print('PATCHED_COPY_ONLY=true')
print('PATCH_SCOPE=KdfBindingExperiment.derive+AlternateKdf.derive')
PY
javac --release 8 -cp "$JV" -d "$OUT/agent-classes" \
  "$OUT/agent-src/AgentProbe.java" "$OUT/agent-src/BindingAgent.java"
jar cfm "$OUT/d2151-agent.jar" "$D215/MANIFEST.MF" -C "$OUT/agent-classes" .
sha256sum "$OUT/d2151-agent.jar" > "$OUT/AGENT_SHA256.txt"
echo 'COMPILE=PASS'
for REP in 1 2 3; do
 for VARIANT in ORIGINAL ALTERNATE; do
  for MODE in HONEST FORGED_REGISTRATION; do
   for AMODE in AUDIT ENFORCE; do
    DIR="$OUT/rep$REP/$VARIANT/$MODE/$AMODE"
    mkdir -p "$DIR"
    CP="$D212/classes:$BC:$JV:$OUT/d2151-agent.jar"
    [[ "$VARIANT" == ORIGINAL ]] || CP="$D214/alt-classes:$CP"
    if (cd "$DIR" && timeout --signal=TERM --kill-after=10s 90s \
       java -Xms128m -Xmx1024m -Dd215.mode="$AMODE" \
       -javaagent:"$OUT/d2151-agent.jar" -cp "$CP" \
       RegistrationTrustExperiment "$MODE" APPLICATION_REGISTRY ENFORCED \
       >run.log 2>&1); then RC=0; else RC=$?; fi
    echo "$RC" > "$DIR/exit-code.txt"
    echo "REP=$REP VARIANT=$VARIANT MODE=$MODE AGENT=$AMODE EXIT=$RC"
   done
  done
 done
done
python3 - "$OUT" <<'PY'
from pathlib import Path
import csv,sys
root=Path(sys.argv[1]);rows=[]
for rep in (1,2,3):
 for variant in ('ORIGINAL','ALTERNATE'):
  for mode in ('HONEST','FORGED_REGISTRATION'):
   for agent in ('AUDIT','ENFORCE'):
    d=root/f'rep{rep}'/variant/mode/agent
    s=(d/'run.log').read_text(errors='replace')
    v=dict(line.split('=',1) for line in s.splitlines() if line.startswith('AGENT_SUMMARY_') and '=' in line)
    forged=mode=='FORGED_REGISTRATION';blocked=forged and agent=='ENFORCE'
    expected={
       'AGENT_SUMMARY_TRANSFORMS': str(2 if variant=='ORIGINAL' else 3),
       'AGENT_SUMMARY_CAPTURES':'2',
       'AGENT_SUMMARY_DERIVES':str(1 if blocked else 2),
       'AGENT_SUMMARY_MISMATCHES':str(1 if blocked else 2 if forged else 0),
       'AGENT_SUMMARY_COVERAGE_GAPS':'0',
       'AGENT_SUMMARY_COVERAGE_BLOCKS':'0',
       'AGENT_SUMMARY_RECORDS':str(int(not blocked)),
       'AGENT_SUMMARY_BLOCKS':str(int(blocked)),
       'AGENT_SUMMARY_END':'true',
    }
    rc=int((d/'exit-code.txt').read_text().strip())
    ok=rc==int(blocked) and all(v.get(k)==x for k,x in expected.items())
    ok &= 'AGENT_TRANSFORM_ERROR=' not in s
    if blocked:ok &= 'D215_BLOCKED_UNBOUND_KDF' in s
    else:ok &= 'RESULT=PASS' in s
    rows.append(dict(rep=rep,variant=variant,mode=mode,agent=agent,exit=rc,expected_match=bool(ok)))
with (root/'results.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
matched=sum(r['expected_match'] for r in rows)
print(f'CHECKED={matched}/{len(rows)}')
for k,var,mode,rc in [
 ('ORIGINAL_FORGED_BLOCKS','ORIGINAL','FORGED_REGISTRATION',1),
 ('ALTERNATE_FORGED_BLOCKS','ALTERNATE','FORGED_REGISTRATION',1),
 ('ALTERNATE_HONEST_ALLOWED','ALTERNATE','HONEST',0),
 ('ORIGINAL_HONEST_ALLOWED','ORIGINAL','HONEST',0)]:
 found=sum(r['expected_match'] and r['exit']==rc for r in rows if r['variant']==var and r['mode']==mode and r['agent']=='ENFORCE')
 print(f'{k}={found}/3')
if matched!=24:
 print('RESULT=REVIEW_REQUIRED')
 sys.exit(1)
print('RESULT=CONTROLLED_DUAL_KDF_ENTRYPOINTS_PASS')
print('LIMITATION=KNOWN_ENTRYPOINTS_ONLY_NOT_GENERAL_KDF_PROVENANCE')
PY
(cd "$OUT" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt)
echo "RESULT_DIR=$OUT"
echo 'GITHUB_UNCHANGED=true'
