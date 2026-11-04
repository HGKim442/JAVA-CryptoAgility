(
set -euo pipefail
umask 077
ROOT="$HOME/pqc-research/D0-rvsec/runs"
D212="$ROOT/RVSec-D2-registration-provenance-20261026-180412"
D214="$ROOT/RVSec-D2-agent-altkdf-20261104-171835"
D215="$ROOT/RVSec-D2-coverage-failclosed-20261026-184838"
BC="$HOME/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar"
JV="$HOME/.m2/repository/org/javassist/javassist/3.30.2-GA/javassist-3.30.2-GA.jar"
for f in "$D215/d215-agent.jar" "$D215/SHA256SUMS.txt" \
  "$D212/classes/RegistrationTrustExperiment.class" \
  "$D212/classes/KdfBindingExperiment.class" \
  "$D214/alt-classes/RegistrationTrustExperiment.class" \
  "$D214/alt-classes/AlternateKdf.class" "$BC" "$JV"; do
  [[ -f "$f" ]] || { echo "MISSING=$f"; exit 1; }
done
(cd "$D215" && sha256sum -c SHA256SUMS.txt >/dev/null)
(cd "$D214" && sha256sum -c SHA256SUMS.txt >/dev/null)
echo "INPUT_CHECKSUMS=PASS"
mkdir -p "$HOME/pqc-research-private/rvsec-kdf-runs"
OUT="$(mktemp -d "$HOME/pqc-research-private/rvsec-kdf-runs/d215-rerun-XXXXXX")"
for REP in 1 2 3; do
 for VARIANT in ORIGINAL ALTERNATE; do
  for MODE in HONEST FORGED_REGISTRATION; do
   for AMODE in AUDIT ENFORCE; do
    DIR="$OUT/rep$REP/$VARIANT/$MODE/$AMODE"
    mkdir -p "$DIR"
    CP="$D212/classes:$BC:$JV:$D215/d215-agent.jar"
    [[ "$VARIANT" == ORIGINAL ]] || CP="$D214/alt-classes:$CP"
    if (cd "$DIR" && timeout --signal=TERM --kill-after=10s 90s \
      java -Xms128m -Xmx1024m -Dd215.mode="$AMODE" \
      -javaagent:"$D215/d215-agent.jar" -cp "$CP" \
      RegistrationTrustExperiment "$MODE" APPLICATION_REGISTRY ENFORCED \
      > run.log 2>&1); then RC=0; else RC=$?; fi
    echo "$RC" > "$DIR/exit-code.txt"
    echo "REP=$REP VARIANT=$VARIANT MODE=$MODE AGENT_MODE=$AMODE EXIT=$RC"
   done
  done
 done
done
python3 - "$OUT" <<'PY'
from pathlib import Path
import csv,sys
root=Path(sys.argv[1]); rows=[]
for rep in (1,2,3):
 for v in ('ORIGINAL','ALTERNATE'):
  for m in ('HONEST','FORGED_REGISTRATION'):
   for a in ('AUDIT','ENFORCE'):
    path=root/f'rep{rep}'/v/m/a
    raw=(path/'run.log').read_text(errors='replace')
    d={}
    for line in raw.splitlines():
     if '=' in line:
      k,value=line.split('=',1)
      if k.startswith('AGENT_SUMMARY_') or k in ('RESULT','UNBOUND_SECRET_USED','AGENT_MODE','AGENT_PREMAIN','AGENT_COVERAGE_BLOCK_EVENT'):
       d[k]=value.strip()
    alt=v=='ALTERNATE'; forged=m=='FORGED_REGISTRATION'
    cov_block=alt and a=='ENFORCE'
    unbound_block=not alt and forged and a=='ENFORCE'
    block=cov_block or unbound_block
    expect={'AGENT_PREMAIN':'true','AGENT_MODE':a,
       'AGENT_SUMMARY_CAPTURES':'2','AGENT_SUMMARY_TRANSFORMS':'2',
       'AGENT_SUMMARY_DERIVES':str(0 if alt else 1 if unbound_block else 2),
       'AGENT_SUMMARY_MISMATCHES':str(0 if alt or not forged else 1 if unbound_block else 2),
       'AGENT_SUMMARY_COVERAGE_GAPS':str(int(alt)),
       'AGENT_SUMMARY_COVERAGE_BLOCKS':str(int(cov_block)),
       'AGENT_SUMMARY_RECORDS':str(int(not block)),
       'AGENT_SUMMARY_BLOCKS':str(int(block)),
       'AGENT_SUMMARY_END':'true'}
    ok=all(d.get(k)==value for k,value in expect.items())
    ok &= int((path/'exit-code.txt').read_text().strip())==int(block)
    ok &= 'AGENT_TRANSFORM_ERROR=' not in raw
    if cov_block: ok &= 'D215_BLOCKED_KDF_COVERAGE' in raw
    if unbound_block: ok &= 'D215_BLOCKED_UNBOUND_KDF' in raw
    if not block: ok &= d.get('RESULT')=='PASS' and d.get('UNBOUND_SECRET_USED')==str(forged).lower()
    rows.append(dict(rep=rep,variant=v,mode=m,agent_mode=a,expected_match=bool(ok),blocked=bool(block)))
with (root/'results.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
passed=sum(x['expected_match'] for x in rows)
print(f'CHECKED={passed}/{len(rows)}')
for name,condition in [
 ('ORIGINAL_FORGED_BLOCKS',lambda r:r['variant']=='ORIGINAL' and r['mode']=='FORGED_REGISTRATION' and r['agent_mode']=='ENFORCE'),
 ('ALTERNATE_FORGED_BLOCKS',lambda r:r['variant']=='ALTERNATE' and r['mode']=='FORGED_REGISTRATION' and r['agent_mode']=='ENFORCE'),
 ('ALTERNATE_HONEST_BLOCKS',lambda r:r['variant']=='ALTERNATE' and r['mode']=='HONEST' and r['agent_mode']=='ENFORCE')]:
 print(f'{name}={sum(condition(r) and r["expected_match"] for r in rows)}/3')
if passed!=24:
 print('MISMATCHES=',[x for x in rows if not x['expected_match']]);raise SystemExit(1)
print('VERDICT=COVERAGE_AWARE_FAIL_CLOSED_REPRODUCED')
PY
(cd "$OUT" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt)
echo "RESULT_DIR=$OUT"
echo "GITHUB_UNCHANGED=true"
)
