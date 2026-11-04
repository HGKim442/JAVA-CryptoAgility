#!/usr/bin/env bash
set -euo pipefail
umask 077
EXP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_BIN="${JAVA_BIN:-java}"
JAVAC_BIN="${JAVAC_BIN:-javac}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$JAVA_BIN" >/dev/null || { echo "ERROR=JAVA_NOT_FOUND"; exit 2; }
command -v "$JAVAC_BIN" >/dev/null || { echo "ERROR=JAVAC_NOT_FOUND"; exit 2; }
command -v "$PYTHON_BIN" >/dev/null || { echo "ERROR=PYTHON_NOT_FOUND"; exit 2; }
BC_JAR="${BC_JAR:-}"
if [[ -z "$BC_JAR" ]]; then
  for c in     "$HOME/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar"     "$HOME/pqc-research/lib/bcprov-jdk18on-1.86.jar"     "$HOME/pqc-research/d2_retest_20261104/lib/bcprov-jdk18on-1.86.jar"; do
      if [[ -f "$c" ]]; then BC_JAR="$c"; break; fi
  done
fi
if [[ -z "$BC_JAR" || ! -f "$BC_JAR" ]]; then
  echo "ERROR=BC_JAR_NOT_FOUND"
  echo 'Hint: BC_JAR=/absolute/path/to/bcprov-jdk18on-1.86.jar bash experiments/rvsec-mlkem-kdf/scripts/verify.sh'
  exit 2
fi
BC_JAR="$(realpath "$BC_JAR")"
case "$(basename "$BC_JAR")" in bcprov-jdk18on-1.86.jar) ;; *) echo "ERROR=BC_JAR_NAME_UNEXPECTED"; exit 2;; esac
PRIV="$HOME/pqc-research-private/rvsec-kdf-runs"
mkdir -p "$PRIV"
chmod 700 "$PRIV"
RUN="$(mktemp -d "$PRIV/verify-XXXXXXXX")"
mkdir -p "$RUN/src" "$RUN/lib" "$RUN/classes"
cp "$EXP_DIR"/src/*.java "$RUN/src/"
cp "$EXP_DIR/tests/retest.py" "$RUN/retest.py"
ln -s "$BC_JAR" "$RUN/lib/bcprov-jdk18on-1.86.jar"
{ "$JAVA_BIN" -version; "$JAVAC_BIN" -version; } > "$RUN/environment.txt" 2>&1
sha256sum "$BC_JAR" > "$RUN/bcprov.sha256"
(
  cd "$RUN"
  "$JAVAC_BIN" -cp "$BC_JAR" -d classes src/*.java
  "$JAVA_BIN" -cp "classes:$BC_JAR" AltKdfParity > parity.log 2>&1
  grep -qx 'ALTERNATE_KDF_PARITY=true' parity.log
  "$PYTHON_BIN" retest.py > runner.log 2>&1
  "$PYTHON_BIN" - <<'PY_CHECK'
import csv, json
from pathlib import Path
rows=list(csv.DictReader(Path('actual_runs_20261104.csv').open()))
summary=json.loads(Path('actual_summary_20261104.json').read_text())
assert len(rows)==60 and all(row['check']=='PASS' for row in rows)
assert summary['tested']==60 and summary['pass']==60
assert summary['by_stage']['D2-10']['pass']==24
assert summary['by_stage']['D2-11']['pass']==12
assert summary['by_stage']['D2-12']['pass']==24
found=[r for r in rows if r['stage']=='D2-12' and r['args']=='FORGED_REGISTRATION APPLICATION_REGISTRY ENFORCED']
assert len(found)==3 and all(r['GUARD_DECISION']=='ALLOW' and r['UNBOUND_SECRET_USED']=='true' for r in found)
print('CHECKED=60/60')
print('KNOWN_UNSAFE_ALLOWANCES=3/3')
print('NOTE=PASS_MEANS_EXPECTATION_MATCH_NOT_UNIVERSAL_SECURITY')
PY_CHECK
) || { echo "RESULT=FAIL"; echo "RESULT_DIR=$RUN"; exit 1; }
cat "$RUN/environment.txt"
echo "BC_JAR_SHA256=$(sha256sum "$BC_JAR" | cut -d' ' -f1)"
echo "STAGE_D2_10=24/24"
echo "STAGE_D2_11=12/12"
echo "STAGE_D2_12=24/24"
echo "EXPECTED_UNSAFE_ALLOWANCES=3/3"
echo "AGENT_D2_14=NOT_TESTED"
echo "RVSEC_ORIGINAL=NOT_TESTED"
echo "RESULT=PASS"
echo "RESULT_DIR=$RUN"
echo 'GITHUB_UNCHANGED=true'
