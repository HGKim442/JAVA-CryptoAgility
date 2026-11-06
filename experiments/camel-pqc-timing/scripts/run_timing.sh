#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
for app in java mvn python3 sha256sum; do
  command -v "$app" >/dev/null || { echo "MISSING=$app"; exit 2; }
done
sha256sum -c SHA256SUMS.txt
mvn -B -ntp -DskipTests package dependency:build-classpath -Dmdep.outputFile=target/dependencies.classpath
CP="target/classes:$(cat target/dependencies.classpath)"
RUN_DIR="reports/normal_timing_$(date -u +%Y%m%dT%H%M%SZ)_$$"
mkdir -p "$RUN_DIR"
printf '%s\n' "JAVA_VERSION=$(java -version 2>&1 | head -n1)" "HOST=$(uname -s -m)" > "$RUN_DIR/environment.txt"
for i in 1 2 3 4 5; do
  echo "START_FORK=$i"
  java -cp "$CP" CamelPqcP1E1Timing "$i" "$RUN_DIR/fork_${i}.csv" \
    > "$RUN_DIR/fork_${i}.log" 2>&1 || {
      cat "$RUN_DIR/fork_${i}.log"
      echo "FORK_FAILURE=$i"
      exit 1
    }
  grep -q '^RESULT=NORMAL_TIMING_EXPLORATORY_PASS$' "$RUN_DIR/fork_${i}.log" || {
    cat "$RUN_DIR/fork_${i}.log"
    echo "MISSING_PASS_MARKER=$i"
    exit 1
  }
  grep '^MODE=' "$RUN_DIR/fork_${i}.log"
  echo "FORK=$i PASS"
done
python3 scripts/summarize_timing.py "$RUN_DIR" | tee "$RUN_DIR/summary.txt"
sha256sum "$RUN_DIR"/*.csv "$RUN_DIR"/*.log "$RUN_DIR/summary.txt" > "$RUN_DIR/SHA256_REPORT.txt"
echo "RESULT_DIR=$RUN_DIR"
echo "RESULT=FIVE_FORK_TIMING_COLLECTED"
