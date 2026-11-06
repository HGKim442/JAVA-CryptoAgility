#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
umask 077
command -v java >/dev/null || { echo 'MISSING=java'; exit 2; }
command -v mvn >/dev/null || { echo 'MISSING=mvn'; exit 2; }
java -version 2>&1 | head -n 3
mvn -version | head -n 4
mvn -B -ntp -DskipTests package dependency:build-classpath \
  -Dmdep.outputFile=target/dependencies.classpath
CP="target/classes:$(cat target/dependencies.classpath)"
mkdir -p reports
java -cp "$CP" CamelPqcPolicyProbe 2>&1 | tee reports/camel_pqc_poc06_result.txt
printf 'NO_CREDENTIALS_OR_SECRETS_LOGGED=true\n'
