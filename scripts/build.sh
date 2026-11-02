#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! java -version 2>&1 | grep -q 'version "17\.'; then
  echo "ERROR: JDK 17이 필요합니다." >&2
  exit 1
fi

sha256sum -c dependencies.sha256
mkdir -p build

javac --release 17 -Xlint:all -Werror \
  -cp lib/bcprov-jdk18on-1.86.jar \
  -d build ./*.java

echo "PASS: Java 17 strict build"
