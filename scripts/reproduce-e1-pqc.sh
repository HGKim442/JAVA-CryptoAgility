#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

bash scripts/build.sh
python3 e1.py

echo "PASS: E1/PQC 재현 실행 완료"
echo "결과 위치: results/e1/current 및 results/pqc-downgrade/current"
