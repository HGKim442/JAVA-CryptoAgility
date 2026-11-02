#!/usr/bin/env python3
"""Read-only WSL experiment collector. Copies logs/classes/sources (no secrets by default).
Usage: python3 collect_rvsec_baseline_20261102.py
"""
import csv
import hashlib
import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

home = Path.home()
root = home / 'pqc-research/D0-rvsec'
runs = root / 'runs'
out = runs / 'RVSec-PQC-baseline-evidence-20261102'
if out.exists():
    raise SystemExit(f'EXISTS: {out} (will not overwrite; move/rename manually if rerun is needed)')
out.mkdir(parents=True)

cases = {
    'java8_17': runs / 'RVSec-JDK8-17-PQC-comparison-20261102',
    'java21_kem': runs / 'RVSec-JDK21-classfile8-KEM-control-20261102',
    'java21_control': runs / 'RVSec-JDK21-cross-compile-control-20261102',
    'java21_bytecode': runs / 'RVSec-JDK21-bytecode-control-20261102',
    'java21_classfile17': runs / 'RVSec-JDK21-classfile17-control-20261102',
    'java21_kem_original': runs / 'RVSec-JDK21-KEM-policy-20261102',
    'original24': runs / 'RVSec-BC-PQC-observability-20261102-152403-2195',
}
selected_extensions = {'.log', '.csv', '.json', '.java', '.class', '.py', '.mop', '.md', '.txt'}
records = []
missing = []
for label, src in cases.items():
    if not src.is_dir():
        missing.append(str(src)); continue
    for p in sorted(src.rglob('*')):
        if not p.is_file() or p.suffix.lower() not in selected_extensions:
            continue
        rel = p.relative_to(src)
        dest = out / 'sources' / label / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        b = dest.read_bytes()
        records.append({'path': str(dest.relative_to(out)), 'sha256': hashlib.sha256(b).hexdigest(), 'bytes': len(b)})

static = {
    'JavaMOPAgent.jar': runs / 'CryptoAPIBench-run01/JavaMOPAgent.jar',
    'bcprov-jdk18on-1.86.jar': home / '.m2/repository/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar',
    'KeyGeneratorSpec.mop': root / 'rvsec/rvsec/rvsec-agent/src/main/mop/KeyGeneratorSpec.mop',
    'MacSpec.mop': root / 'rvsec/rvsec/rvsec-agent/src/main/mop/MacSpec.mop',
    'SecretKeySpecSpec.mop': root / 'rvsec/rvsec/rvsec-agent/src/main/mop/SecretKeySpecSpec.mop',
}
identities = {}
for name, p in static.items():
    if p.is_file():
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        identities[name] = {'path': str(p), 'sha256': digest, 'bytes': p.stat().st_size}
        if p.suffix == '.mop':
            target = out / 'mop' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
    else:
        identities[name] = {'missing': str(p)}

def warnings(path):
    if not path.is_file():
        return None
    with path.open(newline='', encoding='utf-8') as f:
        return Counter(tuple(sorted(row.items())) for row in csv.DictReader(f))

def app(path):
    if not path.is_file(): return {}
    d = {}
    for line in path.read_text(errors='replace').splitlines():
        if line.startswith('APP_') and '=' in line:
            k, v = line.split('=', 1); d[k] = v
    return d

comparisons = []
for java in ('java8', 'java17'):
    for surface in ('JCA', 'LW'):
        base = cases['java8_17'] / java
        good = base / (surface + '_HYBRID')
        bad = base / (surface + '_OMIT_KEM')
        comparisons.append((java, surface, good, bad))
base = cases['java21_kem']
comparisons.append(('java21', 'javax.crypto.KEM', base / 'on', base / 'omit/on'))
results = []
for version, surface, good, bad in comparisons:
    wg = warnings(good / 'output/summary.csv')
    wb = warnings(bad / 'output/summary.csv')
    ag, ab = app(good / 'run.log'), app(bad / 'run.log')
    present = wg is not None and wb is not None
    status = (present and wg == wb and ag.get('APP_RESULT') == 'PASS' and ab.get('APP_RESULT') == 'PASS'
              and ag.get('APP_MLKEM_USED_IN_KDF') == 'true'
              and ab.get('APP_MLKEM_USED_IN_KDF') == 'false'
              and ag.get('APP_POLICY_VIOLATION') == 'false'
              and ab.get('APP_POLICY_VIOLATION') == 'true')
    results.append({'java': version, 'surface': surface, 'normal_warning_count': None if wg is None else sum(wg.values()),
                    'omit_warning_count': None if wb is None else sum(wb.values()), 'warning_multiset_equal': None if not present else wg == wb,
                    'ground_truth_and_output_check': bool(status), 'normal_path': str(good), 'omit_path': str(bad)})

manifest = {'generated_utc': datetime.now(timezone.utc).isoformat(), 'scope': 'Existing runs only; no execution',
            'excluded': 'No keys/secrets intentionally collected, but check logs before sharing externally',
            'missing_directories': missing, 'identities': identities, 'files': records, 'comparisons': results}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
with (out / 'SHA256SUMS.txt').open('w') as f:
    for r in records:
        f.write(f"{r['sha256']}  {r['path']}\n")
with (out / 'comparison.csv').open('w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=['java','surface','normal_warning_count','omit_warning_count','warning_multiset_equal','ground_truth_and_output_check','normal_path','omit_path'])
    writer.writeheader(); writer.writerows(results)

print('EVIDENCE_DIR=', out)
for r in results:
    print(f"{r['java']} / {r['surface']}: warnings={r['normal_warning_count']}/{r['omit_warning_count']} equal={r['warning_multiset_equal']} CHECK={r['ground_truth_and_output_check']}")
print('COPIED_FILES=', len(records), 'MISSING_DIRS=', len(missing))
print('READ_ONLY_SOURCE_FILES=true')
print('OUTPUT_NEW_DIR_ONLY=true')
