#!/usr/bin/env python3
import csv
import hashlib
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = [('initial', 'initial')] + [
    (f'repeat{i}', f'repeat3/repeat{i}')
    for i in range(1, 4)
]
AGENT_HASH = (
    'a8f888eee1af20c342ff395fea992568'
    'f9546d8fec57222815c81f2460e1608d'
)

def fail(message):
    raise SystemExit('FAIL: ' + str(message))

def read_case(folder, mode):
    target = folder / mode
    log = target / 'run.log'
    csv_path = target / 'summary.csv'
    if not csv_path.is_file():
        csv_path = target / 'output/summary.csv'

    if not log.is_file() or not csv_path.is_file():
        fail('MISSING_LOG_OR_CSV: ' + str(target))

    values = {}
    for line in log.read_text(
        encoding='utf-8', errors='replace'
    ).splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            values[k.strip()] = v.strip()

    expected = {
        'MODE': mode,
        'APP_RESULT': 'PASS',
        'X25519_PROVIDER': 'SunEC',
        'MLKEM_PROVIDER': 'SunJCE',
        'KDF_PROVIDER': 'SunJCE',
        'X25519_SECRET_MATCH': 'true',
        'MLKEM_SECRET_MATCH': 'true',
        'KDF_INPUT_LENGTH': '68' if mode == 'HYBRID' else '34',
        'FINAL_KEY_LENGTH': '32',
        'APP_MLKEM_USED_IN_KDF':
            'true' if mode == 'HYBRID' else 'false',
        'APP_POLICY_VIOLATION':
            'false' if mode == 'HYBRID' else 'true',
    }

    for k, v in expected.items():
        if values.get(k) != v:
            fail(f'{target}: {k} expected={v} actual={values.get(k)}')

    with csv_path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            fail('CSV_HEADER_MISSING: ' + str(csv_path))
        return Counter(
            tuple(sorted(row.items())) for row in reader
        )

def verify(evidence):
    previous_repeat = None

    for label, subdir in CASES:
        a = read_case(evidence / subdir, 'HYBRID')
        b = read_case(evidence / subdir, 'OMIT_KEM')

        na, nb = sum(a.values()), sum(b.values())
        equal = a == b
        stable = (
            None if previous_repeat is None
            else (a, b) == previous_repeat
        )

        print(
            f'{label}: HYBRID={na}, OMIT_KEM={nb}, '
            f'EQUAL={equal}, STABLE={stable}'
        )

        if na != 14 or nb != 14 or not equal:
            fail('WARNING_BASELINE_MISMATCH: ' + label)

        if label != 'initial':
            if stable is False:
                fail('REPEAT_NOT_STABLE: ' + label)
            previous_repeat = (a, b)

    print('EVIDENCE_VERIFY=PASS')

def execute(command, cwd, logfile):
    with logfile.open('w', encoding='utf-8') as f:
        result = subprocess.run(
            command, cwd=cwd,
            stdout=f, stderr=subprocess.STDOUT
        )

    if result.returncode != 0:
        print('\n'.join(
            logfile.read_text(
                encoding='utf-8', errors='replace'
            ).splitlines()[-15:]
        ))
        fail(f'EXECUTION_FAILED: {logfile}')

def rerun():
    home = Path.home()
    java_home = Path(os.environ.get(
        'JAVA25_HOME',
        str(home / '.sdkman/candidates/java/25.0.5.0+8-tem')
    )).expanduser()
    agent = Path(os.environ.get(
        'RVSEC_AGENT',
        str(home / 'pqc-research/D0-rvsec/runs/'
            'CryptoAPIBench-run01/JavaMOPAgent.jar')
    )).expanduser()

    java = java_home / 'bin/java'
    javac = java_home / 'bin/javac'
    source = ROOT / 'src/SunJceHybridProbe.java'

    for p in (java, javac, agent, source):
        if not p.is_file():
            fail('MISSING_PREREQUISITE: ' + str(p))

    digest = hashlib.sha256(agent.read_bytes()).hexdigest()
    if digest != AGENT_HASH:
        fail('AGENT_SHA256_MISMATCH')

    version = subprocess.run(
        [str(java), '-version'],
        capture_output=True, text=True, check=True
    )
    if '25.0.5' not in version.stdout + version.stderr:
        fail('JAVA25_VERSION_MISMATCH')

    output = Path(os.environ.get(
        'D2_OUTPUT_DIR',
        str(home / 'pqc-research/D2-sunjce/reproduction-runs')
    )).expanduser()
    output.mkdir(parents=True, exist_ok=True)

    work = Path(tempfile.mkdtemp(
        prefix='rvsec-d2-', dir=output
    ))
    classes = work / 'classes'
    classes.mkdir()

    execute([
        str(javac), '-source', '8', '-target', '8',
        '-d', str(classes), str(source)
    ], work, work / 'compile.log')

    data = (classes / 'SunJceHybridProbe.class').read_bytes()
    major = int.from_bytes(data[6:8], 'big')
    if data[:4] != bytes.fromhex('CAFEBABE') or major != 52:
        fail('CLASS_VERSION_NOT_52')

    evidence = work / 'evidence'
    for label, subdir in CASES:
        for mode in ('HYBRID', 'OMIT_KEM'):
            folder = evidence / subdir / mode
            folder.mkdir(parents=True)

            execute([
                str(java), '-javaagent:' + str(agent),
                '-cp', str(classes),
                'SunJceHybridProbe', mode
            ], folder, folder / 'run.log')

    verify(evidence)
    print('CLASS_MAJOR_VERSION=52')
    print('INDEPENDENT_RERUN=PASS')
    print('OUTPUT_DIR=' + str(work))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        fail('USAGE: reproduce.py verify|run')

    if sys.argv[1] == 'verify':
        verify(ROOT / 'evidence')
    elif sys.argv[1] == 'run':
        rerun()
    else:
        fail('UNKNOWN_COMMAND')
