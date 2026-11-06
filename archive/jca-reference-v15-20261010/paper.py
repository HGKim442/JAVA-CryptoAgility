"""Offline normal-workload collection, strict validation and evidence indexing."""
import argparse
import collections
import csv
import datetime
import functools
import hashlib
import json
import math
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import uuid

BASE = pathlib.Path(__file__).resolve().parent
PROTOCOL_PATH = BASE / 'paper/protocol.json'
PROTOCOL = json.loads(PROTOCOL_PATH.read_text())
FIELDS = ['fork', 'profile', 'operation', 'plaintext_bytes', 'sample', 'ns',
          'thread_allocated_bytes', 'output_bytes', 'reservation_writes', 'plaintext_sha256', 'correct']
MAX_CSV = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')


def source_hashes():
    paths = [p for pattern in ('*.java', '*.py', '*.sh') for p in BASE.glob(pattern)]
    paths += [PROTOCOL_PATH, BASE / 'paper/claims.json', BASE / 'paper/e1-protocol.json', BASE / 'dependencies.sha256']
    paths += list((BASE / 'research/e1').glob('*.java')) + list((BASE / 'research').glob('*.py'))
    paths += list((BASE / 'lib').glob('*.jar'))
    paths += list((BASE / 'history-v13').glob('*.reference'))
    paths += list((BASE / 'history-v14').glob('*.reference'))
    paths += list((BASE / 'history-v15-review').glob('*.reference'))
    paths += list((BASE / 'history-v15-file-output').glob('*.reference'))
    paths += list((BASE / 'history-v15-parallel').glob('*.reference'))
    paths += list((BASE / 'history-v15-parallel-risk').glob('*.reference'))
    return {str(p.relative_to(BASE)): sha(p) for p in sorted(paths)}


@functools.lru_cache(maxsize=16)
def payload_sha(size):
    # One 256-byte pattern, generated without allocating a large Python int list.
    pattern = bytes((31 * i + 7) % 256 for i in range(256))
    return hashlib.sha256(pattern * (size // 256) + pattern[:size % 256]).hexdigest()


def expected_cells(supported=None):
    supported = set(PROTOCOL['operations']) if supported is None else set(supported)
    cells = set()
    for fork in range(1, 7):
        for profile in (3, 5):
            for size in PROTOCOL['sizes']:
                for operation in ('seal_encode', 'decode_open'):
                    if operation in supported:
                        cells.update((fork, profile, operation, size['bytes'], i) for i in range(size['samples']))
            for operation in ('create_close', 'reopen_close'):
                if operation in supported:
                    cells.update((fork, profile, operation, 0, i) for i in range(7))
        if 'upgrade3_to5' in supported:
            cells.update((fork, 5, 'upgrade3_to5', 4096, i) for i in range(7))
    return cells


def load_rows(path):
    require(path.is_file() and not path.is_symlink(), 'CSV must be a regular non-symlink file')
    require(path.stat().st_size <= MAX_CSV, 'CSV size limit exceeded')
    with path.open(newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == FIELDS, 'CSV header mismatch')
        rows = list(reader)
    require(len(rows) <= PROTOCOL['total_rows'], 'Excess CSV rows')
    return rows


def validate_rows(rows, supported=None):
    cells = expected_cells(supported)
    seen = set()
    normalized = []
    for row in rows:
        require(set(row) == set(FIELDS), 'Malformed CSV row')
        r = dict(row)
        for name in ('fork', 'profile', 'plaintext_bytes', 'sample', 'ns', 'output_bytes'):
            require(isinstance(r[name], str) and r[name].isdigit(), 'Invalid integer: ' + name)
            r[name] = int(r[name])
        for name in ('thread_allocated_bytes', 'reservation_writes'):
            require(isinstance(r[name], str) and (r[name] == '' or r[name].isdigit()), 'Invalid optional metric')
            r[name] = None if r[name] == '' else int(r[name])
        cell = (r['fork'], r['profile'], r['operation'], r['plaintext_bytes'], r['sample'])
        require(cell in cells and cell not in seen, 'Unexpected or duplicate experiment cell')
        require(r['ns'] > 0 and r['correct'] == 'true', 'Failed correctness or nonpositive timing')
        require(r['plaintext_sha256'] == payload_sha(r['plaintext_bytes']), 'Payload hash mismatch')
        if r['operation'] == 'decode_open':
            require(r['output_bytes'] == r['plaintext_bytes'], 'Plaintext output length mismatch')
        elif r['operation'] == 'seal_encode':
            require(r['output_bytes'] >= r['plaintext_bytes'] + 16, 'Ciphertext output length invalid')
        else:
            require(r['output_bytes'] == 0, 'Lifecycle rows must have no timed output')
        seen.add(cell)
        normalized.append(r)
    require(seen == cells, 'Missing experiment cells: ' + str(len(cells - seen)))
    return normalized


def summarize(rows):
    groups = collections.defaultdict(list)
    for row in rows:
        groups[(row['profile'], row['operation'], row['plaintext_bytes'])].append(row)
    result = []
    for (profile, operation, size), group in sorted(groups.items()):
        forks = []
        for fork in range(1, 7):
            selected = [r for r in group if r['fork'] == fork]
            times = sorted(r['ns'] for r in selected)
            allocations = [r['thread_allocated_bytes'] for r in selected]
            reservations = [r['reservation_writes'] for r in selected]
            forks.append({'fork': fork, 'samples': len(times), 'median_ns': statistics.median(times),
                          'median_thread_allocated_bytes': statistics.median(allocations) if all(x is not None for x in allocations) else None,
                          'nonce_reservation_writes': sum(reservations) if all(x is not None for x in reservations) else None})
        medians = [f['median_ns'] for f in forks]
        times = sorted(r['ns'] for r in group)
        alloc = [r['thread_allocated_bytes'] for r in group]
        result.append({'profile': profile, 'operation': operation, 'plaintext_bytes': size,
                       'fresh_jvms': 6, 'samples': len(times), 'forks': forks,
                       'median_of_fork_medians_ns': statistics.median(medians),
                       'fork_median_min_ns': min(medians), 'fork_median_max_ns': max(medians),
                       'pooled_descriptive_p95_ns': times[math.ceil(0.95 * len(times)) - 1],
                       'pooled_median_thread_allocated_bytes': statistics.median(alloc) if all(x is not None for x in alloc) else None})
    return result


def environment():
    cpu_model = None
    cpuinfo = pathlib.Path('/proc/cpuinfo')
    if cpuinfo.exists():
        cpu_model = next((line.split(':', 1)[1].strip() for line in cpuinfo.read_text().splitlines() if line.startswith('model name')), None)
    return {'platform': platform.platform(), 'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
            'cpu_model': cpu_model,
            'java': subprocess.run(['java', '-version'], capture_output=True, text=True, check=True).stderr,
            'filesystem': subprocess.run(['findmnt', '-T', str(BASE), '-no', 'FSTYPE,OPTIONS'], capture_output=True, text=True, check=True).stdout.strip(),
            'jvm_options': PROTOCOL['jvm_options'],
            'limitations': 'local POSIX environment; filesystem fingerprint does not certify durability; machine load is uncontrolled'}


def environment_sha(env):
    return hashlib.sha256(json.dumps(env, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def table(groups):
    text = ['| 프로필 | 작업 | 입력 B | JVM | 표본 | JVM 중앙값의 중앙 µs | JVM 중앙값 범위 µs | 기술적 p95 µs | Java 스레드 할당 중앙 B |',
            '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    for g in groups:
        alloc = g['pooled_median_thread_allocated_bytes']
        text.append(f"| P{g['profile']} | {g['operation']} | {g['plaintext_bytes']:,} | 6 | {g['samples']} | {g['median_of_fork_medians_ns']/1000:.3f} | {g['fork_median_min_ns']/1000:.3f}–{g['fork_median_max_ns']/1000:.3f} | {g['pooled_descriptive_p95_ns']/1000:.3f} | {'미측정' if alloc is None else f'{alloc:,.0f}'} |")
    return '\n'.join(text) + '\n'


def run():
    before = source_hashes()
    digest, name = (BASE / 'dependencies.sha256').read_text().strip().split()
    require(name == 'lib/bcprov-jdk18on-1.86.jar' and sha(BASE / name) == digest, 'Dependency checksum mismatch')
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    output = BASE / 'results/paper' / run_id
    output.mkdir(parents=True, exist_ok=False)
    env = environment()
    record = {'schema_version': 1, 'status': 'running', 'run_id': run_id,
              'implementation': {'id': 'proposed-v15', 'version': 'v15', 'source_sha256': before},
              'protocol_sha256': sha(PROTOCOL_PATH), 'environment_sha256': environment_sha(env),
              'environment': env, 'operation_scopes': {k: v['scope'] for k, v in PROTOCOL['operations'].items()},
              'unsupported_operations': [], 'raw_csv': 'results.csv', 'artifacts_sha256': {}}
    write_json(output / 'metadata.json', record)
    try:
        (BASE / 'build').mkdir(exist_ok=True)
        compile_command = ['java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '--release', '17', '-Xlint:all', '-Werror',
                           '-cp', 'lib/bcprov-jdk18on-1.86.jar', '-d', 'build'] + [p.name for p in sorted(BASE.glob('*.java'))]
        compiled = subprocess.run(compile_command, cwd=BASE, capture_output=True, text=True, timeout=120)
        (output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        require(compiled.returncode == 0, 'Strict compilation failed; see compile.log')
        rows = []
        for fork in range(1, 7):
            command = ['java'] + PROTOCOL['jvm_options'] + ['-cp', 'build:lib/bcprov-jdk18on-1.86.jar',
                      'PaperBenchmark', str(output / f'fork-{fork}.csv'), str(fork)]
            finished = subprocess.run(command, cwd=BASE, capture_output=True, text=True, timeout=180)
            (output / f'fork-{fork}.log').write_text(finished.stdout + finished.stderr)
            require(finished.returncode == 0, f'Fork {fork} failed; partial run retained, not aggregated')
            sample = load_rows(output / f'fork-{fork}.csv')
            require(len(sample) == PROTOCOL['rows_per_fork'] and all(r['fork'] == str(fork) for r in sample), 'Fork row count mismatch')
            rows.extend(sample)
        checked = validate_rows(rows)
        require(source_hashes() == before, 'Sources changed during measurement')
        with (output / 'results.csv').open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS); writer.writeheader(); writer.writerows(rows)
        groups = summarize(checked)
        write_json(output / 'summary.json', {'passed': True, 'rows': len(rows), 'fresh_jvms': 6, 'groups': groups,
                   'comparator_status': 'awaiting_comparator', 'statistical_scope': PROTOCOL['statistics']})
        (output / 'table.md').write_text(table(groups))
        record['artifacts_sha256'] = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file() and p.name != 'metadata.json'}
        record['status'] = 'complete'
        write_json(output / 'metadata.json', record)
        write_json(BASE / 'results/paper/latest.json', {'run_id': run_id, 'status': 'complete', 'metadata_sha256': sha(output / 'metadata.json')})
        print('PASS paper normal workloads fresh_jvms=6 rows=' + str(len(rows)))
    except Exception:
        record['status'] = 'incomplete'; write_json(output / 'metadata.json', record)
        raise


def current():
    pointer = json.loads((BASE / 'results/paper/latest.json').read_text())
    run_id = pointer.get('run_id', '')
    require(isinstance(run_id, str) and run_id and all(c.isalnum() or c == '-' for c in run_id), 'Invalid run id')
    output = BASE / 'results/paper' / run_id
    require(pointer['status'] == 'complete' and sha(output / 'metadata.json') == pointer['metadata_sha256'], 'Run pointer mismatch')
    record = json.loads((output / 'metadata.json').read_text())
    require(record['status'] == 'complete' and record['protocol_sha256'] == sha(PROTOCOL_PATH), 'Incomplete or different protocol')
    require(record['implementation']['source_sha256'] == source_hashes(), 'Current sources differ from measured sources')
    for name, digest in record['artifacts_sha256'].items():
        require(pathlib.Path(name).name == name and sha(output / name) == digest, 'Result artifact checksum mismatch')
    rows = validate_rows(load_rows(output / record['raw_csv']))
    expected = summarize(rows)
    require(json.loads((output / 'summary.json').read_text())['groups'] == expected, 'Summary differs from raw measurements')
    return output, record, expected


def compare(directory):
    output, record, ours = current()
    metadata_path = directory / 'metadata.json'
    require(metadata_path.is_file() and not metadata_path.is_symlink() and metadata_path.stat().st_size <= MAX_CSV, 'Invalid comparator metadata')
    other = json.loads(metadata_path.read_text())
    require(other.get('schema_version') == 1 and other.get('status') == 'complete', 'Comparator has not been measured')
    require(other.get('protocol_sha256') == record['protocol_sha256'], 'Different workload protocol; no numeric comparison produced')
    require(other.get('environment_sha256') == record['environment_sha256'], 'Different environment; rerun both implementations together')
    require(other.get('operation_scopes') == record['operation_scopes'], 'Timing scope mismatch')
    identity = other.get('implementation', {})
    require(isinstance(identity.get('id'), str) and identity['id'] and identity['id'] != 'proposed-v15', 'Distinct comparator identity required')
    require(isinstance(identity.get('version'), str) and identity['version'], 'Comparator version required')
    require(isinstance(identity.get('source_sha256'), dict) and identity['source_sha256'], 'Comparator source hashes required')
    require(all(isinstance(v, str) and len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in identity['source_sha256'].values()), 'Invalid comparator source hashes')
    unsupported = other.get('unsupported_operations', [])
    require(isinstance(unsupported, list) and all(isinstance(x, str) for x in unsupported) and len(unsupported) == len(set(unsupported)) and set(unsupported) <= set(PROTOCOL['operations']), 'Invalid unsupported operation list')
    supported = set(PROTOCOL['operations']) - set(unsupported)
    require(other.get('raw_csv') == 'results.csv', 'Comparator data must be results.csv, no arbitrary paths')
    external = summarize(validate_rows(load_rows(directory / 'results.csv'), supported))
    lookup = {(g['profile'], g['operation'], g['plaintext_bytes']): g for g in external}
    groups = []
    for group in ours:
        key = (group['profile'], group['operation'], group['plaintext_bytes'])
        if group['operation'] not in supported:
            groups.append({'profile': key[0], 'operation': key[1], 'plaintext_bytes': key[2], 'status': 'unsupported'})
        else:
            c = lookup[key]
            groups.append({'profile': key[0], 'operation': key[1], 'plaintext_bytes': key[2], 'status': 'measured',
                           'proposed_median_of_fork_medians_ns': group['median_of_fork_medians_ns'],
                           'comparator_median_of_fork_medians_ns': c['median_of_fork_medians_ns'],
                           'proposed_over_comparator_time_ratio': group['median_of_fork_medians_ns'] / c['median_of_fork_medians_ns']})
    result = {'status': 'normal_workload_comparison', 'comparator': identity, 'groups': groups,
              'source_data_sha256': sha(directory / 'results.csv'), 'metadata_sha256': sha(metadata_path),
              'scope': 'Descriptive timing ratio only; self-declared adapter semantics require manual review. No attack rate or significance claim.'}
    target = output / ('comparison-' + uuid.uuid4().hex[:8] + '.json')
    write_json(target, result)
    print('PASS imported normal comparator; comparison file=' + str(target.relative_to(BASE)))


def audit():
    output, record, groups = current()
    run_record = json.loads((BASE / 'run.json').read_text())
    require(run_record['exit_code'] == 0, 'Full regression run did not pass')
    require(run_record.get('input_sha256') == source_hashes(), 'Regression inputs differ from current source')
    require(run_record['source_sha256'] == {p.name: sha(p) for p in sorted(BASE.glob('*.java'))}, 'Regression Java source mismatch')
    count_files = {'results/recovery/recovery-results.json': 133,
                   'results/security/security-audit-tests.json': 15,
                   'results/security/lifecycle-cleanup-tests.json': 10,
                   'results/security/codec-regression.json': 109,
                   'results/security/cli-checks.json': 81,
                   'results/security/cli-wrapper-checks.json': 6,
                   'results/security/easy-checks.json': 31,
                   'results/security/easy-optimization.json': 25,
                   'results/security/reuse-cleanup.json': 19,
                   'results/security/easy-batch-checks.json': 77,
                   'results/security/store-isolation.json': 8,
                   'results/security/parallel-batch-checks.json': 1435,
                   'results/security/easy-parallel-checks.json': 78,
                   'results/security/parallel-risk-checks.json': 31,
                   'results/security/easy-stream-checks.json': 29,
                   'results/security/parallel-followup-checks.json': 30,
                   'results/security/easy-cancel-checks.json': 10,
                   'results/security/cli-build-checks.json': 13,
                   'results/security/cli-cache-checks.json': 13,
                   'results/security/cli-integrity-checks.json': 7,
                   'results/security/packet-stream-checks.json': 51,
                   'results/security/packet-stream-roundtrips.json': 14,
                   'results/security/decrypt-memory-checks.json': 98,
                   'results/security/decrypt-auth-checks.json': 72,
                   **{'results/file-output/fork-'+str(f)+'/file-output-checks.json': 62 for f in range(1,4)}}
    for name, count in count_files.items():
        result = json.loads((BASE / name).read_text())
        require(result['passed'] is True and result['checks'] == count, 'Evidence count mismatch: ' + name)
    risk = json.loads((BASE / 'results/parallel-risk/summary.json').read_text())
    require(risk['passed'] and (risk['rows'], risk['fresh_jvms'], risk['normal_decryptions']) == (216, 72, 2304), 'Risk comparison incomplete')
    require(risk['current_java_sha256'] == {p.name: sha(p) for p in sorted(BASE.glob('*.java'))}, 'Risk comparison sources changed')
    require(len(risk['raw_sha256']) == 72, 'Risk comparison raw files incomplete')
    for name, digest in risk['raw_sha256'].items():
        require(sha(BASE / name) == digest, 'Risk CSV checksum changed')
    matrix_paths = sorted((BASE / 'results/evidence').glob('fork-*/evidence-matrix.csv'))
    require(len(matrix_paths) == 6, 'Expected six defensive matrix forks')
    identities = None
    for path in matrix_paths:
        with path.open(newline='') as stream:
            matrix = list(csv.DictReader(stream))
        keys = {(r['profile'], r['requirement'], r['case_name']) for r in matrix}
        require(len(matrix) == len(keys) == 76 and all(r['passed'] == 'true' for r in matrix), 'Matrix incomplete, duplicate or failed')
        require(identities is None or identities == keys, 'Matrix case identities differ between forks')
        identities = keys
        require(json.loads((path.parent / 'evidence-summary.json').read_text())['parser_cases'] == 1024, 'Parser trial count mismatch')
    claims = json.loads((BASE / 'paper/claims.json').read_text())
    require(len(claims) == 9 and len({c['id'] for c in claims}) == 9, 'Claim ids missing or duplicated')
    referenced = set(count_files) | {'run.json', 'run.log', 'environment.json', 'summary.json', 'paper/protocol.json', 'paper/claims.json', 'results/paper/latest.json'}
    for claim in claims:
        require(claim['assumptions'] and claim['excludes'], 'Claim scope incomplete')
        for name in claim['sources'] + claim['evidence']:
            relative = pathlib.Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts and (BASE / name).is_file(), 'Missing or invalid claim evidence: ' + name)
            referenced.add(name)
    referenced.update(str(p.relative_to(BASE)) for p in matrix_paths)
    referenced.update(str(p.relative_to(BASE)) for p in output.iterdir() if p.is_file() and not p.name.startswith('comparison-'))
    index = {'passed': True, 'claim_count': 9, 'defensive_matrix_unique_cases': 76, 'defensive_matrix_repeated_rows': 456,
             'parser_trials': 6144, 'normal_workload_rows': PROTOCOL['total_rows'], 'fresh_workload_jvms': 6,
             'evidence_sha256': {name: sha(BASE / name) for name in sorted(referenced)},
             'comparator_status': 'awaiting_comparator',
             'scope': 'Evidence presence, identity, count and digest check; not proof that all security claims are true.'}
    write_json(BASE / 'paper/evidence-index.json', index)
    print('PASS evidence audit claims=9 unique_matrix_cases=76 normal_workload_rows=2226; comparator=awaiting')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('run', 'check', 'audit'):
        sub.add_parser(command)
    compare_parser = sub.add_parser('compare'); compare_parser.add_argument('directory', type=pathlib.Path)
    args = parser.parse_args()
    if args.command == 'run': run()
    elif args.command == 'check':
        current(); print('PASS raw cells, payloads, checksums, source provenance and aggregate equivalence')
    elif args.command == 'audit': audit()
    else: compare(args.directory)


if __name__ == '__main__':
    try: main()
    except (ValueError, KeyError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print('ERROR evidence validation: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
