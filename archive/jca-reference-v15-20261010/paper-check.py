"""Synthetic fixtures test result validation, never benchmark or comparator evidence."""
import copy
import importlib.util
import json
import pathlib
import tempfile
BASE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('paper_tool', BASE / 'paper.py')
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
checks = 0

def check(condition):
    global checks
    if not condition: raise AssertionError('Evidence validator regression')
    checks += 1

def refused(call):
    try: call()
    except (ValueError, KeyError): check(True)
    else: raise AssertionError('Invalid result was accepted')

fixtures = []
for fork, profile, operation, size, sample in sorted(tool.expected_cells()):
    fixtures.append({'fork': str(fork), 'profile': str(profile), 'operation': operation,
                     'plaintext_bytes': str(size), 'sample': str(sample), 'ns': str(1000 + fork + sample),
                     'thread_allocated_bytes': '100', 'output_bytes': str(size + 5000 if operation == 'seal_encode' else size if operation == 'decode_open' else 0),
                     'reservation_writes': '0', 'plaintext_sha256': tool.payload_sha(size), 'correct': 'true'})
valid = tool.validate_rows(fixtures); check(len(valid) == 2226)
groups = tool.summarize(valid); check(len(groups) == 21 and all(g['fresh_jvms'] == 6 for g in groups))
refused(lambda: tool.validate_rows(fixtures[:-1]))
refused(lambda: tool.validate_rows(fixtures + [fixtures[0]]))
for field, value in [('ns', '0'), ('ns', '-1'), ('ns', 'NaN'), ('fork', '7'), ('sample', '999'),
                     ('plaintext_sha256', '0' * 64), ('correct', 'false'), ('output_bytes', '0'),
                     ('thread_allocated_bytes', '-1'), ('reservation_writes', '-1'), ('operation', 'attack_rate')]:
    rows = copy.deepcopy(fixtures); target = next(r for r in rows if r['operation'] == 'seal_encode'); target[field] = value
    refused(lambda rows=rows: tool.validate_rows(rows))
rows = copy.deepcopy(fixtures)
for r in rows: r['thread_allocated_bytes'] = ''; r['reservation_writes'] = ''
check(all(g['pooled_median_thread_allocated_bytes'] is None for g in tool.summarize(tool.validate_rows(rows))))
supported = set(tool.PROTOCOL['operations']) - {'upgrade3_to5'}
rows = [r for r in fixtures if r['operation'] in supported]; check(len(tool.validate_rows(rows, supported)) == 2184)
refused(lambda: tool.validate_rows(fixtures, supported)); check(tool.validate_rows([], set()) == [])
with tempfile.TemporaryDirectory(prefix='paper-validator-') as temp:
    path = pathlib.Path(temp) / 'fixture.csv'; path.write_text('wrong,header\n'); refused(lambda: tool.load_rows(path))
    link = pathlib.Path(temp) / 'link.csv'; link.symlink_to(path); refused(lambda: tool.load_rows(link))
output, record, actual = tool.current(); check(len(actual) == 21)
with tempfile.TemporaryDirectory(prefix='paper-import-refusals-') as temp:
    root = pathlib.Path(temp); meta = copy.deepcopy(record)
    for field, value in [('status', 'awaiting_comparator'), ('protocol_sha256', '0' * 64),
                         ('environment_sha256', '0' * 64), ('operation_scopes', {}), ('raw_csv', '../results.csv')]:
        candidate = copy.deepcopy(meta); candidate[field] = value
        candidate['implementation']['id'] = 'SYNTHETIC_VALIDATION_FIXTURE_NOT_COMPARATOR'
        (root / 'metadata.json').write_text(json.dumps(candidate)); refused(lambda: tool.compare(root))
result = {'passed': True, 'checks': checks,
          'scope': 'Synthetic invalid/missing/duplicate result fixtures and actual raw-result checks. No comparator measurements produced.'}
(BASE / 'results/security/paper-validation-checks.json').write_text(json.dumps(result, indent=2) + '\n')
print('PASS paper evidence validator checks=' + str(checks))
