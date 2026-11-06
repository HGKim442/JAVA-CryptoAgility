#!/usr/bin/env python3
"""No third-party Python dependencies. Check five JVM forks and summarize within-fork latency."""
import csv
import statistics as stats
import sys
from pathlib import Path


def pct(values, frac):
    s = sorted(values)
    return s[max(0, min(len(s) - 1, int((len(s) - 1) * frac + 0.999999)))]


def main():
    d = Path(sys.argv[1]); forks = []
    for i in range(1, 6):
        f = d / f"fork_{i}.csv"
        with f.open(newline="") as h:
            rows = list(csv.DictReader(h))
        phase = {}
        for row in rows:
            assert row['fork'] == str(i), f"unexpected fork {i}"
            key = (row['phase'], row['mode'])
            assert row['phase'] in ('roundtrip', 'policy_only')
            assert row['mode'] in ('V0','V1','V2')
            phase.setdefault(key, []).append(int(row['elapsed_ns']) / int(row['operations']))
        for m in ('V0','V1','V2'):
            assert len(phase[('roundtrip',m)]) == 300
            assert len(phase[('policy_only',m)]) == 120
        forks.append(phase)
    for metric, unit in (('roundtrip','us'), ('policy_only','ns')):
        scale = 1000 if metric == 'roundtrip' else 1
        print(f"METRIC={metric} UNIT={unit} (each fork contains independent process samples)")
        fork_medians = {}
        for m in ('V0','V1','V2'):
            series = [stats.median(x[(metric,m)])/scale for x in forks]
            fork_medians[m] = series
            print(f"MODE={m} FORK_MEDIANS={','.join(f'{v:.3f}' for v in series)} "
                  f"MEDIAN_OF_FORK_MEDIANS={stats.median(series):.3f}")
        ratios = [(v2/v0 - 1)*100 for v0, v2 in zip(fork_medians['V0'],fork_medians['V2']) if v0 > 0]
        print(f"NORMAL_V2_V0_RELATIVE_DIFF_FORK_PCT={','.join(f'{r:+.2f}' for r in ratios)}")
        print(f"NORMAL_V2_V0_MEDIAN_FORK_DIFF_PCT={stats.median(ratios):+.2f}")
        print("INTERPRETATION=EXPLORATORY_DO_NOT_CLAIM_PRODUCTION_OVERHEAD")
    print("RESULT=FIVE_FORK_TIMING_SUMMARY_PASS")


if __name__ == '__main__':
    main()
