# D2 KDF Agent Verification

Date: 2026-11-04

## WSL verification

| Experiment | Expected results |
|---|---:|
| D2-10/11/12 | 60/60 |
| D2-14 | 24/24 |
| D2-15 | 24/24 |
| D2-15.1 | 24/24 |

## D2-14

The original agent missed a forged-secret condition
when the alternate KDF entrypoint was used.

Alternate-path misses: 3/3.

## D2-15

Coverage-aware fail-closed behavior blocked
the forged alternate KDF path (3/3).

However, it also rejected the honest alternate
KDF path (3/3).

## D2-15.1

Both known KDF entrypoints were instrumented.

- Original honest: allowed 3/3
- Original forged: blocked 3/3
- Alternate honest: allowed 3/3
- Alternate forged: blocked 3/3
- All expected outcomes: 24/24

## Limitations

This is controlled instrumentation of two known
KDF entrypoints, not generic key provenance tracking.

The original RVSec 0.2.0 has not been modified.
Its original warning comparison was not rerun
during these D2 agent experiments.

The D2-15/15.1 scripts currently depend on
previously retained local D2 experiment artifacts.
They are not yet standalone clone-and-run tests.

Full raw execution logs and generated binaries
remain outside the public Git repository.
