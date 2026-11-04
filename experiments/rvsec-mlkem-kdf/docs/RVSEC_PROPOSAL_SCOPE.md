# Separate RVSec proposal — not an implementation claim

## Existing observation

Earlier RVSec 0.2.0 original instrumentation produced matching warning multisets for five normal vs ML-KEM secret-omission pairs (Java 8/17 BC JCA/Lightweight and Java 21 standard KEM + BC, with classfile major-52 workaround for Java 21). The original tool does not claim PQC KDF-contribution checking, so this is **out-of-scope policy behavior**, not automatically an RVSec bug.

## Optional proposed extension

Explore a policy-aware event chain `ML-KEM shared-secret source → permitted transforms → final KDF sink → selected policy/request context`. In `PQC_REQUIRED`, report demonstrated absence of a required source, and return `INDETERMINATE` for uninstrumented paths rather than assuming compliance.

D2-12 demonstrates why app-provided source metadata is not sufficient evidence. D2-11 shows mutable inputs may change between check and use. D2-14 prior Java Agent experiments motivate supporting multiple KDF entrypoints, but they are **not reproduced by this branch checkpoint**.

## Next verification checkpoint

1. Run this D2-10/11/12 package on the researcher's WSL and preserve runtime, BC JAR hash, and result CSV privately.
2. Recover the **actual D2-14 agent source and matching original logs**, replay agent-equipped alternate KDF test.
3. Re-run RVSec 0.2.0 unchanged with normal vs omission pairs and compare CSV warning multisets.
4. Only then finalize an optional rule proposal to upstream. Do not send this branch's test program as proof of independently functioning runtime taint tracking.
