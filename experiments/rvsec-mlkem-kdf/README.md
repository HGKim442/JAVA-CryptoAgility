# RVSec / ML-KEM KDF contribution: controlled D2 verification

**Status: experimental control code; NOT an RVSec patch, not a generic PQC-policy detector.**

This branch preserves the original D2-10/11/12 Java test sources **without modifications** and provides a reproducible runner. The test programs use real X25519 and ML-KEM-768 operations via Bouncy Castle 1.86. The KDF is an experimental labeled HMAC construction, **not a standardized hybrid protocol**.

## What is verified

- **D2-10**: `HONEST`, `OMIT`, `SUBSTITUTE`, `WRONG_SESSION` under `ENFORCED`/`AUDIT_ONLY` (8 conditions × 3 repeats).
- **D2-11**: input mutation after check with `DIRECT` vs `PINNED` copy (4 × 3).
- **D2-12**: a forged *application-supplied expected value* can fool a local guard, while an independent provider-derived reference can reject it (8 × 3).
- `AlternateKdf`/`AltKdfParity`: verifies alternate Java KDF implementation returns the same key for equal inputs. **This does NOT verify the Java-Agent D2-14 bypass**.

All 60 cases are judged against **predeclared controlled expectations**: `60/60 PASS` does **not** mean 60 vulnerabilities were prevented. For example D2-12 `FORGED_REGISTRATION APPLICATION_REGISTRY ENFORCED` is expected to demonstrate a **false allowance** (`GUARD_DECISION=ALLOW`, `UNBOUND_SECRET_USED=true`).

These are application-controlled experiments that have access to the intended KEM secrets and ground truth; they do **not independently prove** that RVSec can monitor arbitrary applications or that ML-KEM contributes securely to every KDF.

## Run in WSL/Linux (JDK 21 recommended)

You need `bcprov-jdk18on-1.86.jar` locally. No binary JAR is checked in.

```bash
BC_JAR=/absolute/path/to/bcprov-jdk18on-1.86.jar \
  bash experiments/rvsec-mlkem-kdf/scripts/verify.sh
```

Or omit `BC_JAR` and the runner checks known Maven/experiment locations under `~/pqc-research`.

The runner compiles sources into a **private directory outside the Git branch**, runs tests, and prints `RESULT=PASS` / `RESULT=FAIL`, `RESULT_DIR`, a summary of 60 cases and the JAR hash. Send these output lines to the research partner before committing/pushing.

## Boundaries and publication

- **RVSec 0.2.0 baseline**: earlier 5 pairs of normal vs ML-KEM-omission code gave equal original warning multisets. Those original RVSec runs are *not rerun here*.
- D2-13/14/15 Java-agent tests, multi-thread / cancellation phases D2-16–24 and independent runtime monitoring remain **out of scope for this first branch checkpoint**.
- Never commit private keys, shared secrets, keystore files, local absolute paths, confidential findings, raw unrelated logs or third-party patches.
- This is research evidence for an **optional RVSec feature proposal**, not a claim of vulnerability in RVSec.

See [`docs/EXPERIMENT_MATRIX.md`](docs/EXPERIMENT_MATRIX.md), [`docs/RVSEC_PROPOSAL_SCOPE.md`](docs/RVSEC_PROPOSAL_SCOPE.md) and [`docs/SOURCE_SHA256SUMS.txt`](docs/SOURCE_SHA256SUMS.txt).
