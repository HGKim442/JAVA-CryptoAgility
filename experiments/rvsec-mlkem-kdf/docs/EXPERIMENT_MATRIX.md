# D2 controlled experiments and expected outcomes

| Stage | Conditions | Expected observation |
|---|---|---|
| D2-10 | `HONEST/ENFORCED` | guard allows, record succeeds |
| D2-10 | `OMIT/SUBSTITUTE/WRONG_SESSION` + `ENFORCED` | guard rejects, record not processed |
| D2-10 | same invalid modes + `AUDIT_ONLY` | guard warns but record can succeed; expected unsafe path |
| D2-11 | `HONEST` + `DIRECT/PINNED` | KDF input binding stays true |
| D2-11 | `MUTATE_AFTER_CHECK/DIRECT` | binding false: TOCTOU example |
| D2-11 | `MUTATE_AFTER_CHECK/PINNED` | binding true under protected-copy experiment |
| D2-12 | `HONEST` | both reference mechanisms permit |
| D2-12 | `FORGED_REGISTRATION/APPLICATION_REGISTRY/ENFORCED` | **unsafe**: guard allows and unbound secret used |
| D2-12 | `FORGED_REGISTRATION/PROVIDER_REFERENCE/ENFORCED` | guard denies and no unbound secret used |
| D2-12 | `FORGED_REGISTRATION/PROVIDER_REFERENCE/AUDIT_ONLY` | guard denies but audit-only mode continues; unsafe path |

Each stage repeats conditions 3 times (24 + 12 + 24 = 60). `PASS` in `retest.py` means the observed behavior matches the controlled expectation, *not that security checks always succeeded*.

## Current evidence boundaries

The user-reported 2026-11-04 controlled run recorded 60/60 matching expectations. The runner provides a fresh **environment-specific** replay to be checked independently. Java Agent D2-14 is **not** measured by `AltKdfParity`.
