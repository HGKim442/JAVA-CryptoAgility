# JAVA-CryptoAgility

Java Cryptographic Agility and Post-Quantum
Cryptography (PQC) Transition Research.

## Public Research Artifacts

### JSSE TLS 1.3 PQC Negotiation Baseline (E2)

- Runtime: Eclipse Temurin JDK 25.0.5
- Protocol: TLS 1.3
- Hybrid group: X25519MLKEM768
- Classical group: x25519

[Experiment Report](docs/jsse-pqc-e2/README.md)

[Experiment Script](scripts/jsse_pqc_policy_matrix.sh)

## Research Objective

Evaluate whether cryptographic policy decisions
match the cryptographic mechanisms actually used.

The JSSE experiment verifies negotiated TLS
key-exchange groups and fail-closed behavior.

## Reproduction

Run:

    bash scripts/jsse_pqc_policy_matrix.sh

The script currently assumes a WSL environment
and machine-specific JDK and output paths.

## Scope and Limitations

- Public reference experiments only.
- Not a complete JCA/JCE policy enforcement system.
- No third-party vulnerability claims.
- No unpublished security findings or private
  research evidence are distributed here.
