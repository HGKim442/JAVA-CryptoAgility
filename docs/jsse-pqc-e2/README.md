# JSSE TLS 1.3 PQC Negotiation Baseline

Date: 2026-11-03
Runtime: Eclipse Temurin JDK 25.0.5+8-LTS
Research: Java JCA/JCE Cryptographic Agility
Experiment: E2 - PQC Migration Policy

## Objective

Verify whether the actual TLS 1.3 negotiated key exchange
group satisfies the intended cryptographic policy.

A successful TLS connection does not necessarily mean
that post-quantum cryptography was negotiated.

## Experimental Results

| Case | Negotiated Group | Result |
|---|---|---|
| PQC_FIRST | X25519MLKEM768 | PASS |
| CLASSICAL_FIRST | x25519 | PASS |
| CLASSICAL_PEER_OPPORTUNISTIC | x25519 | PASS |
| CLASSICAL_PEER_PQC_REQUIRED | None | REJECT |
| HYBRID_SERVER_PQC_REQUIRED | X25519MLKEM768 | PASS |
| HYBRID_SERVER_RETRY | X25519MLKEM768 | PASS |

## Findings

1. TLS handshake success alone is insufficient to prove PQC usage.
2. The negotiated key exchange group must be verified.
3. Hybrid-only restrictions reject classical-only peers.
4. These experiments establish a fail-closed reference baseline.

## Scope and Limitations

- Local JSSE TLS 1.3 experiments only.
- PQC_REQUIRED represents a named-group restriction,
  not an independent runtime policy engine.
- No third-party vulnerabilities are claimed.
- Unpublished third-party security findings are excluded.

## Execution

Run from WSL/Linux with a compatible JDK, Python 3,
Bash, and keytool:

    bash scripts/jsse_pqc_policy_matrix.sh
