# BlackMess Threat Model — Summary
**Date:** 2026-04-02T21:19:49Z
**Standards:** BSI IT-Grundschutz, STRIDE, NIST SP 800-30, ISO 27005

## Assets (6)
| ID | Asset | Sensitivity | Protection |
|---|---|---|---|
| A1 | User Messages | CRITICAL | E2EE Hybrid KEM + AES-256-GCM |
| A2 | Authentication Credentials | CRITICAL | WebAuthn + ML-DSA-65 + JWT |
| A3 | Database Credentials | HIGH | ML-KEM-1024 encrypted vault |
| A4 | User Private Keys | CRITICAL | Never leaves client device |
| A5 | Communication Metadata | HIGH | IPFS + anti-forensik + self-destructing |
| A6 | ML-DSA-65 Public Keys | LOW | Stored in MFADevice — public by design |

## Threats (8) — 7 Mitigated
| ID | Category | Likelihood | Impact | Status |
|---|---|---|---|---|
| TH1 | SPOOFING | MEDIUM | CRITICAL | MITIGATED |
| TH2 | TAMPERING | MEDIUM | HIGH | MITIGATED |
| TH3 | REPUDIATION | LOW | MEDIUM | MITIGATED |
| TH4 | INFORMATION_DISCLOSURE | MEDIUM | CRITICAL | MITIGATED |
| TH5 | QUANTUM_ATTACK | FUTURE | CRITICAL | MITIGATED |
| TH6 | REPLAY_ATTACK | HIGH | CRITICAL | MITIGATED |
| TH7 | DENIAL_OF_SERVICE | HIGH | MEDIUM | PARTIALLY_MITIGATED |
| TH8 | ELEVATION_OF_PRIVILEGE | LOW | CRITICAL | MITIGATED |

## Quantum Threat Status
All classical algorithms replaced or supplemented with NIST FIPS 203/204 compliant PQC.
Hybrid KEM ensures security during classical-to-quantum transition period.
