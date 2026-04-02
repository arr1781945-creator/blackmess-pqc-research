# BlackMess PQC Research Suite

> Post-Quantum Cryptography implementation and benchmarks for enterprise banking messaging.
> **Author:** BlackMess Research — Ternate, North Maluku, Indonesia
> **Platform:** Android/Termux, Python 3.12, liboqs 0.15.0

## Overview

This repository contains 9 independent research experiments demonstrating practical viability of NIST-standardized post-quantum cryptographic algorithms (FIPS 203, FIPS 204) on commodity ARM hardware.

## Key Results

| Experiment | Finding |
|---|---|
| ML-KEM-1024 vs RSA-3072 | **673x faster** key generation |
| ML-DSA-65 vs ECDSA P-256 | Comparable verify latency (0.85ms vs 0.88ms) |
| Hybrid KEM overhead | +2.258ms vs pure ML-KEM — negligible |
| Replay attack prevention | 4/4 attack vectors blocked |
| NIST FIPS 203/204 | All property tests PASS |
| Threat model | 7/8 threats fully mitigated |

## Experiments

| File | Description |
|---|---|
| `benchmark_pqc.py` | RSA-3072 vs ML-KEM-1024 (50 iterations) |
| `pq_mfa_simulation.py` | ML-DSA-65 replacing ECDSA in WebAuthn flow |
| `pq_secrets.py` | ML-KEM-1024 encrypted credential vault |
| `pq_replay_prevention.py` | One-time nonce + TTL challenge system |
| `pq_hybrid_kem.py` | X25519 + ML-KEM-1024 hybrid key exchange |
| `nist_test_vectors.py` | NIST FIPS 203/204 property verification |
| `threat_model_generator.py` | BSI IT-Grundschutz + STRIDE threat model |
| `key_rotation_protocol.py` | Full key lifecycle + compromise response |
| `side_channel_analysis.py` | Timing analysis — 200 iterations per op |

## Production Integration

Research implemented in [BlackMess](https://black-message.vercel.app) Django backend:
- `apps/users/pq_mfa.py` — ML-DSA-65 MFA layer on top of WebAuthn/FIDO2
- `apps/messaging/hybrid_kem.py` — Hybrid KEM E2EE (X25519 + ML-KEM-1024)

JWT claims include `pq_verified: true` and `pq_algorithm: ML-DSA-65`.

## Standards Compliance

| Standard | Status |
|---|---|
| NIST FIPS 203 (ML-KEM) | ✅ Implemented |
| NIST FIPS 204 (ML-DSA) | ✅ Implemented |
| BSI TR-02102-1 | ✅ Hybrid KEM compliant |
| ANSSI PQC Guide | ✅ Double-layer KEM |
| OJK POJK 11/2022 | ✅ Banking MFA requirement |
| NSA CNSA 2.0 | ✅ PQC adopted |

## Setup

```bash
pip install liboqs-python cryptography
python benchmark_pqc.py
ENOFFILE
