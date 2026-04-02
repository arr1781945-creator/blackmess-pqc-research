# BlackMess — Threat Model Document
**Version:** 1.0 | **Date:** 2026 | **Author:** BlackMess Research, Ternate, Indonesia
**Standard:** BSI IT-Grundschutz, STRIDE, NIST SP 800-30

---

## 1. System Overview

BlackMess adalah enterprise messaging platform untuk perbankan Indonesia (OJK/BI compliant) dengan post-quantum cryptography.

**Assets yang dilindungi:**
- Pesan pengguna (E2EE, zero-knowledge)
- Kredensial autentikasi (JWT, WebAuthn, ML-DSA-65)
- Database credentials (ML-KEM-1024 vault)
- Private keys pengguna (tidak pernah ke server)
- Metadata komunikasi (IPFS, anti-forensik)

---

## 2. Attacker Model

| Attacker | Kapabilitas | Target |
|---|---|---|
| Network Attacker | Sadap traffic, MITM | Pesan, credentials |
| Quantum Attacker | Shor's algorithm, Grover's | RSA/ECDSA keys |
| Compromised Server | Akses DB, logs | Plaintext, keys |
| Insider Threat | Akses fisik, admin | Private keys |
| Nation-State | Resources tak terbatas | Semua |

---

## 3. Threat Analysis (STRIDE)

### 3.1 Spoofing
- **Threat:** Attacker palsukan identitas user
- **Mitigation:** WebAuthn/FIDO2 + ML-DSA-65 double MFA
- **Status:** ✅ MITIGATED

### 3.2 Tampering
- **Threat:** Modifikasi pesan dalam transit
- **Mitigation:** AES-256-GCM dengan AAD binding (channel_id + message_id)
- **Status:** ✅ MITIGATED

### 3.3 Repudiation
- **Threat:** User menyangkal kirim pesan
- **Mitigation:** ML-DSA-65 signature per pesan, audit log Django Axes
- **Status:** ✅ MITIGATED

### 3.4 Information Disclosure
- **Threat:** Kebocoran pesan atau credentials
- **Mitigation:** E2EE Hybrid KEM, PQC vault, zero-knowledge
- **Status:** ✅ MITIGATED

### 3.5 Denial of Service
- **Threat:** Overload server authentication
- **Mitigation:** Django Axes rate limiting, JWT stateless, Redis cache
- **Status:** ✅ MITIGATED

### 3.6 Elevation of Privilege
- **Threat:** User biasa akses data admin
- **Mitigation:** RBAC, clearance_level JWT claim, Django permissions
- **Status:** ✅ MITIGATED

---

## 4. Quantum Threat Analysis

| Attack | Target | Classical Defense | PQC Defense |
|---|---|---|---|
| Shor's Algorithm | RSA, ECDH, ECDSA | VULNERABLE | ML-KEM-1024, ML-DSA-65 |
| Grover's Algorithm | AES-128 | Weakened | AES-256 (adequate) |
| Harvest Now Decrypt Later | TLS traffic | VULNERABLE | Hybrid KEM |
| Quantum Replay | Auth tokens | Challenge-response | + ML-DSA-65 + nonce |

---

## 5. Key Compromise Protocol

### ML-DSA-65 Private Key Compromise
1. User report ke admin via secure channel
2. Admin revoke MFADevice record di database
3. User generate keypair baru via POST /auth/pq/register/?force_rotate=true
4. Semua JWT lama diinvalidate via blacklist
5. Audit log dicatat dengan timestamp

### ML-KEM-1024 Private Key Compromise
1. Generate new keypair
2. Re-encrypt semua session keys dengan public key baru
3. Notify semua conversation partners untuk re-establish session
4. Old private key dihapus dari memory

---

## 6. Security Controls Summary

| Control | Implementation | Standard |
|---|---|---|
| PQC Key Exchange | X25519 + ML-KEM-1024 Hybrid | NIST FIPS 203, BSI TR-02102 |
| PQC Signatures | ML-DSA-65 | NIST FIPS 204 |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | HKDF-SHA512 / HKDF-SHA256 | RFC 5869 |
| MFA | WebAuthn/FIDO2 + ML-DSA-65 | FIDO2, FIPS 204 |
| Replay Prevention | One-time nonce + TTL 30s | NIST SP 800-63B |
| Access Control | RBAC + clearance_level | NIST SP 800-162 |
| Rate Limiting | Django Axes | NIST SP 800-63B |
| Audit Logging | Django Axes + custom | ISO 27001 A.12.4 |

---

## 7. Residual Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| liboqs side-channel at C level | Low | High | Formal verification needed |
| Browser no ML-DSA-65 support | High | Medium | Server-side fallback implemented |
| Private key loss (user) | Medium | High | Key backup protocol documented |
| Railway infrastructure compromise | Low | High | PQC vault mitigates credentials |
