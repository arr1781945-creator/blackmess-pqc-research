"""
Threat Model Generator — BlackMess PQC
Menghasilkan threat model formal dalam format JSON + Markdown
BSI IT-Grundschutz + STRIDE + NIST SP 800-30
BlackMess Research - Ternate, Indonesia
"""
import json
import time
import hashlib

def separator(title):
    print(f"\n{'='*55}\n  {title}\n{'='*55}")

def log(status, msg):
    print(f"\n  {'✅' if status else '❌'} {msg}")

THREAT_MODEL = {
    "metadata": {
        "platform": "BlackMess Enterprise Messaging",
        "version": "2.0",
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "author": "BlackMess Research — Ternate, Indonesia",
        "standards": ["BSI IT-Grundschutz", "STRIDE", "NIST SP 800-30", "ISO 27005"],
    },
    "assets": [
        {"id": "A1", "name": "User Messages", "sensitivity": "CRITICAL",
         "protection": "E2EE Hybrid KEM + AES-256-GCM"},
        {"id": "A2", "name": "Authentication Credentials", "sensitivity": "CRITICAL",
         "protection": "WebAuthn + ML-DSA-65 + JWT"},
        {"id": "A3", "name": "Database Credentials", "sensitivity": "HIGH",
         "protection": "ML-KEM-1024 encrypted vault"},
        {"id": "A4", "name": "User Private Keys", "sensitivity": "CRITICAL",
         "protection": "Never leaves client device"},
        {"id": "A5", "name": "Communication Metadata", "sensitivity": "HIGH",
         "protection": "IPFS + anti-forensik + self-destructing"},
        {"id": "A6", "name": "ML-DSA-65 Public Keys", "sensitivity": "LOW",
         "protection": "Stored in MFADevice — public by design"},
    ],
    "attackers": [
        {"id": "T1", "name": "Network Attacker", "level": "HIGH",
         "capabilities": ["Traffic interception", "MITM", "Replay attacks"],
         "motivation": "Credential theft, message interception"},
        {"id": "T2", "name": "Quantum Attacker", "level": "CRITICAL",
         "capabilities": ["Shor's algorithm", "Grover's algorithm", "Harvest-now-decrypt-later"],
         "motivation": "Break classical cryptography"},
        {"id": "T3", "name": "Compromised Server", "level": "HIGH",
         "capabilities": ["DB access", "Log access", "Memory dump"],
         "motivation": "Mass credential theft"},
        {"id": "T4", "name": "Insider Threat", "level": "MEDIUM",
         "capabilities": ["Physical access", "Admin privileges"],
         "motivation": "Data exfiltration"},
        {"id": "T5", "name": "Nation-State Actor", "level": "CRITICAL",
         "capabilities": ["Unlimited resources", "Zero-days", "Supply chain"],
         "motivation": "Intelligence gathering"},
    ],
    "threats": [
        {
            "id": "TH1", "category": "SPOOFING",
            "description": "Attacker impersonates legitimate user",
            "affected_assets": ["A2"],
            "affected_attackers": ["T1", "T5"],
            "likelihood": "MEDIUM", "impact": "CRITICAL",
            "mitigations": [
                "WebAuthn/FIDO2 phishing-resistant authentication",
                "ML-DSA-65 quantum-safe signature layer",
                "One-time challenge nonce with 30s TTL",
                "JWT pq_verified claim enforcement",
            ],
            "residual_risk": "LOW",
            "status": "MITIGATED",
        },
        {
            "id": "TH2", "category": "TAMPERING",
            "description": "Message modification in transit",
            "affected_assets": ["A1"],
            "affected_attackers": ["T1", "T5"],
            "likelihood": "MEDIUM", "impact": "HIGH",
            "mitigations": [
                "AES-256-GCM authenticated encryption",
                "AAD binding: channel_id + message_id",
                "Per-message HKDF key derivation",
                "Hybrid KEM session key — quantum-safe",
            ],
            "residual_risk": "VERY LOW",
            "status": "MITIGATED",
        },
        {
            "id": "TH3", "category": "REPUDIATION",
            "description": "User denies sending message",
            "affected_assets": ["A1", "A2"],
            "affected_attackers": ["T4"],
            "likelihood": "LOW", "impact": "MEDIUM",
            "mitigations": [
                "ML-DSA-65 per-message signature",
                "Django Axes audit logging",
                "JWT claim binding to user identity",
                "Immutable IPFS storage references",
            ],
            "residual_risk": "LOW",
            "status": "MITIGATED",
        },
        {
            "id": "TH4", "category": "INFORMATION_DISCLOSURE",
            "description": "Credential or message leakage",
            "affected_assets": ["A1", "A2", "A3"],
            "affected_attackers": ["T1", "T2", "T3", "T5"],
            "likelihood": "MEDIUM", "impact": "CRITICAL",
            "mitigations": [
                "Hybrid KEM E2EE — quantum-safe",
                "ML-KEM-1024 encrypted vault for credentials",
                "Zero-knowledge proof for sensitive operations",
                "Anti-forensik + self-destructing messages",
                "Private keys never leave client device",
            ],
            "residual_risk": "LOW",
            "status": "MITIGATED",
        },
        {
            "id": "TH5", "category": "QUANTUM_ATTACK",
            "description": "Shor's algorithm breaks RSA/ECDSA/ECDH",
            "affected_assets": ["A1", "A2", "A3", "A4"],
            "affected_attackers": ["T2", "T5"],
            "likelihood": "FUTURE", "impact": "CRITICAL",
            "mitigations": [
                "ML-KEM-1024 replaces ECDH (FIPS 203)",
                "ML-DSA-65 replaces ECDSA (FIPS 204)",
                "Hybrid KEM: quantum-safe even if classical broken",
                "AES-256 resistant to Grover (128-bit quantum security)",
            ],
            "residual_risk": "VERY LOW",
            "status": "MITIGATED",
        },
        {
            "id": "TH6", "category": "REPLAY_ATTACK",
            "description": "Attacker replays captured auth response",
            "affected_assets": ["A2"],
            "affected_attackers": ["T1", "T5"],
            "likelihood": "HIGH", "impact": "CRITICAL",
            "mitigations": [
                "One-time challenge nonce via Django cache",
                "30-second TTL per challenge",
                "Server-side challenge registry",
                "Timestamp binding in signed payload",
            ],
            "residual_risk": "VERY LOW",
            "status": "MITIGATED",
        },
        {
            "id": "TH7", "category": "DENIAL_OF_SERVICE",
            "description": "Auth endpoint flooding",
            "affected_assets": ["A2"],
            "affected_attackers": ["T1", "T5"],
            "likelihood": "HIGH", "impact": "MEDIUM",
            "mitigations": [
                "Django Axes rate limiting",
                "JWT stateless — no DB per request",
                "Redis cache for challenge storage",
                "Railway auto-scaling",
            ],
            "residual_risk": "MEDIUM",
            "status": "PARTIALLY_MITIGATED",
        },
        {
            "id": "TH8", "category": "ELEVATION_OF_PRIVILEGE",
            "description": "Unauthorized access to admin functions",
            "affected_assets": ["A1", "A2", "A3"],
            "affected_attackers": ["T3", "T4"],
            "likelihood": "LOW", "impact": "CRITICAL",
            "mitigations": [
                "RBAC with clearance_level JWT claim",
                "Django permissions per endpoint",
                "Separate admin URL /_bank_admin_7x9q/",
                "MFA required for admin access",
            ],
            "residual_risk": "LOW",
            "status": "MITIGATED",
        },
    ],
    "residual_risks": [
        {"risk": "Python-level side-channel timing variance",
         "level": "LOW", "note": "liboqs C-level is constant-time"},
        {"risk": "Browser no ML-DSA-65 native support",
         "level": "MEDIUM", "note": "Server-side fallback implemented"},
        {"risk": "User private key loss",
         "level": "MEDIUM", "note": "Key rotation protocol documented"},
        {"risk": "Supply chain attack on liboqs",
         "level": "LOW", "note": "Pin to verified version 0.15.0"},
    ],
}

def generate_threat_model():
    separator("GENERATING THREAT MODEL")

    # Hitung risk score
    likelihood_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "FUTURE": 1, "CRITICAL": 4}
    impact_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    residual_map = {"VERY LOW": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}

    print("\n  Threat Analysis:")
    print(f"  {'ID':<6} {'Category':<25} {'Likelihood':<12} {'Impact':<10} {'Status'}")
    print(f"  {'─'*70}")

    for t in THREAT_MODEL["threats"]:
        l = likelihood_map.get(t["likelihood"], 1)
        i = impact_map.get(t["impact"], 1)
        risk = l * i
        status_icon = "✅" if t["status"] == "MITIGATED" else "⚠️ "
        print(f"  {t['id']:<6} {t['category']:<25} {t['likelihood']:<12} {t['impact']:<10} {status_icon} {t['status']}")

    mitigated = sum(1 for t in THREAT_MODEL["threats"] if t["status"] == "MITIGATED")
    total = len(THREAT_MODEL["threats"])
    log(mitigated >= total * 0.8, f"Threats mitigated: {mitigated}/{total}")

    # Simpan JSON
    with open("threat_model.json", "w") as f:
        json.dump(THREAT_MODEL, f, indent=2)
    log(True, "threat_model.json saved")

    # Generate markdown summary
    md = f"""# BlackMess Threat Model — Summary
**Date:** {THREAT_MODEL['metadata']['date']}
**Standards:** {', '.join(THREAT_MODEL['metadata']['standards'])}

## Assets ({len(THREAT_MODEL['assets'])})
| ID | Asset | Sensitivity | Protection |
|---|---|---|---|
"""
    for a in THREAT_MODEL["assets"]:
        md += f"| {a['id']} | {a['name']} | {a['sensitivity']} | {a['protection']} |\n"

    md += f"\n## Threats ({total}) — {mitigated} Mitigated\n"
    md += "| ID | Category | Likelihood | Impact | Status |\n|---|---|---|---|---|\n"
    for t in THREAT_MODEL["threats"]:
        md += f"| {t['id']} | {t['category']} | {t['likelihood']} | {t['impact']} | {t['status']} |\n"

    md += "\n## Quantum Threat Status\n"
    md += "All classical algorithms replaced or supplemented with NIST FIPS 203/204 compliant PQC.\n"
    md += "Hybrid KEM ensures security during classical-to-quantum transition period.\n"

    with open("threat_model_summary.md", "w") as f:
        f.write(md)
    log(True, "threat_model_summary.md saved")

    return THREAT_MODEL

if __name__ == "__main__":
    print("\n"+"="*55)
    print("  THREAT MODEL GENERATOR")
    print("  BSI IT-Grundschutz + STRIDE + NIST SP 800-30")
    print("  BlackMess Research | Ternate, Indonesia")
    print("="*55)
    tm = generate_threat_model()
    separator("SUMMARY")
    print(f"\n  Assets protected: {len(tm['assets'])}")
    print(f"  Attacker profiles: {len(tm['attackers'])}")
    print(f"  Threats analyzed: {len(tm['threats'])}")
    mitigated = sum(1 for t in tm['threats'] if t['status'] == 'MITIGATED')
    print(f"  Threats mitigated: {mitigated}/{len(tm['threats'])}")
    print(f"  Residual risks: {len(tm['residual_risks'])}")
    print(f"\n  Overall security posture: {'STRONG' if mitigated >= 7 else 'MODERATE'}")
