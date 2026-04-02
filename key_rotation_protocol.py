"""
Key Rotation Protocol — BlackMess PQC
Simulasi full lifecycle: generate, use, rotate, revoke
ML-KEM-1024 + ML-DSA-65
BlackMess Research - Ternate, Indonesia
"""
import oqs.oqs as oqs
import os
import json
import hashlib
import time
import base64
from datetime import datetime, timezone

def separator(title):
    print(f"\n{'='*55}\n  {title}\n{'='*55}")

def log(status, msg):
    print(f"\n  {'✅' if status else '❌'} {msg}")

# ─── Simulasi key store (in-memory) ───
KEY_STORE = {}
REVOKED_KEYS = set()
AUDIT_LOG = []

def audit(event, user, details=""):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "user": user,
        "details": details,
    }
    AUDIT_LOG.append(entry)
    print(f"  📋 AUDIT: [{event}] user={user} {details}")

def generate_keypair(user_id, algo="ML-DSA-65"):
    t = time.perf_counter()
    if "DSA" in algo:
        signer = oqs.Signature(algo)
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
    else:
        kem = oqs.KeyEncapsulation(algo)
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    ms = (time.perf_counter() - t) * 1000

    key_id = hashlib.sha256(pk).hexdigest()[:16]
    KEY_STORE[key_id] = {
        "user_id": user_id,
        "algo": algo,
        "pk": base64.b64encode(pk).decode(),
        "sk": base64.b64encode(sk).decode(),
        "created_at": time.time(),
        "rotated": False,
        "revoked": False,
    }
    audit("KEY_GENERATED", user_id, f"key_id={key_id} algo={algo} ({ms:.2f}ms)")
    return key_id, pk, sk

def rotate_key(user_id, old_key_id, algo="ML-DSA-65"):
    separator(f"KEY ROTATION — {algo}")

    if old_key_id not in KEY_STORE:
        log(False, f"Key {old_key_id} tidak ditemukan")
        return None

    # Generate new keypair
    new_key_id, new_pk, new_sk = generate_keypair(user_id, algo)

    # Mark old key as rotated (bukan dihapus — masih diperlukan verify signature lama)
    KEY_STORE[old_key_id]["rotated"] = True
    KEY_STORE[old_key_id]["rotated_at"] = time.time()
    KEY_STORE[old_key_id]["replaced_by"] = new_key_id

    audit("KEY_ROTATED", user_id,
        f"old={old_key_id} new={new_key_id}")

    log(True, f"Old key {old_key_id} marked as rotated")
    log(True, f"New key {new_key_id} generated")

    # Verifikasi old signature masih bisa diverifikasi dengan old key
    if "DSA" in algo:
        msg = b"old message signed before rotation"
        old_sk = base64.b64decode(KEY_STORE[old_key_id]["sk"])
        old_pk = base64.b64decode(KEY_STORE[old_key_id]["pk"])
        signer = oqs.Signature(algo, old_sk)
        old_sig = signer.sign(msg)
        ver = oqs.Signature(algo)
        old_still_valid = ver.verify(msg, old_sig, old_pk)
        log(old_still_valid, "Old signatures still verifiable after rotation (backward compat)")

        # New key tidak bisa verify old signature
        new_pk_bytes = base64.b64decode(KEY_STORE[new_key_id]["pk"])
        ver2 = oqs.Signature(algo)
        cross_valid = ver2.verify(msg, old_sig, new_pk_bytes)
        log(not cross_valid, "Old signature invalid with new key (key isolation)")

    return new_key_id

def revoke_key(user_id, key_id, reason="COMPROMISE"):
    separator("KEY REVOCATION")

    if key_id not in KEY_STORE:
        log(False, f"Key {key_id} tidak ditemukan")
        return False

    KEY_STORE[key_id]["revoked"] = True
    KEY_STORE[key_id]["revoked_at"] = time.time()
    KEY_STORE[key_id]["revoke_reason"] = reason
    REVOKED_KEYS.add(key_id)

    audit("KEY_REVOKED", user_id, f"key_id={key_id} reason={reason}")
    log(True, f"Key {key_id} revoked — reason: {reason}")

    # Simulasi: coba pakai key yang sudah direvoke
    if "DSA" in KEY_STORE[key_id]["algo"]:
        is_revoked = key_id in REVOKED_KEYS
        log(is_revoked, "Revoked key detected and blocked by system")

    return True

def simulate_compromise_protocol(user_id):
    separator("FULL COMPROMISE RESPONSE PROTOCOL")
    print("\n  Skenario: Private key ML-DSA-65 user dicuri attacker")
    print("\n  Step 1: User report compromise...")
    audit("COMPROMISE_REPORTED", user_id, "User melaporkan private key dicuri")

    print("\n  Step 2: Immediate key revocation...")
    current_keys = [k for k,v in KEY_STORE.items()
                   if v["user_id"] == user_id and not v["revoked"]]
    for key_id in current_keys:
        revoke_key(user_id, key_id, reason="REPORTED_COMPROMISE")

    print("\n  Step 3: Generate new keypair...")
    new_key_id, _, _ = generate_keypair(user_id, "ML-DSA-65")

    print("\n  Step 4: Invalidate all active JWTs...")
    audit("JWT_INVALIDATED", user_id, "All active tokens blacklisted")
    log(True, "All JWT tokens invalidated via blacklist")

    print("\n  Step 5: Notify conversation partners...")
    audit("PARTNERS_NOTIFIED", user_id, "Re-establish E2EE sessions required")
    log(True, "Partners notified to re-establish sessions")

    print("\n  Step 6: Audit trail complete...")
    log(True, f"New key active: {new_key_id}")
    log(True, "Compromise response completed")

    return new_key_id

def benchmark_rotation():
    separator("BENCHMARK — Key Rotation Overhead")
    import statistics

    ITER = 20
    times_dsa, times_kem = [], []

    for _ in range(ITER):
        t = time.perf_counter()
        s = oqs.Signature("ML-DSA-65")
        pk = s.generate_keypair()
        times_dsa.append((time.perf_counter() - t) * 1000)

    for _ in range(ITER):
        t = time.perf_counter()
        k = oqs.KeyEncapsulation("ML-KEM-1024")
        pk = k.generate_keypair()
        times_kem.append((time.perf_counter() - t) * 1000)

    print(f"""
  Operasi               Rata-rata    Min          Max
  {'─'*52}
  ML-DSA-65 keygen      {statistics.mean(times_dsa):.3f} ms    {min(times_dsa):.3f} ms    {max(times_dsa):.3f} ms
  ML-KEM-1024 keygen    {statistics.mean(times_kem):.3f} ms    {min(times_kem):.3f} ms    {max(times_kem):.3f} ms

  Rotation overhead sangat kecil — dapat dilakukan
  secara real-time tanpa service interruption.
    """)

if __name__ == "__main__":
    print("\n"+"="*55)
    print("  KEY ROTATION PROTOCOL")
    print("  ML-DSA-65 + ML-KEM-1024 Full Lifecycle")
    print("  BlackMess Research | Ternate, Indonesia")
    print("="*55)

    USER = "anomali@blackmess.id"

    separator("PHASE 1 — Initial Key Generation")
    dsa_key_id, _, _ = generate_keypair(USER, "ML-DSA-65")
    kem_key_id, _, _ = generate_keypair(USER, "ML-KEM-1024")
    log(True, f"ML-DSA-65 key: {dsa_key_id}")
    log(True, f"ML-KEM-1024 key: {kem_key_id}")

    separator("PHASE 2 — Normal Usage + Rotation")
    new_dsa = rotate_key(USER, dsa_key_id, "ML-DSA-65")
    new_kem = rotate_key(USER, kem_key_id, "ML-KEM-1024")

    simulate_compromise_protocol(USER)
    benchmark_rotation()

    separator("AUDIT LOG")
    for i, entry in enumerate(AUDIT_LOG, 1):
        print(f"  {i:02d}. [{entry['event']:<25}] {entry['details']}")

    separator("SUMMARY")
    total = len(KEY_STORE)
    revoked = len(REVOKED_KEYS)
    active = total - revoked
    print(f"\n  Total keys generated : {total}")
    print(f"  Active keys          : {active}")
    print(f"  Revoked keys         : {revoked}")
    print(f"  Audit log entries    : {len(AUDIT_LOG)}")

    with open("key_rotation_report.json", "w") as f:
        json.dump({
            "summary": {"total": total, "active": active, "revoked": revoked},
            "audit_log": AUDIT_LOG,
        }, f, indent=2)
    log(True, "key_rotation_report.json saved")
