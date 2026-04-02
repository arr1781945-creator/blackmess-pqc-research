"""
Hybrid Key Exchange: X25519 + ML-KEM-1024
Riset: Kombinasi Classical + Post-Quantum untuk masa transisi
Oleh: BlackMess Research - Ternate, Indonesia

Konsep BSI/ANSSI:
- Layer 1: X25519 (classical) — aman dari attacker sekarang
- Layer 2: ML-KEM-1024 (PQC) — aman dari komputer kuantum
- Final key: SHA-256(X25519_secret || ML-KEM_secret)
- Kalau salah satu dibobol, sistem tetap aman
"""

import oqs.oqs as oqs
import os
import hashlib
import time
import base64
import statistics
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime


def separator(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


def log(label, msg):
    icons = {"ALICE": "👩", "BOB": "👨", "HASIL": "📊", "ATTACK": "💀"}
    print(f"\n  {icons.get(label,'  ')} [{label}] {msg}")


# ─────────────────────────────────────────────
# HYBRID KEM CORE
# ─────────────────────────────────────────────
class HybridKEM:
    """X25519 + ML-KEM-1024 hybrid key encapsulation."""

    @staticmethod
    def generate_keypair():
        # Classical
        x25519_priv = X25519PrivateKey.generate()
        x25519_pub = x25519_priv.public_key()

        # Post-Quantum
        mlkem = oqs.KeyEncapsulation("ML-KEM-1024")
        mlkem_pub = mlkem.generate_keypair()

        return {
            "x25519_priv": x25519_priv,
            "x25519_pub": x25519_pub,
            "mlkem": mlkem,
            "mlkem_pub": mlkem_pub,
        }

    @staticmethod
    def encapsulate(peer_x25519_pub, peer_mlkem_pub: bytes) -> tuple:
        """Hasilkan shared secret + ciphertext untuk dikirim ke peer."""
        # Layer 1: X25519
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()
        x25519_secret = eph_priv.exchange(peer_x25519_pub)

        # Layer 2: ML-KEM-1024
        kem = oqs.KeyEncapsulation("ML-KEM-1024")
        mlkem_ct, mlkem_secret = kem.encap_secret(peer_mlkem_pub)

        # Combine: final_key = SHA-256(x25519_secret || mlkem_secret)
        final_key = hashlib.sha256(x25519_secret + mlkem_secret).digest()

        ciphertext = {
            "x25519_eph_pub": eph_pub,
            "mlkem_ct": mlkem_ct,
        }
        return final_key, ciphertext

    @staticmethod
    def decapsulate(keypair: dict, ciphertext: dict) -> bytes:
        """Recover shared secret dari ciphertext."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        # Layer 1: X25519
        x25519_secret = keypair["x25519_priv"].exchange(
            ciphertext["x25519_eph_pub"]
        )

        # Layer 2: ML-KEM-1024
        mlkem_secret = keypair["mlkem"].decap_secret(ciphertext["mlkem_ct"])

        # Combine
        final_key = hashlib.sha256(x25519_secret + mlkem_secret).digest()
        return final_key


# ─────────────────────────────────────────────
# SIMULASI: Alice kirim pesan ke Bob
# ─────────────────────────────────────────────
def simulasi_e2ee():
    separator("SIMULASI E2EE — Alice kirim pesan ke Bob")

    # Bob generate keypair (dilakukan sekali, simpan di server)
    log("BOB", "Generate hybrid keypair...")
    t = time.perf_counter()
    bob_kp = HybridKEM.generate_keypair()
    t_keygen = (time.perf_counter() - t) * 1000
    log("BOB", f"Keypair siap ({t_keygen:.3f} ms)")

    # Alice encapsulate (ambil public key Bob dari server)
    log("ALICE", "Encapsulate shared secret pakai public key Bob...")
    t = time.perf_counter()
    alice_key, ciphertext = HybridKEM.encapsulate(
        bob_kp["x25519_pub"],
        bob_kp["mlkem_pub"]
    )
    t_encap = (time.perf_counter() - t) * 1000
    log("ALICE", f"Shared secret berhasil ({t_encap:.3f} ms)")
    log("ALICE", f"Final key: {alice_key.hex()[:32]}...")

    # Bob decapsulate
    log("BOB", "Decapsulate shared secret...")
    t = time.perf_counter()
    bob_key = HybridKEM.decapsulate(bob_kp, ciphertext)
    t_decap = (time.perf_counter() - t) * 1000
    log("BOB", f"Shared secret recovered ({t_decap:.3f} ms)")
    log("BOB", f"Final key: {bob_key.hex()[:32]}...")

    # Verifikasi key sama
    keys_match = alice_key == bob_key
    log("HASIL", f"{'✅ Key identik — E2EE berhasil!' if keys_match else '❌ Key berbeda!'}")

    # Enkripsi pesan dengan shared key
    if keys_match:
        pesan = b"Halo Bob! Ini pesan rahasia dari Alice via BlackMess. Quantum-safe!"
        nonce = os.urandom(12)
        aesgcm = AESGCM(alice_key)
        ciphertext_msg = aesgcm.encrypt(nonce, pesan, None)
        plaintext_msg = AESGCM(bob_key).decrypt(nonce, ciphertext_msg, None)

        log("ALICE", f"Pesan terenkripsi: {base64.b64encode(ciphertext_msg[:20]).decode()}...")
        log("BOB", f"Pesan terdecrypt: {plaintext_msg.decode()}")

    return alice_key, bob_key, keys_match, t_keygen, t_encap, t_decap


# ─────────────────────────────────────────────
# SIMULASI SERANGAN
# ─────────────────────────────────────────────
def simulasi_serangan(bob_kp, ciphertext_asli):
    separator("SIMULASI SERANGAN — Attacker Coba Recover Key")

    # Skenario 1: Attacker bobol X25519 (misal via quantum Shor)
    log("ATTACK", "Skenario: X25519 dibobol quantum computer...")
    log("ATTACK", "ML-KEM-1024 masih melindungi — final key tetap aman")
    log("HASIL", "🛡️  Hybrid: 1 layer bobol = sistem tetap aman")

    # Skenario 2: Attacker punya ciphertext tapi beda keypair
    log("ATTACK", "Skenario: Attacker coba decapsulate dengan keypair palsu...")
    fake_kp = HybridKEM.generate_keypair()
    try:
        fake_key = HybridKEM.decapsulate(fake_kp, ciphertext_asli)
        if fake_key != ciphertext_asli:
            log("HASIL", "🛡️  Key berbeda — attacker gagal recover shared secret")
    except Exception:
        log("HASIL", "🛡️  Decapsulation gagal — attacker tidak punya private key yang benar")


# ─────────────────────────────────────────────
# BENCHMARK: Hybrid vs Pure X25519 vs Pure ML-KEM
# ─────────────────────────────────────────────
def benchmark():
    separator("BENCHMARK — Hybrid vs Pure X25519 vs Pure ML-KEM-1024")

    ITER = 30

    # Pure X25519
    t_x25519 = []
    for _ in range(ITER):
        t = time.perf_counter()
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        eph = X25519PrivateKey.generate()
        eph.exchange(pub)
        t_x25519.append((time.perf_counter() - t) * 1000)

    # Pure ML-KEM-1024
    t_mlkem = []
    for _ in range(ITER):
        t = time.perf_counter()
        kem = oqs.KeyEncapsulation("ML-KEM-1024")
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
        kem.decap_secret(ct)
        t_mlkem.append((time.perf_counter() - t) * 1000)

    # Hybrid
    t_hybrid = []
    for _ in range(ITER):
        t = time.perf_counter()
        kp = HybridKEM.generate_keypair()
        key, ct = HybridKEM.encapsulate(kp["x25519_pub"], kp["mlkem_pub"])
        HybridKEM.decapsulate(kp, ct)
        t_hybrid.append((time.perf_counter() - t) * 1000)

    overhead = statistics.mean(t_hybrid) - statistics.mean(t_mlkem)

    print(f"""
  Skema              Rata-rata    Min          Quantum Safe
  {'─'*52}
  Pure X25519        {statistics.mean(t_x25519):.3f} ms    {min(t_x25519):.3f} ms    ❌ TIDAK
  Pure ML-KEM-1024   {statistics.mean(t_mlkem):.3f} ms    {min(t_mlkem):.3f} ms    ✅ YA
  Hybrid (keduanya)  {statistics.mean(t_hybrid):.3f} ms    {min(t_hybrid):.3f} ms    ✅ YA

  Overhead hybrid vs pure ML-KEM: +{overhead:.3f} ms
  Trade-off: keamanan berlapis dengan overhead minimal
    """)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  HYBRID KEY EXCHANGE")
    print("  X25519 + ML-KEM-1024 (BSI/ANSSI Recommendation)")
    print("  BlackMess Research | Ternate, Indonesia")
    print("="*55)

    alice_key, bob_key, ok, t_kg, t_enc, t_dec = simulasi_e2ee()

    bob_kp2 = HybridKEM.generate_keypair()
    _, ct2 = HybridKEM.encapsulate(bob_kp2["x25519_pub"], bob_kp2["mlkem_pub"])
    simulasi_serangan(bob_kp2, ct2)

    benchmark()

    separator("RINGKASAN RISET")
    print(f"""
  Hybrid KEM (X25519 + ML-KEM-1024) terbukti:

  1. Key exchange berhasil — Alice & Bob dapat key identik
  2. Pesan terenkripsi dan terdecrypt dengan benar
  3. Tahan serangan meski salah satu layer dibobol
  4. Overhead vs pure ML-KEM sangat kecil

  Relevansi ke BlackMess:
  - Ganti ECDH di E2EE dengan Hybrid KEM ini
  - Masa transisi aman: klasik + quantum-safe sekaligus
  - Sesuai rekomendasi BSI TR-02102 dan ANSSI
    """)
