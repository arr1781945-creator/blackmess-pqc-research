"""
Post-Quantum MFA Simulation
Riset: Mengganti ECDSA dengan Dilithium di alur WebAuthn/FIDO2
Oleh: BlackMess Research - Ternate, Indonesia

Alur simulasi:
1. REGISTRATION  - User generate keypair Dilithium, simpan public key di "server"
2. AUTHENTICATION - Server kirim challenge, user sign pakai Dilithium private key
3. VERIFICATION  - Server verifikasi signature dengan public key yang tersimpan

Catatan riset:
- Browser native belum support Dilithium (masih ECDSA/EdDSA)
- Ini proof-of-concept yang membuktikan Dilithium BISA menggantikan ECDSA
- Relevan untuk sistem perbankan (OJK/BI) yang butuh quantum-safe MFA
"""

import oqs.oqs as oqs
import os
import hashlib
import json
import time
import base64
from datetime import datetime


# ─────────────────────────────────────────────
# SIMULASI DATABASE SERVER (in-memory)
# ─────────────────────────────────────────────
SERVER_DB = {}  # { user_id: { public_key, algorithm, registered_at } }


def log(label, msg, data=None):
    print(f"\n  [{label}] {msg}")
    if data:
        print(f"         {data}")


def separator(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# ─────────────────────────────────────────────
# TAHAP 1: REGISTRATION
# ─────────────────────────────────────────────
def registration(user_id: str, algorithm: str = "ML-DSA-65") -> dict:
    separator(f"TAHAP 1: REGISTRATION ({algorithm})")
    log("CLIENT", f"User '{user_id}' memulai registrasi...")

    # 1a. Generate Dilithium keypair (di sisi client/device)
    t_start = time.perf_counter()
    signer = oqs.Signature(algorithm)
    public_key = signer.generate_keypair()
    t_keygen = (time.perf_counter() - t_start) * 1000

    log("CLIENT", f"Keypair Dilithium berhasil dibuat ({t_keygen:.3f} ms)")
    log("CLIENT", f"Public Key size: {len(public_key)} bytes")
    log("CLIENT", f"Private Key size: {len(signer.export_secret_key())} bytes")

    # 1b. Kirim public key ke server untuk disimpan
    SERVER_DB[user_id] = {
        "public_key": public_key,
        "algorithm": algorithm,
        "registered_at": datetime.now().isoformat(),
    }

    log("SERVER", f"Public key '{user_id}' tersimpan di database")
    log("SERVER", f"Public Key (base64): {base64.b64encode(public_key[:32]).decode()}...")

    # Kembalikan signer (private key tetap di client)
    return {"signer": signer, "public_key": public_key, "user_id": user_id}


# ─────────────────────────────────────────────
# TAHAP 2: AUTHENTICATION - Server kirim challenge
# ─────────────────────────────────────────────
def server_generate_challenge(user_id: str) -> dict:
    separator("TAHAP 2: AUTHENTICATION - Server Generate Challenge")

    if user_id not in SERVER_DB:
        raise ValueError(f"User '{user_id}' tidak ditemukan di database!")

    # Server generate random challenge (seperti WebAuthn)
    challenge_raw = os.urandom(32)
    challenge_b64 = base64.b64encode(challenge_raw).decode()

    # Tambahkan metadata (mirip authenticatorData di WebAuthn)
    auth_data = {
        "challenge": challenge_b64,
        "origin": "https://blackmess.id",
        "timestamp": datetime.now().isoformat(),
        "user_id": user_id,
    }

    log("SERVER", "Challenge dikirim ke client")
    log("SERVER", f"Challenge (32 bytes): {challenge_b64[:20]}...")
    log("SERVER", f"Origin: {auth_data['origin']}")

    return auth_data


# ─────────────────────────────────────────────
# TAHAP 3: CLIENT - Sign challenge dengan Dilithium
# ─────────────────────────────────────────────
def client_sign_challenge(signer: oqs.Signature, auth_data: dict) -> dict:
    separator("TAHAP 3: CLIENT - Sign Challenge dengan Dilithium")

    # Buat message yang akan ditandatangani
    # (mirip clientDataJSON di WebAuthn)
    client_data = json.dumps({
        "type": "pq.get",
        "challenge": auth_data["challenge"],
        "origin": auth_data["origin"],
        "timestamp": auth_data["timestamp"],
    }, sort_keys=True).encode()

    # Hash message dulu (SHA-256), lalu sign
    message_hash = hashlib.sha256(client_data).digest()

    t_start = time.perf_counter()
    signature = signer.sign(message_hash)
    t_sign = (time.perf_counter() - t_start) * 1000

    log("CLIENT", f"Challenge ditandatangani dengan Dilithium ({t_sign:.3f} ms)")
    log("CLIENT", f"Signature size: {len(signature)} bytes")
    log("CLIENT", f"Signature (base64): {base64.b64encode(signature[:32]).decode()}...")

    return {
        "user_id": auth_data["user_id"],
        "client_data": client_data,
        "message_hash": message_hash,
        "signature": signature,
    }


# ─────────────────────────────────────────────
# TAHAP 4: SERVER - Verifikasi Signature
# ─────────────────────────────────────────────
def server_verify(response: dict) -> bool:
    separator("TAHAP 4: SERVER - Verifikasi Signature")

    user_id = response["user_id"]

    if user_id not in SERVER_DB:
        log("SERVER", "❌ GAGAL: User tidak ditemukan!")
        return False

    user_record = SERVER_DB[user_id]
    public_key = user_record["public_key"]
    algorithm = user_record["algorithm"]

    log("SERVER", f"Mengambil public key '{user_id}' dari database...")
    log("SERVER", f"Algoritma: {algorithm}")

    # Verifikasi signature
    verifier = oqs.Signature(algorithm)

    t_start = time.perf_counter()
    try:
        is_valid = verifier.verify(
            response["message_hash"],
            response["signature"],
            public_key
        )
        t_verify = (time.perf_counter() - t_start) * 1000

        if is_valid:
            log("SERVER", f"✅ SIGNATURE VALID! ({t_verify:.3f} ms)")
            log("SERVER", "Autentikasi berhasil — User diizinkan masuk")
        else:
            log("SERVER", f"❌ SIGNATURE TIDAK VALID! ({t_verify:.3f} ms)")

        return is_valid

    except Exception as e:
        log("SERVER", f"❌ ERROR verifikasi: {e}")
        return False


# ─────────────────────────────────────────────
# TAHAP 5: TEST SERANGAN - Signature Palsu
# ─────────────────────────────────────────────
def test_serangan(user_id: str, auth_data: dict):
    separator("TAHAP 5: SIMULASI SERANGAN - Signature Palsu")
    log("ATTACKER", "Mencoba memalsukan signature tanpa private key...")

    fake_signature = os.urandom(3293)  # Ukuran signature ML-DSA-65

    fake_response = {
        "user_id": user_id,
        "client_data": b"fake_data",
        "message_hash": hashlib.sha256(b"fake_data").digest(),
        "signature": fake_signature,
    }

    result = server_verify(fake_response)
    if not result:
        log("HASIL", "🛡️  Sistem BERHASIL menolak signature palsu!")
    else:
        log("HASIL", "⚠️  PERINGATAN: Signature palsu diterima (tidak seharusnya terjadi)")


# ─────────────────────────────────────────────
# BENCHMARK PERBANDINGAN DILITHIUM vs ECDSA
# ─────────────────────────────────────────────
def benchmark_vs_ecdsa():
    separator("BONUS: Benchmark ML-DSA-65 vs ECDSA (P-256)")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes as h
    from cryptography.hazmat.backends import default_backend
    import statistics

    ITER = 30
    pesan = hashlib.sha256(b"BlackMess challenge data").digest()

    # ECDSA
    waktu_ecdsa_keygen, waktu_ecdsa_sign, waktu_ecdsa_verify = [], [], []
    for _ in range(ITER):
        t = time.perf_counter()
        priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pub = priv.public_key()
        waktu_ecdsa_keygen.append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        sig = priv.sign(pesan, ec.ECDSA(h.SHA256()))
        waktu_ecdsa_sign.append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        pub.verify(sig, pesan, ec.ECDSA(h.SHA256()))
        waktu_ecdsa_verify.append((time.perf_counter() - t) * 1000)

    # ML-DSA-65
    waktu_dil_keygen, waktu_dil_sign, waktu_dil_verify = [], [], []
    dil_sig_size = 0
    dil_pk_size = 0
    for _ in range(ITER):
        t = time.perf_counter()
        s = oqs.Signature("ML-DSA-65")
        pk = s.generate_keypair()
        waktu_dil_keygen.append((time.perf_counter() - t) * 1000)
        dil_pk_size = len(pk)

        t = time.perf_counter()
        sig = s.sign(pesan)
        waktu_dil_sign.append((time.perf_counter() - t) * 1000)
        dil_sig_size = len(sig)

        t = time.perf_counter()
        v = oqs.Signature("ML-DSA-65")
        v.verify(pesan, sig, pk)
        waktu_dil_verify.append((time.perf_counter() - t) * 1000)

    print(f"""
  {'Metrik':<22} {'ECDSA (P-256)':<18} {'ML-DSA-65 (PQC)':<18}
  {'-'*58}
  {'Key Generation':<22} {statistics.mean(waktu_ecdsa_keygen):.3f} ms{'':<10} {statistics.mean(waktu_dil_keygen):.3f} ms
  {'Sign':<22} {statistics.mean(waktu_ecdsa_sign):.4f} ms{'':<9} {statistics.mean(waktu_dil_sign):.4f} ms
  {'Verify':<22} {statistics.mean(waktu_ecdsa_verify):.4f} ms{'':<9} {statistics.mean(waktu_dil_verify):.4f} ms
  {'Public Key Size':<22} {'64 bytes':<18} {dil_pk_size} bytes
  {'Signature Size':<22} {'~72 bytes':<18} {dil_sig_size} bytes
  {'Quantum Safe?':<22} {'❌ TIDAK':<18} {'✅ YA'}
    """)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  POST-QUANTUM MFA SIMULATION")
    print("  ML-DSA-65 sebagai pengganti ECDSA di WebAuthn")
    print("  BlackMess Research | Ternate, Indonesia")
    print("="*55)

    USER = "anomali@blackmess.id"
    ALGO = "ML-DSA-65"

    # Alur normal
    reg = registration(USER, ALGO)
    auth_data = server_generate_challenge(USER)
    response = client_sign_challenge(reg["signer"], auth_data)
    hasil = server_verify(response)

    # Test serangan
    test_serangan(USER, auth_data)

    # Benchmark
    benchmark_vs_ecdsa()

    separator("RINGKASAN RISET")
    print("""
  Riset ini membuktikan:
  1. ML-DSA-65 DAPAT menggantikan ECDSA di alur WebAuthn
  2. Sistem tahan terhadap signature palsu (serangan klasik)
  3. Trade-off: ukuran signature lebih besar, tapi QUANTUM SAFE
  4. Relevan untuk MFA perbankan OJK/BI di era post-quantum

  Next Step: Integrasi ke Django backend BlackMess
  sebagai custom WebAuthn authenticator.
    """)
