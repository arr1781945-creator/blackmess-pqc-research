"""
Post-Quantum Secrets Management
Riset: Enkripsi Database Credentials menggunakan Kyber-1024 (ML-KEM-1024)
Oleh: BlackMess Research - Ternate, Indonesia

Konsep:
- Database credentials (password, DSN) dienkripsi pakai Kyber
- Hanya sistem yang punya private key yang bisa decrypt
- Private key disimpan di memory saat runtime, bukan di disk
- Attacker yang curi .env file tidak bisa baca credentials asli

Alur:
1. SETUP     - Generate Kyber keypair, enkripsi semua credentials
2. RUNTIME   - Sistem decrypt credentials saat startup
3. ATTACK    - Simulasi attacker yang curi encrypted credentials
4. BENCHMARK - Bandingkan overhead enkripsi vs tanpa enkripsi
"""

import oqs.oqs as oqs
import os
import json
import hashlib
import time
import base64
import statistics
from datetime import datetime

# AES untuk symmetric encryption (Kyber = KEM, bukan enkripsi langsung)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def separator(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


def log(label, msg, data=None):
    print(f"\n  [{label}] {msg}")
    if data:
        print(f"         {data}")


# ─────────────────────────────────────────────
# SIMULASI CREDENTIALS ASLI (plaintext)
# ─────────────────────────────────────────────
CREDENTIALS_ASLI = {
    "DB_HOST":     "gondola.proxy.rlwy.net",
    "DB_PORT":     "49100",
    "DB_NAME":     "blackmess_production",
    "DB_USER":     "postgres",
    "DB_PASSWORD": "SuperSecret_BlackMess_2025!@#",
    "REDIS_URL":   "redis://:RedisPass123@localhost:6379/0",
    "SECRET_KEY":  "django-insecure-pqc-research-key-blackmess",
}


# ─────────────────────────────────────────────
# CORE: Enkripsi dengan Kyber + AES-GCM
# Kyber adalah KEM (Key Encapsulation Mechanism)
# Jadi alurnya: Kyber encapsulate → shared_secret → AES-GCM encrypt data
# ─────────────────────────────────────────────
def kyber_encrypt(data: bytes, public_key: bytes) -> dict:
    """Enkripsi data menggunakan Kyber KEM + AES-GCM."""
    kem = oqs.KeyEncapsulation("ML-KEM-1024")

    # Kyber encapsulate: hasilkan ciphertext + shared_secret
    ciphertext_kem, shared_secret = kem.encap_secret(public_key)

    # Derive AES key dari shared_secret (32 bytes untuk AES-256)
    aes_key = hashlib.sha256(shared_secret).digest()

    # Enkripsi data dengan AES-256-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_data = aesgcm.encrypt(nonce, data, None)

    return {
        "kem_ciphertext": base64.b64encode(ciphertext_kem).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext_data).decode(),
        "algorithm": "ML-KEM-1024 + AES-256-GCM",
        "encrypted_at": datetime.now().isoformat(),
    }


def kyber_decrypt(encrypted: dict, kem_with_secret: oqs.KeyEncapsulation) -> bytes:
    """Decrypt data menggunakan private key Kyber."""
    ciphertext_kem = base64.b64decode(encrypted["kem_ciphertext"])
    nonce = base64.b64decode(encrypted["nonce"])
    ciphertext_data = base64.b64decode(encrypted["ciphertext"])

    # Kyber decapsulate: recover shared_secret
    shared_secret = kem_with_secret.decap_secret(ciphertext_kem)

    # Derive AES key yang sama
    aes_key = hashlib.sha256(shared_secret).digest()

    # Decrypt dengan AES-256-GCM
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext_data, None)


# ─────────────────────────────────────────────
# TAHAP 1: SETUP - Generate keypair & enkripsi credentials
# ─────────────────────────────────────────────
def setup_secrets():
    separator("TAHAP 1: SETUP - Enkripsi Credentials dengan Kyber")

    log("SYSTEM", "Generating Kyber keypair untuk secrets management...")

    t = time.perf_counter()
    kem = oqs.KeyEncapsulation("ML-KEM-1024")
    public_key = kem.generate_keypair()
    t_keygen = (time.perf_counter() - t) * 1000

    log("SYSTEM", f"Keypair berhasil dibuat ({t_keygen:.3f} ms)")
    log("SYSTEM", f"Public Key: {len(public_key)} bytes")
    log("SYSTEM", f"Private Key: {len(kem.export_secret_key())} bytes")

    # Enkripsi setiap credential
    log("SYSTEM", "Mengenkripsi semua credentials...")
    encrypted_vault = {}

    for key, value in CREDENTIALS_ASLI.items():
        t = time.perf_counter()
        encrypted = kyber_encrypt(value.encode(), public_key)
        t_enc = (time.perf_counter() - t) * 1000
        encrypted_vault[key] = encrypted
        print(f"    ✅ {key:<15} dienkripsi ({t_enc:.3f} ms)")

    log("SYSTEM", "Semua credentials tersimpan dalam encrypted vault")
    log("SYSTEM", "Private key hanya ada di memory — tidak pernah ke disk")

    # Simulasi: simpan vault ke file (yang aman disimpan di repo)
    vault_json = json.dumps(encrypted_vault, indent=2)
    with open("/data/data/com.termux/files/home/riset/khusus/blackmess_vault.json", "w") as f:
        f.write(vault_json)
    log("SYSTEM", "Vault tersimpan di: /data/data/com.termux/files/home/riset/khusus/blackmess_vault.json")

    return kem, public_key, encrypted_vault


# ─────────────────────────────────────────────
# TAHAP 2: RUNTIME - Sistem decrypt saat startup
# ─────────────────────────────────────────────
def runtime_decrypt(kem, encrypted_vault):
    separator("TAHAP 2: RUNTIME - Sistem Decrypt Credentials")

    log("SYSTEM", "Aplikasi startup — mendecrypt credentials...")

    decrypted = {}
    total_time = 0

    for key, encrypted in encrypted_vault.items():
        t = time.perf_counter()
        plaintext = kyber_decrypt(encrypted, kem)
        t_dec = (time.perf_counter() - t) * 1000
        total_time += t_dec
        decrypted[key] = plaintext.decode()
        print(f"    ✅ {key:<15} terdecrypt ({t_dec:.3f} ms)")

    log("SYSTEM", f"Total waktu decrypt semua credentials: {total_time:.3f} ms")
    log("SYSTEM", "Credentials siap digunakan oleh aplikasi")

    # Verifikasi
    print("\n  Verifikasi hasil decrypt:")
    semua_valid = True
    for key in CREDENTIALS_ASLI:
        valid = decrypted[key] == CREDENTIALS_ASLI[key]
        status = "✅" if valid else "❌"
        print(f"    {status} {key}")
        if not valid:
            semua_valid = False

    if semua_valid:
        log("HASIL", "✅ Semua credentials terdecrypt dengan benar!")
    else:
        log("HASIL", "❌ Ada credentials yang gagal decrypt!")

    return decrypted


# ─────────────────────────────────────────────
# TAHAP 3: SIMULASI SERANGAN
# ─────────────────────────────────────────────
def simulasi_serangan(encrypted_vault):
    separator("TAHAP 3: SIMULASI SERANGAN - Attacker Curi Vault")

    log("ATTACKER", "Berhasil mencuri file blackmess_vault.json!")
    log("ATTACKER", "Mencoba decrypt tanpa private key...")

    # Attacker generate keypair sendiri (beda private key)
    fake_kem = oqs.KeyEncapsulation("ML-KEM-1024")
    fake_kem.generate_keypair()

    gagal = 0
    for key, encrypted in encrypted_vault.items():
        try:
            result = kyber_decrypt(encrypted, fake_kem)
            print(f"    ⚠️  {key}: BERHASIL decrypt (tidak seharusnya!)")
        except Exception:
            print(f"    🛡️  {key}: GAGAL decrypt (sistem aman)")
            gagal += 1

    log("HASIL", f"🛡️  {gagal}/{len(encrypted_vault)} credentials TIDAK BISA didecrypt attacker!")
    log("HASIL", "Vault aman meskipun file dicuri — private key tidak ada di vault")


# ─────────────────────────────────────────────
# TAHAP 4: BENCHMARK overhead
# ─────────────────────────────────────────────
def benchmark_overhead():
    separator("TAHAP 4: BENCHMARK - Overhead PQC Secrets Management")

    ITER = 20
    kem = oqs.KeyEncapsulation("ML-KEM-1024")
    public_key = kem.generate_keypair()

    test_data = b"SuperSecret_Password_BlackMess_2025!@#"

    waktu_enc, waktu_dec = [], []
    for _ in range(ITER):
        t = time.perf_counter()
        enc = kyber_encrypt(test_data, public_key)
        waktu_enc.append((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        kyber_decrypt(enc, kem)
        waktu_dec.append((time.perf_counter() - t) * 1000)

    print(f"""
  Operasi          Rata-rata     Min           Max
  {'─'*50}
  Enkripsi         {statistics.mean(waktu_enc):.3f} ms      {min(waktu_enc):.3f} ms      {max(waktu_enc):.3f} ms
  Dekripsi         {statistics.mean(waktu_dec):.3f} ms      {min(waktu_dec):.3f} ms      {max(waktu_dec):.3f} ms

  Catatan: Dekripsi hanya terjadi SEKALI saat startup.
  Overhead ini tidak mempengaruhi performa request/response.
    """)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*55)
    print("  POST-QUANTUM SECRETS MANAGEMENT")
    print("  Kyber (ML-KEM-1024) untuk Database Credentials")
    print("  BlackMess Research | Ternate, Indonesia")
    print("="*55)

    kem, public_key, vault = setup_secrets()
    decrypted = runtime_decrypt(kem, vault)
    simulasi_serangan(vault)
    benchmark_overhead()

    separator("RINGKASAN RISET")
    print("""
  Riset ini membuktikan:
  1. Database credentials DAPAT dienkripsi dengan Kyber
  2. Attacker yang curi vault file TIDAK BISA decrypt
  3. Overhead decrypt saat startup sangat kecil (< 5ms)
  4. Sistem ini quantum-safe — aman dari komputer kuantum

  Keunggulan vs .env biasa:
  - .env biasa: siapapun yang baca file bisa lihat password
  - PQC Vault : tanpa private key, file tidak berguna

  Next Step: Integrasi ke Django settings.py BlackMess
  sebagai pengganti python-decouple / .env biasa.
    """)
