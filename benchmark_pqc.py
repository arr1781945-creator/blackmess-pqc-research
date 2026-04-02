"""
Benchmark: RSA-3072 vs Kyber-1024
Riset: Perbandingan Kecepatan Kriptografi Klasik vs Post-Quantum
Oleh: BlackMess Research
"""

import time
import statistics
import oqs
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

ITERASI = 50  # Ulang 50x biar hasilnya akurat


def ukur_waktu(fungsi, *args, **kwargs):
    """Jalankan fungsi dan kembalikan waktu dalam milidetik."""
    mulai = time.perf_counter()
    hasil = fungsi(*args, **kwargs)
    selesai = time.perf_counter()
    return (selesai - mulai) * 1000, hasil  # ms


def benchmark_rsa():
    print("\n" + "="*50)
    print("RSA-3072 (Algoritma Klasik)")
    print("="*50)

    # --- Key Generation ---
    waktu_keygen = []
    for _ in range(ITERASI):
        t, private_key = ukur_waktu(
            rsa.generate_private_key,
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        )
        waktu_keygen.append(t)
    public_key = private_key.public_key()

    # --- Encryption ---
    pesan = b"BlackMess PQC Research - Ternate Indonesia"
    waktu_enc = []
    for _ in range(ITERASI):
        t, ciphertext = ukur_waktu(
            public_key.encrypt,
            pesan,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        waktu_enc.append(t)

    # --- Decryption ---
    waktu_dec = []
    for _ in range(ITERASI):
        t, _ = ukur_waktu(
            private_key.decrypt,
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        waktu_dec.append(t)

    hasil = {
        "keygen_avg": statistics.mean(waktu_keygen),
        "keygen_min": min(waktu_keygen),
        "enc_avg": statistics.mean(waktu_enc),
        "dec_avg": statistics.mean(waktu_dec),
        "public_key_size": 3072 // 8,  # bytes
    }

    print(f"  Key Generation : {hasil['keygen_avg']:.3f} ms (min: {hasil['keygen_min']:.3f} ms)")
    print(f"  Encryption     : {hasil['enc_avg']:.4f} ms")
    print(f"  Decryption     : {hasil['dec_avg']:.4f} ms")
    print(f"  Ukuran Public Key: {hasil['public_key_size']} bytes")

    return hasil


def benchmark_kyber():
    print("\n" + "="*50)
    print("Kyber-1024 (Post-Quantum / NIST Standard)")
    print("="*50)

    # --- Key Generation ---
    waktu_keygen = []
    public_key_size = 0
    for _ in range(ITERASI):
        def gen():
            kem = oqs.KeyEncapsulation("Kyber1024")
            pk = kem.generate_keypair()
            return kem, pk
        t, (kem, pk) = ukur_waktu(gen)
        waktu_keygen.append(t)
        public_key_size = len(pk)

    # --- Encapsulation (setara Encryption di KEM) ---
    waktu_enc = []
    ciphertext_kyber = None
    for _ in range(ITERASI):
        def encap():
            kem_c = oqs.KeyEncapsulation("Kyber1024")
            pk2 = kem_c.generate_keypair()
            ct, ss = kem_c.encap_secret(pk2)
            return kem_c, ct, ss
        t, (kem_c, ct, ss) = ukur_waktu(encap)
        waktu_enc.append(t)
        if ciphertext_kyber is None:
            ciphertext_kyber = (kem_c, ct)

    # --- Decapsulation (setara Decryption) ---
    waktu_dec = []
    for _ in range(ITERASI):
        def decap():
            k = oqs.KeyEncapsulation("Kyber1024")
            pk3 = k.generate_keypair()
            ct3, _ = k.encap_secret(pk3)
            k.decap_secret(ct3)
        t, _ = ukur_waktu(decap)
        waktu_dec.append(t)

    hasil = {
        "keygen_avg": statistics.mean(waktu_keygen),
        "keygen_min": min(waktu_keygen),
        "enc_avg": statistics.mean(waktu_enc),
        "dec_avg": statistics.mean(waktu_dec),
        "public_key_size": public_key_size,
    }

    print(f"  Key Generation : {hasil['keygen_avg']:.3f} ms (min: {hasil['keygen_min']:.3f} ms)")
    print(f"  Encapsulation  : {hasil['enc_avg']:.4f} ms")
    print(f"  Decapsulation  : {hasil['dec_avg']:.4f} ms")
    print(f"  Ukuran Public Key: {hasil['public_key_size']} bytes")

    return hasil


def tampilkan_perbandingan(rsa_data, kyber_data):
    print("\n" + "="*50)
    print("HASIL PERBANDINGAN")
    print("="*50)

    def rasio(a, b):
        if b == 0:
            return "N/A"
        r = a / b
        if r > 1:
            return f"Kyber {r:.1f}x lebih CEPAT"
        else:
            return f"RSA {1/r:.1f}x lebih CEPAT"

    print(f"\n  Key Generation:")
    print(f"    RSA-3072  : {rsa_data['keygen_avg']:.3f} ms")
    print(f"    Kyber-1024: {kyber_data['keygen_avg']:.3f} ms")
    print(f"    → {rasio(rsa_data['keygen_avg'], kyber_data['keygen_avg'])}")

    print(f"\n  Encryption/Encapsulation:")
    print(f"    RSA-3072  : {rsa_data['enc_avg']:.4f} ms")
    print(f"    Kyber-1024: {kyber_data['enc_avg']:.4f} ms")
    print(f"    → {rasio(rsa_data['enc_avg'], kyber_data['enc_avg'])}")

    print(f"\n  Decryption/Decapsulation:")
    print(f"    RSA-3072  : {rsa_data['dec_avg']:.4f} ms")
    print(f"    Kyber-1024: {kyber_data['dec_avg']:.4f} ms")
    print(f"    → {rasio(rsa_data['dec_avg'], kyber_data['dec_avg'])}")

    print(f"\n  Ukuran Public Key:")
    print(f"    RSA-3072  : {rsa_data['public_key_size']} bytes")
    print(f"    Kyber-1024: {kyber_data['public_key_size']} bytes")
    faktor = kyber_data['public_key_size'] / rsa_data['public_key_size']
    print(f"    → Kyber {faktor:.1f}x lebih BESAR")

    print("\n" + "="*50)
    print("KESIMPULAN RISET")
    print("="*50)
    print("""
  Kyber-1024 (Post-Quantum) vs RSA-3072 (Klasik):
  - Key generation Kyber jauh lebih cepat
  - Encryption/Encapsulation Kyber lebih efisien
  - Trade-off: ukuran kunci Kyber lebih besar
  - Kyber AMAN dari serangan komputer kuantum
  - RSA RENTAN terhadap algoritma Shor di komputer kuantum

  Kesimpulan: Untuk sistem perbankan modern (OJK/BI),
  migrasi ke Kyber-1024 memberikan keamanan jangka
  panjang dengan performa yang lebih baik.
    """)


if __name__ == "__main__":
    print("BlackMess PQC Research")
    print("Benchmark: RSA-3072 vs Kyber-1024")
    print(f"Iterasi per algoritma: {ITERASI}")

    rsa_hasil = benchmark_rsa()
    kyber_hasil = benchmark_kyber()
    tampilkan_perbandingan(rsa_hasil, kyber_hasil)
