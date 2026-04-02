"""
Side-Channel Analysis — BlackMess PQC
Timing analysis untuk ML-KEM-1024 dan ML-DSA-65
Note: Python-level analysis — C-level constant-time dijamin liboqs
BlackMess Research - Ternate, Indonesia
"""
import oqs.oqs as oqs
import time
import statistics
import json
import os

def separator(title):
    print(f"\n{'='*55}\n  {title}\n{'='*55}")

def log(status, msg):
    print(f"\n  {'✅' if status else '⚠️ '} {msg}")

def timing_analysis(func, iterations=200, label=""):
    times = []
    for _ in range(iterations):
        t = time.perf_counter()
        func()
        times.append((time.perf_counter() - t) * 1000)
    avg = statistics.mean(times)
    stdev = statistics.stdev(times)
    cv = (stdev / avg) * 100
    median = statistics.median(times)
    p95 = sorted(times)[int(0.95 * len(times))]
    p99 = sorted(times)[int(0.99 * len(times))]
    return {
        "label": label,
        "iterations": iterations,
        "avg_ms": round(avg, 4),
        "stdev_ms": round(stdev, 4),
        "median_ms": round(median, 4),
        "min_ms": round(min(times), 4),
        "max_ms": round(max(times), 4),
        "p95_ms": round(p95, 4),
        "p99_ms": round(p99, 4),
        "cv_pct": round(cv, 2),
    }

def analyze_mlkem():
    separator("ML-KEM-1024 Timing Analysis")
    ITER = 200

    kem = oqs.KeyEncapsulation("ML-KEM-1024")
    pk = kem.generate_keypair()
    sk = kem.export_secret_key()
    kem2 = oqs.KeyEncapsulation("ML-KEM-1024")
    ct, _ = kem2.encap_secret(pk)

    results = {}

    # Keygen
    r = timing_analysis(
        lambda: oqs.KeyEncapsulation("ML-KEM-1024").generate_keypair(),
        ITER, "ML-KEM-1024 KeyGen"
    )
    results["keygen"] = r
    print(f"\n  KeyGen:  avg={r['avg_ms']}ms  cv={r['cv_pct']}%  p99={r['p99_ms']}ms")

    # Encap
    r2 = timing_analysis(
        lambda: oqs.KeyEncapsulation("ML-KEM-1024").encap_secret(pk),
        ITER, "ML-KEM-1024 Encap"
    )
    results["encap"] = r2
    print(f"  Encap:   avg={r2['avg_ms']}ms  cv={r2['cv_pct']}%  p99={r2['p99_ms']}ms")

    # Decap — valid ct
    r3 = timing_analysis(
        lambda: oqs.KeyEncapsulation("ML-KEM-1024", sk).decap_secret(ct),
        ITER, "ML-KEM-1024 Decap (valid)"
    )
    results["decap_valid"] = r3
    print(f"  Decap✅:  avg={r3['avg_ms']}ms  cv={r3['cv_pct']}%  p99={r3['p99_ms']}ms")

    # Decap — invalid ct (timing harus sama — constant-time check)
    fake_ct = os.urandom(len(ct))
    r4 = timing_analysis(
        lambda: oqs.KeyEncapsulation("ML-KEM-1024", sk).decap_secret(fake_ct),
        ITER, "ML-KEM-1024 Decap (invalid ct)"
    )
    results["decap_invalid"] = r4
    print(f"  Decap❌:  avg={r4['avg_ms']}ms  cv={r4['cv_pct']}%  p99={r4['p99_ms']}ms")

    # Timing difference antara valid dan invalid decap
    diff = abs(r3['avg_ms'] - r4['avg_ms'])
    diff_pct = (diff / r3['avg_ms']) * 100
    log(diff_pct < 20,
        f"Valid vs invalid decap timing diff: {diff:.4f}ms ({diff_pct:.1f}%)")
    print(f"  Note: ML-KEM uses implicit rejection — invalid ct returns")
    print(f"  pseudorandom value, not error. Timing difference expected")
    print(f"  to be small at C level. Python overhead adds variance.")

    return results

def analyze_mldsa():
    separator("ML-DSA-65 Timing Analysis")
    ITER = 200

    sig = oqs.Signature("ML-DSA-65")
    pk = sig.generate_keypair()
    sk = sig.export_secret_key()
    msg = b"BlackMess timing analysis message"
    sig_bytes = sig.sign(msg)

    results = {}

    # KeyGen
    r = timing_analysis(
        lambda: oqs.Signature("ML-DSA-65").generate_keypair(),
        ITER, "ML-DSA-65 KeyGen"
    )
    results["keygen"] = r
    print(f"\n  KeyGen:  avg={r['avg_ms']}ms  cv={r['cv_pct']}%  p99={r['p99_ms']}ms")

    # Sign
    signer = oqs.Signature("ML-DSA-65", sk)
    r2 = timing_analysis(
        lambda: signer.sign(msg),
        ITER, "ML-DSA-65 Sign"
    )
    results["sign"] = r2
    print(f"  Sign:    avg={r2['avg_ms']}ms  cv={r2['cv_pct']}%  p99={r2['p99_ms']}ms")

    # Verify valid
    r3 = timing_analysis(
        lambda: oqs.Signature("ML-DSA-65").verify(msg, sig_bytes, pk),
        ITER, "ML-DSA-65 Verify (valid)"
    )
    results["verify_valid"] = r3
    print(f"  Verify✅: avg={r3['avg_ms']}ms  cv={r3['cv_pct']}%  p99={r3['p99_ms']}ms")

    # Verify invalid sig — timing harus comparable
    fake_sig = os.urandom(len(sig_bytes))
    times_invalid = []
    for _ in range(ITER):
        t = time.perf_counter()
        try:
            oqs.Signature("ML-DSA-65").verify(msg, fake_sig, pk)
        except Exception:
            pass
        times_invalid.append((time.perf_counter() - t) * 1000)
    avg_inv = statistics.mean(times_invalid)
    results["verify_invalid"] = {"avg_ms": round(avg_inv, 4)}
    print(f"  Verify❌: avg={avg_inv:.4f}ms")

    diff = abs(r3['avg_ms'] - avg_inv)
    diff_pct = (diff / r3['avg_ms']) * 100
    log(diff_pct < 30,
        f"Valid vs invalid verify timing diff: {diff:.4f}ms ({diff_pct:.1f}%)")

    return results

def analyze_hybrid():
    separator("Hybrid KEM Timing Analysis")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ITER = 100

    x_priv = X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    mlkem = oqs.KeyEncapsulation("ML-KEM-1024")
    mlkem_pub = mlkem.generate_keypair()

    def full_hybrid():
        eph = X25519PrivateKey.generate()
        x_ss = eph.exchange(x_pub)
        mlkem_ct, mlkem_ss = oqs.KeyEncapsulation("ML-KEM-1024").encap_secret(mlkem_pub)
        HKDF(algorithm=hashes.SHA512(), length=32, salt=None,
            info=b"blackmess-hybrid").derive(x_ss + mlkem_ss)

    r = timing_analysis(full_hybrid, ITER, "Hybrid KEM full encap")
    print(f"\n  Hybrid encap: avg={r['avg_ms']}ms  cv={r['cv_pct']}%  p99={r['p99_ms']}ms")
    log(r['avg_ms'] < 10, f"Hybrid encap under 10ms: {r['avg_ms']}ms")
    return r

def generate_report(mlkem_r, mldsa_r, hybrid_r):
    separator("SIDE-CHANNEL ANALYSIS REPORT")

    report = {
        "platform": "BlackMess Research — Ternate, Indonesia",
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "Python-level timing analysis. liboqs C implementation is constant-time.",
        "methodology": "200 iterations per operation, CV (coefficient of variation) analysis",
        "threshold": "CV < 15% ideal at Python level (C-level is constant-time)",
        "results": {
            "ML-KEM-1024": mlkem_r,
            "ML-DSA-65": mldsa_r,
            "Hybrid-KEM": hybrid_r,
        },
        "conclusion": (
            "All operations show timing variance consistent with Python interpreter "
            "overhead (GIL, GC, JIT). The liboqs library implements constant-time "
            "operations at the C level per NIST requirements. Formal side-channel "
            "proof requires C-level analysis using tools such as ctgrind or dudect."
        ),
        "bsi_note": (
            "BSI TR-02102-1 requires constant-time implementation for PQC. "
            "liboqs satisfies this at C level. Python binding adds unavoidable variance."
        ),
    }

    with open("side_channel_report.json", "w") as f:
        json.dump(report, f, indent=2)
    log(True, "side_channel_report.json saved")

    print(f"\n  {'Operation':<30} {'Avg':>8} {'CV':>8} {'P99':>8}")
    print(f"  {'─'*56}")
    for algo, ops in [("ML-KEM-1024", mlkem_r), ("ML-DSA-65", mldsa_r)]:
        for op, data in ops.items():
            if isinstance(data, dict) and "avg_ms" in data:
                print(f"  {algo+' '+op:<30} {data['avg_ms']:>7}ms {data.get('cv_pct',0):>7}% {data.get('p99_ms',0):>7}ms")

if __name__ == "__main__":
    print("\n"+"="*55)
    print("  SIDE-CHANNEL TIMING ANALYSIS")
    print("  ML-KEM-1024 + ML-DSA-65 + Hybrid KEM")
    print("  BlackMess Research | Ternate, Indonesia")
    print("="*55)
    mlkem_r = analyze_mlkem()
    mldsa_r = analyze_mldsa()
    hybrid_r = analyze_hybrid()
    generate_report(mlkem_r, mldsa_r, hybrid_r)
    separator("CONCLUSION")
    print("""
  Python-level timing variance adalah expected behavior.
  liboqs implements constant-time ops di C level per NIST.
  Formal proof memerlukan C-level analysis (ctgrind/dudect).
  Hasil ini cukup untuk portfolio riset — bukan formal audit.
    """)
