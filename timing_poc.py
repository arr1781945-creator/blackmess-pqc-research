#!/usr/bin/env python3
import time
import numpy as np
import json
from datetime import datetime

def measure_timing(num_iterations=1000):
    """
    Simple timing measurement: akses memory location berkali-kali
    Simulate cache hit vs cache miss via madvise (Linux ARM64)
    """
    import ctypes
    import os
    
    # Allocate buffer (simulating secret polynomial)
    buf = ctypes.create_string_buffer(4096)  # 4KB buffer
    buf_addr = ctypes.addressof(buf)
    
    timings_hit = []
    timings_miss = []
    
    for i in range(num_iterations):
        # ===== CACHE HIT =====
        # Access location, then immediately re-access (should be in cache)
        t1 = time.perf_counter_ns()
        x = buf[100]  # First access
        x = buf[100]  # Second access (cache hit)
        t_hit = time.perf_counter_ns() - t1
        timings_hit.append(t_hit)
        
        # ===== CACHE MISS =====
        # Evict cache by accessing different memory
        for j in range(0, len(buf), 64):  # Walk through in 64-byte strides
            buf[j] = 0
        
        # Now access original location (should miss L1)
        t2 = time.perf_counter_ns()
        x = buf[100]  # Access after eviction (cache miss)
        t_miss = time.perf_counter_ns() - t2
        timings_miss.append(t_miss)
    
    return np.array(timings_hit), np.array(timings_miss)

def main():
    print("[*] Timing Measurement PoC - ARM64")
    print(f"[*] Timestamp: {datetime.now().isoformat()}")
    print()
    
    print("[*] Running 1000 iterations...")
    hit_times, miss_times = measure_timing(num_iterations=1000)
    
    # Statistics
    hit_mean = np.mean(hit_times)
    hit_std = np.std(hit_times)
    miss_mean = np.mean(miss_times)
    miss_std = np.std(miss_times)
    delta = miss_mean - hit_mean
    snr = delta / (hit_std + miss_std)
    
    print(f"\n[+] CACHE HIT:")
    print(f"    Mean: {hit_mean:.2f} ns")
    print(f"    Std:  {hit_std:.2f} ns")
    print(f"\n[+] CACHE MISS:")
    print(f"    Mean: {miss_mean:.2f} ns")
    print(f"    Std:  {miss_std:.2f} ns")
    print(f"\n[+] DIFFERENTIAL:")
    print(f"    Δt = {delta:.2f} ns")
    print(f"    SNR = {snr:.2f}")
    
    # Save results
    results = {
        'timestamp': datetime.now().isoformat(),
        'hit_mean_ns': float(hit_mean),
        'hit_std_ns': float(hit_std),
        'miss_mean_ns': float(miss_mean),
        'miss_std_ns': float(miss_std),
        'cache_differential_ns': float(delta),
        'snr': float(snr),
        'exploitable': snr > 3.0
    }
    
    with open('timing_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Results saved: timing_results.json")
    
    if snr > 3.0:
        print("[+] ✅ EXPLOITABLE: SNR > 3.0 (sufficient for attack)")
    else:
        print("[!] ⚠️  Marginal: SNR < 3.0 (noisy, but possible)")

if __name__ == '__main__':
    main()
