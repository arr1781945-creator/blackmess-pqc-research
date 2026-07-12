# Post-Quantum Cryptography (PQC) 231 Algorithms Benchmark

## Project Overview
Comprehensive security analysis and benchmarking of 231 post-quantum cryptography algorithms, including side-channel attack assessment and threat modeling.

## Directory Structure
├── blackmess-pqc-research/     # Main research data & analysis
├── benchmark/                   # Performance benchmarks
└── liboqs/                      # LibOQS library integration
## Key Components

### 1. Benchmarking (231 Algorithms)
- Comprehensive performance metrics across all PQC families
- Algorithm comparison and ranking analysis
- Category-based statistics and performance profiling
- Detailed latency and throughput measurements

### 2. Side-Channel Analysis (SCA)
- Cache timing attacks (Flush+Reload, Prime+Probe)
- Timing oracle attacks (Kocher Attack methodology)
- Differential Power Analysis (DPA/CPA) simulations
- Spectre v1 and L1 Terminal Fault (L1TF) exploitation
- Real-world electromagnetic radiation analysis
- Covert channel vulnerability assessment

### 3. Threat Model
- STRIDE framework-based threat identification
- 20 critical security threats mapped to algorithms
- Risk assessment with severity levels (Critical/High/Medium)
- Comprehensive mitigation strategies
- Post-quantum specific vulnerability mapping
- Asset-threat relationship matrices

### 4. Algorithms Covered (231 Total)
- Lattice-based: ML-KEM, ML-DSA, Falcon, NTRU, Dilithium
- Code-based: BIKE, HQC, Classic McEliece variants
- Hash-based: SLH-DSA, SPHINCS+, XMSS
- Isogeny-based: SIKE variants
- Multivariate: Oil-Vinegar, Rainbow variants

## Key Findings

### Most Vulnerable Algorithms (SCA Perspective)
1. **Falcon-1024** - 16,704 bits leaked (92.1% accuracy)
2. **SLH_DSA_PURE_SHA2_128S** - 16,568 bits leaked (99.8% accuracy)
3. **OV-V-pkc-skc** - 16,168 bits leaked (97.4% accuracy)

### Most Resistant Algorithms
- **ML-KEM-768** - Minimal timing variance (7.8% accuracy only)
- Constant-time implementations showing superior resilience
- Power analysis resistant designs

### Critical Risk Areas
- Timing side-channels in signature algorithms
- Power consumption patterns in key operations
- Cache-based information leakage
- Quantum computer threats to classical schemes
- Weak RNG implementations

## Research Data

### SCA Analysis Results
- 4 attack vectors tested (Cache, Timing, Power, Spectre)
- 6+ algorithms evaluated per attack type
- 87-99% success rates on vulnerable implementations
- L1 cache line eviction metrics: 39-510 lines

### Threat Assessment
- Total threats identified: 20
- Critical severity: 2 threats
- High severity: 12 threats
- Medium severity: 6 threats

## Files

### Core Research
- `threat_model` - C++ threat model generator and analyzer
- `comprehensive_all_analysis.txt` - Complete algorithm evaluation
- `sca_analysis_all.csv` - SCA test results with metrics
- `deployment_matrix.txt` - Recommended deployment configurations

### Supporting Data
- `benchmark_kem_all.csv` - KEM performance data
- `benchmark_sig_all.csv` - Signature scheme performance
- `algorithm_comparison.txt` - Side-by-side algorithm comparison
- `anomaly_analysis_report.txt` - Statistical anomaly detection

## Requirements
- C++17 or higher compiler (GCC, Clang)
- LibOQS for cryptographic implementations
- CMake for build system

## Installation & Usage

```bash
cd ~/riset/khusus/blackmess-pqc-research

# Build threat model analyzer
clang++ -std=c++17 -Wall -Wextra threat_model.cpp -o threat_model

# Run threat model report
./threat_model

# View SCA analysis
cat sca_analysis_all.csv

# Check deployment recommendations
cat deployment_matrix.txt
Methodology
Benchmarking Approach
Standardized test vectors (NIST compliance)
Consistent hardware environment
Multiple runs per algorithm (n=100+)
Timing measurements with cycle-accurate counters
Threat Modeling
Asset identification and categorization
Threat enumeration using STRIDE
Vulnerability mapping to implementation
Risk scoring based on impact and likelihood
Mitigation feasibility assessment
SCA Evaluation
Real-world attack simulations
Covert channel establishment
Information leakage quantification
Success rate measurement
Correlation analysis with secret data
Security Recommendations
Implement Constant-Time Algorithms
Eliminate timing-dependent branches
Uniform memory access patterns
Cache-oblivious data structures
Post-Quantum Migration Strategy
Hybrid classical-PQC approaches
Gradual algorithm rollout
Continuous security monitoring
Side-Channel Hardening
Power consumption masking
Random instruction injection
Electromagnetic shielding
Key Management
Secure erasure protocols
Memory encryption
Hardware security modules (HSM)
Development Practices
Code review and security audits
Fuzzing and symbolic execution
Regular dependency updates
Cryptanalysis monitoring
References
NIST Post-Quantum Cryptography Standardization Project (PQC)
TCHES (Transactions on Cryptographic Hardware and Embedded Systems)
LibOQS (Open Quantum Safe) Documentation
Cache Timing Attacks on Implementations of AES
Power Analysis: An Effective Attack on Implementations
Research Team
Cryptography & Security Analysis
Side-Channel Evaluation
Post-Quantum Standardization Compliance
License
Research data and analysis available for academic and security research purposes.
Note: This comprehensive research evaluates post-quantum cryptographic algorithms for real-world security vulnerabilities, deployment readiness, and quantum-era transition planning. Results inform cryptographic selection and implementation hardening strategies.
