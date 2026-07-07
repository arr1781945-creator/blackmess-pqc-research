#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class PQHybridKEM {
private:
    struct HybridScheme {
        std::string name;
        std::string classical_kem;
        std::string pqc_kem;
        int classical_pk_bytes;
        int pqc_pk_bytes;
        int total_pk_bytes;
        double classical_keygen_ms;
        double pqc_keygen_ms;
        double hybrid_keygen_ms;
        std::string security_model;
    };

    std::vector<HybridScheme> schemes;

public:
    PQHybridKEM() {
        // Hybrid Scheme 1: ECC + ML-KEM-768
        schemes.push_back({
            "ECC-ML-KEM-768",
            "ECDH-P256",
            "ML-KEM-768",
            65,
            1184,
            1249,
            0.08,
            0.213,
            0.293,
            "Post-Quantum + Classical"
        });

        // Hybrid Scheme 2: RSA + ML-KEM-1024
        schemes.push_back({
            "RSA-ML-KEM-1024",
            "RSA-2048",
            "ML-KEM-1024",
            294,
            1568,
            1862,
            1.2,
            0.310,
            1.51,
            "Post-Quantum + Classical"
        });

        // Hybrid Scheme 3: ECDH + ML-KEM-512 (Lightweight)
        schemes.push_back({
            "ECC-ML-KEM-512",
            "ECDH-P256",
            "ML-KEM-512",
            65,
            800,
            865,
            0.08,
            0.145,
            0.225,
            "Post-Quantum + Classical"
        });

        // Pure PQC for comparison
        schemes.push_back({
            "ML-KEM-768-Pure",
            "None",
            "ML-KEM-768",
            0,
            1184,
            1184,
            0.0,
            0.213,
            0.213,
            "Post-Quantum Only"
        });
    }

    json analyze_hybrid_security() {
        json analysis;
        analysis["hybrid_security_models"] = json::array();

        for (const auto& scheme : schemes) {
            json scheme_obj;
            scheme_obj["scheme_name"] = scheme.name;
            scheme_obj["components"] = {
                {"classical_component", scheme.classical_kem},
                {"pqc_component", scheme.pqc_kem},
                {"security_model", scheme.security_model}
            };
            
            scheme_obj["security_properties"] = {
                {"resists_classical_attacks", true},
                {"resists_quantum_attacks", scheme.pqc_kem != "None"},
                {"composite_security", true},
                {"worst_case_resistance", "PQC Component Strength"}
            };

            analysis["hybrid_security_models"].push_back(scheme_obj);
        }

        return analysis;
    }

    json calculate_overhead() {
        json overhead;
        overhead["overhead_analysis"] = json::array();

        // Reference: pure ECC
        int ecc_only_pk = 65;
        int mlkem512_pk = 800;

        for (const auto& scheme : schemes) {
            double pk_overhead = ((double)(scheme.total_pk_bytes - ecc_only_pk) / ecc_only_pk) * 100;
            double time_overhead = scheme.hybrid_keygen_ms > 0 ? 
                                  ((scheme.hybrid_keygen_ms - 0.08) / 0.08) * 100 : 0;

            overhead["overhead_analysis"].push_back({
                {"scheme", scheme.name},
                {"pk_size_bytes", scheme.total_pk_bytes},
                {"pk_overhead_percent", std::round(pk_overhead * 100) / 100.0},
                {"keygen_time_ms", scheme.hybrid_keygen_ms},
                {"time_overhead_percent", std::round(time_overhead * 100) / 100.0},
                {"acceptable", pk_overhead < 200}
            });
        }

        return overhead;
    }

    json migration_roadmap() {
        json roadmap;
        roadmap["migration_strategy"] = {
            {"phase_1", {
                {"timeline", "2024-2025"},
                {"action", "Deploy hybrid ECC-ML-KEM-768 scheme"},
                {"rationale", "Provides immediate quantum resistance while maintaining classical security"}
            }},
            {"phase_2", {
                {"timeline", "2025-2026"},
                {"action", "Monitor PQC standardization and cryptanalysis"},
                {"rationale", "Ensure algorithms remain secure as research progresses"}
            }},
            {"phase_3", {
                {"timeline", "2026-2027"},
                {"action", "Transition to pure PQC if cryptanalytic confidence increases"},
                {"rationale", "Reduce overhead while maintaining quantum resistance"}
            }},
            {"phase_4", {
                {"timeline", "2027+"},
                {"action", "Full PQC deployment with legacy support"},
                {"rationale", "Complete migration to post-quantum infrastructure"}
            }}
        };

        return roadmap;
    }

    void print_comparison() {

        std::cout << std::left
                  << std::setw(25) << "Scheme"
                  << std::setw(20) << "Classical"
                  << std::setw(20) << "PQC"
                  << std::setw(15) << "Total PK"
                  << std::setw(15) << "KeyGen (ms)"
                  << std::setw(15) << "Overhead %\n";

        int ecc_pk = 65;
        for (const auto& scheme : schemes) {
            double overhead = ((double)(scheme.total_pk_bytes - ecc_pk) / ecc_pk) * 100;
            std::cout << std::left
                      << std::setw(25) << scheme.name
                      << std::setw(20) << scheme.classical_kem
                      << std::setw(20) << scheme.pqc_kem
                      << std::setw(15) << scheme.total_pk_bytes
                      << std::fixed << std::setprecision(3)
                      << std::setw(15) << scheme.hybrid_keygen_ms
                      << std::setw(15) << overhead << "\n";
        }

    }

    json export_full_analysis() {
        json analysis;
        analysis["analysis_type"] = "PQ_Hybrid_KEM_Analysis";
        analysis["timestamp"] = "2026-01-15T10:30:00Z";
        analysis["security_analysis"] = analyze_hybrid_security();
        analysis["overhead_metrics"] = calculate_overhead();
        analysis["migration_roadmap"] = migration_roadmap();
        return analysis;
    }
};

int main() {
    PQHybridKEM hybrid;
    hybrid.print_comparison();

    auto security = hybrid.analyze_hybrid_security();
    std::cout << "\nHybrid Security Analysis:\n" << security.dump(2) << "\n";

    auto roadmap = hybrid.migration_roadmap();
    std::cout << "\nMigration Roadmap:\n" << roadmap.dump(2) << "\n";

    return 0;
}
