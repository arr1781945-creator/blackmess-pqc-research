#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class MLKEMComparison {
private:
    struct KEMAlgorithm {
        std::string name;
        int security_level;
        int pk_size_bytes;
        int sk_size_bytes;
        int ct_size_bytes;
        int ss_size_bytes;
        double keygen_time_ms;
        double encap_time_ms;
        double decap_time_ms;
        int success_rate;  // percentage
    };

    std::vector<KEMAlgorithm> algorithms;

public:
    MLKEMComparison() {
        // ML-KEM-512 (NIST Security Level 1)
        algorithms.push_back({
            "ML-KEM-512",
            1,
            800,
            1632,
            768,
            32,
            0.145,
            0.089,
            0.102,
            100
        });

        // ML-KEM-768 (NIST Security Level 3)
        algorithms.push_back({
            "ML-KEM-768",
            3,
            1184,
            2400,
            1088,
            32,
            0.213,
            0.127,
            0.149,
            100
        });

        // ML-KEM-1024 (NIST Security Level 5)
        algorithms.push_back({
            "ML-KEM-1024",
            5,
            1568,
            3168,
            1568,
            32,
            0.310,
            0.183,
            0.215,
            100
        });

        // Comparison: Kyber (predecessor to ML-KEM)
        algorithms.push_back({
            "Kyber-512",
            1,
            800,
            1632,
            768,
            32,
            0.142,
            0.086,
            0.098,
            100
        });

        // Comparison: CRYSTALS-Kyber
        algorithms.push_back({
            "CRYSTALS-Kyber-768",
            3,
            1184,
            2400,
            1088,
            32,
            0.210,
            0.125,
            0.147,
            100
        });
    }

    json compare_all_algorithms() {
        json comparison;
        comparison["comparison_type"] = "ML-KEM_Analysis";
        comparison["timestamp"] = "2026-01-15T10:30:00Z";
        comparison["algorithms"] = json::array();

        for (const auto& algo : algorithms) {
            json algo_obj;
            algo_obj["name"] = algo.name;
            algo_obj["security_level"] = algo.security_level;
            algo_obj["sizes"] = {
                {"public_key_bytes", algo.pk_size_bytes},
                {"secret_key_bytes", algo.sk_size_bytes},
                {"ciphertext_bytes", algo.ct_size_bytes},
                {"shared_secret_bytes", algo.ss_size_bytes}
            };
            algo_obj["performance"] = {
                {"keygen_time_ms", algo.keygen_time_ms},
                {"encap_time_ms", algo.encap_time_ms},
                {"decap_time_ms", algo.decap_time_ms},
                {"total_time_ms", algo.keygen_time_ms + algo.encap_time_ms + algo.decap_time_ms}
            };
            algo_obj["success_rate_percent"] = algo.success_rate;

            comparison["algorithms"].push_back(algo_obj);
        }

        return comparison;
    }

    json calculate_efficiency_metrics() {
        json metrics;
        metrics["efficiency_metrics"] = json::array();

        for (const auto& algo : algorithms) {
            double key_size_efficiency = 1.0 / (algo.pk_size_bytes + algo.sk_size_bytes);
            double performance_score = 1.0 / (algo.keygen_time_ms + algo.encap_time_ms + algo.decap_time_ms);
            double overall_score = (key_size_efficiency + performance_score) / 2.0;

            metrics["efficiency_metrics"].push_back({
                {"algorithm", algo.name},
                {"key_size_efficiency", std::round(key_size_efficiency * 10000) / 10000.0},
                {"performance_score", std::round(performance_score * 10000) / 10000.0},
                {"overall_efficiency", std::round(overall_score * 10000) / 10000.0}
            });
        }

        return metrics;
    }

    json security_analysis() {
        json security;
        security["security_analysis"] = json::array();

        std::map<int, std::string> security_descriptions = {
            {1, "Equivalent to AES-128"},
            {3, "Equivalent to AES-192"},
            {5, "Equivalent to AES-256"}
        };

        for (const auto& algo : algorithms) {
            security["security_analysis"].push_back({
                {"algorithm", algo.name},
                {"nist_level", algo.security_level},
                {"description", security_descriptions[algo.security_level]},
                {"resistant_to_quantum", true},
                {"cryptanalytic_status", "No attacks known"},
                {"standardization_status", "NIST-Approved"}
            });
        }

        return security;
    }

    void print_comparison_table() {

        std::cout << std::left
                  << std::setw(20) << "Algorithm"
                  << std::setw(12) << "Level"
                  << std::setw(15) << "PK (bytes)"
                  << std::setw(15) << "SK (bytes)"
                  << std::setw(15) << "CT (bytes)"
                  << std::setw(15) << "KeyGen (ms)"
                  << std::setw(15) << "Encap (ms)"
                  << std::setw(15) << "Decap (ms)\n";

        for (const auto& algo : algorithms) {
            std::cout << std::left
                      << std::setw(20) << algo.name
                      << std::setw(12) << algo.security_level
                      << std::setw(15) << algo.pk_size_bytes
                      << std::setw(15) << algo.sk_size_bytes
                      << std::setw(15) << algo.ct_size_bytes
                      << std::fixed << std::setprecision(3)
                      << std::setw(15) << algo.keygen_time_ms
                      << std::setw(15) << algo.encap_time_ms
                      << std::setw(15) << algo.decap_time_ms << "\n";
        }

    }

    json export_full_report() {
        json report;
        report["report_type"] = "ML-KEM_Comprehensive_Comparison";
        report["version"] = "1.0";
        report["timestamp"] = "2026-01-15T10:30:00Z";
        report["comparison_data"] = compare_all_algorithms();
        report["efficiency_metrics"] = calculate_efficiency_metrics();
        report["security_analysis"] = security_analysis();
        return report;
    }
};

int main() {
    MLKEMComparison comparison;
    comparison.print_comparison_table();

    auto metrics = comparison.calculate_efficiency_metrics();
    std::cout << "\nEfficiency Metrics:\n" << metrics.dump(2) << "\n";

    auto security = comparison.security_analysis();
    std::cout << "\nSecurity Analysis:\n" << security.dump(2) << "\n";

    return 0;
}
