#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class PQReplayPrevention {
private:
    struct ReplayMechanism {
        std::string name;
        std::string description;
        std::string technique;
        bool quantum_resistant;
        double computational_overhead_percent;
        int state_size_bytes;
        std::vector<std::string> vulnerabilities;
    };

    std::vector<ReplayMechanism> mechanisms;

public:
    PQReplayPrevention() {
        // Mechanism 1: Timestamp-based (Classical)
        mechanisms.push_back({
            "Timestamp-based Replay Prevention",
            "Uses synchronized clocks with timestamp validation",
            "Time Window Verification",
            false,
            0.5,
            8,
            {"Clock skew attacks", "Vulnerable to quantum-enhanced timing attacks"}
        });

        // Mechanism 2: Nonce-based with PQC
        mechanisms.push_back({
            "ML-KEM Nonce-based Prevention",
            "Uses cryptographically secure nonces with ML-KEM signing",
            "Nonce + ML-DSA Signature",
            true,
            5.2,
            64,
            {"None known"}
        });

        // Mechanism 3: Sequence Numbers with PQC
        mechanisms.push_back({
            "Sequence Number (PQC-Enhanced)",
            "Monotonically increasing sequence numbers with ML-KEM binding",
            "Sequence Counter + ML-KEM Commitment",
            true,
            3.8,
            32,
            {"None known"}
        });

        // Mechanism 4: Merkle Tree based (Post-Quantum)
        mechanisms.push_back({
            "Merkle Tree Stateful Signature",
            "Uses stateful signatures based on Merkle trees (XMSS-like with PQC)",
            "Stateful ML-DSA + Merkle Chain",
            true,
            8.5,
            256,
            {"Requires state management"}
        });

        // Mechanism 5: Blockchain/Ledger based
        mechanisms.push_back({
            "Distributed Ledger Approach",
            "Immutable recording of all transactions in PQC-protected ledger",
            "PQC-signed Transaction Log",
            true,
            12.0,
            512,
            {"Requires network consensus overhead"}
        });
    }

    json analyze_replay_attacks() {
        json analysis;
        analysis["replay_attack_vectors"] = json::array();

        std::vector<std::string> attack_vectors = {
            "Message Replay",
            "Session Replay",
            "Authentication Replay",
            "Quantum-Enhanced Replay"
        };

        for (const auto& mechanism : mechanisms) {
            json mech_obj;
            mech_obj["mechanism"] = mechanism.name;
            mech_obj["vulnerabilities"] = mechanism.vulnerabilities;
            mech_obj["protection_level"] = json::array();

            for (const auto& vector : attack_vectors) {
                bool protected_against = true;
                std::string level = "PROTECTED";

                if (!mechanism.quantum_resistant && vector == "Quantum-Enhanced Replay") {
                    protected_against = false;
                    level = "VULNERABLE";
                }

                mech_obj["protection_level"].push_back({
                    {"attack_vector", vector},
                    {"protected", protected_against},
                    {"level", level}
                });
            }

            analysis["replay_attack_vectors"].push_back(mech_obj);
        }

        return analysis;
    }

    json performance_impact_analysis() {
        json performance;
        performance["performance_metrics"] = json::array();

        for (const auto& mech : mechanisms) {
            json perf_obj;
            perf_obj["mechanism"] = mech.name;
            perf_obj["overhead_percent"] = mech.computational_overhead_percent;
            perf_obj["state_size_bytes"] = mech.state_size_bytes;

            // Calculate relative scores
            double efficiency = 100.0 / (mech.computational_overhead_percent + 1.0);
            double scalability = 1.0 / (mech.state_size_bytes / 64.0);

            perf_obj["efficiency_score"] = std::round(efficiency * 100) / 100.0;
            perf_obj["scalability_score"] = std::round(scalability * 10000) / 10000.0;

            performance["performance_metrics"].push_back(perf_obj);
        }

        return performance;
    }

    json implementation_guidelines() {
        json guidelines;
        guidelines["recommended_implementations"] = json::array();

        guidelines["recommended_implementations"].push_back({
            {"scenario", "Real-time Systems"},
            {"mechanism", "Sequence Number (PQC-Enhanced)"},
            {"rationale", "Low overhead, minimal state requirements"},
            {"nonce_size_bits", 64},
            {"update_frequency", "Per-message"}
        });

        guidelines["recommended_implementations"].push_back({
            {"scenario", "High-Security Transactions"},
            {"mechanism", "ML-KEM Nonce-based Prevention"},
            {"rationale", "Strong quantum resistance with reasonable overhead"},
            {"nonce_size_bits", 256},
            {"update_frequency", "Per-session"}
        });

        guidelines["recommended_implementations"].push_back({
            {"scenario", "Long-term Audit Trail"},
            {"mechanism", "Distributed Ledger Approach"},
            {"rationale", "Immutable record with quantum resistance"},
            {"nonce_size_bits", 512},
            {"update_frequency", "Per-transaction"}
        });

        return guidelines;
    }

    void print_replay_prevention_comparison() {

        std::cout << std::left
                  << std::setw(40) << "Mechanism"
                  << std::setw(15) << "Quantum Safe"
                  << std::setw(18) << "Overhead %"
                  << std::setw(15) << "State (bytes)"
                  << std::setw(20) << "Vulnerabilities\n";

        for (const auto& mech : mechanisms) {
            std::string vuln_str = mech.vulnerabilities.empty() ? "None" : mech.vulnerabilities[0];
            std::cout << std::left
                      << std::setw(40) << mech.name.substr(0, 38)
                      << std::setw(15) << (mech.quantum_resistant ? "Yes" : "No")
                      << std::fixed << std::setprecision(1)
                      << std::setw(18) << mech.computational_overhead_percent
                      << std::setw(15) << mech.state_size_bytes
                      << std::setw(20) << vuln_str.substr(0, 18) << "\n";
        }

    }

    json export_full_analysis() {
        json report;
        report["analysis_type"] = "PQ_Replay_Prevention";
        report["timestamp"] = "2026-01-15T10:30:00Z";
        report["replay_attack_analysis"] = analyze_replay_attacks();
        report["performance_metrics"] = performance_impact_analysis();
        report["implementation_guidelines"] = implementation_guidelines();
        return report;
    }
};

int main() {
    PQReplayPrevention replay;
    replay.print_replay_prevention_comparison();

    auto attacks = replay.analyze_replay_attacks();
    std::cout << "\nReplay Attack Analysis:\n" << attacks.dump(2) << "\n";

    auto performance = replay.performance_impact_analysis();
    std::cout << "\nPerformance Metrics:\n" << performance.dump(2) << "\n";

    return 0;
}
