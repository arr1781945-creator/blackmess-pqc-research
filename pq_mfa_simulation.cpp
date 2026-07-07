#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <random>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class PQMFASimulation {
private:
    struct MFAFactor {
        std::string name;
        std::string type;
        int key_size_bits;
        double success_rate;
        double compromise_probability;
        std::string quantum_resistant;
    };

    struct MFAConfiguration {
        std::string name;
        std::vector<MFAFactor> factors;
        double overall_security;
    };

    std::vector<MFAConfiguration> configurations;
    std::mt19937 rng{std::random_device{}()};

public:
    PQMFASimulation() {
        // Configuration 1: Classical 2FA
        configurations.push_back({
            "Classical 2FA (TOTP + Password)",
            {
                {"Password", "Knowledge", 128, 0.99, 0.001, "No"},
                {"TOTP", "Possession", 160, 0.98, 0.05, "No"}
            },
            0.0
        });

        // Configuration 2: Hybrid 2FA (PQC + TOTP)
        configurations.push_back({
            "Hybrid 2FA (PQC + TOTP)",
            {
                {"ML-KEM-768 Password", "Knowledge", 256, 0.99, 0.0001, "Yes"},
                {"TOTP", "Possession", 160, 0.98, 0.05, "No"}
            },
            0.0
        });

        // Configuration 3: Full PQC MFA
        configurations.push_back({
            "Full PQC 3FA (ML-KEM + ML-DSA + Biometric)",
            {
                {"ML-KEM-768", "Knowledge", 256, 0.99, 0.00001, "Yes"},
                {"ML-DSA-65", "Possession", 256, 0.99, 0.00001, "Yes"},
                {"Biometric (PQC-resistant)", "Biometric", 512, 0.95, 0.001, "Yes"}
            },
            0.0
        });

        // Configuration 4: Hardware Security Key + PQC
        configurations.push_back({
            "Hardware Key + PQC",
            {
                {"Hardware Security Key", "Possession", 256, 0.999, 0.00001, "Yes"},
                {"ML-KEM-768 Challenge-Response", "Knowledge", 256, 0.99, 0.00001, "Yes"}
            },
            0.0
        });

        // Calculate overall security for each configuration
        calculate_security_metrics();
    }

    void calculate_security_metrics() {
        for (auto& config : configurations) {
            double combined_security = 1.0;
            for (const auto& factor : config.factors) {
                // Security = success_rate * (1 - compromise_prob)
                double factor_security = factor.success_rate * (1.0 - factor.compromise_probability);
                combined_security *= factor_security;
            }
            config.overall_security = combined_security;
        }
    }

    json simulate_attack_resistance() {
        json simulation;
        simulation["attack_scenarios"] = json::array();

        std::vector<std::string> attack_types = {
            "Brute Force Attack",
            "Side-Channel Attack",
            "Quantum Computer Attack",
            "Phishing Attack",
            "Hardware Compromise"
        };

        for (const auto& config : configurations) {
            json config_obj;
            config_obj["configuration"] = config.name;
            config_obj["security_score"] = std::round(config.overall_security * 10000) / 10000.0;
            config_obj["attack_resistance"] = json::array();

            for (const auto& attack : attack_types) {
                bool resistant = false;
                if (attack == "Quantum Computer Attack") {
                    // Check if any factor is quantum-resistant
                    for (const auto& factor : config.factors) {
                        if (factor.quantum_resistant == "Yes") {
                            resistant = true;
                            break;
                        }
                    }
                } else {
                    // Classical attacks
                    resistant = config.overall_security > 0.95;
                }

                config_obj["attack_resistance"].push_back({
                    {"attack_type", attack},
                    {"resistant", resistant},
                    {"mitigation_level", resistant ? "HIGH" : "MEDIUM"}
                });
            }

            simulation["attack_scenarios"].push_back(config_obj);
        }

        return simulation;
    }

    json cost_benefit_analysis() {
        json analysis;
        analysis["cost_analysis"] = json::array();

        std::map<std::string, double> deployment_costs = {
            {"Classical 2FA (TOTP + Password)", 0.1},
            {"Hybrid 2FA (PQC + TOTP)", 2.5},
            {"Full PQC 3FA (ML-KEM + ML-DSA + Biometric)", 8.0},
            {"Hardware Key + PQC", 35.0}
        };

        for (const auto& config : configurations) {
            double cost = deployment_costs[config.name];
            double benefit_score = config.overall_security * 100;
            double roi = benefit_score / (cost > 0 ? cost : 1.0);

            analysis["cost_analysis"].push_back({
                {"configuration", config.name},
                {"deployment_cost_usd", cost},
                {"security_benefit_score", std::round(benefit_score * 100) / 100.0},
                {"roi_ratio", std::round(roi * 100) / 100.0},
                {"recommended", roi > 50 ? true : false}
            });
        }

        return analysis;
    }

    void print_mfa_comparison() {

        std::cout << std::left
                  << std::setw(40) << "Configuration"
                  << std::setw(15) << "Factors"
                  << std::setw(18) << "Security Score"
                  << std::setw(18) << "Quantum Safe"
                  << std::setw(20) << "Cost (USD)\n";

        std::map<std::string, double> costs = {
            {"Classical 2FA (TOTP + Password)", 0.1},
            {"Hybrid 2FA (PQC + TOTP)", 2.5},
            {"Full PQC 3FA (ML-KEM + ML-DSA + Biometric)", 8.0},
            {"Hardware Key + PQC", 35.0}
        };

        for (const auto& config : configurations) {
            bool has_pqc = false;
            for (const auto& factor : config.factors) {
                if (factor.quantum_resistant == "Yes") {
                    has_pqc = true;
                    break;
                }
            }

            std::cout << std::left
                      << std::setw(40) << config.name.substr(0, 38)
                      << std::setw(15) << config.factors.size()
                      << std::fixed << std::setprecision(4)
                      << std::setw(18) << config.overall_security
                      << std::setw(18) << (has_pqc ? "Yes" : "No")
                      << std::setw(20) << costs[config.name] << "\n";
        }

    }

    json export_full_simulation() {
        json report;
        report["simulation_type"] = "PQ_MFA_Analysis";
        report["timestamp"] = "2026-01-15T10:30:00Z";
        report["configurations"] = json::array();

        for (const auto& config : configurations) {
            json config_obj;
            config_obj["name"] = config.name;
            config_obj["security_score"] = config.overall_security;
            config_obj["factors"] = json::array();

            for (const auto& factor : config.factors) {
                config_obj["factors"].push_back({
                    {"name", factor.name},
                    {"type", factor.type},
                    {"key_size_bits", factor.key_size_bits},
                    {"quantum_resistant", factor.quantum_resistant}
                });
            }

            report["configurations"].push_back(config_obj);
        }

        report["attack_analysis"] = simulate_attack_resistance();
        report["cost_benefit"] = cost_benefit_analysis();

        return report;
    }
};

int main() {
    PQMFASimulation mfa;
    mfa.print_mfa_comparison();

    auto attacks = mfa.simulate_attack_resistance();
    std::cout << "\nAttack Resistance Analysis:\n" << attacks.dump(2) << "\n";

    auto cost = mfa.cost_benefit_analysis();
    std::cout << "\nCost-Benefit Analysis:\n" << cost.dump(2) << "\n";

    return 0;
}
