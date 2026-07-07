#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <random>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class PQSecretsManagement {
private:
    struct Secret {
        std::string secret_id;
        std::string name;
        std::string type;  // API_KEY, PASSWORD, PRIVATE_KEY, CERTIFICATE
        std::string encryption_algorithm;
        int key_size_bits;
        std::string rotation_status;
        bool quantum_resistant;
        time_t last_rotated;
        time_t next_rotation;
        int access_count;
    };

    struct VaultConfiguration {
        std::string name;
        std::string kms_type;
        bool supports_pqc;
        int max_secrets;
        double encryption_overhead_percent;
    };

    std::vector<Secret> secrets;
    std::vector<VaultConfiguration> vault_configs;
    std::mt19937 rng{std::random_device{}()};

public:
    PQSecretsManagement() {
        // Vault Configurations
        vault_configs.push_back({
            "Classical Key Management System",
            "HSM-based (RSA/AES)",
            false,
            10000,
            2.5
        });

        vault_configs.push_back({
            "Hybrid PQC Vault",
            "HSM with ML-KEM support",
            true,
            10000,
            4.2
        });

        vault_configs.push_back({
            "Cloud-based PQC Vault",
            "Cloud KMS with ML-KEM/ML-DSA",
            true,
            50000,
            3.8
        });

        vault_configs.push_back({
            "Hardware Security Module + PQC",
            "Next-gen HSM with integrated PQC",
            true,
            100000,
            5.5
        });

        // Initialize secrets
        initialize_secrets();
    }

    void initialize_secrets() {
        time_t now = time(nullptr);

        // Classical API Key
        secrets.push_back({
            "SECRET-001",
            "Production API Key",
            "API_KEY",
            "RSA-2048",
            2048,
            "Active",
            false,
            now - (30 * 24 * 3600),
            now + (30 * 24 * 3600),
            1245
        });

        // PQC-Protected Password
        secrets.push_back({
            "SECRET-002",
            "Database Admin Password",
            "PASSWORD",
            "ML-KEM-768",
            768,
            "Active",
            true,
            now - (7 * 24 * 3600),
            now + (23 * 24 * 3600),
            568
        });

        // Classical Private Key
        secrets.push_back({
            "SECRET-003",
            "TLS Private Key",
            "PRIVATE_KEY",
            "ECDSA-P256",
            256,
            "Active",
            false,
            now - (365 * 24 * 3600),
            now + (335 * 24 * 3600),
            8934
        });

        // PQC Certificate
        secrets.push_back({
            "SECRET-004",
            "ML-DSA-65 Certificate",
            "CERTIFICATE",
            "ML-DSA-65",
            256,
            "Active",
            true,
            now - (60 * 24 * 3600),
            now + (300 * 24 * 3600),
            234
        });

        // Backup Key
        secrets.push_back({
            "SECRET-005",
            "Backup Encryption Key",
            "PRIVATE_KEY",
            "AES-256",
            256,
            "Pending Rotation",
            true,
            now - (90 * 24 * 3600),
            now + (5 * 24 * 3600),
            89
        });
    }

    json analyze_secret_inventory() {
        json inventory;
        inventory["total_secrets"] = secrets.size();
        inventory["secrets"] = json::array();

        int pqc_count = 0, classical_count = 0;

        for (const auto& secret : secrets) {
            json secret_obj;
            secret_obj["secret_id"] = secret.secret_id;
            secret_obj["name"] = secret.name;
            secret_obj["type"] = secret.type;
            secret_obj["encryption_algorithm"] = secret.encryption_algorithm;
            secret_obj["key_size_bits"] = secret.key_size_bits;
            secret_obj["quantum_resistant"] = secret.quantum_resistant;
            secret_obj["access_count"] = secret.access_count;

            // Calculate rotation urgency
            time_t now = time(nullptr);
            int days_until_rotation = (secret.next_rotation - now) / (24 * 3600);
            secret_obj["days_until_rotation"] = days_until_rotation;
            secret_obj["rotation_urgency"] = days_until_rotation < 7 ? "CRITICAL" :
                                            days_until_rotation < 30 ? "HIGH" : "NORMAL";

            inventory["secrets"].push_back(secret_obj);

            if (secret.quantum_resistant) pqc_count++;
            else classical_count++;
        }

        inventory["summary"] = {
            {"pqc_protected", pqc_count},
            {"classical_protected", classical_count},
            {"pqc_coverage_percent", (pqc_count * 100) / (pqc_count + classical_count)}
        };

        return inventory;
    }

    json assess_vault_options() {
        json assessment;
        assessment["vault_options"] = json::array();

        for (const auto& vault : vault_configs) {
            json vault_obj;
            vault_obj["name"] = vault.name;
            vault_obj["kms_type"] = vault.kms_type;
            vault_obj["supports_pqc"] = vault.supports_pqc;
            vault_obj["max_secrets"] = vault.max_secrets;
            vault_obj["encryption_overhead_percent"] = vault.encryption_overhead_percent;

            // Calculate suitability score
            double score = 50.0;
            if (vault.supports_pqc) score += 30.0;
            if (vault.max_secrets > 50000) score += 10.0;
            if (vault.encryption_overhead_percent < 5.0) score += 10.0;

            vault_obj["suitability_score"] = std::round(score * 100) / 100.0;
            vault_obj["recommended"] = vault.supports_pqc;

            assessment["vault_options"].push_back(vault_obj);
        }

        return assessment;
    }

    json secret_rotation_schedule() {
        json schedule;
        schedule["rotation_schedule"] = json::array();

        time_t now = time(nullptr);

        for (const auto& secret : secrets) {
            int days_until = (secret.next_rotation - now) / (24 * 3600);
            
            json rotation_obj;
            rotation_obj["secret_id"] = secret.secret_id;
            rotation_obj["name"] = secret.name;
            rotation_obj["current_algorithm"] = secret.encryption_algorithm;
            rotation_obj["proposed_algorithm"] = secret.quantum_resistant ? 
                                                 secret.encryption_algorithm : 
                                                 "ML-KEM-768";
            rotation_obj["scheduled_rotation_days"] = days_until;
            rotation_obj["priority"] = days_until < 7 ? "CRITICAL" :
                                      days_until < 30 ? "HIGH" : "MEDIUM";

            schedule["rotation_schedule"].push_back(rotation_obj);
        }

        return schedule;
    }

    json access_control_policies() {
        json policies;
        policies["access_policies"] = json::array();

        std::vector<std::string> roles = {"Admin", "Application", "Auditor", "Service"};

        for (const auto& role : roles) {
            json policy;
            policy["role"] = role;
            policy["permissions"] = json::array();

            if (role == "Admin") {
                policy["permissions"] = json::array({
                    "Read", "Write", "Delete", "Rotate", "Audit"
                });
            } else if (role == "Application") {
                policy["permissions"] = json::array({
                    "Read", "Use"
                });
            } else if (role == "Auditor") {
                policy["permissions"] = json::array({
                    "Read", "Audit"
                });
            } else {
                policy["permissions"] = json::array({
                    "Use"
                });
            }

            policies["access_policies"].push_back(policy);
        }

        return policies;
    }

    void print_secrets_summary() {

        std::cout << "VAULT CONFIGURATIONS:\n";
        std::cout << std::left
                  << std::setw(35) << "Vault Type"
                  << std::setw(20) << "PQC Support"
                  << std::setw(18) << "Max Secrets"
                  << std::setw(20) << "Overhead %\n";

        for (const auto& vault : vault_configs) {
            std::cout << std::left
                      << std::setw(35) << vault.name.substr(0, 33)
                      << std::setw(20) << (vault.supports_pqc ? "Yes" : "No")
                      << std::setw(18) << vault.max_secrets
                      << std::fixed << std::setprecision(1)
                      << std::setw(20) << vault.encryption_overhead_percent << "%\n";
        }

        std::cout << "\n\nSECRET INVENTORY:\n";
        std::cout << std::left
                  << std::setw(18) << "Secret ID"
                  << std::setw(28) << "Name"
                  << std::setw(18) << "Algorithm"
                  << std::setw(15) << "QR"
                  << std::setw(15) << "Accesses"
                  << std::setw(20) << "Urgency\n";

        time_t now = time(nullptr);
        for (const auto& secret : secrets) {
            int days = (secret.next_rotation - now) / (24 * 3600);
            std::string urgency = days < 7 ? "CRITICAL" : days < 30 ? "HIGH" : "NORMAL";

            std::cout << std::left
                      << std::setw(18) << secret.secret_id
                      << std::setw(28) << secret.name.substr(0, 26)
                      << std::setw(18) << secret.encryption_algorithm
                      << std::setw(15) << (secret.quantum_resistant ? "Yes" : "No")
                      << std::setw(15) << secret.access_count
                      << std::setw(20) << urgency << "\n";
        }

    }

    json export_full_report() {
        json report;
        report["report_type"] = "PQ_Secrets_Management";
        report["timestamp"] = "2026-01-15T10:30:00Z";
        report["secret_inventory"] = analyze_secret_inventory();
        report["vault_assessment"] = assess_vault_options();
        report["rotation_schedule"] = secret_rotation_schedule();
        report["access_policies"] = access_control_policies();
        return report;
    }
};

int main() {
    PQSecretsManagement secrets;
    secrets.print_secrets_summary();

    auto inventory = secrets.analyze_secret_inventory();
    std::cout << "\nSecret Inventory:\n" << inventory.dump(2) << "\n";

    auto vault = secrets.assess_vault_options();
    std::cout << "\nVault Assessment:\n" << vault.dump(2) << "\n";

    return 0;
}
