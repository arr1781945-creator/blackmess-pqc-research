#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class KeyRotationProtocol {
private:
    struct RotationPolicy {
        std::string name;
        int rotation_interval_days;
        std::string trigger_event;
        bool requires_pqc;
        double migration_effort_percent;
        std::vector<std::string> compatibility_issues;
    };

    struct KeyLifecycle {
        std::string key_id;
        std::string algorithm;
        std::string status;  // Active, Pending, Retired, Compromised
        time_t creation_time;
        time_t rotation_time;
        time_t expiration_time;
        int rotations_performed;
    };

    std::vector<RotationPolicy> policies;
    std::vector<KeyLifecycle> key_lifecycles;

public:
    KeyRotationProtocol() {
        // Policy 1: Classical Key Rotation
        policies.push_back({
            "Classical RSA Rotation",
            365,
            "Annual or Compromise Detection",
            false,
            0.0,
            {"No quantum resistance"}
        });

        // Policy 2: Accelerated PQC Rotation
        policies.push_back({
            "Accelerated ML-KEM Rotation",
            90,
            "Quarterly or Compromise",
            true,
            15.0,
            {"Increased operational overhead", "Requires new infrastructure"}
        });

        // Policy 3: Hybrid Rotation Strategy
        policies.push_back({
            "Hybrid Classical-PQC Rotation",
            180,
            "Semi-annual or Event-driven",
            true,
            25.0,
            {"Managing two key types", "Backward compatibility maintenance"}
        });

        // Policy 4: Emergency Rotation
        policies.push_back({
            "Emergency Compromise Rotation",
            0,
            "Immediate (Compromise Detected)",
            true,
            100.0,
            {"Critical service disruption", "High operational stress"}
        });

        // Policy 5: Staged Migration Rotation
        policies.push_back({
            "Staged PQC Migration",
            180,
            "Phased transition (12-24 months)",
            true,
            40.0,
            {"Requires parallel infrastructure", "Extended transition period"}
        });

        // Initialize key lifecycles
        initialize_key_lifecycles();
    }

    void initialize_key_lifecycles() {
        time_t now = time(nullptr);

        // Active classical key
        key_lifecycles.push_back({
            "KEY-RSA-2048-001",
            "RSA-2048",
            "Active",
            now - (365 * 24 * 3600),  // 1 year ago
            now,
            now + (365 * 24 * 3600),  // expires in 1 year
            3
        });

        // Active PQC key
        key_lifecycles.push_back({
            "KEY-MLKEM-768-001",
            "ML-KEM-768",
            "Active",
            now - (90 * 24 * 3600),   // 90 days ago
            now - (45 * 24 * 3600),   // rotated 45 days ago
            now + (45 * 24 * 3600),   // expires in 45 days
            8
        });

        // Pending rotation
        key_lifecycles.push_back({
            "KEY-MLKEM-768-002",
            "ML-KEM-768",
            "Pending",
            now - (30 * 24 * 3600),   // 30 days ago
            now + (15 * 24 * 3600),   // rotation scheduled in 15 days
            now + (105 * 24 * 3600),  // expires in 105 days
            0
        });

        // Retired key
        key_lifecycles.push_back({
            "KEY-RSA-2048-002",
            "RSA-2048",
            "Retired",
            now - (730 * 24 * 3600),  // 2 years ago
            now - (365 * 24 * 3600),  // rotated 1 year ago
            now - (1 * 24 * 3600),    // expired yesterday
            5
        });
    }

    json analyze_rotation_policies() {
        json analysis;
        analysis["rotation_policies"] = json::array();

        for (const auto& policy : policies) {
            json policy_obj;
            policy_obj["name"] = policy.name;
            policy_obj["rotation_interval_days"] = policy.rotation_interval_days;
            policy_obj["trigger_event"] = policy.trigger_event;
            policy_obj["requires_pqc"] = policy.requires_pqc;
            policy_obj["migration_effort_percent"] = policy.migration_effort_percent;
            policy_obj["compatibility_issues"] = policy.compatibility_issues;

            // Calculate deployment score
            double score = 100.0 - policy.migration_effort_percent;
            policy_obj["deployment_feasibility_score"] = std::round(score * 100) / 100.0;

            analysis["rotation_policies"].push_back(policy_obj);
        }

        return analysis;
    }

    json assess_key_lifecycle_status() {
        json status;
        status["key_inventory"] = json::array();
        status["total_keys"] = key_lifecycles.size();

        int active_count = 0, pending_count = 0, retired_count = 0;

        for (const auto& key : key_lifecycles) {
            json key_obj;
            key_obj["key_id"] = key.key_id;
            key_obj["algorithm"] = key.algorithm;
            key_obj["status"] = key.status;
            key_obj["rotations_performed"] = key.rotations_performed;

            // Calculate days until rotation
            time_t now = time(nullptr);
            int days_until_rotation = (key.rotation_time - now) / (24 * 3600);
            int days_until_expiration = (key.expiration_time - now) / (24 * 3600);

            key_obj["days_until_next_rotation"] = days_until_rotation;
            key_obj["days_until_expiration"] = days_until_expiration;
            key_obj["rotation_urgency"] = days_until_rotation < 30 ? "URGENT" : 
                                         days_until_rotation < 90 ? "HIGH" : "NORMAL";

            status["key_inventory"].push_back(key_obj);

            if (key.status == "Active") active_count++;
            else if (key.status == "Pending") pending_count++;
            else if (key.status == "Retired") retired_count++;
        }

        status["key_summary"] = {
            {"active", active_count},
            {"pending_rotation", pending_count},
            {"retired", retired_count}
        };

        return status;
    }

    json migration_timeline() {
        json timeline;
        timeline["migration_phases"] = json::array();

        timeline["migration_phases"].push_back({
            {"phase", "Phase 1: Assessment"},
            {"duration_months", 2},
            {"timeline", "Months 0-2"},
            {"activities", json::array({
                "Inventory all cryptographic systems",
                "Evaluate quantum threat landscape",
                "Select appropriate PQC algorithms (ML-KEM-768 for key encapsulation)"
            })},
            {"pqc_deployment", "0%"}
        });

        timeline["migration_phases"].push_back({
            {"phase", "Phase 2: Hybrid Deployment"},
            {"duration_months", 6},
            {"timeline", "Months 3-8"},
            {"activities", json::array({
                "Deploy hybrid classical-PQC systems",
                "Implement ML-KEM alongside existing RSA/ECC",
                "Begin key rotation policy updates"
            })},
            {"pqc_deployment", "25%"}
        });

        timeline["migration_phases"].push_back({
            {"phase", "Phase 3: Accelerated Migration"},
            {"duration_months", 8},
            {"timeline", "Months 9-16"},
            {"activities", json::array({
                "Increase PQC system deployment",
                "Implement PQC-specific key rotation protocols",
                "Retire legacy RSA-2048 systems"
            })},
            {"pqc_deployment", "60%"}
        });

        timeline["migration_phases"].push_back({
            {"phase", "Phase 4: Full Deployment"},
            {"duration_months", 6},
            {"timeline", "Months 17-22"},
            {"activities", json::array({
                "Complete PQC deployment across all systems",
                "Finalize key rotation procedures",
                "Maintain legacy support for interoperability"
            })},
            {"pqc_deployment", "100%"}
        });

        return timeline;
    }

    json emergency_rotation_procedure() {
        json emergency;
        emergency["emergency_procedures"] = {
            {"name", "Compromise-Triggered Emergency Rotation"},
            {"activation_time_seconds", 60},
            {"steps", json::array({
                {"step", 1, "Detect key compromise through monitoring"},
                {"step", 2, "Trigger emergency alert to security team"},
                {"step", 3, "Revoke compromised keys immediately"},
                {"step", 4, "Activate pre-generated backup keys"},
                {"step", 5, "Issue new ML-KEM-768 keys to all systems"},
                {"step", 6, "Re-encrypt in-flight data with new keys"},
                {"step", 7, "Audit all systems for unauthorized access"},
                {"step", 8, "Communicate rotation status to stakeholders"}
            })}
        };

        return emergency;
    }

    void print_key_rotation_status() {

        std::cout << "ROTATION POLICIES:\n";
        std::cout << std::left
                  << std::setw(40) << "Policy"
                  << std::setw(20) << "Interval (days)"
                  << std::setw(15) << "PQC"
                  << std::setw(20) << "Migration Effort\n";

        for (const auto& policy : policies) {
            std::cout << std::left
                      << std::setw(40) << policy.name.substr(0, 38)
                      << std::setw(20) << policy.rotation_interval_days
                      << std::setw(15) << (policy.requires_pqc ? "Yes" : "No")
                      << std::fixed << std::setprecision(1)
                      << std::setw(20) << policy.migration_effort_percent << "%\n";
        }

        std::cout << "\n\nKEY LIFECYCLE STATUS:\n";
        std::cout << std::left
                  << std::setw(25) << "Key ID"
                  << std::setw(20) << "Algorithm"
                  << std::setw(15) << "Status"
                  << std::setw(18) << "Rotations"
                  << std::setw(20) << "Urgency\n";

        for (const auto& key : key_lifecycles) {
            time_t now = time(nullptr);
            int days_until_rotation = (key.rotation_time - now) / (24 * 3600);
            std::string urgency = days_until_rotation < 30 ? "URGENT" : 
                                 days_until_rotation < 90 ? "HIGH" : "NORMAL";

            std::cout << std::left
                      << std::setw(25) << key.key_id.substr(0, 23)
                      << std::setw(20) << key.algorithm
                      << std::setw(15) << key.status
                      << std::setw(18) << key.rotations_performed
                      << std::setw(20) << urgency << "\n";
        }

    }

    json export_full_report() {
        json report;
        report["report_type"] = "Key_Rotation_Protocol";
        report["timestamp"] = "2026-01-15T10:30:00Z";
        report["rotation_policies"] = analyze_rotation_policies();
        report["key_lifecycle_status"] = assess_key_lifecycle_status();
        report["migration_timeline"] = migration_timeline();
        report["emergency_procedures"] = emergency_rotation_procedure();
        return report;
    }
};

int main() {
    KeyRotationProtocol krp;
    krp.print_key_rotation_status();

    auto policies = krp.analyze_rotation_policies();
    std::cout << "\nRotation Policies:\n" << policies.dump(2) << "\n";

    auto timeline = krp.migration_timeline();
    std::cout << "\nMigration Timeline:\n" << timeline.dump(2) << "\n";

    return 0;
}
