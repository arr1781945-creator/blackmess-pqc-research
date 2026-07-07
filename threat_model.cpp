#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class ThreatModel {
private:
    struct Threat {
        std::string id;
        std::string name;
        std::string description;
        std::string category;
        int severity;      // 1-10
        int likelihood;    // 1-10
        int risk_score;    // severity * likelihood
        std::vector<std::string> mitigations;
    };

    struct Asset {
        std::string name;
        std::string type;
        std::string criticality;
        std::vector<std::string> threats;
    };

    std::vector<Threat> threats;
    std::vector<Asset> assets;

public:
    // Identifikasi threats untuk PQC systems
    void identify_threats() {
        // Threat 1: Quantum Computing Threat
        threats.push_back({
            "QC-001",
            "Quantum Computer Attack",
            "Future quantum computers could break RSA/ECC using Shor's algorithm",
            "Cryptographic",
            9,
            7,
            0,
            {
                "Migrate to post-quantum cryptography (ML-KEM, ML-DSA)",
                "Implement hybrid classical-PQC systems",
                "Regular cryptographic agility audits"
            }
        });

        // Threat 2: Side-Channel Attacks
        threats.push_back({
            "SCA-001",
            "Timing Side-Channel",
            "Timing variations in cryptographic operations leak key information",
            "Implementation",
            8,
            8,
            0,
            {
                "Use constant-time implementations",
                "Implement masking and blinding techniques",
                "Cache-timing aware programming"
            }
        });

        // Threat 3: Fault Injection
        threats.push_back({
            "FI-001",
            "Fault Injection Attack",
            "Inducing faults in cryptographic hardware to recover keys",
            "Physical",
            7,
            5,
            0,
            {
                "Error detection and correction codes",
                "Redundant computation",
                "Tamper detection mechanisms"
            }
        });

        // Threat 4: Supply Chain
        threats.push_back({
            "SC-001",
            "Compromised Cryptographic Library",
            "Malicious modifications in open-source PQC libraries",
            "Supply Chain",
            9,
            3,
            0,
            {
                "Code review and verification",
                "Use signed releases from trusted sources",
                "SBOM (Software Bill of Materials) tracking"
            }
        });

        // Threat 5: Implementation Flaws
        threats.push_back({
            "IM-001",
            "Weak Random Number Generation",
            "Poor entropy in key generation reduces security",
            "Implementation",
            9,
            6,
            0,
            {
                "Use cryptographically secure RNG (hardware-based)",
                "Regular entropy source testing",
                "Multiple entropy sources (XOR combination)"
            }
        });

        // Threat 6: Harvest Now, Decrypt Later
        threats.push_back({
            "HNDL-001",
            "Harvest Now, Decrypt Later",
            "Adversary collects encrypted data now, decrypts when quantum computers available",
            "Cryptographic",
            10,
            8,
            0,
            {
                "Implement long-term key retention policies",
                "Use PQC for data with long confidentiality requirements",
                "Post-quantum hybrid encryption"
            }
        });

        // Threat 7: Algorithm Weakness Discovery
        threats.push_back({
            "AW-001",
            "Cryptanalytic Breakthrough",
            "New attacks discovered against ML-KEM or other PQC algorithms",
            "Cryptographic",
            8,
            2,
            0,
            {
                "Follow NIST recommendations closely",
                "Implement cryptographic agility",
                "Stay updated with academic research"
            }
        });

        // Calculate risk scores
        for (auto& threat : threats) {
            threat.risk_score = threat.severity * threat.likelihood;
        }
    }

    // Define critical assets
    void define_assets() {
        assets.push_back({
            "Master Key",
            "Cryptographic Material",
            "CRITICAL",
            {"QC-001", "SCA-001", "IM-001"}
        });

        assets.push_back({
            "PQC Implementation",
            "Software",
            "CRITICAL",
            {"IM-001", "FI-001", "SC-001"}
        });

        assets.push_back({
            "Hardware Accelerator",
            "Hardware",
            "HIGH",
            {"SCA-001", "FI-001", "HNDL-001"}
        });

        assets.push_back({
            "Long-term Encrypted Data",
            "Data",
            "CRITICAL",
            {"HNDL-001", "QC-001", "AW-001"}
        });

        assets.push_back({
            "Key Management System",
            "Infrastructure",
            "CRITICAL",
            {"QC-001", "SC-001", "IM-001"}
        });
    }

    // Generate threat matrix
    json generate_threat_matrix() {
        json matrix;
        matrix["total_threats"] = (int)threats.size();
        int critical_count = 0;
        int high_count = 0;
        int medium_count = 0;
        matrix["threats"] = json::array();

        for (const auto& threat : threats) {
            int risk = threat.risk_score;
            std::string severity_level;
            
            if (risk >= 70) {
                severity_level = "CRITICAL";
                critical_count++;
            } else if (risk >= 50) {
                severity_level = "HIGH";
                high_count++;
            } else {
                severity_level = "MEDIUM";
                medium_count++;
            }

            json threat_obj;
            threat_obj["id"] = threat.id;
            threat_obj["name"] = threat.name;
            threat_obj["category"] = threat.category;
            threat_obj["severity"] = threat.severity;
            threat_obj["likelihood"] = threat.likelihood;
            threat_obj["risk_score"] = threat.risk_score;
            threat_obj["risk_level"] = severity_level;
            threat_obj["mitigations"] = threat.mitigations;

            matrix["threats"].push_back(threat_obj);
        }

        matrix["critical_count"] = critical_count;
        matrix["high_count"] = high_count;
        matrix["medium_count"] = medium_count;

        return matrix;
    }

    // Vulnerability assessment
    json assess_vulnerabilities() {
        json assessment;
        assessment["assessment_date"] = "2026-01-15";
        assessment["vulnerabilities"] = json::array();

        std::map<std::string, int> vuln_counts;

        for (const auto& asset : assets) {
            for (const auto& threat_id : asset.threats) {
                vuln_counts[threat_id]++;
            }
        }

        for (const auto& threat : threats) {
            int affected_assets = vuln_counts[threat.id];
            double impact_factor = (affected_assets / static_cast<double>(assets.size())) * 10;

            assessment["vulnerabilities"].push_back({
                {"threat_id", threat.id},
                {"threat_name", threat.name},
                {"affected_assets", affected_assets},
                {"impact_factor", std::round(impact_factor * 100) / 100.0},
                {"remediation_priority", affected_assets >= 3 ? "URGENT" : "NORMAL"}
            });
        }

        return assessment;
    }

    // Risk heatmap
    void print_risk_heatmap() {

        std::cout << std::left 
                  << std::setw(15) << "Threat ID"
                  << std::setw(30) << "Name"
                  << std::setw(8) << "Sev"
                  << std::setw(8) << "Lik"
                  << std::setw(8) << "Risk"
                  << std::setw(12) << "Level\n";

        for (const auto& threat : threats) {
            std::string level = threat.risk_score >= 70 ? "CRITICAL" : 
                               threat.risk_score >= 50 ? "HIGH" : "MEDIUM";
            
            std::cout << std::left 
                      << std::setw(15) << threat.id
                      << std::setw(30) << threat.name.substr(0, 28)
                      << std::setw(8) << threat.severity
                      << std::setw(8) << threat.likelihood
                      << std::setw(8) << threat.risk_score
                      << std::setw(12) << level << "\n";
        }

    }

    json export_full_threat_model() {
        json model;
        model["model_type"] = "PQC_Threat_Model";
        model["version"] = "1.0";
        model["timestamp"] = "2026-01-15T10:30:00Z";
        model["threat_matrix"] = generate_threat_matrix();
        model["vulnerability_assessment"] = assess_vulnerabilities();
        
        json assets_json = json::array();
        for (const auto& asset : assets) {
            assets_json.push_back({
                {"name", asset.name},
                {"type", asset.type},
                {"criticality", asset.criticality},
                {"affected_threats", asset.threats}
            });
        }
        model["assets"] = assets_json;

        return model;
    }
};

int main() {
    ThreatModel tm;
    tm.identify_threats();
    tm.define_assets();
    
    tm.print_risk_heatmap();
    
    auto full_model = tm.export_full_threat_model();
    std::cout << "\nFull Threat Model (JSON):\n" << full_model.dump(2) << "\n";
    
    return 0;
}
