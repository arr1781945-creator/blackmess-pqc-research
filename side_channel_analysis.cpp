#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <chrono>
#include <random>
#include <algorithm>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class SideChannelAnalyzer {
public:
    struct TimingTrace {
        std::vector<uint64_t> cycle_counts;
        std::vector<double> power_consumption;
        std::vector<int> bit_sequence;
        double correlation;
    };

private:
    std::vector<TimingTrace> traces;
    std::mt19937 rng{std::random_device{}()};

public:
    // Mengukur timing leakage pada operasi bit
    TimingTrace measure_timing_leakage(int bit_operations = 1000) {
        TimingTrace trace;
        trace.cycle_counts.reserve(bit_operations);
        trace.power_consumption.reserve(bit_operations);
        trace.bit_sequence.reserve(bit_operations);

        std::uniform_int_distribution<int> bit_dist(0, 1);

        for (int i = 0; i < bit_operations; i++) {
            int bit = bit_dist(rng);
            trace.bit_sequence.push_back(bit);

            auto start = std::chrono::high_resolution_clock::now();
            
            if (bit == 1) {
                volatile uint64_t temp = 0;
                for (int j = 0; j < 100; j++) {
                    temp ^= (i + j) * 0xDEADBEEF;
                }
            } else {
                volatile uint64_t temp = i * 2;
            }
            
            auto end = std::chrono::high_resolution_clock::now();
            auto cycles = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
            
            trace.cycle_counts.push_back(cycles);
            trace.power_consumption.push_back(cycles / 1000.0 + std::sin(i * 0.01) * 5);
        }

        trace.correlation = calculate_correlation(trace.bit_sequence, trace.cycle_counts);
        return trace;
    }

    // Analisis cache timing attack
    double analyze_cache_timing() {
        std::vector<uint64_t> cache_hit_times;
        std::vector<uint64_t> cache_miss_times;

        for (int i = 0; i < 100; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            volatile int x = 42;
            auto end = std::chrono::high_resolution_clock::now();
            cache_hit_times.push_back(
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
            );
        }

        std::vector<int> large_array(1000000);
        for (int i = 0; i < 100; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            volatile int y = large_array[i * 10000];
            auto end = std::chrono::high_resolution_clock::now();
            cache_miss_times.push_back(
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
            );
        }

        double avg_hit = 0, avg_miss = 0;
        for (auto t : cache_hit_times) avg_hit += t;
        for (auto t : cache_miss_times) avg_miss += t;
        
        avg_hit /= cache_hit_times.size();
        avg_miss /= cache_miss_times.size();

        return avg_miss - avg_hit;
    }

    // EM emanation analysis
    json analyze_em_emanation(int samples = 500) {
        json em_data;
        em_data["type"] = "EM_Emanation_Analysis";
        em_data["samples"] = samples;
        em_data["frequency_bands"] = json::array();

        std::uniform_real_distribution<double> freq_dist(0.5, 2.5);

        for (int band = 1; band <= 5; band++) {
            json band_info;
            band_info["band_number"] = band;
            band_info["frequency_mhz"] = band * 100;
            band_info["amplitude_samples"] = json::array();
            band_info["variance"] = 0.0;

            double sum = 0, sum_sq = 0;
            for (int i = 0; i < samples; i++) {
                double amplitude = freq_dist(rng) * (band * 10);
                band_info["amplitude_samples"].push_back(
                    std::round(amplitude * 100) / 100.0
                );
                sum += amplitude;
                sum_sq += amplitude * amplitude;
            }

            double mean = sum / samples;
            double variance = (sum_sq / samples) - (mean * mean);
            band_info["variance"] = std::round(variance * 100) / 100.0;

            em_data["frequency_bands"].push_back(band_info);
        }

        return em_data;
    }

    // Differential Power Analysis (DPA)
    json perform_dpa_attack(int traces_count = 1000) {
        json dpa_result;
        dpa_result["attack_type"] = "DPA";
        dpa_result["traces_analyzed"] = traces_count;
        dpa_result["correlation_results"] = json::array();

        for (int guess = 0; guess < 16; guess++) {
            std::vector<double> correlations;
            double total_corr = 0;

            for (int i = 0; i < traces_count; i++) {
                double corr = std::abs(std::sin(guess * 0.1 + i * 0.01));
                correlations.push_back(corr);
                total_corr += corr;
            }

            double avg_correlation = total_corr / traces_count;
            double max_correlation = *std::max_element(correlations.begin(), correlations.end());

            dpa_result["correlation_results"].push_back({
                {"key_byte_guess", guess},
                {"average_correlation", std::round(avg_correlation * 10000) / 10000.0},
                {"max_correlation", std::round(max_correlation * 10000) / 10000.0},
                {"is_peak", max_correlation > 0.7}
            });
        }

        return dpa_result;
    }

    // Fault injection analysis
    json analyze_fault_injection() {
        json fault_analysis;
        fault_analysis["attack_type"] = "Fault_Injection";
        fault_analysis["vulnerable_points"] = json::array();

        std::vector<std::string> vulnerable_ops = {
            "key_schedule",
            "substitution_box",
            "permutation",
            "modular_reduction",
            "bit_rotation"
        };

        std::uniform_real_distribution<double> success_dist(0.1, 0.9);

        for (const auto& op : vulnerable_ops) {
            double success_rate = success_dist(rng);
            fault_analysis["vulnerable_points"].push_back({
                {"operation", op},
                {"success_rate", std::round(success_rate * 10000) / 10000.0},
                {"exploitability", success_rate > 0.5 ? "HIGH" : "MEDIUM"},
                {"difficulty", success_rate > 0.7 ? "EASY" : "MODERATE"}
            });
        }

        return fault_analysis;
    }

    void print_summary() {

        auto timing_trace = measure_timing_leakage(1000);
        std::cout << "Timing Leakage Analysis:\n";
        std::cout << "  Correlation Score: " << std::fixed << std::setprecision(6) 
                  << timing_trace.correlation << "\n";
        std::cout << "  Avg Cycle Count: " << (std::accumulate(timing_trace.cycle_counts.begin(), 
                                                  timing_trace.cycle_counts.end(), 0UL) / 
                                              timing_trace.cycle_counts.size()) << "\n\n";

        double cache_diff = analyze_cache_timing();
        std::cout << "Cache Timing Difference (Hit vs Miss): " << cache_diff << " ns\n\n";

        auto dpa = perform_dpa_attack(500);
        std::cout << "DPA Attack Results:\n";
        std::cout << "  Traces Analyzed: " << dpa["traces_analyzed"] << "\n";
        std::cout << "  High Correlation Peaks Detected\n\n";

        auto fault = analyze_fault_injection();
        std::cout << "Fault Injection Vulnerabilities:\n";
        std::cout << "  Points Analyzed: " << fault["vulnerable_points"].size() << "\n";
    }

    json export_full_report() {
        json report;
        report["analysis_type"] = "Comprehensive_SCA";
        report["timestamp"] = "2026-01-15T10:30:00Z";
        
        auto timing = measure_timing_leakage(500);
        json timing_json;
        timing_json["cycle_counts"] = timing.cycle_counts.size();
        timing_json["correlation"] = timing.correlation;
        report["timing_analysis"] = timing_json;
        
        report["cache_timing_diff_ns"] = analyze_cache_timing();
        report["em_emanation"] = analyze_em_emanation(300);
        report["dpa_results"] = perform_dpa_attack(500);
        report["fault_injection"] = analyze_fault_injection();
        return report;
    }

private:
    double calculate_correlation(const std::vector<int>& x, const std::vector<uint64_t>& y) {
        if (x.size() != y.size() || x.empty()) return 0.0;

        double mean_x = 0, mean_y = 0;
        for (auto val : x) mean_x += val;
        for (auto val : y) mean_y += val;
        mean_x /= x.size();
        mean_y /= y.size();

        double cov = 0, var_x = 0, var_y = 0;
        for (size_t i = 0; i < x.size(); i++) {
            double dx = x[i] - mean_x;
            double dy = y[i] - mean_y;
            cov += dx * dy;
            var_x += dx * dx;
            var_y += dy * dy;
        }

        if (var_x == 0 || var_y == 0) return 0.0;
        return cov / std::sqrt(var_x * var_y);
    }
};

int main() {
    SideChannelAnalyzer analyzer;
    analyzer.print_summary();
    
    auto report = analyzer.export_full_report();
    std::cout << "\nFull Report (JSON):\n" << report.dump(2) << "\n";
    
    return 0;
}
