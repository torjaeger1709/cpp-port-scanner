#include "scan_controller.h"
#include "target_helper.h"
#include "scanner_engine.h"
#include "report_generator.h"
#include <iostream>
#include <algorithm>

ScanController::ScanController() {
    TargetHelper::init_networking();
    add_log("[System] Winsock & C++ Port Scanner GUI initialized. Ready.");
}

ScanController::~ScanController() {
    stop_scan();
    TargetHelper::cleanup_networking();
}

void ScanController::start_scan(const ScanConfig& user_config) {
    if (scanning.load()) return;

    stop_scan(); // Ensure previous joinable thread is completely joined

    scanning = true;
    cancel_flag = false;
    completed_count = 0;
    total_count = 1; // Prevent 0 division before target expansion

    current_config = user_config;

    {
        std::lock_guard<std::mutex> lock(results_mutex);
        host_results.clear();
    }

    add_log("[*] Dispatching asynchronous worker thread...");

    scan_thread = std::thread([this]() {
        add_log("[*] Resolving target specification: " + current_config.target_raw + "...");
        current_config.target_ips = TargetHelper::resolve_targets(current_config.target_raw);

        size_t total_calc = current_config.target_ips.size() * current_config.ports.size();
        total_count = total_calc > 0 ? total_calc : 1;

        if (total_calc == 0) {
            add_log("[Error] Target expansion yielded 0 valid targets. Aborting scan.");
            scanning = false;
            return;
        }

        std::string tech_str = "-sT (Connect)";
        if (current_config.scan_type == ScanType::SYN) tech_str = "-sS (Stealth SYN)";
        else if (current_config.scan_type == ScanType::FIN) tech_str = "-sF (Stealth FIN)";
        else if (current_config.scan_type == ScanType::XMAS) tech_str = "-sX (Stealth XMAS)";
        else if (current_config.scan_type == ScanType::NULL_SCAN) tech_str = "-sN (Stealth NULL)";

        add_log("[+] Resolved " + std::to_string(current_config.target_ips.size()) + " host(s). Launching " + tech_str + " across " + std::to_string(current_config.ports.size()) + " port(s)...");

        pool = std::make_unique<ThreadPool>(static_cast<size_t>(current_config.threads));

        // Attach lock-free atomic observers
        current_config.cancel_token = &cancel_flag;
        current_config.progress_cb = [this]() {
            completed_count++;
        };
        current_config.log_cb = [this](const std::string& msg) {
            add_log(msg);
        };

        auto res = ScannerEngine::scan_all(current_config, *pool);

        {
            std::lock_guard<std::mutex> lock(results_mutex);
            host_results = std::move(res);
        }

        add_log("[+] Scan session finalized successfully.");
        scanning = false;
    });
}

void ScanController::stop_scan() {
    if (!scanning.load() && !scan_thread.joinable()) return;

    add_log("[Warning] Cancellation requested. Stopping worker pool...");
    cancel_flag = true;
    
    if (pool) {
        pool->clear_queue();
    }

    if (scan_thread.joinable()) {
        scan_thread.join();
    }

    scanning = false;
    add_log("[*] Background thread joined cleanly.");
}

float ScanController::get_progress() const {
    size_t tot = total_count.load();
    if (tot == 0) return 0.0f;
    float p = static_cast<float>(completed_count.load()) / static_cast<float>(tot);
    return std::min(1.0f, std::max(0.0f, p));
}

std::vector<std::string> ScanController::get_logs() {
    std::vector<std::string> copy;
    // Use non-blocking try_lock to completely eliminate UI FPS drops
    if (logs_mutex.try_lock()) {
        copy = logs;
        logs_mutex.unlock();
    }
    return copy;
}

void ScanController::add_log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(logs_mutex);
    logs.push_back(msg);
    if (logs.size() > 1000) {
        logs.erase(logs.begin(), logs.begin() + 100); // Ring buffer trimming
    }
}

void ScanController::clear_logs() {
    std::lock_guard<std::mutex> lock(logs_mutex);
    logs.clear();
}

std::vector<HostResult> ScanController::get_results() {
    std::lock_guard<std::mutex> lock(results_mutex);
    return host_results;
}

bool ScanController::export_report(const std::string& filepath, OutputFormat format) {
    std::vector<HostResult> snap;
    {
        std::lock_guard<std::mutex> lock(results_mutex);
        snap = host_results;
    }
    if (snap.empty()) {
        add_log("[Error] No scan results available to export.");
        return false;
    }

    bool ok = ReportGenerator::export_file(snap, filepath, format);
    if (ok) {
        add_log("[+] Report exported successfully to: " + filepath);
    } else {
        add_log("[Error] Failed to export report.");
    }
    return ok;
}
