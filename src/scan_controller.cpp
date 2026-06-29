#include "scan_controller.h"
#include "target_helper.h"
#include "scanner_engine.h"
#include "report_generator.h"
#include "raw_socket.h"
#include <iostream>
#include <algorithm>

ScanController::ScanController() {
    TargetHelper::init_networking();
    add_log("[System] Winsock & C++ Port Scanner GUI initialized. Ready.");
}

ScanController::~ScanController() {
    {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (cancel_token) cancel_token->store(true);
        if (pool) pool->clear_queue();
        scanning = false;
    }
    if (scan_thread.joinable()) scan_thread.join();
    if (background_cleaner.joinable()) background_cleaner.join();
    TargetHelper::cleanup_networking();
}

void ScanController::start_scan(const ScanConfig& user_config) {
    // Phase 1: Join previous threads WITHOUT holding state_mutex.
    // scan_thread needs state_mutex to set scanning=false before it exits,
    // so holding state_mutex here while joining would deadlock.
    if (background_cleaner.joinable()) {
        background_cleaner.join();
    }
    if (scan_thread.joinable()) {
        scan_thread.join();
    }

    // Phase 2: Initialize new scan under lock
    std::lock_guard<std::mutex> lock(state_mutex);
    if (scanning.load()) return;

    scanning = true;
    cancel_token = std::make_shared<std::atomic<bool>>(false);
    completed_count = 0;
    total_count = 0;

    current_config = user_config;
    RawSocket::reset_warnings();

    {
        std::lock_guard<std::mutex> res_lock(results_mutex);
        host_results.clear();
    }

    add_log("[*] Dispatching asynchronous worker thread...");

    scan_thread = std::thread([this]() {
        // Attach lock-free atomic observers early for resolution logging
        current_config.cancel_token = cancel_token;
        current_config.progress_cb = [this]() {
            completed_count++;
        };
        current_config.log_cb = [this](const std::string& msg) {
            add_log(msg);
        };

        add_log("[*] Resolving target specification: " + current_config.target_raw + "...");
        current_config.target_ips = TargetHelper::resolve_targets(current_config.target_raw, current_config.log_cb);

        size_t total_calc = current_config.target_ips.size() * current_config.ports.size();
        total_count = total_calc > 0 ? total_calc : 1;

        if (total_calc == 0) {
            add_log("[Error] Target expansion yielded 0 valid targets. Aborting scan.");
            std::lock_guard<std::mutex> st_lock(state_mutex);
            scanning = false;
            return;
        }

        std::string tech_str = "-sT (Connect)";
        if (current_config.scan_type == ScanType::SYN) tech_str = "-sS (Stealth SYN)";
        else if (current_config.scan_type == ScanType::FIN) tech_str = "-sF (Stealth FIN)";
        else if (current_config.scan_type == ScanType::XMAS) tech_str = "-sX (Stealth XMAS)";
        else if (current_config.scan_type == ScanType::NULL_SCAN) tech_str = "-sN (Stealth NULL)";

        add_log("[+] Resolved " + std::to_string(current_config.target_ips.size()) + " host(s). Launching " + tech_str + " across " + std::to_string(current_config.ports.size()) + " port(s)...");

        {
            std::lock_guard<std::mutex> st_lock(state_mutex);
            if (cancel_token && cancel_token->load()) {
                scanning = false;
                return;
            }
            pool = std::make_unique<ThreadPool>(static_cast<size_t>(current_config.threads));
        }

        auto res = ScannerEngine::scan_all(current_config, *pool);

        // Resolve hostnames in parallel using the existing thread pool.
        // This runs on the scan thread (not GUI thread) to prevent UI freeze
        // that previously occurred when get_hostname_lazy() called getnameinfo()
        // synchronously during report export on the calling thread.
        if (!(cancel_token && cancel_token->load()) && !res.empty()) {
            add_log("[*] Resolving reverse DNS for " + std::to_string(res.size()) + " host(s)...");
            for (size_t i = 0; i < res.size(); ++i) {
                pool->enqueue([&res, i]() {
                    res[i].hostname = TargetHelper::resolve_hostname(res[i].ip);
                });
            }
            pool->wait_until_empty();
        }

        {
            std::lock_guard<std::mutex> res_lock(results_mutex);
            host_results = std::move(res);
        }

        add_log("[+] Scan session finalized successfully.");
        {
            std::lock_guard<std::mutex> st_lock(state_mutex);
            scanning = false;
        }
    });
}

void ScanController::stop_scan() {
    // Join old cleaner WITHOUT holding state_mutex to prevent deadlock.
    // background_cleaner waits for scan_thread, which needs state_mutex to finish.
    if (background_cleaner.joinable()) {
        background_cleaner.join();
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (!scanning.load() && !scan_thread.joinable()) return;

        add_log("[Warning] Cancellation requested. Stopping worker pool...");
        if (cancel_token) {
            cancel_token->store(true);
        }
        
        if (pool) {
            pool->clear_queue();
        }
        scanning = false;
    }
    // state_mutex released — scan_thread can now acquire it and finish gracefully.

    if (scan_thread.joinable()) {
        background_cleaner = std::thread([t = std::move(scan_thread), p = std::move(pool), this]() mutable {
            if (t.joinable()) t.join();
            p.reset();
            add_log("[*] Background thread joined cleanly.");
        });
    }
}

float ScanController::get_progress() const {
    size_t tot = total_count.load();
    if (tot == 0) return 0.0f;
    float p = static_cast<float>(completed_count.load()) / static_cast<float>(tot);
    return std::min(1.0f, std::max(0.0f, p));
}

std::vector<std::string> ScanController::get_logs() {
    std::vector<std::string> copy;
    std::lock_guard<std::mutex> lock(logs_mutex);
    copy.assign(logs.begin(), logs.end());
    return copy;
}

void ScanController::add_log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(logs_mutex);
    logs.push_back(msg);
    while (logs.size() > 1000) {
        logs.pop_front();
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
