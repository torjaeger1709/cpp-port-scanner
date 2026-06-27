#ifndef PORTSCANNER_SCAN_CONTROLLER_H
#define PORTSCANNER_SCAN_CONTROLLER_H

#include "common.h"
#include "thread_pool.h"
#include <vector>
#include <deque>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>

class ScanController {
public:
    ScanController();
    ~ScanController();

    ScanController(const ScanController&) = delete;
    ScanController& operator=(const ScanController&) = delete;
    ScanController(ScanController&&) = delete;
    ScanController& operator=(ScanController&&) = delete;

    // Trigger asynchronous background network scan (zero GUI freezing)
    void start_scan(const ScanConfig& user_config);

    // Request immediate cancellation and gracefully join worker thread
    void stop_scan();

    // Status queries
    bool is_scanning() const { return scanning.load(); }
    float get_progress() const;
    size_t get_completed_count() const { return completed_count.load(); }
    size_t get_total_count() const { return total_count.load(); }

    // Thread-safe UI log buffer interaction (non-blocking)
    std::vector<std::string> get_logs();
    void add_log(const std::string& msg);
    void clear_logs();

    // Thread-safe results retrieval
    std::vector<HostResult> get_results();

    // Export report to file
    bool export_report(const std::string& filepath, OutputFormat format);

private:
    std::mutex state_mutex;
    std::atomic<bool> scanning{false};
    std::shared_ptr<std::atomic<bool>> cancel_token = std::make_shared<std::atomic<bool>>(false);
    std::atomic<size_t> completed_count{0};
    std::atomic<size_t> total_count{0};

    std::mutex logs_mutex;
    std::deque<std::string> logs;

    std::mutex results_mutex;
    std::vector<HostResult> host_results;

    std::thread scan_thread;
    std::thread background_cleaner;
    std::unique_ptr<ThreadPool> pool;
    ScanConfig current_config;
};

#endif // PORTSCANNER_SCAN_CONTROLLER_H
