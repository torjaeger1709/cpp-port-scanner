#ifndef PORTSCANNER_SCAN_CONTROLLER_H
#define PORTSCANNER_SCAN_CONTROLLER_H

#include "common.h"
#include "thread_pool.h"
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>

class ScanController {
public:
    ScanController();
    ~ScanController();

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
    std::atomic<bool> scanning{false};
    std::atomic<bool> cancel_flag{false};
    std::atomic<size_t> completed_count{0};
    std::atomic<size_t> total_count{0};

    std::mutex logs_mutex;
    std::vector<std::string> logs;

    std::mutex results_mutex;
    std::vector<HostResult> host_results;

    std::thread scan_thread;
    std::unique_ptr<ThreadPool> pool;
    ScanConfig current_config;
};

#endif // PORTSCANNER_SCAN_CONTROLLER_H
