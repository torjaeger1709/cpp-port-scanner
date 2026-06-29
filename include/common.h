#ifndef PORTSCANNER_COMMON_H
#define PORTSCANNER_COMMON_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <atomic>
#include <memory>

enum class PortStatus {
    OPEN,
    CLOSED,
    FILTERED,
    OPEN_FILTERED   // RFC 793: No response to FIN/NULL/XMAS → cannot distinguish open vs filtered
};

enum class OutputFormat {
    CONSOLE,
    JSON,
    CSV,
    XML
};

enum class ScanType {
    CONNECT,    // Standard TCP Connect Scan (-sT)
    SYN,        // Stealth TCP SYN Scan (-sS)
    FIN,        // Stealth TCP FIN Scan (-sF)
    XMAS,       // Stealth TCP XMAS Scan (-sX)
    NULL_SCAN   // Stealth TCP NULL Scan (-sN)
};

struct PortResult {
    int port;
    PortStatus status;
    std::string service_name;
};

struct HostResult {
    std::string ip;
    std::string hostname;
    std::vector<PortResult> ports;
};

struct ScanConfig {
    std::string target_raw;              // Raw target string (-t)
    std::vector<std::string> target_ips; // Expanded IP list
    std::vector<int> ports;              // Port list (-p)
    std::string output_file;             // Export report filepath (-o)
    OutputFormat format = OutputFormat::CONSOLE; // Export format
    int threads = 100;                   // Number of concurrent threads
    int timeout_ms = 1000;               // Connection timeout per port (ms)
    ScanType scan_type = ScanType::CONNECT; // Scan technique
    bool show_help = false;              // Help flag

    // MVC & Enterprise GUI Asynchronous Observers (Optional)
    std::function<void()> progress_cb = nullptr;                      // Called on each port task completion
    std::function<void(const std::string& log_msg)> log_cb = nullptr; // Real-time UI log event
    std::shared_ptr<std::atomic<bool>> cancel_token = nullptr;        // Cancellation flag for graceful join
};

#endif // PORTSCANNER_COMMON_H
