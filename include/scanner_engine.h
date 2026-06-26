#ifndef PORTSCANNER_SCANNER_ENGINE_H
#define PORTSCANNER_SCANNER_ENGINE_H

#include "common.h"
#include "thread_pool.h"
#include <vector>
#include <string>

namespace ScannerEngine {

    // Common service name lookup corresponding to port number
    std::string get_service_name(int port);

    // Scan a single port on a given IP with specified timeout (ms)
    PortResult scan_port(const std::string& ip, int port, int timeout_ms);

    // Execute multi-threaded scanning across all targets and ports using reusable ThreadPool
    std::vector<HostResult> scan_all(const ScanConfig& config, ThreadPool& pool);

} // namespace ScannerEngine

#endif // PORTSCANNER_SCANNER_ENGINE_H
