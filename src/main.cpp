/*
 * =====================================================================================
 * Project: C++ Port Scanner (CLI Edition)
 * Author / Provided by: Khiem Nguyen
 * License: MIT License
 * =====================================================================================
 */
#include "cli_parser.h"
#include "target_helper.h"
#include "scanner_engine.h"
#include "report_generator.h"
#include "thread_pool.h"
#include <iostream>
#include <chrono>

int main(int argc, char* argv[]) {
    ScanConfig config = CLIParser::parse(argc, argv);

    if (config.show_help || config.target_raw.empty() || config.ports.empty()) {
        CLIParser::print_help(argv[0]);
        if (!config.show_help) {
            std::cerr << "\n[!] Please provide both target (-t) and ports (-p) arguments.\n";
            return 1;
        }
        return 0;
    }

    // Initialize network subsystem (WSAStartup on Windows)
    if (!TargetHelper::init_networking()) {
        return 1;
    }

    // Resolve target (Domain, CIDR, IP) into IPv4 list
    std::cout << "[*] Resolving target: " << config.target_raw << "...\n";
    config.target_ips = TargetHelper::resolve_targets(config.target_raw);

    if (config.target_ips.empty()) {
        std::cerr << "[!] No valid IPv4 addresses found to scan.\n";
        TargetHelper::cleanup_networking();
        return 1;
    }

    // Instantiate Reusable ThreadPool object once for the entire application lifecycle
    ThreadPool pool(config.threads);

    auto start_time = std::chrono::high_resolution_clock::now();

    // Execute multi-threaded scanning using reusable ThreadPool
    std::vector<HostResult> results = ScannerEngine::scan_all(config, pool);

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;

    // Resolve hostnames in parallel before report generation.
    // Previously, getnameinfo() was called lazily during report export,
    // blocking the main thread for each host with no timeout.
    std::cout << "[*] Resolving reverse DNS for " << results.size() << " host(s)...\n";
    for (size_t i = 0; i < results.size(); ++i) {
        pool.enqueue([&results, i]() {
            results[i].hostname = TargetHelper::resolve_hostname(results[i].ip);
        });
    }
    pool.wait_until_empty();

    // Display scan report in console
    ReportGenerator::print_console(results);

    // Export to file if requested (-o)
    if (!config.output_file.empty()) {
        ReportGenerator::export_file(results, config.output_file, config.format);
    }

    std::cout << "[Info] Total execution time: " << elapsed.count() << " seconds.\n";

    TargetHelper::cleanup_networking();
    return 0;
}
