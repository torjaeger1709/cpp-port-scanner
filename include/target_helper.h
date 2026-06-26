#ifndef PORTSCANNER_TARGET_HELPER_H
#define PORTSCANNER_TARGET_HELPER_H

#include <string>
#include <vector>
#include <cstdint>

namespace TargetHelper {

    // Initialize network library (WSAStartup on Windows)
    bool init_networking();

    // Cleanup network library (WSACleanup on Windows)
    void cleanup_networking();

    // Check if a string is a valid IPv4 address
    bool is_valid_ipv4(const std::string& ip);

    // Resolve raw target (IP, Domain, CIDR) into a list of IPv4 addresses
    std::vector<std::string> resolve_targets(const std::string& raw_target);

    // Reverse DNS lookup from IP to Hostname
    std::string resolve_hostname(const std::string& ip);

} // namespace TargetHelper

#endif // PORTSCANNER_TARGET_HELPER_H
