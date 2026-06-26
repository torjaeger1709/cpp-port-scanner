#include "target_helper.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

namespace TargetHelper {

bool init_networking() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "[Error] Winsock initialization failed with error code: " << result << std::endl;
        return false;
    }
#endif
    return true;
}

void cleanup_networking() {
#ifdef _WIN32
    WSACleanup();
#endif
}

bool is_valid_ipv4(const std::string& ip) {
    struct sockaddr_in sa{};
    int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return result == 1;
}

static uint32_t ip_to_host_int(const std::string& ip) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

static std::string host_int_to_ip(uint32_t ip_int) {
    struct in_addr addr{};
    addr.s_addr = htonl(ip_int);
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != nullptr) {
        return std::string(buf);
    }
    return "";
}

std::vector<std::string> resolve_targets(const std::string& raw_target) {
    std::vector<std::string> results;

    // Check CIDR format (e.g., 192.168.1.0/24)
    size_t slash_pos = raw_target.find('/');
    if (slash_pos != std::string::npos) {
        std::string base_ip = raw_target.substr(0, slash_pos);
        std::string prefix_str = raw_target.substr(slash_pos + 1);

        if (!is_valid_ipv4(base_ip)) {
            std::cerr << "[Error] Invalid base IP address in CIDR target: " << base_ip << std::endl;
            return results;
        }

        int prefix = 0;
        try {
            prefix = std::stoi(prefix_str);
        } catch (...) {
            std::cerr << "[Error] Invalid CIDR subnet prefix: " << prefix_str << std::endl;
            return results;
        }

        if (prefix < 0 || prefix > 32) {
            std::cerr << "[Error] CIDR prefix must be between 0 and 32." << std::endl;
            return results;
        }

        uint32_t ip_int = ip_to_host_int(base_ip);
        uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
        uint32_t network = ip_int & mask;
        uint32_t broadcast = network | (~mask);

        // For /31 or /32 include all addresses; for larger subnets omit network and broadcast addresses
        uint32_t start = network;
        uint32_t end = broadcast;
        if (prefix <= 30) {
            start = network + 1;
            end = broadcast - 1;
        }

        // Memory protection against excessive expansion (> 65536 hosts)
        if (end < start) {
            return results;
        }
        if (end - start > 65536) {
            std::cerr << "[Warning] Subnet range is too large (" << (end - start + 1) << " hosts). Limiting scan to the first 65536 hosts." << std::endl;
            end = start + 65536;
        }

        for (uint32_t curr = start; curr <= end; ++curr) {
            results.push_back(host_int_to_ip(curr));
        }

        return results;
    }

    // If no '/', check if it is a plain IP address
    if (is_valid_ipv4(raw_target)) {
        results.push_back(raw_target);
        return results;
    }

    // If it is a Domain Name (e.g., example.com or localhost), resolve via DNS
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; // Only resolve IPv4 for MVP
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(raw_target.c_str(), nullptr, &hints, &res);
    if (status != 0 || res == nullptr) {
        std::cerr << "[Error] Failed to resolve DNS for target: '" << raw_target << "'" << std::endl;
        return results;
    }

    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        auto* ipv4 = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
        
        std::string ip_obj(ip_str);
        if (std::find(results.begin(), results.end(), ip_obj) == results.end()) {
            results.push_back(ip_obj);
        }
    }

    freeaddrinfo(res);
    return results;
}

std::string resolve_hostname(const std::string& ip) {
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
        return "";
    }

    char host[NI_MAXHOST];
    int status = getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                             host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (status == 0) {
        return std::string(host);
    }
    return "";
}

} // namespace TargetHelper
