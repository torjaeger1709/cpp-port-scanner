#include "scanner_engine.h"
#include "target_helper.h"
#include "raw_socket.h"
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #define CLOSE_SOCKET closesocket
  #define IS_WOULDBLOCK (WSAGetLastError() == WSAEWOULDBLOCK)
  typedef int SOCKLEN_T;
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <poll.h>
  #include <cerrno>
  #define CLOSE_SOCKET close
  #define IS_WOULDBLOCK (errno == EINPROGRESS)
  #define SOCKET int
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  typedef socklen_t SOCKLEN_T;
#endif

namespace ScannerEngine {

static bool set_nonblocking(SOCKET sock) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

std::string get_service_name(int port) {
    static const std::unordered_map<int, std::string> services = {
        {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
        {25, "smtp"}, {53, "domain"}, {80, "http"}, {110, "pop3"},
        {135, "msrpc"}, {139, "netbios-ssn"}, {143, "imap"}, {443, "https"},
        {445, "microsoft-ds"}, {1433, "ms-sql-s"}, {1521, "oracle"},
        {3306, "mysql"}, {3389, "ms-wbt-server"}, {5432, "postgresql"},
        {6379, "redis"}, {8080, "http-proxy"}, {8443, "https-alt"}
    };

    auto it = services.find(port);
    if (it != services.end()) {
        return it->second;
    }
    return "unknown";
}

static std::string grab_banner(SOCKET sock, int port, int timeout_ms, const std::string& ip) {
    // Switch socket back to blocking mode for reliable handshake I/O
#ifdef _WIN32
    u_long mode = 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        return get_service_name(port);
    }
    DWORD timeout = timeout_ms;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == SOCKET_ERROR) {
        return get_service_name(port);
    }
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1 || fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) != 0) {
        return get_service_name(port);
    }
    struct timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == SOCKET_ERROR) {
        return get_service_name(port);
    }
#endif

    char buf[256]{};

    // Stage 1: Passive Banner Grabbing (Server-speak-first: SSH, FTP, SMTP, Telnet)
    // Wait up to 300ms to capture unsolicited welcome greetings without sending garbage data
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;
    int ready = WSAPoll(&pfd, 1, 300);
    bool has_data = (ready > 0 && (pfd.revents & POLLIN));
#else
    struct pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;
    int ready = poll(&pfd, 1, 300);
    bool has_data = (ready > 0 && (pfd.revents & POLLIN));
#endif

    if (has_data) {
        int bytes = recv(sock, buf, sizeof(buf) - 1, 0);
        if (bytes > 0) {
            std::string res(buf, bytes);
            if (res.find("SSH-") != std::string::npos) {
                size_t eol = res.find('\n');
                if (eol != std::string::npos) {
                    std::string ver = res.substr(0, (eol > 0 && res[eol-1] == '\r') ? eol - 1 : eol);
                    return "ssh (" + ver + ")";
                }
                return "ssh";
            } else if (res.find("220 ") != std::string::npos || res.find("FTP") != std::string::npos) {
                return "ftp";
            } else if (res.find("SMTP") != std::string::npos || res.find("ESMTP") != std::string::npos) {
                return "smtp";
            }
            // Clean printable ASCII
            std::string cleaned;
            for (char c : res) {
                if (c >= 32 && c <= 126) cleaned += c;
                if (cleaned.size() >= 30) break;
            }
            if (!cleaned.empty()) return cleaned;
        }
    }

    // Stage 2: Active Banner Grabbing (Client-speak-first: HTTP, etc.)
    // Proactively transmit HTTP GET probe with Host header
    std::string http_probe = "GET / HTTP/1.1\r\nHost: " + ip + "\r\nUser-Agent: CppPortScanner/1.0\r\nConnection: close\r\n\r\n";
    send(sock, http_probe.c_str(), static_cast<int>(http_probe.length()), 0);

    std::memset(buf, 0, sizeof(buf));
    int bytes = recv(sock, buf, sizeof(buf) - 1, 0);
    if (bytes > 0) {
        std::string res(buf, bytes);
        if (res.find("HTTP/1.") != std::string::npos || res.find("HTTP/2") != std::string::npos) {
            size_t srv_pos = res.find("Server: ");
            if (srv_pos == std::string::npos) srv_pos = res.find("server: ");
            if (srv_pos != std::string::npos) {
                size_t eol = res.find("\r\n", srv_pos);
                if (eol != std::string::npos && eol >= srv_pos + 8) {
                    std::string srv_val = res.substr(srv_pos + 8, eol - (srv_pos + 8));
                    return "http (" + srv_val + ")";
                }
            }
            return "http (web server)";
        }
        
        std::string cleaned;
        for (char c : res) {
            if (c >= 32 && c <= 126) cleaned += c;
            if (cleaned.size() >= 30) break;
        }
        if (!cleaned.empty()) return cleaned;
    }

    return get_service_name(port);
}

PortResult scan_port(const std::string& ip, int port, int timeout_ms) {
    PortResult result{port, PortStatus::CLOSED, get_service_name(port)};

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        return result;
    }

    if (!set_nonblocking(sock)) {
        CLOSE_SOCKET(sock);
        return result;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int connect_res = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    bool is_open = false;

    if (connect_res == 0) {
        is_open = true;
    } else if (IS_WOULDBLOCK) {
        // High-performance asynchronous polling replacing legacy select() to eliminate FD_SETSIZE bottlenecks
#ifdef _WIN32
        WSAPOLLFD pfd{};
        pfd.fd = sock;
        pfd.events = POLLOUT;
        int poll_res = WSAPoll(&pfd, 1, timeout_ms);
        bool write_ready = (poll_res > 0 && (pfd.revents & POLLOUT) && !(pfd.revents & (POLLERR | POLLHUP)));
#else
        struct pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLOUT;
        int poll_res = poll(&pfd, 1, timeout_ms);
        bool write_ready = (poll_res > 0 && (pfd.revents & POLLOUT) && !(pfd.revents & (POLLERR | POLLHUP)));
#endif

        if (write_ready) {
            int so_error = 0;
            SOCKLEN_T len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) == 0 && so_error == 0) {
                is_open = true;
            } else {
                result.status = PortStatus::CLOSED;
            }
        } else if (poll_res == 0) {
            result.status = PortStatus::FILTERED;
        } else {
            result.status = PortStatus::CLOSED;
        }
    } else {
        result.status = PortStatus::CLOSED;
    }

    if (is_open) {
        result.status = PortStatus::OPEN;
        result.service_name = grab_banner(sock, port, timeout_ms, ip);
    }

    CLOSE_SOCKET(sock);
    return result;
}

std::vector<HostResult> scan_all(const ScanConfig& config, ThreadPool& pool) {
    std::vector<HostResult> host_results(config.target_ips.size());

    // Initialize host structures
    for (size_t i = 0; i < config.target_ips.size(); ++i) {
        host_results[i].ip = config.target_ips[i];
        host_results[i].hostname = ""; // Lazy resolve later when reporting
        host_results[i].ports.resize(config.ports.size());
    }

    size_t total_tasks = config.target_ips.size() * config.ports.size();
    if (total_tasks == 0) return host_results;

    std::string scan_desc = "Standard TCP Connect Scan (-sT)";
    switch (config.scan_type) {
        case ScanType::SYN: scan_desc = "Stealth TCP SYN Scan (-sS)"; break;
        case ScanType::FIN: scan_desc = "Stealth TCP FIN Scan (-sF)"; break;
        case ScanType::XMAS: scan_desc = "Stealth TCP XMAS Scan (-sX)"; break;
        case ScanType::NULL_SCAN: scan_desc = "Stealth TCP NULL Scan (-sN)"; break;
        case ScanType::CONNECT: default: break;
    }

    std::cout << "[*] Starting " << scan_desc << " of " << total_tasks << " targets ("
              << config.target_ips.size() << " hosts x " << config.ports.size() << " ports) using reusable ThreadPool & WSAPoll...\n";

    for (size_t h = 0; h < config.target_ips.size(); ++h) {
        for (size_t p = 0; p < config.ports.size(); ++p) {
            pool.enqueue([&, h, p]() {
                if (config.cancel_token && config.cancel_token->load()) {
                    if (config.progress_cb) config.progress_cb();
                    return;
                }

                int port = config.ports[p];
                PortResult pr;
                if (config.scan_type == ScanType::CONNECT) {
                    pr = scan_port(config.target_ips[h], port, config.timeout_ms);
                } else {
                    pr = RawSocket::raw_tcp_scan_port(config.target_ips[h], port, config.timeout_ms, config.scan_type);
                }

                // Slot-based thread-safe direct write eliminating mutex bottlenecks
                host_results[h].ports[p] = pr;

                if (pr.status == PortStatus::OPEN && config.log_cb) {
                    config.log_cb("[+] Discovered open port " + std::to_string(port) + "/tcp on " + config.target_ips[h] + " (" + pr.service_name + ")");
                }

                if (config.progress_cb) {
                    config.progress_cb();
                }
            });
        }
    }

    pool.wait_until_empty();

    if (config.log_cb) {
        config.log_cb("[*] Scan execution finished.");
    }
    std::cout << "[+] Scan completed.\n\n";
    return host_results;
}

} // namespace ScannerEngine
