/*
 * Raw Socket Engine & Npcap Kernel Injection Notes:
 *
 * 1. Windows OS Security Limitation (tcpip.sys / afd.sys):
 *    Starting from Windows XP SP2, Microsoft implemented strict security restrictions in the network driver
 *    stack (tcpip.sys). Applications in user-space are prohibited from sending arbitrary TCP packets
 *    over raw sockets. Any attempt to call sendto() with crafted TCP headers will return WSAEACCES or be dropped.
 *
 * 2. Solution (Npcap / WinPcap Architecture):
 *    Professional tools bypass tcpip.sys entirely by integrating Npcap driver layer via wpcap.dll.
 *
 * 3. Linux Compliance & RFC 793 Inverse Scans:
 *    On Linux systems executed with root privileges, all raw scans (-sS, -sF, -sX, -sN) operate with 100% RFC 793 compliance.
 */

#include "raw_socket.h"
#include "scanner_engine.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <atomic>
#include <random>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #define CLOSE_SOCKET closesocket
  typedef int SOCKLEN_T;
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <cerrno>
  #define CLOSE_SOCKET close
  #define SOCKET int
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR (-1)
  typedef socklen_t SOCKLEN_T;
#endif

namespace RawSocket {

static std::atomic<bool> g_raw_warned{false};
static std::atomic<bool> g_send_warned{false};

void reset_warnings() {
    g_raw_warned = false;
    g_send_warned = false;
}

// Thread-safe random generation using C++11 <random>
static uint32_t get_random_u32() {
    thread_local std::mt19937 generator(std::random_device{}());
    return generator();
}

static uint16_t get_random_u16(uint16_t min_val, uint16_t max_val) {
    thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<uint16_t> dist(min_val, max_val);
    return dist(generator);
}

// Thread-safe source port pool to prevent collisions between concurrent probes
class SourcePortPool {
public:
    static SourcePortPool& instance() {
        static SourcePortPool pool;
        return pool;
    }

    uint16_t acquire() {
        std::lock_guard<std::mutex> lock(mtx_);
        for (int attempts = 0; attempts < 1000; ++attempts) {
            uint16_t port = get_random_u16(49152, 65535);
            if (in_use_.find(port) == in_use_.end()) {
                in_use_.insert(port);
                return port;
            }
        }
        // Fallback: extremely unlikely — all ports in use
        uint16_t port = get_random_u16(49152, 65535);
        return port;
    }

    void release(uint16_t port) {
        std::lock_guard<std::mutex> lock(mtx_);
        in_use_.erase(port);
    }

private:
    SourcePortPool() = default;
    std::mutex mtx_;
    std::unordered_set<uint16_t> in_use_;
};

// RAII guard to ensure source port is always released
struct SourcePortGuard {
    uint16_t port;
    SourcePortGuard(uint16_t p) : port(p) {}
    ~SourcePortGuard() { SourcePortPool::instance().release(port); }
    SourcePortGuard(const SourcePortGuard&) = delete;
    SourcePortGuard& operator=(const SourcePortGuard&) = delete;
};

// Multi-thread shared sniffer dispatcher
class RawSnifferDispatcher {
public:
    struct Expectation {
        uint32_t dst_addr;
        uint16_t port;
        uint16_t src_port;
        ScanType type;
        std::atomic<int> result_status{-1}; // -1: pending, 0: closed, 1: open
        std::atomic<uint32_t> ack_seq{0};
    };

    static RawSnifferDispatcher& instance() {
        static RawSnifferDispatcher inst;
        return inst;
    }

    void register_expect(Expectation* exp) {
        std::unique_lock<std::shared_mutex> lock(mtx);
        ensure_running();
        expectations.push_back(exp);
    }

    void unregister_expect(Expectation* exp) {
        std::unique_lock<std::shared_mutex> lock(mtx);
        auto it = std::find(expectations.begin(), expectations.end(), exp);
        if (it != expectations.end()) {
            expectations.erase(it);
        }
    }

    void stop_and_cleanup() {
        std::thread thread_to_join;
        {
            std::unique_lock<std::shared_mutex> lock(mtx);
            running = false;
            expectations.clear();
            // Move thread out under lock. After this, member sniffer_thread
            // is not joinable, so a concurrent ensure_running() call won't
            // trigger std::terminate by assigning to a joinable thread.
            thread_to_join = std::move(sniffer_thread);
        }
        if (thread_to_join.joinable()) {
            thread_to_join.join();
        }
    }

private:
    RawSnifferDispatcher() = default;
    ~RawSnifferDispatcher() {
        stop_and_cleanup();
    }

    void ensure_running() {
        if (!running) {
            running = true;
            sniffer_thread = std::thread([this]() { sniff_loop(); });
        }
    }

    void sniff_loop() {
        SOCKET sniff_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sniff_sock == INVALID_SOCKET) {
            return;
        }

#ifdef _WIN32
        DWORD tv = 100;
        setsockopt(sniff_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        struct timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms
        setsockopt(sniff_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        alignas(4) char recv_buf[1024];
        while (running) {
            struct sockaddr_in from{};
            SOCKLEN_T fromlen = sizeof(from);
            int rbytes = recvfrom(sniff_sock, recv_buf, sizeof(recv_buf), 0, reinterpret_cast<struct sockaddr*>(&from), &fromlen);
            if (rbytes <= 0) continue;

            auto* rip = reinterpret_cast<IPv4Header*>(recv_buf);
            if (rip->protocol != IPPROTO_TCP) continue;

            int ip_hdr_len = (rip->ihl_ver & 0x0F) * 4;
            if (ip_hdr_len < 20 || ip_hdr_len > 60 || rbytes < ip_hdr_len + static_cast<int>(sizeof(TCPHeader))) continue;

            auto* rtcp = reinterpret_cast<TCPHeader*>(recv_buf + ip_hdr_len);
            uint16_t r_src_port = ntohs(rtcp->source);
            uint16_t r_dst_port = ntohs(rtcp->dest);
            uint32_t r_saddr = rip->saddr;

            std::shared_lock<std::shared_mutex> lock(mtx);
            for (auto* exp : expectations) {
                if (exp->dst_addr == r_saddr && exp->port == r_src_port && exp->src_port == r_dst_port) {
                    if (exp->type == ScanType::SYN) {
                        if ((rtcp->flags & 0x12) == 0x12) { // SYN + ACK -> Port is OPEN
                            exp->ack_seq = rtcp->ack_seq;
                            exp->result_status = 1;
                        } else if ((rtcp->flags & 0x04) != 0) { // RST -> Port is CLOSED
                            exp->result_status = 0;
                        }
                    } else {
                        // RFC 793 Inverse Scans (-sF, -sX, -sN)
                        if ((rtcp->flags & 0x04) != 0) { // RST received -> Port is CLOSED
                            exp->result_status = 0;
                        }
                    }
                }
            }
        }
        CLOSE_SOCKET(sniff_sock);
    }

    std::shared_mutex mtx;
    std::vector<Expectation*> expectations;
    std::atomic<bool> running{false};
    std::thread sniffer_thread;
};

void cleanup_sniffer() {
    RawSnifferDispatcher::instance().stop_and_cleanup();
}

std::string get_local_ip(const std::string& target_ip) {
    static std::mutex cache_mtx;
    static std::unordered_map<std::string, std::string> ip_cache;
    {
        std::lock_guard<std::mutex> lock(cache_mtx);
        auto it = ip_cache.find(target_ip);
        if (it != ip_cache.end()) return it->second;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return "127.0.0.1";

    struct sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(80);
    inet_pton(AF_INET, target_ip.c_str(), &serv.sin_addr);

    if (connect(s, reinterpret_cast<struct sockaddr*>(&serv), sizeof(serv)) != 0) {
        CLOSE_SOCKET(s);
        return "127.0.0.1";
    }

    struct sockaddr_in name{};
    SOCKLEN_T namelen = sizeof(name);
    if (getsockname(s, reinterpret_cast<struct sockaddr*>(&name), &namelen) != 0) {
        CLOSE_SOCKET(s);
        return "127.0.0.1";
    }

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &name.sin_addr, buf, sizeof(buf));
    CLOSE_SOCKET(s);
    std::string res(buf);

    {
        std::lock_guard<std::mutex> lock(cache_mtx);
        ip_cache[target_ip] = res;
    }
    return res;
}

uint16_t calculate_checksum(const uint16_t* ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes > 0) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

struct ExpectGuard {
    RawSnifferDispatcher& disp;
    RawSnifferDispatcher::Expectation* exp;
    ExpectGuard(RawSnifferDispatcher& d, RawSnifferDispatcher::Expectation* e) : disp(d), exp(e) {
        disp.register_expect(exp);
    }
    ~ExpectGuard() {
        disp.unregister_expect(exp);
    }
};

struct ThreadRawSocketHolder {
    SOCKET s = INVALID_SOCKET;
    ~ThreadRawSocketHolder() {
        if (s != INVALID_SOCKET) {
            CLOSE_SOCKET(s);
        }
    }
};

PortResult raw_tcp_scan_port(const std::string& target_ip, int port, int timeout_ms, ScanType type) {
    thread_local ThreadRawSocketHolder tl_holder;
    if (tl_holder.s == INVALID_SOCKET) {
        tl_holder.s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (tl_holder.s != INVALID_SOCKET) {
            int optval = 1;
            if (setsockopt(tl_holder.s, IPPROTO_IP, IP_HDRINCL, reinterpret_cast<const char*>(&optval), sizeof(optval)) == SOCKET_ERROR) {
                CLOSE_SOCKET(tl_holder.s);
                tl_holder.s = INVALID_SOCKET;
            }
        }
    }

    SOCKET raw_sock = tl_holder.s;
    if (raw_sock == INVALID_SOCKET) {
        if (!g_raw_warned.exchange(true)) {
            std::cerr << "[Warning] Raw socket creation restricted by OS driver (tcpip.sys / lack of root permissions).\n"
                      << "          Automatically falling back to standard TCP Connect Scan (-sT).\n";
        }
        return ScannerEngine::scan_port(target_ip, port, timeout_ms);
    }

    std::string local_ip = get_local_ip(target_ip);
    uint32_t src_addr = 0;
    uint32_t dst_addr = 0;
    inet_pton(AF_INET, local_ip.c_str(), &src_addr);
    inet_pton(AF_INET, target_ip.c_str(), &dst_addr);

    uint16_t src_port = SourcePortPool::instance().acquire();
    SourcePortGuard src_port_guard(src_port);

    alignas(4) char packet[sizeof(IPv4Header) + sizeof(TCPHeader)]{};
    auto* ip = reinterpret_cast<IPv4Header*>(packet);
    auto* tcp = reinterpret_cast<TCPHeader*>(packet + sizeof(IPv4Header));

    ip->ihl_ver = (4 << 4) | 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(IPv4Header) + sizeof(TCPHeader));
    ip->id = htons(get_random_u16(1, 65535));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = src_addr;
    ip->daddr = dst_addr;
    ip->check = calculate_checksum(reinterpret_cast<uint16_t*>(ip), sizeof(IPv4Header));

    tcp->source = htons(src_port);
    tcp->dest = htons(static_cast<uint16_t>(port));
    tcp->seq = htonl(get_random_u32());
    tcp->ack_seq = 0;
    tcp->doff_res = (sizeof(TCPHeader) / 4) << 4;

    uint8_t target_flags = 0x02; // SYN
    switch (type) {
        case ScanType::FIN:
            target_flags = 0x01; // FIN
            break;
        case ScanType::XMAS:
            target_flags = 0x01 | 0x08 | 0x20; // FIN + PSH + URG
            break;
        case ScanType::NULL_SCAN:
            target_flags = 0x00; // NULL
            break;
        case ScanType::SYN:
        default:
            target_flags = 0x02; // SYN
            break;
    }
    tcp->flags = target_flags;

    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    struct {
        PseudoHeader psh;
        TCPHeader tcph;
    } psh_packet{};

    psh_packet.psh.saddr = src_addr;
    psh_packet.psh.daddr = dst_addr;
    psh_packet.psh.zero = 0;
    psh_packet.psh.protocol = IPPROTO_TCP;
    psh_packet.psh.tcp_len = htons(sizeof(TCPHeader));
    std::memcpy(&psh_packet.tcph, tcp, sizeof(TCPHeader));

    tcp->check = calculate_checksum(reinterpret_cast<uint16_t*>(&psh_packet), sizeof(psh_packet));

    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(static_cast<uint16_t>(port));
    dest.sin_addr.s_addr = dst_addr;

    RawSnifferDispatcher::Expectation exp{dst_addr, static_cast<uint16_t>(port), src_port, type};
    ExpectGuard guard(RawSnifferDispatcher::instance(), &exp);

    int send_res = sendto(raw_sock, packet, sizeof(packet), 0, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    if (send_res <= 0) {
        if (!g_send_warned.exchange(true)) {
            std::cerr << "[Warning] Sending raw TCP packet blocked by Windows kernel driver (tcpip.sys).\n"
                      << "          Automatically falling back to standard TCP Connect Scan (-sT).\n";
        }
        return ScannerEngine::scan_port(target_ip, port, timeout_ms);
    }

    auto start_wait = std::chrono::steady_clock::now();
    while (exp.result_status.load() == -1 &&
           std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_wait).count() < timeout_ms) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    PortStatus default_status = (type == ScanType::SYN) ? PortStatus::FILTERED : PortStatus::OPEN_FILTERED;
    PortResult result{port, default_status, ScannerEngine::get_service_name(port)};

    int status = exp.result_status.load();
    if (status == 1) {
        result.status = PortStatus::OPEN;
        if (type == ScanType::SYN) {
            // Send RST to teardown connection stealthily
            tcp->flags = 0x04; // RST
            tcp->seq = exp.ack_seq.load();
            tcp->ack_seq = 0;
            tcp->check = 0;
            std::memcpy(&psh_packet.tcph, tcp, sizeof(TCPHeader));
            tcp->check = calculate_checksum(reinterpret_cast<uint16_t*>(&psh_packet), sizeof(psh_packet));
            sendto(raw_sock, packet, sizeof(packet), 0, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
        }
    } else if (status == 0) {
        result.status = PortStatus::CLOSED;
    }

    return result;
}

} // namespace RawSocket
