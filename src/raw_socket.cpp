/*
 * Raw Socket Engine & Npcap Kernel Injection Notes:
 *
 * 1. Windows OS Security Limitation (tcpip.sys / afd.sys):
 *    Starting from Windows XP SP2, Microsoft implemented strict security restrictions in the network driver
 *    stack (tcpip.sys). Specifically, applications in user-space are prohibited from sending arbitrary TCP packets
 *    over raw sockets (socket(AF_INET, SOCK_RAW, IPPROTO_RAW) or IPPROTO_TCP). Any attempt to call sendto() with
 *    a crafted TCP SYN/FIN/XMAS header will return WSAEACCES (10013) or be dropped silently by the kernel.
 *
 * 2. Solution (Npcap / WinPcap Architecture):
 *    Professional tools (like Nmap on Windows) bypass tcpip.sys entirely by integrating Npcap (NDIS 6 light-weight
 *    filter kernel driver). Npcap attaches directly to the Network Interface Card (NIC) driver layer via wpcap.dll.
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

std::string get_local_ip(const std::string& target_ip) {
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
    return std::string(buf);
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

PortResult raw_tcp_scan_port(const std::string& target_ip, int port, int timeout_ms, ScanType type) {
    // Attempt raw socket creation
    SOCKET raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock == INVALID_SOCKET) {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true)) {
            std::cerr << "[Warning] Raw socket creation restricted by OS driver (tcpip.sys / lack of root permissions).\n"
                      << "          Automatically falling back to standard TCP Connect Scan (-sT).\n";
        }
        return ScannerEngine::scan_port(target_ip, port, timeout_ms);
    }

    int optval = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, reinterpret_cast<const char*>(&optval), sizeof(optval));

    std::string local_ip = get_local_ip(target_ip);
    uint32_t src_addr = inet_addr(local_ip.c_str());
    uint32_t dst_addr = inet_addr(target_ip.c_str());

    uint16_t src_port = static_cast<uint16_t>(49152 + (rand() % 10000));

    char packet[sizeof(IPv4Header) + sizeof(TCPHeader)]{};
    auto* ip = reinterpret_cast<IPv4Header*>(packet);
    auto* tcp = reinterpret_cast<TCPHeader*>(packet + sizeof(IPv4Header));

    ip->ihl_ver = (4 << 4) | 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(IPv4Header) + sizeof(TCPHeader));
    ip->id = htons(static_cast<uint16_t>(rand() % 65535));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = src_addr;
    ip->daddr = dst_addr;
    ip->check = calculate_checksum(reinterpret_cast<uint16_t*>(ip), sizeof(IPv4Header));

    tcp->source = htons(src_port);
    tcp->dest = htons(static_cast<uint16_t>(port));
    tcp->seq = htonl(static_cast<uint32_t>(rand()));
    tcp->ack_seq = 0;
    tcp->doff_res = (sizeof(TCPHeader) / 4) << 4;

    // Set TCP flags based on ScanType
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

    int send_res = sendto(raw_sock, packet, sizeof(packet), 0, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    if (send_res <= 0) {
        CLOSE_SOCKET(raw_sock);
        static std::atomic<bool> send_warned{false};
        if (!send_warned.exchange(true)) {
            std::cerr << "[Warning] Sending raw TCP packet blocked by Windows kernel driver (tcpip.sys).\n"
                      << "          Automatically falling back to standard TCP Connect Scan (-sT).\n";
        }
        return ScannerEngine::scan_port(target_ip, port, timeout_ms);
    }

    // Sniff incoming response packets
    SOCKET sniff_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sniff_sock == INVALID_SOCKET) {
        sniff_sock = raw_sock;
    }

    struct timeval rcv_tv{};
    rcv_tv.tv_sec = timeout_ms / 1000;
    rcv_tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sniff_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rcv_tv), sizeof(rcv_tv));

    auto start_wait = std::chrono::steady_clock::now();
    char recv_buf[512]{};

    // Default state: SYN scan defaults to FILTERED on timeout; FIN/XMAS/NULL default to OPEN (RFC 793 inverse logic)
    PortStatus default_status = (type == ScanType::SYN) ? PortStatus::FILTERED : PortStatus::OPEN;
    PortResult result{port, default_status, ScannerEngine::get_service_name(port)};

    while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_wait).count() < timeout_ms) {
        struct sockaddr_in from{};
        SOCKLEN_T fromlen = sizeof(from);
        int rbytes = recvfrom(sniff_sock, recv_buf, sizeof(recv_buf), 0, reinterpret_cast<struct sockaddr*>(&from), &fromlen);
        if (rbytes <= 0) break;

        auto* rip = reinterpret_cast<IPv4Header*>(recv_buf);
        if (rip->protocol != IPPROTO_TCP || rip->saddr != dst_addr) continue;

        int ip_hdr_len = (rip->ihl_ver & 0x0F) * 4;
        if (rbytes < ip_hdr_len + static_cast<int>(sizeof(TCPHeader))) continue;

        auto* rtcp = reinterpret_cast<TCPHeader*>(recv_buf + ip_hdr_len);
        if (ntohs(rtcp->dest) != src_port || ntohs(rtcp->source) != port) continue;

        if (type == ScanType::SYN) {
            if ((rtcp->flags & 0x12) == 0x12) { // SYN + ACK -> Port is OPEN
                result.status = PortStatus::OPEN;

                // Immediately send RST to stealthily teardown connection
                tcp->flags = 0x04; // RST
                tcp->seq = rtcp->ack_seq;
                tcp->ack_seq = 0;
                tcp->check = 0;
                std::memcpy(&psh_packet.tcph, tcp, sizeof(TCPHeader));
                tcp->check = calculate_checksum(reinterpret_cast<uint16_t*>(&psh_packet), sizeof(psh_packet));
                sendto(raw_sock, packet, sizeof(packet), 0, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
                break;
            } else if ((rtcp->flags & 0x04) != 0) { // RST -> Port is CLOSED
                result.status = PortStatus::CLOSED;
                break;
            }
        } else {
            // RFC 793 Inverse Scans (-sF, -sX, -sN)
            if ((rtcp->flags & 0x04) != 0) { // RST received -> Port is definitely CLOSED
                result.status = PortStatus::CLOSED;
                break;
            }
        }
    }

    if (sniff_sock != raw_sock && sniff_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(sniff_sock);
    }
    CLOSE_SOCKET(raw_sock);

    return result;
}

} // namespace RawSocket
