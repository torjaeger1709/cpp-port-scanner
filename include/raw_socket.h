#ifndef PORTSCANNER_RAW_SOCKET_H
#define PORTSCANNER_RAW_SOCKET_H

#include "common.h"
#include <string>
#include <cstdint>

namespace RawSocket {

#pragma pack(push, 1)

struct IPv4Header {
    uint8_t  ihl_ver;      // Version (4 bits) + Internet header length (4 bits)
    uint8_t  tos;          // Type of service
    uint16_t tot_len;      // Total length
    uint16_t id;           // Identification
    uint16_t frag_off;     // Fragment offset
    uint8_t  ttl;          // Time to live
    uint8_t  protocol;     // Protocol
    uint16_t check;        // Checksum
    uint32_t saddr;        // Source address
    uint32_t daddr;        // Destination address
};

struct TCPHeader {
    uint16_t source;       // Source port
    uint16_t dest;         // Destination port
    uint32_t seq;          // Sequence number
    uint32_t ack_seq;      // Acknowledgement number
    uint8_t  doff_res;     // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;        // Flags (FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32)
    uint16_t window;       // Window size
    uint16_t check;        // Checksum
    uint16_t urg_ptr;      // Urgent pointer
};

struct PseudoHeader {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
};

#pragma pack(pop)

    // Reset one-time warning flags displayed in logs/console
    void reset_warnings();

    // Stop sniffer thread and cleanup dispatcher resources
    void cleanup_sniffer();

    // Discover local interface IPv4 address routing to target
    std::string get_local_ip(const std::string& target_ip);

    // Calculate internet checksum (RFC 1071)
    uint16_t calculate_checksum(const uint16_t* ptr, int nbytes);

    // Perform raw TCP stealth scan (SYN, FIN, XMAS, NULL) on target port
    PortResult raw_tcp_scan_port(const std::string& target_ip, int port, int timeout_ms, ScanType type);

} // namespace RawSocket

#endif // PORTSCANNER_RAW_SOCKET_H
