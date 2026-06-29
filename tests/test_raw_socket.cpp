#include <gtest/gtest.h>
#include "raw_socket.h"
#include <cstring>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

// Test packed struct sizes (must match network protocol headers exactly)
TEST(RawSocketTest, IPv4HeaderSize) {
    EXPECT_EQ(sizeof(RawSocket::IPv4Header), 20u);
}

TEST(RawSocketTest, TCPHeaderSize) {
    EXPECT_EQ(sizeof(RawSocket::TCPHeader), 20u);
}

TEST(RawSocketTest, PseudoHeaderSize) {
    EXPECT_EQ(sizeof(RawSocket::PseudoHeader), 12u);
}

// Test RFC 1071 internet checksum
TEST(RawSocketTest, ChecksumZeroData) {
    // All zeros: one's complement sum is 0, complement is 0xFFFF
    uint16_t data[10];
    std::memset(data, 0, sizeof(data));
    uint16_t result = RawSocket::calculate_checksum(data, sizeof(data));
    EXPECT_EQ(result, 0xFFFF);
}

TEST(RawSocketTest, ChecksumSymmetry) {
    // Same data should always produce same checksum
    uint16_t data[] = {0x4500, 0x0034, 0x1234, 0x4000, 0x4006, 0x0000, 0xC0A8, 0x0101, 0x0A00, 0x0001};
    uint16_t result1 = RawSocket::calculate_checksum(data, sizeof(data));
    uint16_t result2 = RawSocket::calculate_checksum(data, sizeof(data));
    EXPECT_EQ(result1, result2);
}

TEST(RawSocketTest, ChecksumKnownIPv4Header) {
    // Construct a minimal IPv4 header and verify checksum is non-zero
    RawSocket::IPv4Header ip{};
    ip.ihl_ver = (4 << 4) | 5;  // Version 4, IHL 5
    ip.tos = 0;
    ip.tot_len = htons(20);
    ip.id = htons(0x1234);
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = 6;  // TCP
    ip.check = 0;
    ip.saddr = htonl(0xC0A80101);  // 192.168.1.1
    ip.daddr = htonl(0x0A000001);  // 10.0.0.1

    uint16_t checksum = RawSocket::calculate_checksum(
        reinterpret_cast<const uint16_t*>(&ip), sizeof(ip));
    EXPECT_NE(checksum, 0);

    // Verify: setting checksum and recalculating should yield 0 or 0xFFFF
    ip.check = checksum;
    uint16_t verify = RawSocket::calculate_checksum(
        reinterpret_cast<const uint16_t*>(&ip), sizeof(ip));
    // RFC 1071: if checksum is correct, recomputing over entire header gives 0xFFFF (or 0)
    EXPECT_TRUE(verify == 0xFFFF || verify == 0x0000);
}

TEST(RawSocketTest, ChecksumNonZeroData) {
    uint16_t data[] = {0xFFFF, 0xFFFF};
    uint16_t result = RawSocket::calculate_checksum(data, sizeof(data));
    // Sum of 0xFFFF + 0xFFFF = 0x1FFFE, folded = 0xFFFF, complement = 0x0000
    EXPECT_EQ(result, 0x0000);
}
