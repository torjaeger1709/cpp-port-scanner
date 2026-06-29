/**
 * @file test_target_helper.cpp
 * @brief Unit tests for TargetHelper namespace (target_helper.h).
 *
 * Covers:
 *   - IPv4 address validation (is_valid_ipv4)
 *   - Target resolution / CIDR expansion (resolve_targets)
 *
 * NOTE: On Windows, inet_pton requires WSAStartup, so we use a test fixture
 *       with SetUpTestSuite / TearDownTestSuite to initialise and tear down
 *       the Winsock library once for the entire suite.
 */

#include <gtest/gtest.h>
#include "target_helper.h"

#include <algorithm>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Fixture – initialises Winsock once for every test in the suite
// ---------------------------------------------------------------------------
class TargetHelperTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(TargetHelper::init_networking())
            << "Failed to initialise networking (WSAStartup).";
    }

    static void TearDownTestSuite() {
        TargetHelper::cleanup_networking();
    }
};

// ===========================  is_valid_ipv4  ===============================

TEST_F(TargetHelperTest, ValidIP_Normal) {
    EXPECT_TRUE(TargetHelper::is_valid_ipv4("192.168.1.1"));
}

TEST_F(TargetHelperTest, ValidIP_Localhost) {
    EXPECT_TRUE(TargetHelper::is_valid_ipv4("127.0.0.1"));
}

TEST_F(TargetHelperTest, ValidIP_AllZeros) {
    EXPECT_TRUE(TargetHelper::is_valid_ipv4("0.0.0.0"));
}

TEST_F(TargetHelperTest, ValidIP_Max) {
    EXPECT_TRUE(TargetHelper::is_valid_ipv4("255.255.255.255"));
}

TEST_F(TargetHelperTest, InvalidIP_Empty) {
    EXPECT_FALSE(TargetHelper::is_valid_ipv4(""));
}

TEST_F(TargetHelperTest, InvalidIP_Letters) {
    EXPECT_FALSE(TargetHelper::is_valid_ipv4("abc.def.ghi.jkl"));
}

TEST_F(TargetHelperTest, InvalidIP_TooManyOctets) {
    EXPECT_FALSE(TargetHelper::is_valid_ipv4("1.2.3.4.5"));
}

TEST_F(TargetHelperTest, InvalidIP_OutOfRange) {
    EXPECT_FALSE(TargetHelper::is_valid_ipv4("256.0.0.1"));
}

TEST_F(TargetHelperTest, InvalidIP_Negative) {
    EXPECT_FALSE(TargetHelper::is_valid_ipv4("-1.0.0.1"));
}

// ===========================  resolve_targets  =============================

TEST_F(TargetHelperTest, CIDR_24) {
    auto results = TargetHelper::resolve_targets("192.168.1.0/24");
    // /24 = 256 addresses; network (.0) and broadcast (.255) excluded → 254
    EXPECT_EQ(results.size(), 254u);
}

TEST_F(TargetHelperTest, CIDR_32) {
    auto results = TargetHelper::resolve_targets("192.168.1.1/32");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results.front(), "192.168.1.1");
}

TEST_F(TargetHelperTest, CIDR_31) {
    auto results = TargetHelper::resolve_targets("192.168.1.0/31");
    // /31 point-to-point link — 2 usable addresses per RFC 3021
    EXPECT_EQ(results.size(), 2u);
}

TEST_F(TargetHelperTest, CIDR_30) {
    auto results = TargetHelper::resolve_targets("192.168.1.0/30");
    // /30 = 4 addresses; network (.0) and broadcast (.3) excluded → 2
    EXPECT_EQ(results.size(), 2u);
}

TEST_F(TargetHelperTest, CIDR_InvalidPrefix) {
    auto results = TargetHelper::resolve_targets("192.168.1.0/33");
    EXPECT_TRUE(results.empty());
}

TEST_F(TargetHelperTest, CIDR_InvalidBase) {
    auto results = TargetHelper::resolve_targets("invalid/24");
    EXPECT_TRUE(results.empty());
}

TEST_F(TargetHelperTest, SingleIP) {
    auto results = TargetHelper::resolve_targets("10.0.0.1");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results.front(), "10.0.0.1");
}
