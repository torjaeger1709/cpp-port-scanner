// tests/test_common.cpp
// Unit tests for enums and structs defined in common.h

#include <gtest/gtest.h>
#include "common.h"

// ---------------------------------------------------------------------------
// PortStatus enum
// ---------------------------------------------------------------------------
TEST(Common_PortStatus, PortStatusValues) {
    // All 4 enum values must exist and be distinct
    PortStatus a = PortStatus::OPEN;
    PortStatus b = PortStatus::CLOSED;
    PortStatus c = PortStatus::FILTERED;
    PortStatus d = PortStatus::OPEN_FILTERED;

    EXPECT_NE(static_cast<int>(a), static_cast<int>(b));
    EXPECT_NE(static_cast<int>(a), static_cast<int>(c));
    EXPECT_NE(static_cast<int>(a), static_cast<int>(d));
    EXPECT_NE(static_cast<int>(b), static_cast<int>(c));
    EXPECT_NE(static_cast<int>(b), static_cast<int>(d));
    EXPECT_NE(static_cast<int>(c), static_cast<int>(d));
}

// ---------------------------------------------------------------------------
// ScanType enum
// ---------------------------------------------------------------------------
TEST(Common_ScanType, ScanTypeValues) {
    ScanType a = ScanType::CONNECT;
    ScanType b = ScanType::SYN;
    ScanType c = ScanType::FIN;
    ScanType d = ScanType::XMAS;
    ScanType e = ScanType::NULL_SCAN;

    // Collect and verify all 5 are distinct
    std::vector<int> vals = {
        static_cast<int>(a), static_cast<int>(b), static_cast<int>(c),
        static_cast<int>(d), static_cast<int>(e)
    };
    for (size_t i = 0; i < vals.size(); ++i)
        for (size_t j = i + 1; j < vals.size(); ++j)
            EXPECT_NE(vals[i], vals[j]) << "ScanType values at index "
                                        << i << " and " << j << " collide";
}

// ---------------------------------------------------------------------------
// OutputFormat enum
// ---------------------------------------------------------------------------
TEST(Common_OutputFormat, OutputFormatValues) {
    OutputFormat a = OutputFormat::CONSOLE;
    OutputFormat b = OutputFormat::JSON;
    OutputFormat c = OutputFormat::CSV;
    OutputFormat d = OutputFormat::XML;

    std::vector<int> vals = {
        static_cast<int>(a), static_cast<int>(b),
        static_cast<int>(c), static_cast<int>(d)
    };
    for (size_t i = 0; i < vals.size(); ++i)
        for (size_t j = i + 1; j < vals.size(); ++j)
            EXPECT_NE(vals[i], vals[j]) << "OutputFormat values at index "
                                        << i << " and " << j << " collide";
}

// ---------------------------------------------------------------------------
// PortResult construction
// ---------------------------------------------------------------------------
TEST(Common_PortResult, PortResultConstruction) {
    PortResult pr{80, PortStatus::OPEN, "http"};

    EXPECT_EQ(pr.port, 80);
    EXPECT_EQ(pr.status, PortStatus::OPEN);
    EXPECT_EQ(pr.service_name, "http");
}

// ---------------------------------------------------------------------------
// HostResult construction
// ---------------------------------------------------------------------------
TEST(Common_HostResult, HostResultConstruction) {
    HostResult hr;
    hr.ip = "192.168.1.1";
    hr.hostname = "myhost";
    hr.ports.push_back(PortResult{22, PortStatus::OPEN, "ssh"});
    hr.ports.push_back(PortResult{80, PortStatus::CLOSED, "http"});

    EXPECT_EQ(hr.ip, "192.168.1.1");
    EXPECT_EQ(hr.hostname, "myhost");
    ASSERT_EQ(hr.ports.size(), 2u);
    EXPECT_EQ(hr.ports[0].port, 22);
    EXPECT_EQ(hr.ports[0].status, PortStatus::OPEN);
    EXPECT_EQ(hr.ports[0].service_name, "ssh");
    EXPECT_EQ(hr.ports[1].port, 80);
    EXPECT_EQ(hr.ports[1].status, PortStatus::CLOSED);
    EXPECT_EQ(hr.ports[1].service_name, "http");
}

// ---------------------------------------------------------------------------
// ScanConfig defaults
// ---------------------------------------------------------------------------
TEST(Common_ScanConfig, ScanConfigDefaults) {
    ScanConfig cfg;

    EXPECT_EQ(cfg.threads, 100);
    EXPECT_EQ(cfg.timeout_ms, 1000);
    EXPECT_EQ(cfg.scan_type, ScanType::CONNECT);
    EXPECT_EQ(cfg.format, OutputFormat::CONSOLE);
    EXPECT_FALSE(cfg.show_help);
    EXPECT_EQ(cfg.cancel_token, nullptr);
}
