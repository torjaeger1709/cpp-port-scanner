#include <gtest/gtest.h>
#include "scanner_engine.h"

TEST(ScannerEngineTest, KnownPort_FTP) {
    EXPECT_EQ(ScannerEngine::get_service_name(21), "ftp");
}

TEST(ScannerEngineTest, KnownPort_SSH) {
    EXPECT_EQ(ScannerEngine::get_service_name(22), "ssh");
}

TEST(ScannerEngineTest, KnownPort_HTTP) {
    EXPECT_EQ(ScannerEngine::get_service_name(80), "http");
}

TEST(ScannerEngineTest, KnownPort_HTTPS) {
    EXPECT_EQ(ScannerEngine::get_service_name(443), "https");
}

TEST(ScannerEngineTest, KnownPort_MySQL) {
    EXPECT_EQ(ScannerEngine::get_service_name(3306), "mysql");
}

TEST(ScannerEngineTest, KnownPort_Redis) {
    EXPECT_EQ(ScannerEngine::get_service_name(6379), "redis");
}

TEST(ScannerEngineTest, KnownPort_PostgreSQL) {
    EXPECT_EQ(ScannerEngine::get_service_name(5432), "postgresql");
}

TEST(ScannerEngineTest, KnownPort_SMTP) {
    EXPECT_EQ(ScannerEngine::get_service_name(25), "smtp");
}

TEST(ScannerEngineTest, KnownPort_DNS) {
    EXPECT_EQ(ScannerEngine::get_service_name(53), "domain");
}

TEST(ScannerEngineTest, KnownPort_RDP) {
    EXPECT_EQ(ScannerEngine::get_service_name(3389), "ms-wbt-server");
}

TEST(ScannerEngineTest, KnownPort_HTTPProxy) {
    EXPECT_EQ(ScannerEngine::get_service_name(8080), "http-proxy");
}

TEST(ScannerEngineTest, KnownPort_Telnet) {
    EXPECT_EQ(ScannerEngine::get_service_name(23), "telnet");
}

TEST(ScannerEngineTest, KnownPort_POP3) {
    EXPECT_EQ(ScannerEngine::get_service_name(110), "pop3");
}

TEST(ScannerEngineTest, KnownPort_IMAP) {
    EXPECT_EQ(ScannerEngine::get_service_name(143), "imap");
}

TEST(ScannerEngineTest, UnknownPort) {
    EXPECT_EQ(ScannerEngine::get_service_name(12345), "unknown");
}

TEST(ScannerEngineTest, UnknownPort_Zero) {
    EXPECT_EQ(ScannerEngine::get_service_name(0), "unknown");
}

TEST(ScannerEngineTest, UnknownPort_Negative) {
    EXPECT_EQ(ScannerEngine::get_service_name(-1), "unknown");
}

TEST(ScannerEngineTest, UnknownPort_Large) {
    EXPECT_EQ(ScannerEngine::get_service_name(99999), "unknown");
}
