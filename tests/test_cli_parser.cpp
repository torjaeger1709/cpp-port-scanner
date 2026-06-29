#include <gtest/gtest.h>
#include "cli_parser.h"

// Helper to create argv from string literals
#define MAKE_ARGV(...) \
    const char* args_[] = { __VA_ARGS__ }; \
    int argc_ = sizeof(args_) / sizeof(args_[0]); \
    char** argv_ = const_cast<char**>(args_)

TEST(CLIParserTest, EmptyArgs) {
    MAKE_ARGV("scanner");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_TRUE(config.show_help);
}

TEST(CLIParserTest, HelpFlag) {
    MAKE_ARGV("scanner", "-h");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_TRUE(config.show_help);
}

TEST(CLIParserTest, HelpFlagLong) {
    MAKE_ARGV("scanner", "--help");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_TRUE(config.show_help);
}

TEST(CLIParserTest, TargetParsing) {
    MAKE_ARGV("scanner", "-t", "192.168.1.1", "-p", "80");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.target_raw, "192.168.1.1");
}

TEST(CLIParserTest, PortParsingSingle) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80");
    auto config = CLIParser::parse(argc_, argv_);
    ASSERT_EQ(config.ports.size(), 1u);
    EXPECT_EQ(config.ports[0], 80);
}

TEST(CLIParserTest, PortParsingMultiple) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "22,80,443");
    auto config = CLIParser::parse(argc_, argv_);
    ASSERT_EQ(config.ports.size(), 3u);
    EXPECT_EQ(config.ports[0], 22);
    EXPECT_EQ(config.ports[1], 80);
    EXPECT_EQ(config.ports[2], 443);
}

TEST(CLIParserTest, PortParsingRange) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "1-5");
    auto config = CLIParser::parse(argc_, argv_);
    ASSERT_EQ(config.ports.size(), 5u);
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(config.ports[i], i + 1);
    }
}

TEST(CLIParserTest, PortParsingReverseRange) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "5-1");
    auto config = CLIParser::parse(argc_, argv_);
    ASSERT_EQ(config.ports.size(), 5u);
    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(config.ports[i], i + 1);
    }
}

TEST(CLIParserTest, PortParsingDedup) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80,80,443");
    auto config = CLIParser::parse(argc_, argv_);
    ASSERT_EQ(config.ports.size(), 2u);
    EXPECT_EQ(config.ports[0], 80);
    EXPECT_EQ(config.ports[1], 443);
}

TEST(CLIParserTest, ScanTypeSYN) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-sS");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.scan_type, ScanType::SYN);
}

TEST(CLIParserTest, ScanTypeFIN) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-sF");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.scan_type, ScanType::FIN);
}

TEST(CLIParserTest, ScanTypeXMAS) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-sX");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.scan_type, ScanType::XMAS);
}

TEST(CLIParserTest, ScanTypeNULL) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-sN");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.scan_type, ScanType::NULL_SCAN);
}

TEST(CLIParserTest, ScanTypeCONNECT) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-sT");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.scan_type, ScanType::CONNECT);
}

TEST(CLIParserTest, ThreadsOption) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "--threads", "50");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.threads, 50);
}

TEST(CLIParserTest, TimeoutOption) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "--timeout", "2000");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.timeout_ms, 2000);
}

TEST(CLIParserTest, OutputFile) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-o", "report.json");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.output_file, "report.json");
}

TEST(CLIParserTest, FormatExplicitCSV) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-o", "report.txt", "-f", "csv");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.format, OutputFormat::CSV);
}

TEST(CLIParserTest, FormatAutoJson) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-o", "report.json");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.format, OutputFormat::JSON);
}

TEST(CLIParserTest, FormatAutoCsv) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-o", "report.csv");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.format, OutputFormat::CSV);
}

TEST(CLIParserTest, FormatAutoXml) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "-o", "report.xml");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.format, OutputFormat::XML);
}

TEST(CLIParserTest, PortOutOfRange) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "99999");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_TRUE(config.ports.empty());
}

TEST(CLIParserTest, DefaultValues) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.threads, 100);
    EXPECT_EQ(config.timeout_ms, 1000);
    EXPECT_EQ(config.scan_type, ScanType::CONNECT);
    EXPECT_EQ(config.format, OutputFormat::CONSOLE);
    EXPECT_FALSE(config.show_help);
}

TEST(CLIParserTest, SynLongFlag) {
    MAKE_ARGV("scanner", "-t", "x", "-p", "80", "--syn");
    auto config = CLIParser::parse(argc_, argv_);
    EXPECT_EQ(config.scan_type, ScanType::SYN);
}
