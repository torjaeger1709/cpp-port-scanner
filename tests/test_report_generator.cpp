#include <gtest/gtest.h>
#include "report_generator.h"
#include <fstream>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

static std::vector<HostResult> make_test_results() {
    HostResult host;
    host.ip = "192.168.1.1";
    host.hostname = "testhost";
    host.ports = {
        {22, PortStatus::OPEN, "ssh"},
        {80, PortStatus::OPEN, "http"},
        {443, PortStatus::CLOSED, "https"},
        {8080, PortStatus::FILTERED, "http-proxy"},
        {9090, PortStatus::OPEN_FILTERED, "unknown"}
    };
    return {host};
}

static std::string read_file_content(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

class ReportGeneratorTest : public ::testing::Test {
protected:
    fs::path temp_dir;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / "port_scanner_test";
        fs::create_directories(temp_dir);
    }

    void TearDown() override {
        fs::remove_all(temp_dir);
    }

    std::string temp_file(const std::string& name) {
        return (temp_dir / name).string();
    }
};

TEST_F(ReportGeneratorTest, ExportJSON_Success) {
    auto results = make_test_results();
    std::string path = temp_file("test.json");
    bool ok = ReportGenerator::export_file(results, path, OutputFormat::JSON);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(fs::exists(path));
}

TEST_F(ReportGeneratorTest, ExportJSON_Content) {
    auto results = make_test_results();
    std::string path = temp_file("test.json");
    ReportGenerator::export_file(results, path, OutputFormat::JSON);
    std::string content = read_file_content(path);

    EXPECT_NE(content.find("192.168.1.1"), std::string::npos);
    EXPECT_NE(content.find("ssh"), std::string::npos);
    EXPECT_NE(content.find("OPEN"), std::string::npos);
    EXPECT_NE(content.find("CLOSED"), std::string::npos);
}

TEST_F(ReportGeneratorTest, ExportJSON_OpenFiltered) {
    auto results = make_test_results();
    std::string path = temp_file("test_of.json");
    ReportGenerator::export_file(results, path, OutputFormat::JSON);
    std::string content = read_file_content(path);
    EXPECT_NE(content.find("OPEN|FILTERED"), std::string::npos);
}

TEST_F(ReportGeneratorTest, ExportCSV_Success) {
    auto results = make_test_results();
    std::string path = temp_file("test.csv");
    bool ok = ReportGenerator::export_file(results, path, OutputFormat::CSV);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(fs::exists(path));
}

TEST_F(ReportGeneratorTest, ExportCSV_Content) {
    auto results = make_test_results();
    std::string path = temp_file("test.csv");
    ReportGenerator::export_file(results, path, OutputFormat::CSV);
    std::string content = read_file_content(path);

    // Should have header and data rows
    EXPECT_NE(content.find("192.168.1.1"), std::string::npos);
    EXPECT_NE(content.find("22"), std::string::npos);
    EXPECT_NE(content.find("ssh"), std::string::npos);
}

TEST_F(ReportGeneratorTest, ExportCSV_OpenFiltered) {
    auto results = make_test_results();
    std::string path = temp_file("test_of.csv");
    ReportGenerator::export_file(results, path, OutputFormat::CSV);
    std::string content = read_file_content(path);
    // CSV should contain the open|filtered status (possibly quoted)
    EXPECT_TRUE(content.find("open|filtered") != std::string::npos ||
                content.find("OPEN|FILTERED") != std::string::npos);
}

TEST_F(ReportGeneratorTest, ExportXML_Success) {
    auto results = make_test_results();
    std::string path = temp_file("test.xml");
    bool ok = ReportGenerator::export_file(results, path, OutputFormat::XML);
    EXPECT_TRUE(ok);
    EXPECT_TRUE(fs::exists(path));
}

TEST_F(ReportGeneratorTest, ExportXML_Content) {
    auto results = make_test_results();
    std::string path = temp_file("test.xml");
    ReportGenerator::export_file(results, path, OutputFormat::XML);
    std::string content = read_file_content(path);

    EXPECT_NE(content.find("192.168.1.1"), std::string::npos);
    EXPECT_NE(content.find("<port"), std::string::npos);
    EXPECT_NE(content.find("ssh"), std::string::npos);
}

TEST_F(ReportGeneratorTest, ExportXML_OpenFiltered) {
    auto results = make_test_results();
    std::string path = temp_file("test_of.xml");
    ReportGenerator::export_file(results, path, OutputFormat::XML);
    std::string content = read_file_content(path);
    EXPECT_TRUE(content.find("open|filtered") != std::string::npos ||
                content.find("OPEN|FILTERED") != std::string::npos);
}
