#ifndef PORTSCANNER_REPORT_GENERATOR_H
#define PORTSCANNER_REPORT_GENERATOR_H

#include "common.h"
#include <vector>
#include <string>

namespace ReportGenerator {

    // Display scan results formatted in Console
    void print_console(const std::vector<HostResult>& results);

    // Export scan results to JSON, CSV, or XML file format
    bool export_file(const std::vector<HostResult>& results, const std::string& filepath, OutputFormat format);

} // namespace ReportGenerator

#endif // PORTSCANNER_REPORT_GENERATOR_H
