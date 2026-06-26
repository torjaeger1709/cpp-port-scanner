#ifndef PORTSCANNER_CLI_PARSER_H
#define PORTSCANNER_CLI_PARSER_H

#include "common.h"

namespace CLIParser {

    // Print usage instructions
    void print_help(const char* prog_name);

    // Parse command line arguments into ScanConfig
    ScanConfig parse(int argc, char* argv[]);

} // namespace CLIParser

#endif // PORTSCANNER_CLI_PARSER_H
