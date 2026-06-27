/*
 * =====================================================================================
 * Project: C++ Port Scanner (MVC Edition)
 * Author / Provided by: Khiem Nguyen
 * License: MIT License
 * =====================================================================================
 */
#include "cli_parser.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace CLIParser {

void print_help(const char* prog_name) {
    std::cout << "=================================================================\n";
    std::cout << "                   C++ MODULAR CLI PORT SCANNER\n";
    std::cout << "=================================================================\n";
    std::cout << "Usage:\n";
    std::cout << "  " << prog_name << " -t <target> -p <ports> [scan technique] [options]\n\n";
    std::cout << "Required Arguments:\n";
    std::cout << "  -t, --target <target>          Scan target (e.g., 192.168.1.1, scanme.nmap.org, 10.0.0.0/24)\n";
    std::cout << "  -p, --ports <ports>            Ports to scan (e.g., 80 | 22,80,443 | 1-1024)\n\n";
    std::cout << "Scan Techniques:\n";
    std::cout << "  -sT                            Standard TCP Connect Scan (default - 3-way handshake)\n";
    std::cout << "  -sS, --syn                     Stealth TCP SYN Scan (half-open - requires Admin)\n";
    std::cout << "  -sF                            Stealth TCP FIN Scan (RFC 793 inverse scan)\n";
    std::cout << "  -sX                            Stealth TCP XMAS Scan (FIN+PSH+URG flags)\n";
    std::cout << "  -sN                            Stealth TCP NULL Scan (no flags set)\n\n";
    std::cout << "Additional Options:\n";
    std::cout << "  -o, --output <file>            Save scan report to file\n";
    std::cout << "  -f, --format <json|csv|xml>    Report file format\n";
    std::cout << "  --threads <num>                Number of concurrent scan threads (default: 100)\n";
    std::cout << "  --timeout <ms>                 Maximum connection timeout per port (default: 1000ms)\n";
    std::cout << "  -h, --help                     Display this help menu\n";
    std::cout << "=================================================================\n";
}

static std::vector<int> parse_ports(const std::string& port_str) {
    std::vector<int> ports;
    std::stringstream ss(port_str);
    std::string item;

    while (std::getline(ss, item, ',')) {
        size_t dash_pos = item.find('-');
        if (dash_pos != std::string::npos) {
            try {
                int start = std::stoi(item.substr(0, dash_pos));
                int end = std::stoi(item.substr(dash_pos + 1));
                if (start > end) std::swap(start, end);
                start = std::max(1, start);
                end = std::min(65535, end);
                for (int p = start; p <= end; ++p) {
                    ports.push_back(p);
                }
            } catch (...) {
                std::cerr << "[Warning] Ignoring invalid port range: " << item << std::endl;
            }
        } else {
            try {
                int p = std::stoi(item);
                if (p >= 1 && p <= 65535) {
                    ports.push_back(p);
                } else {
                    std::cerr << "[Warning] Port out of valid range (1-65535): " << p << std::endl;
                }
            } catch (...) {
                std::cerr << "[Warning] Ignoring invalid port token: " << item << std::endl;
            }
        }
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

ScanConfig parse(int argc, char* argv[]) {
    ScanConfig config;
    if (argc <= 1) {
        config.show_help = true;
        return config;
    }

    bool format_explicit = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            config.show_help = true;
            return config;
        } else if (arg == "-sT") {
            config.scan_type = ScanType::CONNECT;
        } else if (arg == "-sS" || arg == "--syn") {
            config.scan_type = ScanType::SYN;
        } else if (arg == "-sF") {
            config.scan_type = ScanType::FIN;
        } else if (arg == "-sX") {
            config.scan_type = ScanType::XMAS;
        } else if (arg == "-sN") {
            config.scan_type = ScanType::NULL_SCAN;
        } else if (arg == "-t" || arg == "--target") {
            if (i + 1 < argc) {
                config.target_raw = argv[++i];
            } else {
                std::cerr << "[Error] Missing value for argument " << arg << std::endl;
            }
        } else if (arg == "-p" || arg == "--ports") {
            if (i + 1 < argc) {
                config.ports = parse_ports(argv[++i]);
            } else {
                std::cerr << "[Error] Missing value for argument " << arg << std::endl;
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                config.output_file = argv[++i];
            } else {
                std::cerr << "[Error] Missing value for argument " << arg << std::endl;
            }
        } else if (arg == "-f" || arg == "--format") {
            if (i + 1 < argc) {
                format_explicit = true;
                std::string fmt = to_lower(argv[++i]);
                if (fmt == "json") config.format = OutputFormat::JSON;
                else if (fmt == "csv") config.format = OutputFormat::CSV;
                else if (fmt == "xml") config.format = OutputFormat::XML;
                else {
                    std::cerr << "[Warning] Unsupported format: " << fmt << ". Defaulting to JSON.\n";
                    config.format = OutputFormat::JSON;
                }
            } else {
                std::cerr << "[Error] Missing value for argument " << arg << std::endl;
            }
        } else if (arg == "--threads") {
            if (i + 1 < argc) {
                try {
                    config.threads = std::max(1, std::stoi(argv[++i]));
                } catch (...) {
                    std::cerr << "[Error] Invalid value for threads.\n";
                }
            } else {
                std::cerr << "[Error] Missing value for argument " << arg << std::endl;
            }
        } else if (arg == "--timeout") {
            if (i + 1 < argc) {
                try {
                    config.timeout_ms = std::max(10, std::stoi(argv[++i]));
                } catch (...) {
                    std::cerr << "[Error] Invalid value for timeout.\n";
                }
            } else {
                std::cerr << "[Error] Missing value for argument " << arg << std::endl;
            }
        } else {
            std::cerr << "[Warning] Ignoring unrecognized argument: " << arg << std::endl;
        }
    }

    if (!config.output_file.empty() && !format_explicit) {
        std::string lower_out = to_lower(config.output_file);
        if (lower_out.size() >= 5 && lower_out.substr(lower_out.size() - 5) == ".json") {
            config.format = OutputFormat::JSON;
        } else if (lower_out.size() >= 4 && lower_out.substr(lower_out.size() - 4) == ".csv") {
            config.format = OutputFormat::CSV;
        } else if (lower_out.size() >= 4 && lower_out.substr(lower_out.size() - 4) == ".xml") {
            config.format = OutputFormat::XML;
        }
    }

    return config;
}

} // namespace CLIParser
