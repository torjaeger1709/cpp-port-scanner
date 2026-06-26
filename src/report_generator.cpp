#include "report_generator.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace ReportGenerator {

static std::string status_to_str(PortStatus status) {
    switch (status) {
        case PortStatus::OPEN: return "OPEN";
        case PortStatus::CLOSED: return "CLOSED";
        case PortStatus::FILTERED: return "FILTERED";
    }
    return "UNKNOWN";
}

static std::string status_to_lower(PortStatus status) {
    switch (status) {
        case PortStatus::OPEN: return "open";
        case PortStatus::CLOSED: return "closed";
        case PortStatus::FILTERED: return "filtered";
    }
    return "unknown";
}

void print_console(const std::vector<HostResult>& results) {
    std::cout << "=================================================================\n";
    std::cout << "                      PORT SCAN RESULTS\n";
    std::cout << "=================================================================\n";

    for (const auto& host : results) {
        std::cout << "Host: " << host.ip;
        if (!host.hostname.empty()) {
            std::cout << " (" << host.hostname << ")";
        }
        std::cout << "\n";

        int open_count = 0;
        for (const auto& p : host.ports) {
            if (p.status == PortStatus::OPEN) open_count++;
        }

        if (open_count == 0) {
            std::cout << "  -> All " << host.ports.size() << " scanned ports are CLOSED or FILTERED.\n\n";
            continue;
        }

        std::cout << std::left << std::setw(10) << "PORT"
                  << std::setw(12) << "STATE"
                  << "SERVICE\n";
        std::cout << "---------------------------------------------------------\n";

        for (const auto& p : host.ports) {
            if (p.status == PortStatus::OPEN) {
                std::string port_proto = std::to_string(p.port) + "/tcp";
                std::cout << std::left << std::setw(10) << port_proto
                          << std::setw(12) << "open"
                          << p.service_name << "\n";
            }
        }
        std::cout << "\n";
    }
}

static std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else o << c;
    }
    return o.str();
}

static bool export_csv(const std::vector<HostResult>& results, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) return false;

    out << "IP,Hostname,Port,Protocol,State,Service\n";
    for (const auto& h : results) {
        for (const auto& p : h.ports) {
            out << h.ip << ","
                << "\"" << h.hostname << "\","
                << p.port << ",tcp,"
                << status_to_str(p.status) << ","
                << "\"" << p.service_name << "\"\n";
        }
    }
    return true;
}

static bool export_json(const std::vector<HostResult>& results, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) return false;

    out << "{\n  \"generator\": \"C++ Modular CLI Port Scanner\",\n  \"scan_results\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& h = results[i];
        out << "    {\n";
        out << "      \"ip\": \"" << escape_json(h.ip) << "\",\n";
        out << "      \"hostname\": \"" << escape_json(h.hostname) << "\",\n";
        out << "      \"ports\": [\n";
        for (size_t j = 0; j < h.ports.size(); ++j) {
            const auto& p = h.ports[j];
            out << "        {\n";
            out << "          \"port\": " << p.port << ",\n";
            out << "          \"protocol\": \"tcp\",\n";
            out << "          \"state\": \"" << status_to_str(p.status) << "\",\n";
            out << "          \"service\": \"" << escape_json(p.service_name) << "\"\n";
            out << "        }" << (j + 1 < h.ports.size() ? "," : "") << "\n";
        }
        out << "      ]\n";
        out << "    }" << (i + 1 < results.size() ? "," : "") << "\n";
    }
    out << "  ]\n}\n";
    return true;
}

static bool export_xml(const std::vector<HostResult>& results, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) return false;

    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<nmaprun scanner=\"C++ Modular PortScanner\" version=\"1.0\">\n";
    for (const auto& h : results) {
        out << "  <host>\n";
        out << "    <address addr=\"" << h.ip << "\" addrtype=\"ipv4\"/>\n";
        if (!h.hostname.empty()) {
            out << "    <hostnames><hostname name=\"" << h.hostname << "\"/></hostnames>\n";
        } else {
            out << "    <hostnames/>\n";
        }
        out << "    <ports>\n";
        for (const auto& p : h.ports) {
            out << "      <port protocol=\"tcp\" portid=\"" << p.port << "\">\n";
            out << "        <state state=\"" << status_to_lower(p.status) << "\"/>\n";
            out << "        <service name=\"" << p.service_name << "\"/>\n";
            out << "      </port>\n";
        }
        out << "    </ports>\n";
        out << "  </host>\n";
    }
    out << "</nmaprun>\n";
    return true;
}

bool export_file(const std::vector<HostResult>& results, const std::string& filepath, OutputFormat format) {
    bool ok = false;
    switch (format) {
        case OutputFormat::CSV:
            ok = export_csv(results, filepath);
            break;
        case OutputFormat::XML:
            ok = export_xml(results, filepath);
            break;
        case OutputFormat::JSON:
        default:
            ok = export_json(results, filepath);
            break;
    }

    if (ok) {
        std::cout << "[+] Successfully exported scan report to file: " << filepath << "\n";
    } else {
        std::cerr << "[Error] Failed to write report data to file: " << filepath << "\n";
    }
    return ok;
}

} // namespace ReportGenerator
