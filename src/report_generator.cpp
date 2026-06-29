#include "report_generator.h"
#include "target_helper.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <mutex>

namespace ReportGenerator {

static std::string status_to_str(PortStatus status) {
    switch (status) {
        case PortStatus::OPEN: return "OPEN";
        case PortStatus::CLOSED: return "CLOSED";
        case PortStatus::FILTERED: return "FILTERED";
        case PortStatus::OPEN_FILTERED: return "OPEN|FILTERED";
    }
    return "UNKNOWN";
}

static std::string status_to_lower(PortStatus status) {
    switch (status) {
        case PortStatus::OPEN: return "open";
        case PortStatus::CLOSED: return "closed";
        case PortStatus::FILTERED: return "filtered";
        case PortStatus::OPEN_FILTERED: return "open|filtered";
    }
    return "unknown";
}

static std::string get_hostname_lazy(const HostResult& h) {
    if (!h.hostname.empty()) return h.hostname;
    static std::mutex dns_cache_mtx;
    static std::unordered_map<std::string, std::string> dns_cache;
    {
        std::lock_guard<std::mutex> lock(dns_cache_mtx);
        auto it = dns_cache.find(h.ip);
        if (it != dns_cache.end()) return it->second;
    }
    std::string resolved = TargetHelper::resolve_hostname(h.ip);
    {
        std::lock_guard<std::mutex> lock(dns_cache_mtx);
        dns_cache[h.ip] = resolved;
    }
    return resolved;
}

void print_console(const std::vector<HostResult>& results) {
    std::cout << "=================================================================\n";
    std::cout << "                      PORT SCAN RESULTS\n";
    std::cout << "=================================================================\n";

    for (const auto& host : results) {
        std::string hostname = get_hostname_lazy(host);
        std::cout << "Host: " << host.ip;
        if (!hostname.empty()) {
            std::cout << " (" << hostname << ")";
        }
        std::cout << "\n";

        int open_count = 0;
        for (const auto& p : host.ports) {
            if (p.status == PortStatus::OPEN || p.status == PortStatus::OPEN_FILTERED) open_count++;
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
            if (p.status == PortStatus::OPEN || p.status == PortStatus::OPEN_FILTERED) {
                std::string port_proto = std::to_string(p.port) + "/tcp";
                std::string state = (p.status == PortStatus::OPEN_FILTERED) ? "open|filtered" : "open";
                std::cout << std::left << std::setw(10) << port_proto
                          << std::setw(16) << state
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
        else if (static_cast<unsigned char>(c) < 0x20) {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c)) << std::dec;
        }
        else o << c;
    }
    return o.str();
}

static std::string escape_csv(const std::string& s) {
    std::string res;
    bool formula_trigger = (!s.empty() && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r'));
    if (formula_trigger) {
        res += "'";
    }
    for (char c : s) {
        if (c == '"') res += "\"\"";
        else res += c;
    }
    return "\"" + res + "\"";
}

static std::string escape_xml(const std::string& s) {
    std::string res;
    for (char c : s) {
        switch (c) {
            case '&':  res += "&amp;"; break;
            case '\"': res += "&quot;"; break;
            case '\'': res += "&apos;"; break;
            case '<':  res += "&lt;"; break;
            case '>':  res += "&gt;"; break;
            default:   res += c; break;
        }
    }
    return res;
}

static bool export_csv(const std::vector<HostResult>& results, const std::string& filepath) {
    std::ofstream out(filepath);
    if (!out.is_open()) return false;

    out << "IP,Hostname,Port,Protocol,State,Service\n";
    for (const auto& h : results) {
        std::string hostname = get_hostname_lazy(h);
        for (const auto& p : h.ports) {
            out << escape_csv(h.ip) << ","
                << escape_csv(hostname) << ","
                << p.port << ",tcp,"
                << status_to_str(p.status) << ","
                << escape_csv(p.service_name) << "\n";
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
        std::string hostname = get_hostname_lazy(h);
        out << "    {\n";
        out << "      \"ip\": \"" << escape_json(h.ip) << "\",\n";
        out << "      \"hostname\": \"" << escape_json(hostname) << "\",\n";
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
        std::string hostname = get_hostname_lazy(h);
        out << "  <host>\n";
        out << "    <address addr=\"" << escape_xml(h.ip) << "\" addrtype=\"ipv4\"/>\n";
        if (!hostname.empty()) {
            out << "    <hostnames><hostname name=\"" << escape_xml(hostname) << "\"/></hostnames>\n";
        } else {
            out << "    <hostnames/>\n";
        }
        out << "    <ports>\n";
        for (const auto& p : h.ports) {
            out << "      <port protocol=\"tcp\" portid=\"" << p.port << "\">\n";
            out << "        <state state=\"" << status_to_lower(p.status) << "\"/>\n";
            out << "        <service name=\"" << escape_xml(p.service_name) << "\"/>\n";
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
