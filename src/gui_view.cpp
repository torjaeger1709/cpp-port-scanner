/*
 * =====================================================================================
 * Project: C++ Port Scanner (MVC Edition)
 * Author / Provided by: Khiem Nguyen
 * License: MIT License
 * =====================================================================================
 */
#include "gui_view.h"
#include "imgui.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>
#include <cstdio>

namespace GuiView {

struct GuiState {
    char target_buf[256] = "scanme.nmap.org";
    char port_buf[256] = "22,80,443";
    char export_buf[256] = "report.json";
    int scan_tech_idx = 0; // 0: Connect, 1: SYN, 2: FIN, 3: XMAS, 4: NULL_SCAN
    int threads_val = 100;
    int timeout_val = 1000;
    int export_fmt_idx = 0; // 0: JSON, 1: CSV, 2: XML
};

static GuiState& get_state() {
    static GuiState state;
    return state;
}

void setup_theme() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 8.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 6.0f;
    style.TabRounding = 6.0f;
    style.ItemSpacing = ImVec2(10, 8);
    style.FramePadding = ImVec2(10, 6);

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text]                   = ImVec4(0.96f, 0.97f, 0.98f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.55f, 0.60f, 0.68f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.06f, 0.09f, 0.16f, 1.00f); // Slate 950
    colors[ImGuiCol_ChildBg]                = ImVec4(0.11f, 0.15f, 0.24f, 0.85f); // Slate 900
    colors[ImGuiCol_PopupBg]                = ImVec4(0.11f, 0.15f, 0.24f, 0.95f);
    colors[ImGuiCol_Border]                 = ImVec4(0.20f, 0.26f, 0.38f, 0.50f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.16f, 0.21f, 0.33f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.22f, 0.29f, 0.44f, 1.00f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(0.02f, 0.71f, 0.83f, 0.40f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.06f, 0.09f, 0.16f, 1.00f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.06f, 0.09f, 0.16f, 1.00f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.11f, 0.15f, 0.24f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.02f, 0.71f, 0.83f, 1.00f); // Cyan 500
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.02f, 0.71f, 0.83f, 1.00f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.03f, 0.85f, 0.98f, 1.00f);
    colors[ImGuiCol_Button]                 = ImVec4(0.02f, 0.52f, 0.78f, 1.00f); // Sky 600
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.02f, 0.65f, 0.90f, 1.00f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.02f, 0.42f, 0.65f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.16f, 0.21f, 0.33f, 1.00f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.22f, 0.29f, 0.44f, 1.00f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.02f, 0.71f, 0.83f, 0.40f);
    colors[ImGuiCol_TableHeaderBg]          = ImVec4(0.14f, 0.19f, 0.30f, 1.00f);
    colors[ImGuiCol_TableBorderStrong]      = ImVec4(0.20f, 0.26f, 0.38f, 1.00f);
    colors[ImGuiCol_TableBorderLight]       = ImVec4(0.16f, 0.21f, 0.33f, 0.50f);
    colors[ImGuiCol_TableRowBg]             = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_TableRowBgAlt]          = ImVec4(1.00f, 1.00f, 1.00f, 0.03f);
}

static std::vector<int> parse_gui_ports(const char* p_str) {
    std::vector<int> res;
    std::string s(p_str);
    size_t start = 0, end = 0;
    while ((end = s.find(',', start)) != std::string::npos) {
        std::string token = s.substr(start, end - start);
        size_t dash = token.find('-');
        if (dash != std::string::npos) {
            try {
                int p1 = std::stoi(token.substr(0, dash));
                int p2 = std::stoi(token.substr(dash + 1));
                if (p1 > p2) std::swap(p1, p2);
                for (int i = std::max(1, p1); i <= std::min(65535, p2); ++i) res.push_back(i);
            } catch(...) {}
        } else {
            try {
                int p = std::stoi(token);
                if (p >= 1 && p <= 65535) res.push_back(p);
            } catch(...) {}
        }
        start = end + 1;
    }
    std::string token = s.substr(start);
    size_t dash = token.find('-');
    if (dash != std::string::npos) {
        try {
            int p1 = std::stoi(token.substr(0, dash));
            int p2 = std::stoi(token.substr(dash + 1));
            if (p1 > p2) std::swap(p1, p2);
            for (int i = std::max(1, p1); i <= std::min(65535, p2); ++i) res.push_back(i);
        } catch(...) {}
    } else {
        try {
            int p = std::stoi(token);
            if (p >= 1 && p <= 65535) res.push_back(p);
        } catch(...) {}
    }
    std::sort(res.begin(), res.end());
    res.erase(std::unique(res.begin(), res.end()), res.end());
    return res;
}

void render_ui(ScanController& controller) {
    GuiState& s = get_state();
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGuiWindowFlags win_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("MainLayout", nullptr, win_flags);

    // Title Header with Author Branding
    ImGui::TextColored(ImVec4(0.02f, 0.85f, 0.98f, 1.00f), "C++ PORT SCANNER");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.05f, 0.85f, 0.55f, 1.00f), "| Provided by Khiem Nguyen");
    ImGui::Separator();

    bool is_busy = controller.is_scanning();

    // Configuration Columns
    if (ImGui::BeginTable("ConfigTable", 2, ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);

        ImGui::Text("Target Specification (IP, Domain, or CIDR Subnet):");
        ImGui::BeginDisabled(is_busy);
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##target", s.target_buf, sizeof(s.target_buf));
        ImGui::EndDisabled();

        ImGui::Spacing();
        ImGui::Text("Port Range / List (e.g., 80,443 | 1-1024):");
        ImGui::BeginDisabled(is_busy);
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##ports", s.port_buf, sizeof(s.port_buf));
        ImGui::EndDisabled();

        ImGui::Spacing();
        ImGui::Text("Concurrency & Network Settings:");
        ImGui::BeginDisabled(is_busy);
        
        // Synced Slider + InputInt for precise thread control
        ImGui::SetNextItemWidth(-110);
        ImGui::SliderInt("##th_slide", &s.threads_val, 1, 500, "Threads: %d"); ImGui::SameLine();
        ImGui::SetNextItemWidth(100);
        ImGui::InputInt("##th_input", &s.threads_val, 10, 50);
        s.threads_val = std::max(1, std::min(1000, s.threads_val));

        // Synced Slider + InputInt for timeout control
        ImGui::SetNextItemWidth(-110);
        ImGui::SliderInt("##to_slide", &s.timeout_val, 50, 5000, "Timeout: %dms"); ImGui::SameLine();
        ImGui::SetNextItemWidth(100);
        ImGui::InputInt("##to_input", &s.timeout_val, 100, 500);
        s.timeout_val = std::max(10, std::min(10000, s.timeout_val));
        
        ImGui::EndDisabled();

        ImGui::TableSetColumnIndex(1);
        ImGui::Text("Stealth Scan Technique:");
        ImGui::BeginDisabled(is_busy);
        // Extended vertical box height (180px) with explicit NoScrollbar flag for clean look
        ImGui::BeginChild("TechniqueBox", ImVec2(-1, 180.0f), true, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        ImGui::RadioButton("-sT (Standard TCP Connect Scan - Default)", &s.scan_tech_idx, 0);
        ImGui::RadioButton("-sS (Stealth TCP SYN Scan - Half-Open)", &s.scan_tech_idx, 1);
        ImGui::RadioButton("-sF (Stealth TCP FIN Scan - RFC 793 Inverse)", &s.scan_tech_idx, 2);
        ImGui::RadioButton("-sX (Stealth TCP XMAS Scan - FIN+PSH+URG)", &s.scan_tech_idx, 3);
        ImGui::RadioButton("-sN (Stealth TCP NULL Scan - Zero Flags)", &s.scan_tech_idx, 4);
        ImGui::EndChild();
        ImGui::EndDisabled();

        ImGui::EndTable();
    }

    ImGui::Spacing();

    // Action Toolbar & Live Status
    float progress = controller.get_progress();
    if (!is_busy) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.05f, 0.65f, 0.45f, 1.00f)); // Emerald Green
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.06f, 0.80f, 0.55f, 1.00f));
        if (ImGui::Button("START SCAN", ImVec2(180, 42))) {
            controller.clear_logs();
            ScanConfig cfg;
            cfg.target_raw = s.target_buf;
            cfg.ports = parse_gui_ports(s.port_buf);
            cfg.threads = s.threads_val;
            cfg.timeout_ms = s.timeout_val;
            static const ScanType scan_type_lookup[] = {
                ScanType::CONNECT, ScanType::SYN, ScanType::FIN, ScanType::XMAS, ScanType::NULL_SCAN
            };
            if (s.scan_tech_idx < 0 || s.scan_tech_idx >= static_cast<int>(sizeof(scan_type_lookup)/sizeof(scan_type_lookup[0]))) {
                s.scan_tech_idx = 0;
            }
            cfg.scan_type = scan_type_lookup[s.scan_tech_idx];
            controller.start_scan(cfg);
        }
        ImGui::PopStyleColor(2);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.85f, 0.20f, 0.25f, 1.00f)); // Crimson Red
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.95f, 0.30f, 0.35f, 1.00f));
        if (ImGui::Button("CANCEL SCAN", ImVec2(180, 42))) {
            controller.stop_scan();
        }
        ImGui::PopStyleColor(2);
    }

    ImGui::SameLine();
    ImGui::ProgressBar(progress, ImVec2(-1, 42), is_busy ? "Scanning in progress..." : "Idle / Ready");

    ImGui::Spacing();

    // Live Console Logs and Results Splitter
    float child_height = (ImGui::GetContentRegionAvail().y - 50) / 2.0f;

    ImGui::TextColored(ImVec4(0.02f, 0.85f, 0.98f, 1.00f), "Real-Time Event Logs Console:");
    if (ImGui::BeginChild("LogConsole", ImVec2(-1, child_height), true, ImGuiWindowFlags_HorizontalScrollbar)) {
        auto logs = controller.get_logs();
        for (const auto& l : logs) {
            if (l.find("[+]") != std::string::npos) ImGui::TextColored(ImVec4(0.05f, 0.85f, 0.55f, 1.0f), "%s", l.c_str());
            else if (l.find("[Error]") != std::string::npos) ImGui::TextColored(ImVec4(0.95f, 0.25f, 0.30f, 1.0f), "%s", l.c_str());
            else if (l.find("[Warning]") != std::string::npos) ImGui::TextColored(ImVec4(0.98f, 0.75f, 0.10f, 1.0f), "%s", l.c_str());
            else ImGui::TextUnformatted(l.c_str());
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
        ImGui::EndChild();
    }

    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.02f, 0.85f, 0.98f, 1.00f), "Discovered Port Results Table:");
    if (ImGui::BeginChild("TableChild", ImVec2(-1, child_height), true)) {
        // Optimized Data Table Widths: Fixed compact widths for short status fields, large flexible weights for banners
        if (ImGui::BeginTable("ResultsTable", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Host IP", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Hostname", ImGuiTableColumnFlags_WidthStretch, 0.8f);
            ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthFixed, 50.0f);
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 65.0f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Service Banner", ImGuiTableColumnFlags_WidthStretch, 2.0f);
            ImGui::TableHeadersRow();

            struct FlatRow {
                const std::string* ip;
                const std::string* hostname;
                int port;
                PortStatus status;
                const std::string* service_name;
            };
            static std::vector<HostResult> cached_res;
            static std::vector<FlatRow> flat_rows;
            static float last_fetch_time = -10.0f;
            float now = (float)ImGui::GetTime();

            if (is_busy) {
                if (now - last_fetch_time > 0.2f) {
                    cached_res = controller.get_results();
                    flat_rows.clear();
                    for (const auto& hr : cached_res) {
                        for (const auto& pr : hr.ports) {
                            flat_rows.push_back({&hr.ip, &hr.hostname, pr.port, pr.status, &pr.service_name});
                        }
                    }
                    last_fetch_time = now;
                }
            } else if (last_fetch_time != -1.0f) {
                cached_res = controller.get_results();
                flat_rows.clear();
                for (const auto& hr : cached_res) {
                    for (const auto& pr : hr.ports) {
                        flat_rows.push_back({&hr.ip, &hr.hostname, pr.port, pr.status, &pr.service_name});
                    }
                }
                last_fetch_time = -1.0f;
            }

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(flat_rows.size()));
            while (clipper.Step()) {
                for (int row_idx = clipper.DisplayStart; row_idx < clipper.DisplayEnd; row_idx++) {
                    const auto& item = flat_rows[row_idx];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(item.ip->c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(item.hostname->c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%d", item.port);
                    ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted("tcp");
                    ImGui::TableSetColumnIndex(4);
                    if (item.status == PortStatus::OPEN) {
                        ImGui::TextColored(ImVec4(0.05f, 0.85f, 0.55f, 1.0f), "OPEN");
                    } else if (item.status == PortStatus::OPEN_FILTERED) {
                        ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.0f, 1.0f), "OPEN|FILTERED");
                    } else if (item.status == PortStatus::FILTERED) {
                        ImGui::TextColored(ImVec4(0.98f, 0.75f, 0.10f, 1.0f), "FILTERED");
                    } else {
                        ImGui::TextColored(ImVec4(0.55f, 0.60f, 0.68f, 1.0f), "CLOSED");
                    }
                    ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(item.service_name->c_str());
                }
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();
    }

    // Export Footer
    ImGui::Text("Export Scan Report:"); ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputText("##export_file", s.export_buf, sizeof(s.export_buf)); ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::Combo("##export_fmt", &s.export_fmt_idx, "JSON\0CSV\0XML\0\0"); ImGui::SameLine();
    if (ImGui::Button("SAVE REPORT")) {
        static const OutputFormat export_fmt_lookup[] = {
            OutputFormat::JSON, OutputFormat::CSV, OutputFormat::XML
        };
        if (s.export_fmt_idx < 0 || s.export_fmt_idx >= static_cast<int>(sizeof(export_fmt_lookup)/sizeof(export_fmt_lookup[0]))) {
            s.export_fmt_idx = 0;
        }
        controller.export_report(s.export_buf, export_fmt_lookup[s.export_fmt_idx]);
    }

    ImGui::End();
}

} // namespace GuiView
