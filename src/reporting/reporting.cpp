#include "packetforge/reporting.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
namespace packetforge {
std::string html_escape(const std::string& value) {
    std::string result;
    for (char c:value) switch (c) {
        case '&':result+="&amp;";break; case '<':result+="&lt;";break; case '>':result+="&gt;";break;
        case '"':result+="&quot;";break; case '\'':result+="&#39;";break; default:result+=c;
    }
    return result;
}
std::string csv_field(const std::string& value) {
    std::string result="\"";
    // Prevent spreadsheet formula execution as well as ordinary CSV quoting.
    if (!value.empty() && (value[0]=='=' || value[0]=='+' || value[0]=='-' || value[0]=='@' || value[0]=='\t' || value[0]=='\r' || value[0]=='\n')) result+='\'';
    for (char c:value) { if (c=='"') result+='"'; result+=c; } result+='"'; return result;
}
namespace {
std::string value(const Json& j) { return j.is_string() ? j.get<std::string>() : j.dump(); }
std::string table(const Json& rows,const std::vector<std::string>& columns) {
    std::ostringstream out; out << "<div class='scroll'><table><thead><tr>";
    for (const auto& column:columns) out << "<th>" << html_escape(column) << "</th>";
    out << "</tr></thead><tbody>";
    for (const auto& row:rows) {
        out << "<tr>"; for (const auto& column:columns) out << "<td>" << html_escape(value(row.at(column))) << "</td>"; out << "</tr>";
    }
    out << "</tbody></table></div>"; return out.str();
}
std::string csv(const Json& rows,const std::vector<std::string>& columns) {
    std::ostringstream out;
    for (std::size_t i=0;i<columns.size();++i) out << (i ? "," : "") << csv_field(columns[i]);
    out << '\n';
    for (const auto& row:rows) {
        for (std::size_t i=0;i<columns.size();++i) out << (i ? "," : "") << csv_field(value(row.at(columns[i])));
        out << '\n';
    }
    return out.str();
}
}
std::string html_report(const Json& data) {
    const auto& stats=data.at("statistics"); const auto& metadata=data.at("metadata");
    std::ostringstream out;
    out << R"HTML(<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>PacketForge — Investigation Report</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0a111c;color:#dce5ef;font:15px/1.6 system-ui,sans-serif}
main{max-width:1200px;margin:auto;padding:42px 24px}header{border-bottom:1px solid #2c4156;padding-bottom:26px;margin-bottom:28px}
h1{font-size:40px;letter-spacing:-1.5px;margin:0;color:#fff}h2{color:#65dbc0;font-size:21px;margin-top:36px}h3{margin:0 0 12px}
.eyebrow{letter-spacing:3px;color:#65dbc0;font-size:12px;text-transform:uppercase}.muted{color:#9cafc5}code,pre{font:13px/1.7 ui-monospace,monospace}
pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;background:#0b1524;border-radius:8px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.card,article{background:#111e2e;border:1px solid #253a50;border-radius:12px;padding:22px}.metric{display:block;font-size:32px;font-weight:700;color:white}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:12px;text-align:left;border-bottom:1px solid #253a50;overflow-wrap:anywhere}
th{color:#8ab5d5;background:#111e2e}article{margin:16px 0;border-left:3px solid #eebd66}.badge{border:1px solid #5b5139;border-radius:5px;padding:3px 8px;color:#eebd66;font:12px ui-monospace,monospace}
footer{margin-top:40px;border-top:1px solid #253a50;padding-top:18px;color:#9cafc5}.bar{height:6px;background:#65dbc0;border-radius:4px;margin-top:8px}a{color:#65dbc0}
@media print{body{background:white;color:#111}.card,article,th,pre{background:#f3f6f8;color:#111}h1,h2,h3,.metric,.muted,footer{color:#111}article{break-inside:avoid}}
</style></head><body><main><header><p class="eyebrow">Network security investigation</p><h1>PacketForge</h1><p class="muted">Passive packet analysis · Explainable intrusion detection</p>)HTML";
    out << "<p>Mode: " << html_escape(value(metadata.at("mode"))) << " · Source: " << html_escape(value(metadata.at("source"))) << "</p>"
        << "<p class='muted'>" << html_escape(value(metadata.at("first_packet"))) << " → " << html_escape(value(metadata.at("last_packet"))) << "</p></header>";
    out << "<section class='grid'>";
    for (const auto& key:{"packets","observed_bytes","unique_flows","total_ids_alerts"})
        out << "<div class='card'><span class='muted'>" << key << "</span><span class='metric'>" << html_escape(value(stats.at(key))) << "</span></div>";
    out << "</section><h2>Protocol distribution</h2><p class='muted'>Layer counters overlap; Ethernet, IP and transport counts are not additive.</p><div class='grid'>";
    const double total=stats.at("packets").get<double>();
    for (const auto& [name,count]:stats.at("protocols").items()) out << "<div class='card'>" << html_escape(name) << " <b>" << count
        << "</b><div class='bar' style='width:" << (total>0 ? count.get<double>()/total*100 : 0) << "%'></div></div>";
    out << "</div><h2>Top sources</h2>" << table(stats.at("top_sources"),{"address","packets"})
        << "<h2>Top destinations</h2>" << table(stats.at("top_destinations"),{"address","packets"})
        << "<h2>Destination ports</h2>" << table(stats.at("destination_ports"),{"port","packets"}) << "<h2>Security observations</h2>";
    if (data.at("alerts").empty()) out << "<p>No alerts were retained. This does not establish that traffic is safe. IDS enabled: " << metadata.at("ids_enabled") << ".</p>";
    for (const auto& alert:data.at("alerts")) {
        out << "<article><span class='badge'>" << html_escape(value(alert.at("severity"))) << "</span><h3>" << html_escape(value(alert.at("title")))
            << "</h3><p><code>" << html_escape(value(alert.at("alert_id"))) << " · " << html_escape(value(alert.at("rule_id"))) << "</code></p><p>"
            << html_escape(value(alert.at("timestamp"))) << " · " << html_escape(value(alert.at("source"))) << " → " << html_escape(value(alert.at("destination")))
            << "</p><p>Observed " << alert.at("observed_count") << " / threshold " << alert.at("threshold") << " within " << alert.at("detection_window_seconds") << " seconds.</p>"
            << "<pre>" << html_escape(alert.at("evidence").dump(2)) << "</pre><p>" << html_escape(value(alert.at("limitations")))
            << "</p><p>Recommendation: " << html_escape(value(alert.at("recommendation"))) << "</p><p>MITRE: " << html_escape(value(alert.at("mitre_technique"))) << "</p></article>";
    }
    out << "<h2>Directional flows</h2>" << table(data.at("flows"),{"source","source_port","destination","destination_port","protocol","packets","observed_bytes","duration_seconds","active"});
    for (const auto& section:{"statistics","metadata","rules","rule_counters"})
        out << "<details><summary><h2>" << section << "</h2></summary><pre>" << html_escape(data.at(section).dump(2)) << "</pre></details>";
    out << "<h2>Investigation limitations</h2><ul>";
    for (const auto& limitation:data.at("limitations")) out << "<li>" << html_escape(value(limitation)) << "</li>";
    out << "</ul><footer>PacketForge · Mayank Kumar Karn<br>Exported " << html_escape(value(metadata.at("export_timestamp")))
        << " · Standalone offline report</footer></main></body></html>"; return out.str();
}
std::vector<std::string> write_reports(const Json& data,const std::string& format,const std::string& prefix) {
    if (format!="json" && format!="csv" && format!="html" && format!="all") throw std::runtime_error("invalid report format");
    std::vector<std::pair<std::string,std::string>> files;
    if (format=="json" || format=="all") files.emplace_back(prefix+".json",data.dump(2)+"\n");
    if (format=="html" || format=="all") files.emplace_back(prefix+".html",html_report(data));
    if (format=="csv" || format=="all") {
        files.emplace_back(prefix+"-alerts.csv",csv(data.at("alerts"),{"alert_id","rule_id","title","timestamp","severity","source","destination","source_port","destination_port","detection_window_seconds","observed_count","threshold","evidence","confidence","limitations","recommendation","mitre_technique"}));
        files.emplace_back(prefix+"-flows.csv",csv(data.at("flows"),{"source","destination","source_port","destination_port","protocol","packets","observed_bytes","wire_bytes","first_seen","last_seen","duration_seconds","tcp_flags","active"}));
    }
    // Refuse overwrites so reports cannot accidentally destroy an input/config file.
    for (const auto& [path,content]:files) { (void)content; if (std::filesystem::exists(path)) throw std::runtime_error("report already exists: "+path+"; choose another --output prefix"); }
    std::vector<std::string> paths;
    for (const auto& [path,content]:files) {
        const auto parent=std::filesystem::path(path).parent_path(); if (!parent.empty()) std::filesystem::create_directories(parent);
        // Exclusive creation closes the race between the preflight check and writing.
        // Investigation metadata is private to the owner on POSIX filesystems.
        const int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if (fd<0) throw std::runtime_error("cannot create report: "+path+": "+std::strerror(errno));
        struct File { int fd; ~File() { if (fd>=0) ::close(fd); } } file{fd};
        std::size_t offset=0;
        while (offset<content.size()) {
            const auto written=::write(fd,content.data()+offset,content.size()-offset);
            if (written<0 && errno==EINTR) continue;
            if (written<=0) throw std::runtime_error("report write failed (partial file retained): "+path);
            offset+=static_cast<std::size_t>(written);
        }
        const int closed=::close(fd); file.fd=-1;
        if (closed<0) throw std::runtime_error("report close failed: "+path);
        paths.push_back(path);
    }
    return paths;
}
}
