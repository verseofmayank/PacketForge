#pragma once
#include "config.hpp"
#include <string>
#include <vector>
namespace packetforge {
std::string html_escape(const std::string& value);
std::string csv_field(const std::string& value);
std::string html_report(const Json& data);
std::vector<std::string> write_reports(const Json& data,const std::string& format,const std::string& prefix);
}
