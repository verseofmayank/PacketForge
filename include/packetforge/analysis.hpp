#pragma once
#include "capture.hpp"
#include "detection.hpp"
#include "flows.hpp"
#include "statistics.hpp"
#include <functional>
namespace packetforge {
class Analysis {
    Config config_;
    bool ids_;
    Timestamp previous_=-1;
public:
    Statistics statistics;
    FlowTable flows;
    DetectionEngine detection;
    std::vector<Json> alerts;
    std::map<std::string,std::uint64_t> alert_counts;
    std::uint64_t total_alerts=0,alerts_not_retained=0;
    Analysis(const Config& config,bool ids) : config_(config),ids_(ids),statistics(config.max_talkers),flows(config),detection(config) {}
    void observe(const Packet& packet,const std::function<void(const Json&)>& emit = {});
    Json report(const std::string& mode,const std::string& source,const CaptureResult& capture) const;
    void summary(std::ostream& out) const;
};
}
