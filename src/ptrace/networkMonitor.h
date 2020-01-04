#pragma once

#include <string>
#include <yaml-cpp/yaml.h>

#include "rulePlugin.h"
#include "utils.h"
#include "report.h"

namespace SAIL
{
namespace rule
{

class NetworkMonitor : public RulePlugin
{
private:
    std::shared_ptr<utils::Utils> up;
    std::shared_ptr<core::Report> report;
public:
    NetworkMonitor(const YAML::Node & config,
        std::shared_ptr<utils::Utils> up,
        std::shared_ptr<core::Report> report);
    virtual ~NetworkMonitor() {};
    virtual void beforeTrap(long tid,
        const core::Histories & history,
        core::RuleCheckMsgs & ruleCheckMsgs) override;
    virtual void afterTrap(long tid,
        const core::Histories & history,
        core::RuleCheckMsgs & ruleCheckMsgs) override;
    virtual void event(long tid, int status) override;
    virtual void end() override;
};

} // namespace core
} // namespace SAIL