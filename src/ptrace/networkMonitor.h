#pragma once

#include <string>
#include <yaml-cpp/yaml.h>

#include "rulePlugin.h"

namespace SAIL
{
namespace rule
{

class NetworkMonitor : public RulePlugin
{
private:

public:
    NetworkMonitor(const YAML::Node & config);
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