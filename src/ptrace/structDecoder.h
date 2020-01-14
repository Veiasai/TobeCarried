#pragma once

#include <string>
#include <yaml-cpp/yaml.h>
#include <set>
#include <vector>
#include <arpa/inet.h>

#include "rulePlugin.h"
#include "utils.h"
#include "report.h"

namespace SAIL
{
namespace rule
{

class StructDecoder : public RulePlugin
{
private:
    std::shared_ptr<utils::Utils> up;
    std::shared_ptr<core::Report> report;

    
public:
    StructDecoder(const YAML::Node & config,
        std::shared_ptr<utils::Utils> up,
        std::shared_ptr<core::Report> report);
    virtual ~StructDecoder() {};
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