#pragma once

#include <string>
#include <vector>
#include <set>
#include <regex>
#include <yaml-cpp/yaml.h>

#include "rulePlugin.h"
#include "report.h"

namespace SAIL
{
namespace rule
{

class FileWhitelist : public RulePlugin
{
private:
    std::string filename;
    std::vector<std::regex> whitelist_patterns;
    std::set<std::string> files;
    std::shared_ptr<utils::Utils> up;
    std::shared_ptr<core::Report> report;

public:
    FileWhitelist(const YAML::Node & config, 
        std::shared_ptr<utils::Utils> up,
        std::shared_ptr<core::Report> report);
    virtual ~FileWhitelist() {};
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