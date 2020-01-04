#pragma once

#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include <memory>

#include "rule.h"
#include "report.h"
#include "rulePlugin.h"
#include "parameter.h"

namespace SAIL { namespace rule {

class RuleManager
{
public:
    virtual ~RuleManager() {};
    virtual void beforeTrap(long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs) = 0;
    virtual void afterTrap(long tid, 
        const core::Histories & history, 
        core::RuleCheckMsgs & ruleCheckMsgs) = 0;
    virtual void event(long tid, int status) = 0;
};

class YamlRuleManager : public RuleManager
{
private:
    // map from syscall number to rules applied
    std::map<int, std::vector<std::unique_ptr<Rule>>> rules;
    std::map<std::string, std::unique_ptr<RulePlugin>> plugins;

    void ruleInit(const YAML::Node & yaml);
    void pluginInit(const YAML::Node & yaml);
public:
    YamlRuleManager(const YAML::Node & yaml);
    virtual ~YamlRuleManager() {};
    virtual void beforeTrap(long tid,
        const core::Histories & history,
        core::RuleCheckMsgs & ruleCheckMsgs) override;
    virtual void afterTrap(long tid,
        const core::Histories & history,
        core::RuleCheckMsgs & ruleCheckMsgs) override;
    virtual void event(long tid, int status) override;
};

}}