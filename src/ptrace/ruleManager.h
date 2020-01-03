#pragma once

#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include <memory>

#include "rule.h"
#include "rulePlugin.h"

namespace SAIL { namespace rule {

class RuleManager
{
public:
    virtual ~RuleManager() {};
    virtual std::vector<core::RuleCheckMsg> check(int syscallNumber, const core::SyscallParameter & sp) = 0;
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
    virtual std::vector<core::RuleCheckMsg> check(int syscall, const core::SyscallParameter & sp) override;
};

}}