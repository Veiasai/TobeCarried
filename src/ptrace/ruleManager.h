#pragma once

#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include <memory>

#include "rule.h"


namespace SAIL { namespace rule {

class RuleManager
{
public:
    virtual ~RuleManager() {};
    virtual int ruleMatch(const YAML::Node & yaml,std::map<int, std::vector<std::unique_ptr<Rule>>> &rules) = 0;
    virtual std::vector<core::RuleCheckMsg> check(int syscallNumber, const core::SyscallParameter & sp) = 0;
};

class YamlRuleManager : public RuleManager
{
private:
    // map from syscall number to rules applied
    std::map<int, std::vector<std::unique_ptr<Rule>>> whitelist_rules;
    std::map<int, std::vector<std::unique_ptr<Rule>>> blacklist_rules;
public:
    YamlRuleManager(const YAML::Node & yaml);
    virtual ~YamlRuleManager() {};
    virtual int ruleMatch(const YAML::Node & yaml,std::map<int, std::vector<std::unique_ptr<Rule>>> &rules) override;
    virtual std::vector<core::RuleCheckMsg> check(int syscall, const core::SyscallParameter & sp) override;
};

}}