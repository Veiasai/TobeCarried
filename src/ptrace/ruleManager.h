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
    virtual std::vector<RuleCheckMsg> check(int syscallNumber, const core::SyscallParameter & sp) = 0;
};

class YamlRuleManger : public RuleManager
{
private:
    // map from syscall number to rules applied
    std::map<int, std::vector<std::unique_ptr<Rule>>> rules;
public:
    YamlRuleManger(const YAML::Node & yaml);
    virtual ~YamlRuleManger() {};
    virtual std::vector<RuleCheckMsg> check(int syscall, const core::SyscallParameter & sp) override;
};

}}